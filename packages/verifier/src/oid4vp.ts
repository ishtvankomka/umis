import {
  ALG,
  DISCLOSABLE_CLAIMS,
  LIMITS,
  URI_SCHEMES,
  UmisError,
  bytesEqual,
  formEncode,
  splitUri,
  utf8Encode,
} from '@umis/core';
import type {
  CheckpointPolicyV1,
  CryptoProvider,
  DisclosableClaim,
  ReplayStore,
  TrustedIssuerEntryV1,
  VerificationResult,
  VerifierContext,
} from '@umis/core';
import { DEFAULT_POLICIES } from '@umis/policy';
import { execute, replayKey, verifyPresentation } from './pipeline.js';
import { createMemoryReplayStore } from './replay.js';

/** The client identifier prefix of a verifier that is known by the address its responses go to (OpenID4VP 1.0, 5.9.3). */
const CLIENT_ID_PREFIX = 'redirect_uri:';
/** The id of the credential query when the caller names none. */
const DEFAULT_QUERY_ID = 'umis';
const QUERY_ID = /^[A-Za-z0-9_-]{1,64}$/;
/** 16 random bytes as base64url are 22 characters; a longer nonce is fine. */
const NONCE = /^[A-Za-z0-9_-]{22,256}$/;
const MAX_QUERIES = 8;
const MAX_VCTS = 8;
const MAX_STATE_CHARS = 512;
const MAX_NAME_CHARS = 200;
const MAX_ADDRESS_CHARS = 1_024;
/** A response is not read when its `vp_token` is longer than this: a presentation is at most `LIMITS.frameMaxBytes`. */
const MAX_VP_TOKEN_CHARS = 65_536;
/** How old the key-binding JWT of a response may be: as long as a request may live. */
const RESPONSE_MAX_AGE_S = LIMITS.requestMaxTtlS;
const LOCAL_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1']);

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);
const malformed = (message: string, cause?: unknown): UmisError => new UmisError('MALFORMED', message, { cause });

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isText(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

/** Whether `text` holds a control character: a UTF-16 code unit from U+0000 to U+001F or from U+007F to U+009F. */
function hasControlCharacter(text: string): boolean {
  for (let index = 0; index < text.length; index++) {
    const unit = text.charCodeAt(index);
    if (unit <= 0x1f || (unit >= 0x7f && unit <= 0x9f)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------------------------
// the query
// ---------------------------------------------------------------------------------------------------------------

/** A DCQL query (OpenID4VP 1.0, section 6) as UMIS uses it: credentials of format `dc+sd-jwt`, asked for by type. */
export interface DcqlQuery {
  credentials: Array<{
    id: string;
    format: 'dc+sd-jwt';
    meta: { vct_values: string[] };
    claims?: Array<{ path: [DisclosableClaim] }>;
  }>;
}

/**
 * The query for UMIS credentials of the given types (`meta.vct_values`) that discloses the given claims, each as the path
 * of one top-level claim (OpenID4VP 1.0, section 6 and appendix B.3.5). The query has one credential query, `id` by
 * default `umis`; repeated types and claims are listed once. A claim that is not a UMIS claim, no type, or an `id` that
 * is not 1 to 64 letters, digits, `_` or `-` is INVALID_ARGUMENT.
 */
export function umisDcqlQuery(i: {
  vcts: readonly string[];
  claims: readonly DisclosableClaim[];
  id?: string;
}): DcqlQuery {
  if (!isRecord(i)) throw invalid('the query input is missing');
  const id = i.id ?? DEFAULT_QUERY_ID;
  if (typeof id !== 'string' || !QUERY_ID.test(id)) throw invalid('id is 1 to 64 letters, digits, "_" or "-"');
  if (!Array.isArray(i.vcts) || i.vcts.length === 0 || !i.vcts.every(isText)) {
    throw invalid('vcts must name at least one credential type');
  }
  if (!Array.isArray(i.claims)) throw invalid('claims must be an array of claim names');
  for (const name of i.claims) {
    if (!(DISCLOSABLE_CLAIMS as readonly string[]).includes(name))
      throw invalid(`"${String(name)}" is not a UMIS claim`);
  }

  const credential: DcqlQuery['credentials'][number] = {
    id,
    format: 'dc+sd-jwt',
    meta: { vct_values: [...new Set<string>(i.vcts)] },
  };
  const claims = [...new Set<DisclosableClaim>(i.claims)];
  if (claims.length > 0) credential.claims = claims.map((name) => ({ path: [name] }));
  return { credentials: [credential] };
}

/** A copy of a query that has been checked: what `createVpRequest` accepts. */
function checkedQuery(query: unknown): DcqlQuery {
  const fail = (reason: string): UmisError => invalid(`dcql ${reason}`);
  if (!isRecord(query) || !Array.isArray(query.credentials)) throw fail('must hold a list of credential queries');
  const list: unknown[] = query.credentials;
  if (list.length < 1 || list.length > MAX_QUERIES) throw fail(`must hold 1 to ${MAX_QUERIES} credential queries`);

  const ids = new Set<string>();
  const credentials = list.map((entry): DcqlQuery['credentials'][number] => {
    if (!isRecord(entry)) throw fail('has a credential query that is not an object');
    const { id, format, meta, claims } = entry;
    if (typeof id !== 'string' || !QUERY_ID.test(id) || ids.has(id)) {
      throw fail('needs an id of 1 to 64 letters, digits, "_" or "-" that is different for every credential query');
    }
    ids.add(id);
    if (format !== 'dc+sd-jwt') throw fail('asks for a format other than dc+sd-jwt');
    const vcts = isRecord(meta) ? meta.vct_values : undefined;
    if (!Array.isArray(vcts) || vcts.length < 1 || vcts.length > MAX_VCTS || !vcts.every(isText)) {
      throw fail(`needs 1 to ${MAX_VCTS} vct_values`);
    }
    const checked: DcqlQuery['credentials'][number] = { id, format, meta: { vct_values: [...vcts] } };
    if (claims !== undefined) {
      if (!Array.isArray(claims)) throw fail('has claims that are not a list');
      checked.claims = claims.map((claim: unknown) => {
        const path = isRecord(claim) ? claim.path : undefined;
        const name: unknown = Array.isArray(path) && path.length === 1 ? path[0] : undefined;
        if (typeof name !== 'string' || !(DISCLOSABLE_CLAIMS as readonly string[]).includes(name)) {
          throw fail('has a claim path that is not the name of one UMIS claim');
        }
        return { path: [name as DisclosableClaim] };
      });
    }
    return checked;
  });
  return { credentials };
}

// ---------------------------------------------------------------------------------------------------------------
// the request
// ---------------------------------------------------------------------------------------------------------------

/** The authorization request of OpenID4VP 1.0 as UMIS sends it: unsigned, by value, answered with `direct_post`. */
export interface VpRequestObject {
  client_id: string;
  response_type: 'vp_token';
  response_mode: 'direct_post';
  response_uri: string;
  nonce: string;
  state: string;
  dcql_query: DcqlQuery;
  client_metadata: {
    vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256']; 'kb-jwt_alg_values': ['ES256'] } };
    client_name?: string;
  };
}

/** The address responses go to: `https`, or `http` on the local machine; no user information, no fragment. */
function responseAddress(value: unknown): string {
  const fail = (reason: string): UmisError => invalid(`responseUri ${reason}`);
  if (typeof value !== 'string' || value.length > MAX_ADDRESS_CHARS || !/^[\x21-\x7e]+$/.test(value)) {
    throw fail('is not an address');
  }
  const { scheme, authority } = splitUri(value);
  const hostAndPort = /^([A-Za-z0-9.-]+)(?::[0-9]{1,5})?$/.exec(authority);
  if (hostAndPort === null || value.includes('#')) throw fail('is not a plain address without a fragment');
  const local = LOCAL_HOSTS.has((hostAndPort[1] ?? '').toLowerCase());
  if (!(scheme === 'https' || (scheme === 'http' && local))) throw fail('must be an https address');
  return value;
}

/**
 * An OpenID4VP 1.0 authorization request for a presentation, to be answered by `direct_post` to `responseUri`. The
 * verifier is identified by `client_id = "redirect_uri:" + responseUri` (section 5.9.3), so the request is not signed and
 * carries its metadata, the formats it can read, in `client_metadata`. `requestObject` holds the parameters; `walletUri`
 * is the same request by value as an `openid4vp://` link (sections 5.1 and 5.2), with the query and the metadata as JSON,
 * for a QR code or a deep link. The caller supplies `nonce` (at least 22 base64url characters, 16 random bytes) and
 * `state`, keeps them for `verifyVpResponse`, and uses each nonce once. `responseUri` must be `https` (or `http` on the
 * local machine); anything the request cannot carry is INVALID_ARGUMENT.
 */
export async function createVpRequest(i: {
  responseUri: string;
  nonce: string;
  state: string;
  dcql: DcqlQuery;
  clientName?: string;
}): Promise<{ requestObject: VpRequestObject; walletUri: string }> {
  if (!isRecord(i)) throw invalid('the request input is missing');
  const responseUri = responseAddress(i.responseUri);
  if (typeof i.nonce !== 'string' || !NONCE.test(i.nonce)) {
    throw invalid('nonce must be at least 22 letters, digits, "_" or "-": 16 random bytes as base64url');
  }
  if (!isText(i.state) || i.state.length > MAX_STATE_CHARS) {
    throw invalid(`state must be a non-empty string of at most ${MAX_STATE_CHARS} characters`);
  }
  const dcql = checkedQuery(i.dcql);

  const metadata: VpRequestObject['client_metadata'] = {
    vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': [ALG], 'kb-jwt_alg_values': [ALG] } },
  };
  if (i.clientName !== undefined) {
    if (!isText(i.clientName) || i.clientName.length > MAX_NAME_CHARS || hasControlCharacter(i.clientName)) {
      throw invalid(`clientName must be text of at most ${MAX_NAME_CHARS} characters without control characters`);
    }
    metadata.client_name = i.clientName;
  }

  const requestObject: VpRequestObject = {
    client_id: CLIENT_ID_PREFIX + responseUri,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: responseUri,
    nonce: i.nonce,
    state: i.state,
    dcql_query: dcql,
    client_metadata: metadata,
  };
  const walletUri = `${URI_SCHEMES.vpRequest}?${formEncode({
    client_id: requestObject.client_id,
    response_type: requestObject.response_type,
    response_mode: requestObject.response_mode,
    response_uri: requestObject.response_uri,
    nonce: requestObject.nonce,
    state: requestObject.state,
    dcql_query: JSON.stringify(dcql),
    client_metadata: JSON.stringify(metadata),
  })}`;
  return { requestObject, walletUri };
}

// ---------------------------------------------------------------------------------------------------------------
// the response
// ---------------------------------------------------------------------------------------------------------------

type ResponseInput = Parameters<typeof verifyVpResponse>[0];

/**
 * The one presentation in a response, or MALFORMED. The body must carry `vp_token`, a JSON object with exactly one
 * credential query id whose value is a list of exactly one presentation, and, when the verifier remembers a `state`, the
 * same `state`. The nonce and the audience of the request must be known: a verifier without them would accept any.
 */
function presentationOf(i: Partial<ResponseInput>): string {
  if (!isText(i.nonce)) throw malformed('the nonce of the request is missing');
  if (!isText(i.audience)) throw malformed('the audience of the request is missing');
  const { body } = i;
  if (!isRecord(body)) throw malformed('the response has no form fields');

  if (i.state !== undefined) {
    const echoed = Object.hasOwn(body, 'state') ? body.state : undefined;
    if (!isText(i.state) || typeof echoed !== 'string' || !bytesEqual(utf8Encode(echoed), utf8Encode(i.state))) {
      throw malformed('the state of the response is not the state of the request');
    }
  }

  const token = Object.hasOwn(body, 'vp_token') ? body.vp_token : undefined;
  if (typeof token !== 'string' || token.length > MAX_VP_TOKEN_CHARS)
    throw malformed('vp_token is missing or too long');
  let answers: unknown;
  try {
    answers = JSON.parse(token);
  } catch (cause) {
    throw malformed('vp_token is not JSON', cause);
  }
  if (!isRecord(answers)) throw malformed('vp_token is not a JSON object');
  const ids = Object.keys(answers);
  if (ids.length !== 1) throw malformed('vp_token answers one credential query');
  const presentations = answers[ids[0]!];
  if (!Array.isArray(presentations) || presentations.length !== 1 || typeof presentations[0] !== 'string') {
    throw malformed('vp_token holds one presentation for the credential query');
  }
  return presentations[0];
}

/**
 * Decides on the response to a request made by {@link createVpRequest}: `body` is the form the wallet posted (`vp_token`
 * and `state`), `nonce` and `state` are those of the request and `audience` is its `client_id`, prefix included. The
 * presentation goes through the nine steps with channel `oid4vp`: its key-binding JWT must carry that audience and nonce
 * and be at most 120 seconds old, the nonce is accepted once (the id `vp:<nonce>` in `replay`; without a `replay` store
 * nothing is remembered), the issuer must be one of `trusted`, and status lists come only from `fetchStatusList`, once for
 * each address and held to the policy's maximum age. The policy is `DEFAULT_POLICIES.login_oid4vp` unless given, and the
 * claims it names in `requestedClaims` must be disclosed; they are the claims the DCQL query of the request asks for.
 *
 * A body with no `vp_token`, more or fewer than one query id or presentation, or a `state` that differs, is MALFORMED,
 * and so is a missing nonce or audience. The function never throws; the result has exactly one reason.
 */
export function verifyVpResponse(i: {
  body: Record<string, string>;
  nonce: string;
  audience: string;
  trusted: readonly TrustedIssuerEntryV1[];
  fetchStatusList: (uri: string) => Promise<string>;
  now: number;
  policy?: CheckpointPolicyV1;
  replay?: ReplayStore;
  state?: string;
  crypto?: CryptoProvider;
}): Promise<VerificationResult> {
  const given: Partial<ResponseInput> = isRecord(i) ? i : {};
  const policy = given.policy ?? DEFAULT_POLICIES.login_oid4vp;
  const ctx: VerifierContext = {
    now: given.now as number,
    audiences: [given.audience as string],
    policy,
    trusted: given.trusted as readonly TrustedIssuerEntryV1[],
    statusLists: new Map(),
    replay: given.replay ?? createMemoryReplayStore(),
    fetchStatusList: given.fetchStatusList,
    ...(given.crypto === undefined ? {} : { crypto: given.crypto }),
  };

  let presentation: string;
  try {
    presentation = presentationOf(given);
  } catch (error) {
    return execute(ctx, 'oid4vp', {}, () => {
      throw error;
    });
  }
  return verifyPresentation(presentation, ctx, {
    channel: 'oid4vp',
    aud: given.audience as string,
    nonce: given.nonce as string,
    maxAgeSeconds: RESPONSE_MAX_AGE_S,
    requiredClaims: (policy as Partial<CheckpointPolicyV1> | null)?.requestedClaims,
    replayKey: (nonce) => replayKey('vp:', nonce),
    replayExpiresAt: ctx.now + RESPONSE_MAX_AGE_S + LIMITS.defaultSkewS,
  });
}
