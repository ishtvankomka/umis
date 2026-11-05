import {
  ALG,
  DISCLOSABLE_CLAIMS,
  URI_SCHEMES,
  UmisError,
  asEcPublicJwk,
  decodeCredential,
  formEncode,
  parseQuery,
  presentCredential,
  publicJwkEquals,
  splitUri,
} from '@umis/core';
import type { CryptoProvider, DisclosableClaim, FetchLike, Signer } from '@umis/core';

/** The client identifier prefix of a verifier that is known by the address its responses go to (OpenID4VP 1.0, 5.9.3). */
const CLIENT_ID_PREFIX = 'redirect_uri:';
const REQUEST_SCHEME = URI_SCHEMES.vpRequest.slice(0, -'://'.length);
const QUERY_ID = /^[A-Za-z0-9_-]{1,64}$/;
/** A request that is longer is refused unread. */
const MAX_REQUEST_CHARS = 16_384;
const MAX_FIELD_CHARS = 1_024;
const MAX_NAME_CHARS = 200;
const MAX_ADDRESS_CHARS = 1_024;
const MAX_QUERIES = 8;
const MAX_VCTS = 8;
/** The answer of the verifier is a small document; a longer one is not read. */
const MAX_BODY_CHARS = 65_536;
const LOCAL_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1']);

type Json = Record<string, unknown>;

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);
const malformed = (message: string): UmisError => new UmisError('MALFORMED', message);
const protocol = (message: string): UmisError => new UmisError('PROTOCOL', message);

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
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

function jsonObject(text: string): Json | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/** An address a wallet may send a presentation to or follow: `https`, or `http` on the local machine; no fragment. */
function webAddress(value: unknown, what: string, code: UmisError['code']): string {
  const fail = (reason: string): UmisError => new UmisError(code, `${what} ${reason}`);
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

// ---------------------------------------------------------------------------------------------------------------
// reading a request
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

/** What a wallet shows the holder about a request, and what it needs to answer it. */
export interface ParsedVpRequest {
  /** The client identifier as the request has it, prefix included: the audience of the answer. */
  clientId: string;
  /** Where the answer is posted. */
  responseUri: string;
  nonce: string;
  state?: string;
  dcql: DcqlQuery;
  /** The name the verifier gives itself. Nobody vouches for it, because the request is not signed. */
  clientName?: string;
  /** The credential types and claims the query names, all credential queries together. */
  requested: { vcts: string[]; claims: DisclosableClaim[] };
}

function readClaim(claim: unknown): { path: [DisclosableClaim] } {
  if (!isRecord(claim)) throw malformed('a claim query is not an object');
  for (const name of Object.keys(claim)) {
    if (name !== 'path') throw protocol(`a claim query with "${name}" is not accepted`);
  }
  const path = own(claim, 'path');
  if (!Array.isArray(path)) throw malformed('a claim query has no path');
  const name: unknown = path.length === 1 ? path[0] : undefined;
  if (typeof name !== 'string' || !(DISCLOSABLE_CLAIMS as readonly string[]).includes(name)) {
    throw protocol('a claim path names one claim of a UMIS credential');
  }
  return { path: [name as DisclosableClaim] };
}

function readQuery(text: string): DcqlQuery {
  const query = jsonObject(text);
  if (query === undefined) throw malformed('dcql_query is not a JSON object');
  for (const name of Object.keys(query)) {
    if (name !== 'credentials') throw protocol(`dcql_query with "${name}" is not accepted`);
  }
  const list = own(query, 'credentials');
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_QUERIES) {
    throw malformed(`dcql_query holds 1 to ${MAX_QUERIES} credential queries`);
  }

  const ids = new Set<string>();
  const credentials = list.map((entry: unknown): DcqlQuery['credentials'][number] => {
    if (!isRecord(entry)) throw malformed('a credential query is not an object');
    for (const name of Object.keys(entry)) {
      if (!['id', 'format', 'meta', 'claims'].includes(name)) {
        throw protocol(`a credential query with "${name}" is not accepted`);
      }
    }
    const id = own(entry, 'id');
    if (typeof id !== 'string' || !QUERY_ID.test(id) || ids.has(id)) {
      throw malformed('every credential query has an id of its own');
    }
    ids.add(id);
    if (own(entry, 'format') !== 'dc+sd-jwt') throw protocol('only credentials of format dc+sd-jwt are accepted');

    const meta = own(entry, 'meta');
    if (!isRecord(meta)) throw malformed('a credential query has no meta');
    for (const name of Object.keys(meta)) {
      if (name !== 'vct_values') throw protocol(`a credential query meta with "${name}" is not accepted`);
    }
    const vcts = own(meta, 'vct_values');
    if (!Array.isArray(vcts) || vcts.length < 1 || vcts.length > MAX_VCTS || !vcts.every(isText)) {
      throw malformed(`vct_values lists 1 to ${MAX_VCTS} credential types`);
    }

    const credential: DcqlQuery['credentials'][number] = { id, format: 'dc+sd-jwt', meta: { vct_values: [...vcts] } };
    const claims = own(entry, 'claims');
    if (claims !== undefined) {
      if (!Array.isArray(claims)) throw malformed('claims is not a list');
      credential.claims = claims.map(readClaim);
    }
    return credential;
  });
  return { credentials };
}

function readClientName(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  const metadata = jsonObject(text);
  if (metadata === undefined) throw malformed('client_metadata is not a JSON object');
  const name = own(metadata, 'client_name');
  const usable = isText(name) && name.length <= MAX_NAME_CHARS && !hasControlCharacter(name);
  return usable ? name : undefined;
}

/**
 * Refuses a query that names a parameter more than once (RFC 6749, section 3.1). `parseQuery` keeps the first value of
 * a repeated name, so a reader that keeps the last one would see another request. Names are compared as `parseQuery`
 * decodes them: `response%5Fmode` is `response_mode`. A broken escape in a name is MALFORMED, as in `parseQuery`.
 */
function refuseRepeatedParameters(query: string): void {
  const names = new Set<string>();
  for (const pair of (query.startsWith('?') ? query.slice(1) : query).split('&')) {
    if (pair === '') continue;
    const separator = pair.indexOf('=');
    const [name = ''] = Object.keys(parseQuery(`${separator === -1 ? pair : pair.slice(0, separator)}=`));
    if (names.has(name)) throw protocol('the request names a parameter more than once');
    names.add(name);
  }
}

/**
 * Reads an OpenID4VP 1.0 authorization request that comes by value in an `openid4vp://` link or QR code (the address
 * `openid4vp://?...` or `openid4vp://authorize?...`). UMIS takes one kind of request: `response_type=vp_token` and
 * `response_mode=direct_post`, a `client_id` of the form `redirect_uri:<response_uri>` whose address is the
 * `response_uri` (which must be `https`, or `http` on the local machine), a `nonce`, an optional `state` and a
 * `dcql_query` that asks for `dc+sd-jwt` credentials by `vct_values` and for whole UMIS claims by path. The request is
 * not signed, so the name in `client_metadata` is the verifier's own word.
 *
 * Text that is not an `openid4vp://` address is UNSUPPORTED_FORMAT. A request that is damaged is MALFORMED. A request
 * that is well formed but outside what UMIS takes is PROTOCOL: one that names a parameter twice, one by reference
 * (`request_uri`) or signed (`request`), one with `transaction_data` (UMIS knows no transaction data type), another
 * response type or mode (`direct_post.jwt` among them), another kind of client identifier, a `client_id` and
 * `response_uri` that differ, and a query with features or claim paths beyond the above.
 */
export function parseVpRequest(walletUri: string): ParsedVpRequest {
  if (typeof walletUri !== 'string') throw invalid('the request address must be a string');
  const text = walletUri.trim();
  if (text.length > MAX_REQUEST_CHARS) throw malformed('the request is too long');
  const parts = splitUri(text);
  if (parts.scheme !== REQUEST_SCHEME) throw new UmisError('UNSUPPORTED_FORMAT', 'not an OpenID4VP request');
  const authority = parts.authority.toLowerCase();
  const plain = text.slice(0, URI_SCHEMES.vpRequest.length).toLowerCase() === URI_SCHEMES.vpRequest;
  if (!plain || (authority !== '' && authority !== 'authorize') || parts.path !== '' || text.includes('#')) {
    throw malformed('the address of the request is not openid4vp://?... or openid4vp://authorize?...');
  }

  refuseRepeatedParameters(parts.query);
  const query = parseQuery(parts.query);
  const field = (name: string): string | undefined => {
    const value = own(query, name);
    return typeof value === 'string' ? value : undefined;
  };
  if (field('request_uri') !== undefined || field('request') !== undefined) {
    throw protocol('a request by reference or as a signed object is not accepted');
  }
  if (field('transaction_data') !== undefined) {
    throw protocol('a request with transaction_data is not accepted: no transaction data type is supported');
  }
  if (field('response_type') !== 'vp_token') throw protocol('only response_type vp_token is accepted');
  if (field('response_mode') !== 'direct_post') throw protocol('only response_mode direct_post is accepted');

  const clientId = field('client_id');
  if (!isText(clientId)) throw malformed('client_id is missing');
  if (!clientId.startsWith(CLIENT_ID_PREFIX)) {
    throw protocol(`only a client_id with the prefix ${CLIENT_ID_PREFIX} is accepted`);
  }
  const responseUri = field('response_uri');
  if (!isText(responseUri)) throw malformed('response_uri is missing');
  if (responseUri !== clientId.slice(CLIENT_ID_PREFIX.length)) {
    throw protocol('client_id and response_uri name different addresses');
  }
  webAddress(responseUri, 'response_uri', 'PROTOCOL');

  const nonce = field('nonce');
  if (!isText(nonce) || nonce.length > MAX_FIELD_CHARS) throw malformed('nonce is missing or too long');
  const state = field('state');
  if (state !== undefined && (state === '' || state.length > MAX_FIELD_CHARS)) {
    throw malformed('state is empty or too long');
  }
  const queryText = field('dcql_query');
  if (queryText === undefined) throw malformed('dcql_query is missing');
  const dcql = readQuery(queryText);
  const clientName = readClientName(field('client_metadata'));

  const vcts = new Set<string>();
  const claims = new Set<DisclosableClaim>();
  for (const credential of dcql.credentials) {
    for (const vct of credential.meta.vct_values) vcts.add(vct);
    for (const claim of credential.claims ?? []) claims.add(claim.path[0]);
  }
  const parsed: ParsedVpRequest = {
    clientId,
    responseUri,
    nonce,
    dcql,
    requested: { vcts: [...vcts], claims: [...claims] },
  };
  if (state !== undefined) parsed.state = state;
  if (clientName !== undefined) parsed.clientName = clientName;
  return parsed;
}

// ---------------------------------------------------------------------------------------------------------------
// answering it
// ---------------------------------------------------------------------------------------------------------------

function fetcher(custom: FetchLike | undefined): FetchLike {
  if (custom !== undefined) {
    if (typeof custom !== 'function') throw invalid('fetch must be a function');
    return custom;
  }
  if (typeof globalThis.fetch !== 'function') throw new UmisError('NETWORK', 'no fetch function is available');
  return (url, init) => globalThis.fetch(url, init);
}

/** The address the verifier asks the user agent to continue at (OpenID4VP 1.0, section 8.2), if it names a usable one. */
async function continuation(response: Awaited<ReturnType<FetchLike>>): Promise<string | undefined> {
  if (response.status < 200 || response.status >= 300) return undefined;
  try {
    const announced = Number(response.headers.get('content-length') ?? 0);
    if (announced > MAX_BODY_CHARS) return undefined;
    const text = await response.text();
    const body = text.length > MAX_BODY_CHARS ? undefined : jsonObject(text);
    return body === undefined ? undefined : webAddress(own(body, 'redirect_uri'), 'redirect_uri', 'PROTOCOL');
  } catch {
    return undefined;
  }
}

/**
 * Answers an OpenID4VP request: reads it as {@link parseVpRequest} does, presents the credential with the claims named
 * in `disclose` and posts the answer to the request's `response_uri` as a form (`vp_token={"<query id>":["<presentation>"]}`
 * and the `state` of the request), as OpenID4VP 1.0 sections 8.1 and 8.2 have it. The key-binding JWT is signed by
 * `signer` at `now` for the audience `client_id` (prefix included) with the nonce of the request, so the answer is good
 * for this request and this verifier only.
 *
 * Nothing beyond the request is disclosed: a claim the credential query does not ask for, a credential of a type it does
 * not name, and a signer that is not the holder key of the credential are INVALID_ARGUMENT, before anything is sent. A
 * request the wallet does not take is as in {@link parseVpRequest}. `fetch` is the global `fetch` unless given; the post
 * asks not to follow redirects (`redirect: 'error'`), so with the global `fetch` the presentation goes to `response_uri`
 * and nowhere else; a post that fails is NETWORK. The result is the HTTP status of the verifier's answer, with
 * `redirectUri` when a successful answer asks the user agent to continue at an `https` address (or `http` on the local
 * machine).
 */
export async function respondToVpRequest(i: {
  walletUri: string;
  sdJwtVc: string;
  disclose: readonly DisclosableClaim[];
  signer: Signer;
  now: number;
  fetch?: FetchLike;
  crypto?: CryptoProvider;
}): Promise<{ status: number; redirectUri?: string }> {
  if (!isRecord(i)) throw invalid('the input is missing');
  if (typeof i.now !== 'number' || !Number.isFinite(i.now)) throw invalid('now must be a finite number of seconds');
  const request = parseVpRequest(i.walletUri);

  const { signer } = i;
  if (typeof signer !== 'object' || signer === null || signer.alg !== ALG || typeof signer.sign !== 'function') {
    throw invalid('expected an ES256 signer');
  }
  const decoded = decodeCredential(i.sdJwtVc);
  if (!publicJwkEquals(asEcPublicJwk(signer.publicJwk), decoded.cnfJwk)) {
    throw invalid('the signer is not the holder key of this credential');
  }
  const credentialQuery = request.dcql.credentials.find((candidate) => candidate.meta.vct_values.includes(decoded.vct));
  if (credentialQuery === undefined) throw invalid('the request does not accept this type of credential');
  if (!Array.isArray(i.disclose)) throw invalid('disclose must be an array of claim names');
  const asked = (credentialQuery.claims ?? []).map((claim) => claim.path[0]);
  const disclose: DisclosableClaim[] = [];
  for (const name of i.disclose) {
    if (!asked.includes(name)) throw invalid(`the request does not ask for "${String(name)}"`);
    if (!disclose.includes(name)) disclose.push(name);
  }
  const send = fetcher(i.fetch);

  const presentation = await presentCredential({
    credential: i.sdJwtVc,
    disclose,
    kb: { signer, aud: request.clientId, nonce: request.nonce, iat: i.now },
    crypto: i.crypto,
  });
  const form: Record<string, string> = {
    vp_token: JSON.stringify(Object.fromEntries([[credentialQuery.id, [presentation]]])),
  };
  if (request.state !== undefined) form.state = request.state;

  let response: Awaited<ReturnType<FetchLike>>;
  try {
    response = await send(request.responseUri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: formEncode(form),
      redirect: 'error',
    });
  } catch (cause) {
    throw new UmisError('NETWORK', 'the response could not be delivered', { cause });
  }
  const redirectUri = await continuation(response);
  return redirectUri === undefined ? { status: response.status } : { status: response.status, redirectUri };
}
