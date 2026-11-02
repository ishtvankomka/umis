import { base64urlDecode } from './bytes.js';
import { decodeJwsUnverified, signJws, type JwsHeader } from './jws.js';
import { DISCLOSABLE_CLAIMS, LIMITS, RISK_CLASSES, TYP, type DisclosableClaim, type RiskClass } from './profile.js';
import { UmisError } from './reasons.js';
import type { AuthorityRequest, PresentationRequestPayloadV1, Signer } from './types.js';

type Json = Record<string, unknown>;

/** 16 random bytes are 22 base64url characters. */
const MIN_NONCE_CHARS = 22;
/** Header members a request may carry; `crit` and everything else are refused, as for every UMIS token. */
const HEADER_MEMBERS: ReadonlySet<string> = new Set(['alg', 'typ', 'kid', 'jwk']);

const malformed = (message: string): UmisError => new UmisError('MALFORMED', message);

function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

function record(value: unknown, what: string): Json {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw malformed(`${what} must be a JSON object`);
  }
  return value as Json;
}

function text(value: unknown, what: string): string {
  if (typeof value !== 'string' || value === '') throw malformed(`${what} must be a non-empty string`);
  return value;
}

function finite(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw malformed(`${what} must be a finite number`);
  return value;
}

function textList(value: unknown, what: string): string[] {
  if (!Array.isArray(value) || value.length === 0) throw malformed(`${what} must be a non-empty array`);
  return value.map((item, index) => text(item, `${what}[${index}]`));
}

function readAuthorityRequest(value: unknown): AuthorityRequest {
  const o = record(value, 'authority');
  const amount = finite(own(o, 'amount'), 'authority.amount');
  if (amount < 0) throw malformed('authority.amount must not be negative');
  const request: AuthorityRequest = {
    action: text(own(o, 'action'), 'authority.action'),
    resource: text(own(o, 'resource'), 'authority.resource'),
    amount,
    unit: text(own(o, 'unit'), 'authority.unit'),
  };
  const object = own(o, 'object');
  if (object !== undefined) request.object = text(object, 'authority.object');
  return request;
}

/** Applies the rules of a presentation request and returns a clean copy; MALFORMED on the first violation. */
function readRequest(raw: Json): PresentationRequestPayloadV1 {
  if (own(raw, 'v') !== 1) throw malformed('v must be 1');
  const nonce = text(own(raw, 'nonce'), 'nonce');
  if (nonce.length < MIN_NONCE_CHARS) throw malformed('the nonce is too short');
  try {
    base64urlDecode(nonce);
  } catch {
    throw malformed('the nonce is not canonical base64url');
  }
  const iat = finite(own(raw, 'iat'), 'iat');
  const exp = finite(own(raw, 'exp'), 'exp');
  if (!(exp > iat && exp - iat <= LIMITS.requestMaxTtlS)) {
    throw malformed(`a request lives for 1 to ${LIMITS.requestMaxTtlS} seconds`);
  }
  const claims = textList(own(raw, 'claims'), 'claims');
  for (const claim of claims) {
    if (!(DISCLOSABLE_CLAIMS as readonly string[]).includes(claim)) throw malformed(`"${claim}" is not a UMIS claim`);
  }

  const request: PresentationRequestPayloadV1 = {
    v: 1,
    nonce,
    aud: text(own(raw, 'aud'), 'aud'),
    iat,
    exp,
    vct: textList(own(raw, 'vct'), 'vct'),
    claims: claims as DisclosableClaim[],
  };

  if (own(raw, 'authority') !== undefined) {
    request.authority = readAuthorityRequest(own(raw, 'authority'));
    if (!claims.includes('authority') || !claims.includes('delegation')) {
      throw malformed('a request for authority also requests the delegation');
    }
  }
  if (own(raw, 'policy') !== undefined) {
    const policy = record(own(raw, 'policy'), 'policy');
    const version = own(policy, 'v');
    const risk = own(policy, 'risk');
    if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 0) {
      throw malformed('policy.v must be a non-negative integer');
    }
    if (typeof risk !== 'string' || !(RISK_CLASSES as readonly string[]).includes(risk)) {
      throw malformed('policy.risk is not a risk class');
    }
    request.policy = { id: text(own(policy, 'id'), 'policy.id'), v: version, risk: risk as RiskClass };
  }
  if (own(raw, 'verifier') !== undefined) {
    const verifier = record(own(raw, 'verifier'), 'verifier');
    request.verifier = { name: text(own(verifier, 'name'), 'verifier.name') };
    if (own(verifier, 'org') !== undefined) request.verifier.org = text(own(verifier, 'org'), 'verifier.org');
  }
  const mutual = own(raw, 'mutual');
  if (mutual !== undefined) {
    if (typeof mutual !== 'boolean') throw malformed('mutual must be a boolean');
    request.mutual = mutual;
  }
  return request;
}

/**
 * Signs a presentation request as an `umis-req+jwt`. The payload must satisfy the rules that
 * {@link decodePresentationRequest} applies, or the call fails with INVALID_ARGUMENT; the header carries the signer's
 * `kid`.
 */
export async function signPresentationRequest(payload: PresentationRequestPayloadV1, signer: Signer): Promise<string> {
  let checked: PresentationRequestPayloadV1;
  try {
    checked = readRequest(record(payload, 'the request'));
  } catch (cause) {
    throw new UmisError('INVALID_ARGUMENT', cause instanceof Error ? cause.message : 'invalid request', { cause });
  }
  return signJws({ header: { typ: TYP.request }, payload: checked, signer });
}

/**
 * Reads a presentation request without checking its signature. MALFORMED unless: `v` is 1; the nonce is canonical
 * base64url of at least 22 characters; the request lives for more than 0 and at most `LIMITS.requestMaxTtlS` seconds;
 * `claims` is a non-empty list of UMIS claims; `vct` is a non-empty list; and a request for `authority` also asks for
 * `delegation`. A `typ` other than `umis-req+jwt` is UNSUPPORTED_FORMAT. The payload that comes back is a clean copy.
 */
export function decodePresentationRequest(jws: string): { header: JwsHeader; payload: PresentationRequestPayloadV1 } {
  const decoded = decodeJwsUnverified<Json>(jws);
  for (const name of Object.keys(decoded.header)) {
    if (!HEADER_MEMBERS.has(name)) throw malformed(`unexpected request header member "${name}"`);
  }
  if (decoded.header.typ !== TYP.request) throw new UmisError('UNSUPPORTED_FORMAT', 'not a UMIS presentation request');
  return { header: decoded.header, payload: readRequest(decoded.payload) };
}
