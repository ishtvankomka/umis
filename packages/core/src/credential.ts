import { base64urlDecode, utf8Decode } from './bytes.js';
import { asEcPublicJwk } from './jwk.js';
import { decodeJwsUnverified } from './jws.js';
import { DISCLOSABLE_CLAIMS, LIMITS, PERIODS, TYP, type DisclosableClaim, type Period } from './profile.js';
import { UmisError } from './reasons.js';
import type {
  AuthorityItem,
  AuthorityLimit,
  CredentialPayload,
  DelegationClaim,
  DelegationParent,
  EcPublicJwk,
  StatusRef,
  UmisClaimSet,
} from './types.js';

/**
 * What a credential looks like for display: the plain claims, the claims behind the disclosures that the string holds,
 * and the names of those disclosures. Nothing here is checked against a digest or a signature.
 */
export interface DecodedCredential {
  issuer: string;
  vct: string;
  jti: string;
  sub: string;
  iat: number;
  exp: number;
  nbf?: number;
  kid?: string;
  cnfJwk: EcPublicJwk;
  status: StatusRef;
  claims: Partial<UmisClaimSet>;
  disclosable: DisclosableClaim[];
  hasKeyBinding: boolean;
}

type Json = Record<string, unknown>;

/** Keys that SD-JWT reserves; the UMIS profile admits none of them below the top level of a credential. */
const RESERVED_KEYS: ReadonlySet<string> = new Set(['_sd', '_sd_alg', '_sd_decoy', '...']);
/** Disclosed values are shallow in every profile claim; anything deeper than this is refused unread. */
const MAX_SCAN_DEPTH = 16;

const malformed = (message: string, cause?: unknown): UmisError => new UmisError('MALFORMED', message, { cause });

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** An own member of a parsed JSON object; inherited properties never count. */
function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

function record(value: unknown, what: string): Json {
  if (!isRecord(value)) throw malformed(`${what} must be a JSON object`);
  return value;
}

function text(value: unknown, what: string): string {
  if (typeof value !== 'string' || value === '') throw malformed(`${what} must be a non-empty string`);
  return value;
}

function finite(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw malformed(`${what} must be a finite number`);
  return value;
}

/** A non-negative safe integer. */
function natural(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw malformed(`${what} must be a non-negative integer`);
  }
  return value;
}

/**
 * Refuses the SD-JWT reserved keys (`_sd`, `_sd_alg`, `_sd_decoy`, `...`) anywhere inside `value`. The profile has no
 * nested, recursive or array-element disclosures, so such a key can only be an attempt to smuggle one in.
 */
export function assertNoReservedKeys(value: unknown, what: string, depth = 0): void {
  if (typeof value !== 'object' || value === null) return;
  if (depth > MAX_SCAN_DEPTH) throw malformed(`${what} is nested too deeply`);
  if (Array.isArray(value)) {
    for (const item of value) assertNoReservedKeys(item, what, depth + 1);
    return;
  }
  for (const [key, member] of Object.entries(value)) {
    if (RESERVED_KEYS.has(key)) throw malformed(`${what} contains the reserved key "${key}"`);
    assertNoReservedKeys(member, what, depth + 1);
  }
}

// ---------------------------------------------------------------------------------------------------------------
// claim shapes
// ---------------------------------------------------------------------------------------------------------------

export function readStatusRef(value: unknown, what: string): StatusRef {
  const o = record(value, what);
  return { uri: text(own(o, 'uri'), `${what}.uri`), idx: natural(own(o, 'idx'), `${what}.idx`) };
}

function readLimit(value: unknown, what: string): AuthorityLimit {
  const o = record(value, what);
  const amount = finite(own(o, 'amount'), `${what}.amount`);
  if (amount < 0) throw malformed(`${what}.amount must not be negative`);
  const limit: AuthorityLimit = { amount, unit: text(own(o, 'unit'), `${what}.unit`) };
  const per = own(o, 'per');
  if (per !== undefined) {
    if (typeof per !== 'string' || !(PERIODS as readonly string[]).includes(per)) {
      throw malformed(`${what}.per must be one of ${PERIODS.join(', ')}`);
    }
    limit.per = per as Period;
  }
  return limit;
}

export function readAuthorityItem(value: unknown, what: string): AuthorityItem {
  const o = record(value, what);
  const item: AuthorityItem = {
    action: text(own(o, 'action'), `${what}.action`),
    resource: text(own(o, 'resource'), `${what}.resource`),
    limit: readLimit(own(o, 'limit'), `${what}.limit`),
  };
  const object = own(o, 'object');
  if (object !== undefined) item.object = text(object, `${what}.object`);
  const validUntil = own(o, 'valid_until');
  if (validUntil !== undefined) item.valid_until = finite(validUntil, `${what}.valid_until`);
  return item;
}

function readAuthorityList(value: unknown, what: string): AuthorityItem[] {
  if (!Array.isArray(value) || value.length === 0) throw malformed(`${what} must be a non-empty array`);
  return value.map((item, index) => readAuthorityItem(item, `${what}[${index}]`));
}

function readParent(value: unknown, what: string): DelegationParent {
  const o = record(value, what);
  return {
    id: text(own(o, 'id'), `${what}.id`),
    status: readStatusRef(own(o, 'status'), `${what}.status`),
    authority: readAuthorityList(own(o, 'authority'), `${what}.authority`),
    exp: finite(own(o, 'exp'), `${what}.exp`),
  };
}

function readDelegation(value: unknown, what: string): DelegationClaim {
  const o = record(value, what);
  const depth = natural(own(o, 'depth'), `${what}.depth`);
  const maxDepth = natural(own(o, 'max_depth'), `${what}.max_depth`);
  const parent = own(o, 'parent');
  return parent === undefined
    ? { depth, max_depth: maxDepth }
    : { parent: readParent(parent, `${what}.parent`), depth, max_depth: maxDepth };
}

/** Validates the value of one disclosable claim and stores a clean copy in `target`; unknown members are dropped. */
export function assignClaim(target: Partial<UmisClaimSet>, name: DisclosableClaim, value: unknown): void {
  const what = `claim "${name}"`;
  switch (name) {
    case 'org': {
      const o = record(value, what);
      const org: UmisClaimSet['org'] = {
        id: text(own(o, 'id'), `${what}.id`),
        name: text(own(o, 'name'), `${what}.name`),
      };
      const lei = own(o, 'lei');
      if (lei !== undefined) org.lei = text(lei, `${what}.lei`);
      target.org = org;
      return;
    }
    case 'org_unit': {
      const o = record(value, what);
      target.org_unit = { id: text(own(o, 'id'), `${what}.id`), name: text(own(o, 'name'), `${what}.name`) };
      return;
    }
    case 'role': {
      const o = record(value, what);
      target.role = { code: text(own(o, 'code'), `${what}.code`), name: text(own(o, 'name'), `${what}.name`) };
      return;
    }
    case 'authority':
      target.authority = readAuthorityList(value, what);
      return;
    case 'delegation':
      target.delegation = readDelegation(value, what);
      return;
    case 'display': {
      const o = record(value, what);
      const display: NonNullable<UmisClaimSet['display']> = { name: text(own(o, 'name'), `${what}.name`) };
      const photoHash = own(o, 'photo_hash');
      if (photoHash !== undefined) display.photo_hash = text(photoHash, `${what}.photo_hash`);
      target.display = display;
      return;
    }
  }
}

/** Reads every claim of `source` whose name is a disclosable claim, validating its shape. */
export function readClaims(source: Json): Partial<UmisClaimSet> {
  const claims: Partial<UmisClaimSet> = {};
  for (const name of DISCLOSABLE_CLAIMS) {
    const value = own(source, name);
    if (value !== undefined) assignClaim(claims, name, value);
  }
  return claims;
}

/** The always-visible claims of a credential, validated and copied; the key's private part never survives. */
export function readCredentialPayload(raw: Json): CredentialPayload {
  const cnf = record(own(raw, 'cnf'), 'cnf');
  let jwk: EcPublicJwk;
  try {
    jwk = asEcPublicJwk(own(cnf, 'jwk'));
  } catch (cause) {
    throw malformed('cnf.jwk is not a P-256 public key', cause);
  }
  const status = record(own(raw, 'status'), 'status');
  const payload: CredentialPayload = {
    iss: text(own(raw, 'iss'), 'iss'),
    sub: text(own(raw, 'sub'), 'sub'),
    jti: text(own(raw, 'jti'), 'jti'),
    iat: finite(own(raw, 'iat'), 'iat'),
    exp: finite(own(raw, 'exp'), 'exp'),
    vct: text(own(raw, 'vct'), 'vct'),
    cnf: { jwk },
    status: { status_list: readStatusRef(own(status, 'status_list'), 'status.status_list') },
  };
  const nbf = own(raw, 'nbf');
  if (nbf !== undefined) payload.nbf = finite(nbf, 'nbf');
  return payload;
}

/** Decodes the text of one disclosure into its three parts: `[salt, name, value]` as JSON, base64url-encoded. */
export function readDisclosure(raw: string): { salt: string; name: DisclosableClaim; value: unknown } {
  let decoded: unknown;
  try {
    decoded = JSON.parse(utf8Decode(base64urlDecode(raw)));
  } catch (cause) {
    if (cause instanceof UmisError) throw cause;
    throw malformed('a disclosure is not valid JSON', cause);
  }
  if (!Array.isArray(decoded) || decoded.length !== 3) {
    throw malformed('a disclosure is an array of salt, claim name and value');
  }
  const [salt, name, value] = decoded as [unknown, unknown, unknown];
  if (typeof salt !== 'string') throw malformed('a disclosure salt must be a string');
  if (typeof name !== 'string' || !(DISCLOSABLE_CLAIMS as readonly string[]).includes(name)) {
    throw malformed('a disclosure names a claim that the profile does not define');
  }
  assertNoReservedKeys(value, `claim "${name}"`);
  return { salt, name: name as DisclosableClaim, value };
}

// ---------------------------------------------------------------------------------------------------------------
// display decoding
// ---------------------------------------------------------------------------------------------------------------

/**
 * Reads a credential (or a presentation) for display. The disclosures are decoded and their shapes checked, but no
 * digest, signature or time is verified, so a result from here must never decide anything: use `parseSdJwt` and the
 * verification functions for that.
 */
export function decodeCredential(sdJwtVc: string): DecodedCredential {
  if (typeof sdJwtVc !== 'string' || sdJwtVc.length > LIMITS.frameMaxBytes) {
    throw malformed('not an SD-JWT of an admissible size');
  }
  const parts = sdJwtVc.split('~');
  if (parts.length < 2) throw malformed('an SD-JWT has at least one "~"');
  const issuer = decodeJwsUnverified<Json>(parts[0] ?? '');
  if (issuer.header.typ !== TYP.sdJwtVc) throw new UmisError('UNSUPPORTED_FORMAT', 'not an SD-JWT VC');

  const payload = readCredentialPayload(issuer.payload);
  const claims = readClaims(issuer.payload);
  const disclosable: DisclosableClaim[] = [];
  for (const raw of parts.slice(1, -1)) {
    const { name, value } = readDisclosure(raw);
    if (Object.hasOwn(claims, name)) throw malformed(`claim "${name}" is given twice`);
    assignClaim(claims, name, value);
    disclosable.push(name);
  }

  const decoded: DecodedCredential = {
    issuer: payload.iss,
    vct: payload.vct,
    jti: payload.jti,
    sub: payload.sub,
    iat: payload.iat,
    exp: payload.exp,
    cnfJwk: payload.cnf.jwk,
    status: payload.status.status_list,
    claims,
    disclosable,
    hasKeyBinding: parts[parts.length - 1] !== '',
  };
  if (payload.nbf !== undefined) decoded.nbf = payload.nbf;
  if (issuer.header.kid !== undefined) decoded.kid = issuer.header.kid;
  return decoded;
}
