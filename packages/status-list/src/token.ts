import { LIMITS, TYP, UmisError, decodeJwsUnverified, publicJwkEquals, signJws, verifyJws } from '@umis/core';
import type { CryptoProvider, EcPublicJwk, ParsedStatusList, Signer, StatusListCache, StatusRef } from '@umis/core';
import { STATUS, isStatusBits, readStatus, statusListFromValues } from './bits.js';
import { decodeLst, encodeLst } from './lst.js';

type Rejection = 'STATUS_LIST_INVALID' | 'STATUS_LIST_STALE';

/** The claims of a status list token that decide whether it may be used, before its list is inflated. */
interface Claims {
  readonly uri: string;
  readonly iat: number;
  readonly exp?: number;
  readonly ttl?: number;
}

interface Checks {
  readonly expectedUri: string;
  readonly now: number;
  readonly maxAgeSeconds: number;
  readonly skew: number;
}

/** Codes `verifyJws` and the payload readers use for a token that is simply not an acceptable status list. */
const TOKEN_PROBLEMS: ReadonlySet<string> = new Set([
  'MALFORMED',
  'UNSUPPORTED_FORMAT',
  'ISSUER_KEY_UNKNOWN',
  'SIGNATURE_INVALID',
  'STATUS_LIST_INVALID',
]);

/** For each list this module verified, the issuer keys that were on offer when its signature was checked. */
const verifiedUnder = new WeakMap<ParsedStatusList, readonly EcPublicJwk[]>();

const invalidList = (message: string, cause?: unknown): UmisError =>
  new UmisError('STATUS_LIST_INVALID', message, { cause });
const invalidArgument = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

const isWhole = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const isNumericDate = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0;

/**
 * Builds and signs a Token Status List (draft-21 section 5.1): header `{typ: 'statuslist+jwt', kid}`, payload
 * `{sub: uri, iat, exp?, ttl?, iss?, status_list: {bits, lst}}`. `values` holds one status per element and every
 * element must fit in `bits` bits. `ttlSeconds` becomes the `ttl` claim.
 */
export async function buildStatusListToken(i: {
  signer: Signer;
  uri: string;
  bits: 1 | 2;
  values: Uint8Array;
  iat: number;
  ttlSeconds?: number;
  exp?: number;
  issuer?: string;
}): Promise<string> {
  if (typeof i.uri !== 'string' || i.uri === '') throw invalidArgument('uri must name the status list');
  if (i.bits !== 1 && i.bits !== 2) throw invalidArgument('a built status list uses 1 or 2 bits per entry');
  if (!isWhole(i.iat)) throw invalidArgument('iat must be a whole number of seconds');
  if (i.exp !== undefined && !(isWhole(i.exp) && i.exp > i.iat)) {
    throw invalidArgument('exp must be a whole number of seconds after iat');
  }
  if (i.ttlSeconds !== undefined && !(isWhole(i.ttlSeconds) && i.ttlSeconds > 0)) {
    throw invalidArgument('ttlSeconds must be a positive whole number of seconds');
  }
  if (i.issuer !== undefined && (typeof i.issuer !== 'string' || i.issuer === '')) {
    throw invalidArgument('issuer must be a non-empty string');
  }

  const packed = statusListFromValues(i.values, i.bits).toBytes();
  const payload: Record<string, unknown> = { sub: i.uri, iat: i.iat };
  if (i.exp !== undefined) payload.exp = i.exp;
  if (i.ttlSeconds !== undefined) payload.ttl = i.ttlSeconds;
  if (i.issuer !== undefined) payload.iss = i.issuer;
  payload.status_list = { bits: i.bits, lst: encodeLst(packed) };
  return signJws({ header: { typ: TYP.statusList }, payload, signer: i.signer });
}

function readClaims(payload: Record<string, unknown>): Claims {
  const { sub, iat, exp, ttl } = payload;
  if (typeof sub !== 'string' || sub === '') throw invalidList('sub must name the status list');
  if (!isNumericDate(iat)) throw invalidList('iat must be a NumericDate');
  if (exp !== undefined && !isNumericDate(exp)) throw invalidList('exp must be a NumericDate');
  if (ttl !== undefined && !(isNumericDate(ttl) && ttl > 0)) throw invalidList('ttl must be a positive number');
  return {
    uri: sub,
    iat,
    ...(exp === undefined ? {} : { exp }),
    ...(ttl === undefined ? {} : { ttl }),
  };
}

function toList(claims: Claims, statusList: unknown): ParsedStatusList {
  if (typeof statusList !== 'object' || statusList === null || Array.isArray(statusList)) {
    throw invalidList('status_list must be an object');
  }
  const { bits, lst } = statusList as Record<string, unknown>;
  if (!isStatusBits(bits)) throw invalidList('status_list.bits must be 1, 2, 4 or 8');
  if (typeof lst !== 'string') throw invalidList('status_list.lst must be a string');
  const packed = decodeLst(lst);
  if (packed.length === 0) throw invalidList('the status list is empty');
  const size = packed.length * (8 / bits);
  return Object.freeze<ParsedStatusList>({
    uri: claims.uri,
    iat: claims.iat,
    ...(claims.exp === undefined ? {} : { exp: claims.exp }),
    ...(claims.ttl === undefined ? {} : { ttl: claims.ttl }),
    bits,
    size,
    get(idx: number): number {
      if (!Number.isSafeInteger(idx) || idx < 0 || idx >= size) {
        throw invalidArgument(`status index ${String(idx)} is outside the list`);
      }
      return readStatus(packed, bits, idx);
    },
  });
}

/**
 * Reads a status list token without checking its signature, freshness or issuer. The `typ` must be `statuslist+jwt`
 * and every claim must be well formed, the list must inflate within `LIMITS.statusListMaxBytes`; anything else is
 * STATUS_LIST_INVALID. Use {@link verifyStatusListToken} before relying on the statuses.
 */
export function parseStatusListToken(token: string): ParsedStatusList {
  let decoded;
  try {
    decoded = decodeJwsUnverified(token);
  } catch (cause) {
    throw invalidList('the token is not a compact ES256 JWS', cause);
  }
  if (decoded.header.typ !== TYP.statusList) throw invalidList(`the token typ is not ${TYP.statusList}`);
  return toList(readClaims(decoded.payload), decoded.payload.status_list);
}

/** The rejection for a list that is another list, comes from the future, is older than S or has expired. */
function timeliness(list: Claims, c: Checks): Rejection | undefined {
  if (list.uri !== c.expectedUri) return 'STATUS_LIST_INVALID';
  if (list.iat > c.now + c.skew) return 'STATUS_LIST_INVALID';
  if (c.now - list.iat > c.maxAgeSeconds) return 'STATUS_LIST_STALE';
  if (list.exp !== undefined && c.now >= list.exp + c.skew) return 'STATUS_LIST_STALE';
  return undefined;
}

function usableKeys(keys: readonly EcPublicJwk[]): EcPublicJwk[] {
  if (!Array.isArray(keys)) return [];
  return (keys as readonly unknown[]).filter((key): key is EcPublicJwk => typeof key === 'object' && key !== null);
}

/** A cached list is reused only if this module verified it and every key it was verified under is still offered. */
function stillTrusted(list: ParsedStatusList, keys: readonly EcPublicJwk[]): boolean {
  const prior = verifiedUnder.get(list);
  if (prior === undefined) return false;
  const current = usableKeys(keys);
  return prior.every((was) => current.some((now) => publicJwkEquals(was, now)));
}

/**
 * Verifies a status list token and returns the list. The checks run in this order and the first failure decides:
 * ES256 signature by one of `keys` with `typ` `statuslist+jwt` (the header `kid` selects the key; without one every key
 * is tried), well-formed claims, `sub === expectedUri`, `iat` not after `now + skew`, age `now - iat` not above
 * `maxAgeSeconds` (an age equal to it passes), `exp` not reached (`now >= exp + skew` is stale), then `bits` and an
 * `lst` that inflates within the size limit. All token problems are reported as STATUS_LIST_INVALID except the two
 * freshness rules, which are STATUS_LIST_STALE. A list found in `cache` skips the signature check and the inflation
 * but goes through the same `sub`, `iat`, age and `exp` checks. Errors that are not about the token (an unavailable
 * crypto backend) and non-finite `now`, `maxAgeSeconds` or `skewSeconds` are thrown.
 */
export async function verifyStatusListToken(
  token: string,
  i: {
    keys: readonly EcPublicJwk[];
    expectedUri: string;
    now: number;
    maxAgeSeconds: number;
    skewSeconds?: number;
    cache?: StatusListCache;
    crypto?: CryptoProvider;
  },
): Promise<
  | { ok: true; list: ParsedStatusList; ageSeconds: number }
  | { ok: false; reason: 'STATUS_LIST_INVALID' | 'STATUS_LIST_STALE' }
> {
  const skew = i.skewSeconds ?? LIMITS.defaultSkewS;
  if (
    !Number.isFinite(i.now) ||
    !Number.isFinite(i.maxAgeSeconds) ||
    i.maxAgeSeconds < 0 ||
    !Number.isFinite(skew) ||
    skew < 0
  ) {
    throw invalidArgument('now must be finite, maxAgeSeconds and skewSeconds finite and not negative');
  }
  const checks: Checks = { expectedUri: i.expectedUri, now: i.now, maxAgeSeconds: i.maxAgeSeconds, skew };
  const rejected = (reason: Rejection) => ({ ok: false as const, reason });
  const accepted = (list: ParsedStatusList) => ({
    ok: true as const,
    list,
    ageSeconds: Math.max(0, i.now - list.iat),
  });
  if (typeof token !== 'string') return rejected('STATUS_LIST_INVALID');

  const cached = i.cache?.get(token);
  if (cached !== undefined && stillTrusted(cached, i.keys)) {
    const reason = timeliness(cached, checks);
    return reason === undefined ? accepted(cached) : rejected(reason);
  }

  let list: ParsedStatusList;
  try {
    const decoded = await verifyJws(token, { typ: TYP.statusList, key: i.keys, crypto: i.crypto });
    const claims = readClaims(decoded.payload);
    const reason = timeliness(claims, checks);
    if (reason !== undefined) return rejected(reason);
    list = toList(claims, decoded.payload.status_list);
  } catch (error) {
    if (error instanceof UmisError && TOKEN_PROBLEMS.has(error.code)) return rejected('STATUS_LIST_INVALID');
    throw error;
  }

  const offered = usableKeys(i.keys).map((key) => ({ ...key }));
  if (offered.length > 0) verifiedUnder.set(list, offered);
  i.cache?.set(token, list);
  return accepted(list);
}

/**
 * The state of the credential that `ref` points to in `list`: VALID (0), SUSPENDED (2) or REVOKED (1, and every other
 * value, so that application-specific types fail closed). An index outside the list, a malformed index and a reference
 * to another list are OUT_OF_RANGE, never VALID.
 */
export function checkStatus(
  ref: StatusRef,
  list: ParsedStatusList,
): 'VALID' | 'REVOKED' | 'SUSPENDED' | 'OUT_OF_RANGE' {
  const idx: unknown = ref?.idx;
  if (ref?.uri !== list.uri || !isWhole(idx) || idx >= list.size) return 'OUT_OF_RANGE';
  const status = list.get(idx);
  if (status === STATUS.VALID) return 'VALID';
  return status === STATUS.SUSPENDED ? 'SUSPENDED' : 'REVOKED';
}
