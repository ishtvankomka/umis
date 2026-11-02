import { base64urlDecode, base64urlEncode, utf8Decode, utf8Encode } from './bytes.js';
import { getDefaultCrypto, type CryptoProvider } from './crypto/provider.js';
import { asEcPublicJwk } from './jwk.js';
import { ALG } from './profile.js';
import { UmisError } from './reasons.js';
import type { EcPublicJwk, Signer } from './types.js';

export interface JwsHeader {
  alg: 'ES256';
  typ?: string;
  kid?: string;
  jwk?: EcPublicJwk;
  [member: string]: unknown;
}

export interface DecodedJws<P = Record<string, unknown>> {
  header: JwsHeader;
  payload: P;
  /** The exact ASCII bytes `<header>.<payload>` that the signature covers. */
  signingInput: Uint8Array;
  /** 64 bytes, r‖s. */
  signature: Uint8Array;
  compact: string;
}

const SIGNATURE_BYTES = 64;
/** Keys tried for one token when the header names no `kid`. */
const MAX_KEY_CANDIDATES = 8;
/** Header members every UMIS JWS may carry; anything else must be allowed explicitly. */
const STANDARD_MEMBERS: ReadonlySet<string> = new Set(['alg', 'typ', 'kid', 'jwk']);

const invalid = (message: string, cause?: unknown): UmisError => new UmisError('INVALID_ARGUMENT', message, { cause });
const malformed = (message: string, cause?: unknown): UmisError => new UmisError('MALFORMED', message, { cause });

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Signs `payload` as a compact ES256 JWS (RFC 7515). `alg` is always ES256. The header carries `kid` (the signer's,
 * unless one is given or a `jwk` is embedded instead) and `jwk` (reduced to its public members). Members of `header`
 * beyond `typ`, `kid` and `jwk` are copied as they are; `crit` is refused because verification refuses it.
 */
export async function signJws(i: {
  header: { typ: string; kid?: string; jwk?: EcPublicJwk } & Record<string, unknown>;
  payload: object;
  signer: Signer;
}): Promise<string> {
  const { header, payload, signer } = i;
  if (!isPlainObject(header)) throw invalid('the JWS header must be an object');
  if (typeof header.typ !== 'string' || header.typ === '') throw invalid('the JWS header needs a typ');
  if (Object.hasOwn(header, 'crit')) throw invalid('critical header extensions are not supported');
  if (!isPlainObject(payload)) throw invalid('the JWS payload must be a JSON object');
  if (signer?.alg !== ALG || typeof signer.sign !== 'function') throw invalid('expected an ES256 signer');

  const jwk = header.jwk === undefined ? undefined : asEcPublicJwk(header.jwk);
  const kid = header.kid ?? (jwk === undefined ? signer.kid : undefined);
  if (kid !== undefined && typeof kid !== 'string') throw invalid('the JWS header kid must be a string');

  const members: Array<[string, unknown]> = [
    ['alg', ALG],
    ['typ', header.typ],
  ];
  if (kid !== undefined) members.push(['kid', kid]);
  if (jwk !== undefined) members.push(['jwk', jwk]);
  for (const [name, value] of Object.entries(header)) {
    if (!STANDARD_MEMBERS.has(name) && value !== undefined) members.push([name, value]);
  }

  let headerJson: string;
  let payloadJson: string;
  try {
    headerJson = JSON.stringify(Object.fromEntries(members));
    payloadJson = JSON.stringify(payload);
  } catch (cause) {
    throw invalid('the JWS header or payload cannot be serialised as JSON', cause);
  }
  const signingText = `${base64urlEncode(utf8Encode(headerJson))}.${base64urlEncode(utf8Encode(payloadJson))}`;
  const signature = await signer.sign(utf8Encode(signingText));
  if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_BYTES) {
    throw invalid('the signer must return the 64-byte signature r||s');
  }
  return `${signingText}.${base64urlEncode(signature)}`;
}

function parseJsonObject(segment: string, what: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(base64urlDecode(segment)));
  } catch (cause) {
    if (cause instanceof UmisError) throw cause;
    throw malformed(`the JWS ${what} is not valid JSON`, cause);
  }
  if (!isPlainObject(value)) throw malformed(`the JWS ${what} is not a JSON object`);
  return value;
}

/**
 * Splits and decodes a compact JWS without checking the signature. Three segments, JSON objects for header and
 * payload and a 64-byte signature are required (MALFORMED otherwise); an `alg` other than ES256 is UNSUPPORTED_FORMAT.
 * The result is for inspection and for key lookup only: nothing in it is trusted until {@link verifyJws} accepts it.
 */
export function decodeJwsUnverified<P = Record<string, unknown>>(compact: string): DecodedJws<P> {
  if (typeof compact !== 'string') throw malformed('a compact JWS is a string');
  const segments = compact.split('.');
  if (segments.length !== 3) throw malformed('a compact JWS has exactly three segments');
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];

  const header = parseJsonObject(headerSegment, 'header');
  if (header.alg !== ALG) throw new UmisError('UNSUPPORTED_FORMAT', 'only ES256 is supported');
  if (header.typ !== undefined && typeof header.typ !== 'string') throw malformed('the JWS typ must be a string');
  if (header.kid !== undefined && typeof header.kid !== 'string') throw malformed('the JWS kid must be a string');
  if (header.jwk !== undefined) {
    try {
      header.jwk = asEcPublicJwk(header.jwk);
    } catch (cause) {
      throw malformed('the JWS jwk is not a P-256 public key', cause);
    }
  }

  const payload = parseJsonObject(payloadSegment, 'payload');
  const signature = base64urlDecode(signatureSegment);
  if (signature.length !== SIGNATURE_BYTES) throw malformed('an ES256 signature has 64 bytes');

  return {
    header: header as JwsHeader,
    payload: payload as P,
    signingInput: utf8Encode(`${headerSegment}.${payloadSegment}`),
    signature,
    compact,
  };
}

function candidateKeys(key: VerifyKey, header: JwsHeader): EcPublicJwk[] {
  if (typeof key === 'function') {
    const resolved = key(header);
    return resolved === undefined ? [] : [resolved];
  }
  if (Array.isArray(key)) {
    const keys = key as readonly EcPublicJwk[];
    const named = header.kid === undefined ? keys : keys.filter((candidate) => candidate?.kid === header.kid);
    return named.slice(0, MAX_KEY_CANDIDATES);
  }
  return key === undefined || key === null ? [] : [key as EcPublicJwk];
}

type VerifyKey = EcPublicJwk | readonly EcPublicJwk[] | ((h: JwsHeader) => EcPublicJwk | undefined);

/**
 * Verifies a compact ES256 JWS and returns it decoded. Checks, in this order, each failing with one code:
 * structure (MALFORMED), `alg` (UNSUPPORTED_FORMAT), header members (MALFORMED: `crit` and every member other than
 * `alg`, `typ`, `kid`, `jwk` and `allowHeader`), exact `typ` (UNSUPPORTED_FORMAT), key lookup (ISSUER_KEY_UNKNOWN) and
 * the signature (SIGNATURE_INVALID). With a key array the header `kid` selects the key; without a `kid` every key is
 * tried in order, at most eight.
 */
export async function verifyJws<P = Record<string, unknown>>(
  compact: string,
  i: {
    typ: string | readonly string[];
    key: VerifyKey;
    allowHeader?: readonly string[];
    crypto?: CryptoProvider;
  },
): Promise<DecodedJws<P>> {
  const decoded = decodeJwsUnverified<P>(compact);
  const { header } = decoded;

  const allowed = i.allowHeader ?? [];
  for (const name of Object.keys(header)) {
    if (name === 'crit') throw malformed('critical header extensions are not supported');
    if (!STANDARD_MEMBERS.has(name) && !allowed.includes(name))
      throw malformed(`unexpected JWS header member "${name}"`);
  }

  const types = typeof i.typ === 'string' ? [i.typ] : i.typ;
  if (typeof header.typ !== 'string' || !types.includes(header.typ)) {
    throw new UmisError('UNSUPPORTED_FORMAT', 'the JWS typ is not the expected one');
  }

  const keys = candidateKeys(i.key, header);
  if (keys.length === 0) throw new UmisError('ISSUER_KEY_UNKNOWN', 'no verification key matches this JWS');

  const crypto = i.crypto ?? getDefaultCrypto();
  for (const key of keys) {
    if (await crypto.verifyEs256(key, decoded.signingInput, decoded.signature)) return decoded;
  }
  throw new UmisError('SIGNATURE_INVALID', 'the JWS signature does not verify');
}
