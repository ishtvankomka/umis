import { SDJwtInstance, type DisclosureFrame, type PresentationFrame } from '@sd-jwt/core';
import { base64urlDecode, base64urlEncode, bytesEqual, utf8Encode } from './bytes.js';
import { assertNoReservedKeys, assignClaim, readClaims, readCredentialPayload, readDisclosure } from './credential.js';
import { getDefaultCrypto, randomId, type CryptoProvider } from './crypto/provider.js';
import { decodeJwsUnverified, type DecodedJws } from './jws.js';
import { ALG, DISCLOSABLE_CLAIMS, LIMITS, SD_ALG, TYP, type DisclosableClaim } from './profile.js';
import { UmisError } from './reasons.js';
import type { CredentialPayload, EcPublicJwk, Signer, UmisClaimSet } from './types.js';

export interface ParsedDisclosure {
  /** The disclosure exactly as it appears in the SD-JWT (base64url). */
  raw: string;
  /** base64url(SHA-256(ASCII(raw))). */
  digest: string;
  salt: string;
  name: DisclosableClaim;
  /** The value as it was disclosed, unvalidated; `ParsedSdJwt.claims` holds the validated copy. */
  value: unknown;
}

export interface ParsedSdJwt {
  issuerJwt: DecodedJws<CredentialPayload & { _sd?: string[]; _sd_alg?: string }>;
  disclosures: ParsedDisclosure[];
  /** Decoded structurally only; its payload members are checked by {@link verifyKeyBinding}. */
  kbJwt?: DecodedJws<{ iat: number; aud: string; nonce: string; sd_hash: string }>;
  /** `<issuer-jwt>~<d1>~…~<dn>~`: the text that `sd_hash` covers (RFC 9901 section 4.3.1). */
  sdHashInput: string;
  /** The claims the verifier can see: the plain ones and the disclosed ones, validated and copied. */
  claims: Partial<UmisClaimSet>;
}

type Json = Record<string, unknown>;

/** Header members of the issuer JWT; anything else, an embedded key included, is refused. */
const ISSUER_HEADER_MEMBERS: ReadonlySet<string> = new Set(['alg', 'typ', 'kid']);
/** Header members of the key-binding JWT. */
const KB_HEADER_MEMBERS: ReadonlySet<string> = new Set(['alg', 'typ']);
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,}$/;
const SIGNATURE_BYTES = 64;

const malformed = (message: string, cause?: unknown): UmisError => new UmisError('MALFORMED', message, { cause });
const invalid = (message: string, cause?: unknown): UmisError => new UmisError('INVALID_ARGUMENT', message, { cause });

function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

// ---------------------------------------------------------------------------------------------------------------
// adapters for the SD-JWT library
// ---------------------------------------------------------------------------------------------------------------

/** The library hashes strings and buffers; here every digest comes from the crypto provider, SHA-256 only. */
function libraryHasher(crypto: CryptoProvider) {
  return async (data: string | ArrayBuffer, alg: string): Promise<Uint8Array> => {
    if (alg !== SD_ALG) throw new UmisError('UNSUPPORTED_FORMAT', 'only sha-256 disclosure digests are supported');
    return crypto.sha256(typeof data === 'string' ? utf8Encode(data) : new Uint8Array(data));
  };
}

/** The library signs text and wants the signature as base64url text. */
function librarySigner(signer: Signer) {
  if (signer === null || typeof signer !== 'object' || signer.alg !== ALG || typeof signer.sign !== 'function') {
    throw invalid('expected an ES256 signer');
  }
  return async (data: string): Promise<string> => {
    const signature = await signer.sign(utf8Encode(data));
    if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_BYTES) {
      throw invalid('the signer must return the 64-byte signature r||s');
    }
    return base64urlEncode(signature);
  };
}

/** Failures of the library on caller input are argument errors; our own errors pass through. */
function asArgumentError(error: unknown, message: string): UmisError {
  return error instanceof UmisError ? error : invalid(message, error);
}

// ---------------------------------------------------------------------------------------------------------------
// issuing and presenting
// ---------------------------------------------------------------------------------------------------------------

/**
 * Issues an SD-JWT VC: `<issuer-jwt>~<disclosure>~…~` (RFC 9901 section 4). Each claim named in `sd` becomes one
 * object-property disclosure with a 16-byte random salt; every other claim stays a plain claim of the payload. `sd`
 * defaults to all claims present; names that `claims` lacks are skipped. The header is
 * `{"typ":"dc+sd-jwt","kid":<signer.kid>,"alg":"ES256"}`. There are no decoys, nested or array-element disclosures.
 * The holder key in `cnf.jwk` is written as `kty`, `crv`, `x` and `y` only.
 */
export async function issueCredential(i: {
  signer: Signer;
  payload: CredentialPayload;
  claims: Partial<UmisClaimSet>;
  sd?: readonly DisclosableClaim[];
  crypto?: CryptoProvider;
}): Promise<string> {
  const crypto = i.crypto ?? getDefaultCrypto();
  const sign = librarySigner(i.signer);

  let plain: CredentialPayload;
  let claims: Partial<UmisClaimSet>;
  try {
    if (typeof i.payload !== 'object' || i.payload === null) throw malformed('the credential payload is missing');
    if (typeof i.claims !== 'object' || i.claims === null) throw malformed('the claims are missing');
    for (const name of Object.keys(i.claims)) {
      if (!(DISCLOSABLE_CLAIMS as readonly string[]).includes(name)) throw malformed(`"${name}" is not a UMIS claim`);
    }
    plain = readCredentialPayload(i.payload as unknown as Json);
    claims = readClaims(i.claims as Json);
  } catch (error) {
    throw error instanceof UmisError && error.code === 'MALFORMED' ? invalid(error.message, error) : error;
  }

  const requested = i.sd ?? DISCLOSABLE_CLAIMS;
  for (const name of requested) {
    if (!(DISCLOSABLE_CLAIMS as readonly string[]).includes(name))
      throw invalid(`"${String(name)}" is not a UMIS claim`);
  }
  const selective = DISCLOSABLE_CLAIMS.filter((name) => Object.hasOwn(claims, name) && requested.includes(name));

  const payload: Json = { iss: plain.iss, sub: plain.sub, jti: plain.jti, iat: plain.iat, exp: plain.exp };
  if (plain.nbf !== undefined) payload.nbf = plain.nbf;
  payload.vct = plain.vct;
  // the holder key travels as bare coordinates: a kid, alg or use member would only add bytes to every QR code
  const { kty, crv, x, y } = plain.cnf.jwk;
  payload.cnf = { jwk: { kty, crv, x, y } };
  payload.status = plain.status;
  for (const name of DISCLOSABLE_CLAIMS) {
    if (Object.hasOwn(claims, name)) payload[name] = claims[name];
  }

  const library = new SDJwtInstance<Json>({
    hasher: libraryHasher(crypto),
    hashAlg: SD_ALG,
    saltGenerator: () => randomId(LIMITS.saltBytes, crypto),
    signer: sign,
    signAlg: ALG,
  });
  try {
    return await library.issue(payload, { _sd: selective } as DisclosureFrame<Json>, {
      header: { typ: TYP.sdJwtVc, kid: i.signer.kid },
    });
  } catch (error) {
    throw asArgumentError(error, 'the credential could not be issued');
  }
}

/**
 * Builds a presentation from a stored credential: the issuer JWT, the disclosures of the claims named in `disclose` (in
 * that order) and a key-binding JWT `{iat, aud, nonce, sd_hash}` signed by `kb.signer` (RFC 9901 section 4.3). Naming a
 * claim that the credential holds no disclosure for is INVALID_ARGUMENT. Whether `kb.signer` is the credential's holder
 * key is not checked here: the verifier does.
 */
export async function presentCredential(i: {
  credential: string;
  disclose: readonly DisclosableClaim[];
  kb: { signer: Signer; aud: string; nonce: string; iat: number };
  crypto?: CryptoProvider;
}): Promise<string> {
  const crypto = i.crypto ?? getDefaultCrypto();
  const { kb } = i;
  if (typeof kb !== 'object' || kb === null) throw invalid('the key-binding input is missing');
  const kbSign = librarySigner(kb.signer);
  if (typeof kb.aud !== 'string' || kb.aud === '') throw invalid('the key-binding audience must be a non-empty string');
  if (typeof kb.nonce !== 'string' || kb.nonce === '')
    throw invalid('the key-binding nonce must be a non-empty string');
  if (typeof kb.iat !== 'number' || !Number.isFinite(kb.iat)) throw invalid('the key-binding iat must be a number');
  if (!Array.isArray(i.disclose)) throw invalid('disclose must be an array of claim names');

  const parsed = await parseSdJwt(i.credential, crypto);
  if (parsed.kbJwt !== undefined) throw invalid('the credential already carries a key-binding JWT');
  const available = new Set<string>(parsed.disclosures.map((disclosure) => disclosure.name));
  const frame: Record<string, boolean> = {};
  for (const name of i.disclose) {
    if (!(DISCLOSABLE_CLAIMS as readonly string[]).includes(name))
      throw invalid(`"${String(name)}" is not a UMIS claim`);
    if (!available.has(name)) throw invalid(`the credential has no disclosure for "${name}"`);
    frame[name] = true;
  }

  const library = new SDJwtInstance<Json>({
    hasher: libraryHasher(crypto),
    hashAlg: SD_ALG,
    kbSigner: kbSign,
    kbSignAlg: ALG,
  });
  try {
    return await library.present(i.credential, frame as PresentationFrame<Json>, {
      kb: { payload: { iat: kb.iat, aud: kb.aud, nonce: kb.nonce } },
    });
  } catch (error) {
    throw asArgumentError(error, 'the presentation could not be built');
  }
}

// ---------------------------------------------------------------------------------------------------------------
// parsing and verification primitives
// ---------------------------------------------------------------------------------------------------------------

/** base64url(SHA-256(ASCII(disclosure))), RFC 9901 section 4.2.3. */
export async function disclosureDigest(disclosure: string, crypto?: CryptoProvider): Promise<string> {
  if (typeof disclosure !== 'string') throw invalid('a disclosure is a string');
  for (let index = 0; index < disclosure.length; index++) {
    if (disclosure.charCodeAt(index) > 0x7f) throw invalid('a disclosure is ASCII text');
  }
  const digest = await (crypto ?? getDefaultCrypto()).sha256(utf8Encode(disclosure));
  return base64urlEncode(digest);
}

function checkHeader(header: Json, allowed: ReadonlySet<string>, what: string): void {
  for (const name of Object.keys(header)) {
    if (!allowed.has(name)) throw malformed(`unexpected ${what} header member "${name}"`);
  }
}

/**
 * Parses an SD-JWT VC or presentation structurally and by the profile, without trusting any of it: the issuer
 * signature, the key binding and the times are separate checks. The text is split at `~`; the first part is the issuer
 * JWT (`typ` dc+sd-jwt), the last is empty or a key-binding JWT, the rest are disclosures. A disclosure must be an
 * array of salt, a profile claim name and a value, must be listed in `_sd`, and must not repeat a digest or a claim
 * name, or clash with a plain claim. Extra `_sd` digests without a disclosure are accepted (claims that stay hidden).
 */
export async function parseSdJwt(s: string, crypto?: CryptoProvider): Promise<ParsedSdJwt> {
  if (typeof s !== 'string') throw malformed('an SD-JWT is a string');
  if (s.length > LIMITS.frameMaxBytes) throw malformed('the SD-JWT exceeds the size limit');
  const provider = crypto ?? getDefaultCrypto();
  const parts = s.split('~');
  if (parts.length < 2) throw malformed('an SD-JWT contains at least one "~"');
  const issuerText = parts[0] ?? '';
  const kbText = parts[parts.length - 1] ?? '';
  const disclosureTexts = parts.slice(1, -1);

  const issuerJwt = decodeJwsUnverified<Json>(issuerText);
  checkHeader(issuerJwt.header, ISSUER_HEADER_MEMBERS, 'issuer JWT');
  if (issuerJwt.header.typ !== TYP.sdJwtVc) throw new UmisError('UNSUPPORTED_FORMAT', 'the typ is not dc+sd-jwt');
  const raw = issuerJwt.payload;

  const sdAlg = own(raw, '_sd_alg');
  if (sdAlg !== undefined && sdAlg !== SD_ALG) {
    throw new UmisError('UNSUPPORTED_FORMAT', 'only sha-256 disclosure digests are supported');
  }
  const sdList = own(raw, '_sd');
  const listed = new Set<string>();
  if (sdList !== undefined) {
    if (!Array.isArray(sdList)) throw malformed('_sd must be an array');
    for (const digest of sdList) {
      if (typeof digest !== 'string') throw malformed('_sd must hold strings');
      if (listed.has(digest)) throw malformed('a digest appears twice in _sd');
      listed.add(digest);
    }
  }
  for (const [name, member] of Object.entries(raw)) {
    if (name === '_sd' || name === '_sd_alg') continue;
    if (name === '...' || name === '_sd_decoy') throw malformed(`the payload contains the reserved key "${name}"`);
    assertNoReservedKeys(member, `claim "${name}"`);
  }

  const plain = readCredentialPayload(raw);
  raw.cnf = plain.cnf;
  raw.status = plain.status;
  const claims = readClaims(raw);

  const disclosures: ParsedDisclosure[] = [];
  const seenDigests = new Set<string>();
  for (const disclosureText of disclosureTexts) {
    if (disclosureText === '') throw malformed('a disclosure is empty');
    const { salt, name, value } = readDisclosure(disclosureText);
    const digest = await disclosureDigest(disclosureText, provider);
    if (!listed.has(digest)) throw malformed('a disclosure is not referenced by _sd');
    if (seenDigests.has(digest)) throw malformed('a disclosure appears twice');
    seenDigests.add(digest);
    if (Object.hasOwn(claims, name)) throw malformed(`claim "${name}" is given twice`);
    assignClaim(claims, name, value);
    disclosures.push({ raw: disclosureText, digest, salt, name, value });
  }

  const parsed: ParsedSdJwt = {
    issuerJwt: issuerJwt as unknown as ParsedSdJwt['issuerJwt'],
    disclosures,
    sdHashInput: s.slice(0, s.length - kbText.length),
    claims,
  };
  if (kbText !== '') parsed.kbJwt = decodeJwsUnverified(kbText);
  return parsed;
}

/** Checks the issuer signature of a parsed SD-JWT against `key`. The key must come from a trusted source. */
export function verifyIssuerSignature(p: ParsedSdJwt, key: EcPublicJwk, crypto?: CryptoProvider): Promise<boolean> {
  return (crypto ?? getDefaultCrypto()).verifyEs256(key, p.issuerJwt.signingInput, p.issuerJwt.signature);
}

type KeyBindingReason =
  'HOLDER_BINDING_INVALID' | 'NONCE_MISMATCH' | 'AUDIENCE_MISMATCH' | 'PRESENTATION_EXPIRED' | 'CLOCK_SKEW';

/**
 * Checks the key-binding JWT of a presentation (RFC 9901 sections 4.3 and 7.3), in this order, stopping at the first
 * failure: the JWT is present, has `typ` kb+jwt and no header members beyond `alg` and `typ`, carries `iat`, `aud`,
 * `nonce` and `sd_hash`, is signed by the credential's `cnf.jwk`, and its `sd_hash` covers exactly the issuer JWT and
 * the disclosures received (all HOLDER_BINDING_INVALID); then the nonce (NONCE_MISMATCH; without an expected `nonce`
 * any value of at least 22 base64url characters passes and is returned so that the caller can record it), the
 * audience (AUDIENCE_MISMATCH), an `iat` more than `skewSeconds` ahead of `now` or before `notBefore - skewSeconds`
 * (CLOCK_SKEW), and an age above `maxAgeSeconds` (PRESENTATION_EXPIRED).
 */
export async function verifyKeyBinding(
  p: ParsedSdJwt,
  c: {
    aud: string | readonly string[];
    nonce?: string;
    now: number;
    maxAgeSeconds: number;
    skewSeconds: number;
    notBefore?: number;
    crypto?: CryptoProvider;
  },
): Promise<{ ok: true; iat: number; nonce: string } | { ok: false; reason: KeyBindingReason }> {
  for (const [name, value] of [
    ['now', c.now],
    ['maxAgeSeconds', c.maxAgeSeconds],
    ['skewSeconds', c.skewSeconds],
  ] as const) {
    if (typeof value !== 'number' || !Number.isFinite(value)) throw invalid(`${name} must be a finite number`);
  }
  if (c.notBefore !== undefined && !Number.isFinite(c.notBefore)) throw invalid('notBefore must be a finite number');
  if (c.nonce !== undefined && (typeof c.nonce !== 'string' || c.nonce === '')) {
    throw invalid('an expected nonce must be a non-empty string');
  }
  const fail = (reason: KeyBindingReason): { ok: false; reason: KeyBindingReason } => ({ ok: false, reason });
  const provider = c.crypto ?? getDefaultCrypto();

  const kb = p.kbJwt;
  if (kb === undefined) return fail('HOLDER_BINDING_INVALID');
  if (kb.header.typ !== TYP.kb) return fail('HOLDER_BINDING_INVALID');
  if (Object.keys(kb.header).some((name) => !KB_HEADER_MEMBERS.has(name))) return fail('HOLDER_BINDING_INVALID');
  const { iat, aud, nonce, sd_hash: sdHash } = kb.payload as Partial<Record<string, unknown>>;
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return fail('HOLDER_BINDING_INVALID');
  if (typeof aud !== 'string' || typeof nonce !== 'string' || typeof sdHash !== 'string') {
    return fail('HOLDER_BINDING_INVALID');
  }

  if (!(await provider.verifyEs256(p.issuerJwt.payload.cnf.jwk, kb.signingInput, kb.signature))) {
    return fail('HOLDER_BINDING_INVALID');
  }
  const expectedHash = base64urlEncode(await provider.sha256(utf8Encode(p.sdHashInput)));
  if (sdHash !== expectedHash) return fail('HOLDER_BINDING_INVALID');

  if (c.nonce !== undefined) {
    if (!bytesEqual(utf8Encode(nonce), utf8Encode(c.nonce))) return fail('NONCE_MISMATCH');
  } else if (!NONCE_PATTERN.test(nonce) || !isCanonicalBase64url(nonce)) {
    return fail('NONCE_MISMATCH');
  }
  const audiences = typeof c.aud === 'string' ? [c.aud] : c.aud;
  if (!audiences.includes(aud)) return fail('AUDIENCE_MISMATCH');

  if (!(iat <= c.now + c.skewSeconds)) return fail('CLOCK_SKEW');
  if (c.notBefore !== undefined && !(iat >= c.notBefore - c.skewSeconds)) return fail('CLOCK_SKEW');
  if (!(c.now - iat <= c.maxAgeSeconds)) return fail('PRESENTATION_EXPIRED');
  return { ok: true, iat, nonce };
}

function isCanonicalBase64url(value: string): boolean {
  try {
    base64urlDecode(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * The time rules of a credential. Expired when `now >= exp + skew`; not yet valid when `now < nbf - skew`; issued in
 * the future when `iat > now + skew` (CLOCK_SKEW). Checked in that order; undefined when all pass. A value that is not
 * a number fails the rule it belongs to.
 */
export function checkCredentialTimes(
  p: { iat: number; exp: number; nbf?: number },
  now: number,
  skewSeconds: number,
): 'CREDENTIAL_EXPIRED' | 'CREDENTIAL_NOT_YET_VALID' | 'CLOCK_SKEW' | undefined {
  if (!Number.isFinite(now) || !Number.isFinite(skewSeconds))
    throw invalid('now and skewSeconds must be finite numbers');
  if (!(now < p.exp + skewSeconds)) return 'CREDENTIAL_EXPIRED';
  if (p.nbf !== undefined && !(now >= p.nbf - skewSeconds)) return 'CREDENTIAL_NOT_YET_VALID';
  if (!(p.iat <= now + skewSeconds)) return 'CLOCK_SKEW';
  return undefined;
}
