import { TYP, UmisError, base64urlDecode, utf8Decode, verifyJws } from '@umis/core';
import type { CryptoProvider, EcPublicJwk } from '@umis/core';
import { invalid, isRecord, isText } from './profile.js';

type Json = Record<string, unknown>;
type KeyProofResult = { ok: true; jwk: EcPublicJwk } | { ok: false; error: 'invalid_proof' | 'invalid_nonce' };

const DEFAULT_MAX_AGE_SECONDS = 300;
/** How far ahead of the issuer's clock a proof may be dated. */
const CLOCK_AHEAD_SECONDS = 60;
/** A key proof is a few hundred characters; the cap only keeps hostile input from being decoded at all. */
const MAX_PROOF_CHARS = 4_096;

const invalidProof = (): KeyProofResult => ({ ok: false, error: 'invalid_proof' });
const invalidNonce = (): KeyProofResult => ({ ok: false, error: 'invalid_nonce' });

/** The header exactly as the wallet wrote it: the decoded one has already been reduced to the public key members. */
function rawHeader(compact: string): Json {
  const header: unknown = JSON.parse(utf8Decode(base64urlDecode(compact.split('.')[0] ?? '')));
  if (!isRecord(header)) throw new UmisError('MALFORMED', 'the JWS header is not a JSON object');
  return header;
}

async function check(
  proofJwt: unknown,
  c: { audience: string; nonce: string; now: number; maxAgeSeconds: number; crypto?: CryptoProvider },
): Promise<KeyProofResult> {
  if (typeof proofJwt !== 'string' || proofJwt.length > MAX_PROOF_CHARS) return invalidProof();

  // the key travels in the header, as a `jwk` and nothing else: no `kid` to look up, no certificate chain, no private part
  const header = rawHeader(proofJwt);
  if (Object.hasOwn(header, 'kid') || Object.hasOwn(header, 'x5c')) return invalidProof();
  const embedded = Object.hasOwn(header, 'jwk') ? header.jwk : undefined;
  if (!isRecord(embedded) || Object.hasOwn(embedded, 'd')) return invalidProof();

  // exact typ, ES256, no unknown or critical header members, and a signature by the embedded key
  const proof = await verifyJws<Json>(proofJwt, { typ: TYP.vciProof, key: (h) => h.jwk, crypto: c.crypto });
  const jwk = proof.header.jwk;
  if (jwk === undefined) return invalidProof();
  const { aud, nonce, iat } = proof.payload;

  const audiences = typeof aud === 'string' ? [aud] : aud;
  if (!Array.isArray(audiences) || !audiences.every((a) => typeof a === 'string') || !audiences.includes(c.audience)) {
    return invalidProof();
  }
  // a nonce that is absent or not the expected one asks the wallet to fetch a fresh one
  if (nonce === undefined) return invalidNonce();
  if (typeof nonce !== 'string') return invalidProof();
  if (nonce !== c.nonce) return invalidNonce();
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return invalidProof();
  if (iat < c.now - c.maxAgeSeconds || iat > c.now + CLOCK_AHEAD_SECONDS) return invalidProof();
  return { ok: true, jwk };
}

/**
 * Verifies the key proof of a credential request (OpenID4VCI 1.0 section 8.2, appendix F.1) and returns the key that the
 * credential is to be bound to.
 *
 * The proof is a JWT with the exact `typ` openid4vci-proof+jwt and `alg` ES256, signed by the public key in its `jwk`
 * header; the header has neither `kid` nor `x5c`, and the `jwk` has no private member. In the payload `aud` equals (or
 * contains) `audience`, the `nonce` is the expected one, and `iat` lies within `[now - maxAgeSeconds, now + 60]`
 * (`maxAgeSeconds` is 300 unless given).
 *
 * A nonce that differs or is missing is `invalid_nonce`; every other failure is `invalid_proof`. Whatever is wrong with
 * `proofJwt` is reported, never thrown. Remembering the nonce and using it up is up to the caller.
 */
export async function verifyKeyProof(i: {
  proofJwt: string;
  audience: string;
  nonce: string;
  now: number;
  maxAgeSeconds?: number;
  crypto?: CryptoProvider;
}): Promise<KeyProofResult> {
  const request: unknown = i;
  if (!isRecord(request)) throw invalid('the key proof check needs an object');
  if (!isText(i.audience)) throw invalid('audience must be a non-empty string');
  if (!isText(i.nonce)) throw invalid('nonce must be a non-empty string');
  if (typeof i.now !== 'number' || !Number.isFinite(i.now)) throw invalid('now must be a finite number of seconds');
  const maxAgeSeconds = i.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
  if (typeof maxAgeSeconds !== 'number' || !Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0) {
    throw invalid('maxAgeSeconds must be a number of seconds, zero or more');
  }
  try {
    return await check(i.proofJwt, {
      audience: i.audience,
      nonce: i.nonce,
      now: i.now,
      maxAgeSeconds,
      crypto: i.crypto,
    });
  } catch (error) {
    // a runtime that cannot verify at all is not the wallet's fault
    if (error instanceof UmisError && error.code === 'CRYPTO_UNAVAILABLE') throw error;
    return invalidProof();
  }
}
