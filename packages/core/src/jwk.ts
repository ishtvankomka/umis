import { base32Encode, utf8Encode } from './bytes.js';
import { decodeCoordinate, thumbprintOf } from './crypto/ec.js';
import { getDefaultCrypto, type CryptoProvider } from './crypto/provider.js';
import { UmisError } from './reasons.js';
import type { EcPublicJwk } from './types.js';

/**
 * RFC 7638 thumbprint: SHA-256 over the required members of an EC, RSA or OKP key in lexicographic order, without
 * whitespace, as unpadded base64url. Members other than the required ones (`kid`, `alg`, `use`, `d`) never enter it.
 * The second member of the parameter type admits interface-typed keys such as {@link EcPublicJwk}, which have no
 * implicit index signature.
 */
export async function jwkThumbprint(
  jwk: { kty: string; [member: string]: unknown } | { kty: string },
  crypto?: CryptoProvider,
): Promise<string> {
  const provider = crypto ?? getDefaultCrypto();
  return thumbprintOf((data) => provider.sha256(data), jwk);
}

/**
 * Short text for people to compare out of band: the thumbprints sorted and joined with ',', hashed with SHA-256, the
 * first 10 bytes as base32 in four groups, e.g. `ABCD-2345-EFGH-6723`. The order of the keys does not matter.
 */
export async function keyFingerprint(jwks: readonly EcPublicJwk[], crypto?: CryptoProvider): Promise<string> {
  if (!Array.isArray(jwks) || jwks.length === 0) {
    throw new UmisError('INVALID_ARGUMENT', 'a key fingerprint needs at least one key');
  }
  const keys: readonly EcPublicJwk[] = jwks;
  const provider = crypto ?? getDefaultCrypto();
  const thumbprints = await Promise.all(keys.map((jwk) => jwkThumbprint(jwk, provider)));
  thumbprints.sort();
  const digest = await provider.sha256(utf8Encode(thumbprints.join(',')));
  const text = base32Encode(digest.subarray(0, 10));
  return `${text.slice(0, 4)}-${text.slice(4, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}`;
}

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

function member(jwk: object, name: string): unknown {
  return Object.hasOwn(jwk, name) ? (jwk as Record<string, unknown>)[name] : undefined;
}

/**
 * Validates a P-256 public key and returns a clean copy: `kty`, `crv`, `x`, `y` and, when present and valid, `kid`,
 * `alg` (ES256) and `use` (sig). The private part `d` and every unknown member are dropped.
 */
export function asEcPublicJwk(jwk: unknown): EcPublicJwk {
  if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) throw invalid('a JWK must be a JSON object');
  if (member(jwk, 'kty') !== 'EC') throw invalid('JWK kty must be "EC"');
  if (member(jwk, 'crv') !== 'P-256') throw invalid('JWK crv must be "P-256"');
  const x = member(jwk, 'x');
  const y = member(jwk, 'y');
  if (
    typeof x !== 'string' ||
    typeof y !== 'string' ||
    decodeCoordinate(x) === undefined ||
    decodeCoordinate(y) === undefined
  ) {
    throw invalid('JWK x and y must be the base64url of 32 bytes');
  }
  const out: EcPublicJwk = { kty: 'EC', crv: 'P-256', x, y };
  const kid = member(jwk, 'kid');
  if (kid !== undefined) {
    if (typeof kid !== 'string') throw invalid('JWK kid must be a string');
    out.kid = kid;
  }
  const alg = member(jwk, 'alg');
  if (alg !== undefined) {
    if (alg !== 'ES256') throw invalid('JWK alg must be "ES256"');
    out.alg = 'ES256';
  }
  const use = member(jwk, 'use');
  if (use !== undefined) {
    if (use !== 'sig') throw invalid('JWK use must be "sig"');
    out.use = 'sig';
  }
  return out;
}

/** Same curve and same point; `kid`, `alg` and `use` do not count. */
export function publicJwkEquals(a: EcPublicJwk, b: EcPublicJwk): boolean {
  return a.crv === b.crv && a.x === b.x && a.y === b.y;
}
