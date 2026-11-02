import { ecdsa, weierstrass } from '@noble/curves/abstract/weierstrass.js';
import { p256 } from '@noble/curves/nist.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { base64urlEncode, bytesEqual, concatBytes } from '../bytes.js';
import { ALG } from '../profile.js';
import { UmisError } from '../reasons.js';
import type { EcPrivateJwk, EcPublicJwk, Signer } from '../types.js';
import { decodeCoordinate, EC_COORDINATE_BYTES, thumbprintOf } from './ec.js';
import type { CryptoProvider } from './provider.js';

/** Bytes of randomness that `randomSecretKey` maps into the P-256 scalar field with negligible bias. */
const SECRET_KEY_SEED_BYTES = 48;
const SIGNATURE_BYTES = 2 * EC_COORDINATE_BYTES;
/** Requests at least this long must not come back as zeros: that is an entropy source that did nothing. */
const ZERO_CHECK_MIN_BYTES = 16;

// The stock `p256` of @noble/curves blinds secret-scalar arithmetic with bytes it takes from `globalThis.crypto` at call
// time, so signing and key derivation would depend on a global that Expo Go does not have. This curve has the same
// parameters and no random source: nothing here reaches outside the arguments, and a missing or replaced
// `globalThis.crypto` cannot change what it does. Key generation draws its randomness through the provider instead.
const noRandomSource = (): never => {
  throw new UmisError('CRYPTO_UNAVAILABLE', 'this curve has no random source of its own; pass a seed');
};
const curve = ecdsa(weierstrass(p256.Point.CURVE(), { randomBytes: noRandomSource }), sha256, {
  randomBytes: noRandomSource,
});

// RFC 6979 deterministic nonces: signing never asks for randomness. WebCrypto and hardware signers produce high-S
// signatures about half the time, so verification accepts both halves; signing emits the low half.
const SIGN_OPTIONS = { prehash: true, lowS: true, format: 'compact', extraEntropy: false } as const;
const VERIFY_OPTIONS = { prehash: true, lowS: false, format: 'compact' } as const;

const sha256Async = async (data: Uint8Array): Promise<Uint8Array> => sha256(data);

/** The public JWK members of a secret key. */
function publicMembers(secretKey: Uint8Array): { kty: 'EC'; crv: 'P-256'; x: string; y: string } {
  const point = curve.getPublicKey(secretKey, false); // 0x04 ‖ x ‖ y
  return {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlEncode(point.slice(1, 1 + EC_COORDINATE_BYTES)),
    y: base64urlEncode(point.slice(1 + EC_COORDINATE_BYTES)),
  };
}

async function signerFromSecretKey(secretKey: Uint8Array, kid: string | undefined): Promise<Signer> {
  const base = publicMembers(secretKey);
  const resolvedKid = kid ?? (await thumbprintOf(sha256Async, base));
  const publicJwk: EcPublicJwk = { ...base, kid: resolvedKid, alg: ALG, use: 'sig' };
  return {
    alg: ALG,
    kid: resolvedKid,
    publicJwk,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return curve.sign(data, secretKey, SIGN_OPTIONS);
    },
  };
}

/**
 * ES256 on the audited `@noble` libraries, for runtimes without WebCrypto (Expo Go) and as an opt-in everywhere else.
 * Randomness comes from `opts.getRandomValues`, else from `globalThis.crypto`; signing and verifying need none.
 */
export function nobleCryptoProvider(
  opts: { getRandomValues?: <T extends Uint8Array>(a: T) => T } = {},
): CryptoProvider {
  const fill = opts.getRandomValues;

  const getRandomValues = <T extends Uint8Array>(array: T): T => {
    if (fill !== undefined) {
      fill(array);
    } else {
      const c: Crypto | undefined = (globalThis as { crypto?: Crypto }).crypto;
      if (c === undefined || c === null || typeof c.getRandomValues !== 'function') {
        throw new UmisError(
          'CRYPTO_UNAVAILABLE',
          'no random source: pass getRandomValues or provide globalThis.crypto',
        );
      }
      c.getRandomValues(array as Uint8Array<ArrayBuffer>);
    }
    if (array.length >= ZERO_CHECK_MIN_BYTES && array.every((byte) => byte === 0)) {
      throw new UmisError('CRYPTO_UNAVAILABLE', 'the random source left the buffer zeroed');
    }
    return array;
  };

  return {
    name: 'noble',

    getRandomValues,

    sha256: sha256Async,

    async verifyEs256(key: EcPublicJwk, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
      if (signature.length !== SIGNATURE_BYTES) return false;
      if (typeof key !== 'object' || key === null || key.kty !== 'EC' || key.crv !== 'P-256') return false;
      const x = decodeCoordinate(key.x);
      const y = decodeCoordinate(key.y);
      if (x === undefined || y === undefined) return false;
      try {
        return curve.verify(signature, data, concatBytes(Uint8Array.of(0x04), x, y), VERIFY_OPTIONS);
      } catch {
        return false; // not a point on the curve
      }
    },

    async generateSigner(o?: { kid?: string }): Promise<Signer> {
      const seed = getRandomValues(new Uint8Array(SECRET_KEY_SEED_BYTES));
      try {
        return await signerFromSecretKey(curve.utils.randomSecretKey(seed), o?.kid);
      } finally {
        seed.fill(0);
      }
    },

    /** The signer's `kid` is `o.kid`, else the `kid` of the JWK, else the RFC 7638 thumbprint. */
    async importSigner(jwk: EcPrivateJwk, o?: { kid?: string }): Promise<Signer> {
      const d =
        typeof jwk === 'object' && jwk !== null && jwk.kty === 'EC' && jwk.crv === 'P-256'
          ? decodeCoordinate(jwk.d)
          : undefined;
      const x = decodeCoordinate(jwk?.x);
      const y = decodeCoordinate(jwk?.y);
      if (d === undefined || x === undefined || y === undefined) {
        throw new UmisError('INVALID_ARGUMENT', 'expected a P-256 private JWK with 32-byte x, y and d');
      }
      let point: Uint8Array;
      try {
        point = curve.getPublicKey(d, false);
      } catch (cause) {
        throw new UmisError('INVALID_ARGUMENT', 'the private scalar is not a valid P-256 key', { cause });
      }
      if (!bytesEqual(point.subarray(1), concatBytes(x, y))) {
        throw new UmisError('INVALID_ARGUMENT', 'x and y do not belong to d');
      }
      return signerFromSecretKey(d, o?.kid ?? jwk.kid);
    },
  };
}

/**
 * Deterministic private key from a seed, for tests and published vectors only: the first 48 bytes of SHA-512(seed) are
 * mapped into the scalar field by noble's `randomSecretKey`. Never use it to protect anything.
 */
export function keyFromSeed(seed: Uint8Array): EcPrivateJwk {
  const secretKey = curve.utils.randomSecretKey(sha512(seed).subarray(0, SECRET_KEY_SEED_BYTES));
  return { ...publicMembers(secretKey), d: base64urlEncode(secretKey) };
}
