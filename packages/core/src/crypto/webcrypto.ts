import { ALG } from '../profile.js';
import { UmisError } from '../reasons.js';
import type { EcPrivateJwk, EcPublicJwk, Signer } from '../types.js';
import { decodeCoordinate, EC_COORDINATE_BYTES, thumbprintOf } from './ec.js';
import type { CryptoProvider } from './provider.js';

const KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' } as const;
const SIGNATURE_BYTES = 2 * EC_COORDINATE_BYTES;

/** Imported verification keys, kept so that repeated checks against the same issuer key skip the import. */
const VERIFY_KEY_CACHE_LIMIT = 256;
const verifyKeyCache = new Map<string, CryptoKey>();

const unavailable = (what: string, cause?: unknown): UmisError =>
  new UmisError('CRYPTO_UNAVAILABLE', `${what} is not available in this runtime`, { cause });

/** Resolved on every call, never cached: a runtime may install or remove `globalThis.crypto` after this module loaded. */
function webCrypto(): Crypto {
  const c: Crypto | undefined = (globalThis as { crypto?: Crypto }).crypto;
  if (c === undefined || c === null) throw unavailable('WebCrypto (globalThis.crypto)');
  return c;
}

function subtle(): SubtleCrypto {
  const s: SubtleCrypto | undefined = webCrypto().subtle;
  if (s === undefined || s === null) throw unavailable('WebCrypto SubtleCrypto');
  return s;
}

/** Web Crypto accepts only views over a plain ArrayBuffer; anything else is copied. */
function bufferSource(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return data.buffer instanceof ArrayBuffer ? (data as Uint8Array<ArrayBuffer>) : new Uint8Array(data);
}

async function importVerifyKey(s: SubtleCrypto, key: EcPublicJwk): Promise<CryptoKey | undefined> {
  if (typeof key !== 'object' || key === null || key.kty !== 'EC' || key.crv !== 'P-256') return undefined;
  if (decodeCoordinate(key.x) === undefined || decodeCoordinate(key.y) === undefined) return undefined;
  const id = `${key.x}.${key.y}`;
  const cached = verifyKeyCache.get(id);
  if (cached !== undefined) return cached;
  let imported: CryptoKey;
  try {
    imported = await s.importKey('jwk', { kty: 'EC', crv: 'P-256', x: key.x, y: key.y }, KEY_ALGORITHM, false, [
      'verify',
    ]);
  } catch {
    return undefined; // not a point on the curve
  }
  if (verifyKeyCache.size >= VERIFY_KEY_CACHE_LIMIT) {
    const oldest = verifyKeyCache.keys().next();
    if (!oldest.done) verifyKeyCache.delete(oldest.value);
  }
  verifyKeyCache.set(id, imported);
  return imported;
}

/**
 * Wraps a WebCrypto key pair. Only the public JWK is ever exported; the private key stays whatever the caller made it
 * (non-extractable for keys generated here).
 */
export async function signerFromKeyPair(keys: CryptoKeyPair, kid?: string): Promise<Signer> {
  if (typeof keys !== 'object' || keys === null) {
    throw new UmisError('INVALID_ARGUMENT', 'expected an ECDSA P-256 key pair');
  }
  const { privateKey, publicKey } = keys;
  const algorithm = privateKey?.algorithm as Partial<EcKeyAlgorithm> | undefined;
  if (
    privateKey?.type !== 'private' ||
    publicKey?.type !== 'public' ||
    algorithm?.name !== 'ECDSA' ||
    algorithm.namedCurve !== 'P-256' ||
    !privateKey.usages.includes('sign')
  ) {
    throw new UmisError('INVALID_ARGUMENT', 'expected an ECDSA P-256 key pair whose private key may sign');
  }
  const exported = await subtle().exportKey('jwk', publicKey);
  const { x, y } = exported;
  if (x === undefined || y === undefined || decodeCoordinate(x) === undefined || decodeCoordinate(y) === undefined) {
    throw new UmisError('INVALID_ARGUMENT', 'the public key is not an uncompressed P-256 point');
  }
  const base = { kty: 'EC', crv: 'P-256', x, y } as const;
  const resolvedKid = kid ?? (await thumbprintOf((data) => webCryptoProvider.sha256(data), base));
  const publicJwk: EcPublicJwk = { ...base, kid: resolvedKid, alg: ALG, use: 'sig' };
  return {
    alg: ALG,
    kid: resolvedKid,
    publicJwk,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      const signature = new Uint8Array(await subtle().sign(SIGN_ALGORITHM, privateKey, bufferSource(data)));
      if (signature.length !== SIGNATURE_BYTES) {
        throw new UmisError('CRYPTO_UNAVAILABLE', 'WebCrypto returned an ECDSA signature that is not r||s of 64 bytes');
      }
      return signature;
    },
  };
}

export const webCryptoProvider: CryptoProvider = {
  name: 'webcrypto',

  getRandomValues<T extends Uint8Array>(array: T): T {
    webCrypto().getRandomValues(array as Uint8Array<ArrayBuffer>);
    return array;
  },

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await subtle().digest('SHA-256', bufferSource(data)));
  },

  async verifyEs256(key: EcPublicJwk, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const s = subtle();
    if (signature.length !== SIGNATURE_BYTES) return false;
    const cryptoKey = await importVerifyKey(s, key);
    if (cryptoKey === undefined) return false;
    try {
      return await s.verify(SIGN_ALGORITHM, cryptoKey, bufferSource(signature), bufferSource(data));
    } catch {
      return false;
    }
  },

  async generateSigner(opts?: { kid?: string }): Promise<Signer> {
    const s = subtle();
    let keys: CryptoKeyPair;
    try {
      keys = await s.generateKey(KEY_ALGORITHM, false, ['sign', 'verify']);
    } catch (cause) {
      throw unavailable('WebCrypto ECDSA P-256 key generation', cause);
    }
    return signerFromKeyPair(keys, opts?.kid);
  },

  /** The signer's `kid` is `opts.kid`, else the `kid` of the JWK, else the RFC 7638 thumbprint. */
  async importSigner(jwk: EcPrivateJwk, opts?: { kid?: string }): Promise<Signer> {
    const s = subtle();
    const shaped =
      typeof jwk === 'object' &&
      jwk !== null &&
      jwk.kty === 'EC' &&
      jwk.crv === 'P-256' &&
      decodeCoordinate(jwk.x) !== undefined &&
      decodeCoordinate(jwk.y) !== undefined &&
      decodeCoordinate(jwk.d) !== undefined;
    if (!shaped) throw new UmisError('INVALID_ARGUMENT', 'expected a P-256 private JWK with 32-byte x, y and d');
    let keys: CryptoKeyPair;
    try {
      const privateKey = await s.importKey(
        'jwk',
        { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d },
        KEY_ALGORITHM,
        false,
        ['sign'],
      );
      const publicKey = await s.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, KEY_ALGORITHM, true, [
        'verify',
      ]);
      keys = { privateKey, publicKey };
    } catch (cause) {
      throw new UmisError('INVALID_ARGUMENT', 'the private JWK was rejected: not a valid P-256 key pair', { cause });
    }
    return signerFromKeyPair(keys, opts?.kid ?? jwk.kid);
  },
};
