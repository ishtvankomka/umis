import { base64urlEncode } from '../bytes.js';
import { UmisError } from '../reasons.js';
import type { EcPrivateJwk, EcPublicJwk, Signer } from '../types.js';
import { webCryptoProvider } from './webcrypto.js';

/** Everything the SDK needs from a cryptographic backend: randomness, SHA-256 and ES256. */
export interface CryptoProvider {
  readonly name: string; //                                       'webcrypto' | 'noble' | custom
  getRandomValues<T extends Uint8Array>(array: T): T;
  sha256(data: Uint8Array): Promise<Uint8Array>;
  /** ES256 over `data` (the provider hashes); `signature` is 64-byte r‖s; MUST accept high-S. */
  verifyEs256(key: EcPublicJwk, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
  generateSigner(opts?: { kid?: string }): Promise<Signer>; //    software P-256, kid defaults to the RFC 7638 thumbprint
  importSigner(jwk: EcPrivateJwk, opts?: { kid?: string }): Promise<Signer>;
}

/** Largest request one `getRandomValues` call serves (Web Crypto quota). */
const MAX_RANDOM_BYTES = 65_536;

let defaultProvider: CryptoProvider | undefined;

/** WebCrypto unless {@link setDefaultCrypto} was called. */
export function getDefaultCrypto(): CryptoProvider {
  return defaultProvider ?? webCryptoProvider;
}

export function setDefaultCrypto(p: CryptoProvider): void {
  const complete =
    typeof p === 'object' &&
    p !== null &&
    typeof p.getRandomValues === 'function' &&
    typeof p.sha256 === 'function' &&
    typeof p.verifyEs256 === 'function' &&
    typeof p.generateSigner === 'function' &&
    typeof p.importSigner === 'function';
  if (!complete) throw new UmisError('INVALID_ARGUMENT', 'the default crypto provider is incomplete');
  defaultProvider = p;
}

export function randomBytes(n: number, crypto?: CryptoProvider): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > MAX_RANDOM_BYTES) {
    throw new UmisError('INVALID_ARGUMENT', `random length must be an integer in [0, ${MAX_RANDOM_BYTES}]`);
  }
  return (crypto ?? getDefaultCrypto()).getRandomValues(new Uint8Array(n));
}

/** Random identifier as unpadded base64url; 16 bytes unless told otherwise. */
export function randomId(bytes = 16, crypto?: CryptoProvider): string {
  return base64urlEncode(randomBytes(bytes, crypto));
}
