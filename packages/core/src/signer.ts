import { getDefaultCrypto, type CryptoProvider } from './crypto/provider.js';
import { signerFromKeyPair } from './crypto/webcrypto.js';
import type { EcPrivateJwk, Signer } from './types.js';

/**
 * Wraps a WebCrypto ECDSA P-256 key pair as a {@link Signer}. Only the public JWK is exported; `kid` defaults to the
 * RFC 7638 thumbprint of the public key.
 */
export function webCryptoSigner(keys: CryptoKeyPair, kid?: string): Promise<Signer> {
  return signerFromKeyPair(keys, kid);
}

/** A fresh software P-256 signer from the given provider (the default one unless told otherwise). */
export function generateSigner(opts?: { crypto?: CryptoProvider; kid?: string }): Promise<Signer> {
  return (opts?.crypto ?? getDefaultCrypto()).generateSigner({ kid: opts?.kid });
}

/** A signer for an existing private JWK; `kid` is the option, else the JWK's own `kid`, else the thumbprint. */
export function importSigner(jwk: EcPrivateJwk, opts?: { crypto?: CryptoProvider; kid?: string }): Promise<Signer> {
  return (opts?.crypto ?? getDefaultCrypto()).importSigner(jwk, { kid: opts?.kid });
}
