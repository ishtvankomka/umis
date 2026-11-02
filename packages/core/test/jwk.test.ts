import { readFileSync } from 'node:fs';
import { calculateJwkThumbprint } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  UmisError,
  asEcPublicJwk,
  generateSigner,
  importSigner,
  jwkThumbprint,
  keyFingerprint,
  publicJwkEquals,
  webCryptoProvider,
  webCryptoSigner,
  type CryptoProvider,
  type EcPublicJwk,
} from '../src/index.js';
import { keyFromSeed, nobleCryptoProvider } from '../src/noble.js';

interface ThumbprintVectors {
  rsa: { key: { kty: string; [member: string]: string }; sha256Hex: string; thumbprint: string };
  ec: Array<{ key: EcPublicJwk; thumbprint: string }>;
  fingerprints: Array<{ keys: number[]; fingerprint: string }>;
}

const vectors = JSON.parse(
  readFileSync(new URL('../../../test-vectors/rfc7638-thumbprint.json', import.meta.url), 'utf8'),
) as ThumbprintVectors;

const providers: Array<[string, CryptoProvider]> = [
  ['webcrypto', webCryptoProvider],
  ['noble', nobleCryptoProvider()],
];

async function codeOf(run: () => Promise<unknown> | unknown): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

describe.each(providers)('JWK thumbprint (RFC 7638) with %s', (_name, crypto) => {
  it('reproduces the RFC 7638 section 3.1 thumbprint, ignoring alg and kid', async () => {
    expect(await jwkThumbprint(vectors.rsa.key, crypto)).toBe(vectors.rsa.thumbprint);
    const { alg: _alg, kid: _kid, ...bare } = vectors.rsa.key;
    expect(await jwkThumbprint(bare, crypto)).toBe(vectors.rsa.thumbprint);
  });

  it('agrees with the known answers and with jose for EC keys, whatever extra members and order the key has', async () => {
    for (const { key, thumbprint } of vectors.ec) {
      expect(await jwkThumbprint(key, crypto)).toBe(thumbprint);
      expect(await calculateJwkThumbprint(key, 'sha256')).toBe(thumbprint);
      const shuffled = { y: key.y, use: 'sig', x: key.x, kid: 'ignored', crv: key.crv, kty: key.kty };
      expect(await jwkThumbprint(shuffled, crypto)).toBe(thumbprint);
    }
    const fresh = await crypto.generateSigner();
    expect(await jwkThumbprint(fresh.publicJwk, crypto)).toBe(await calculateJwkThumbprint(fresh.publicJwk, 'sha256'));
  });

  it('is the default kid of generated and imported signers', async () => {
    const generated = await crypto.generateSigner();
    expect(generated.kid).toBe(await jwkThumbprint(generated.publicJwk, crypto));
    expect(generated.publicJwk.kid).toBe(generated.kid);
    const seeded = keyFromSeed(new TextEncoder().encode('thumbprint-kid'));
    const imported = await crypto.importSigner(seeded);
    expect(imported.kid).toBe(await jwkThumbprint({ kty: 'EC', crv: 'P-256', x: seeded.x, y: seeded.y }, crypto));
    expect((await crypto.importSigner({ ...seeded, kid: 'from-jwk' })).kid).toBe('from-jwk');
    expect((await crypto.importSigner({ ...seeded, kid: 'from-jwk' }, { kid: 'from-option' })).kid).toBe('from-option');
  });

  it('refuses members it cannot hash', async () => {
    expect(await codeOf(() => jwkThumbprint({ kty: 'oct', k: 'AAAA' }, crypto))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => jwkThumbprint({ kty: 'EC', crv: 'P-256', x: vectors.ec[0]!.key.x }, crypto))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await codeOf(() => jwkThumbprint({ kty: '__proto__' }, crypto))).toBe('INVALID_ARGUMENT');
  });
});

describe('key fingerprint', () => {
  const [a, b] = vectors.ec.map((entry) => entry.key) as [EcPublicJwk, EcPublicJwk];

  it('has the XXXX-XXXX-XXXX-XXXX base32 form and matches independently computed values', async () => {
    for (const { keys, fingerprint } of vectors.fingerprints) {
      const result = await keyFingerprint(keys.map((index) => vectors.ec[index]!.key));
      expect(result).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/);
      expect(result).toBe(fingerprint);
    }
  });

  it('ignores key order and changes with the key set, on either provider', async () => {
    for (const [, crypto] of providers) {
      expect(await keyFingerprint([a, b], crypto)).toBe(await keyFingerprint([b, a], crypto));
      expect(await keyFingerprint([a], crypto)).not.toBe(await keyFingerprint([a, b], crypto));
    }
    expect(await codeOf(() => keyFingerprint([]))).toBe('INVALID_ARGUMENT');
  });
});

describe('asEcPublicJwk and publicJwkEquals', () => {
  const key = vectors.ec[0]!.key;

  it('keeps kid, alg and use, and drops the private part and unknown members', () => {
    const clean = asEcPublicJwk({
      ...key,
      kid: 'k1',
      alg: 'ES256',
      use: 'sig',
      d: 'c2VjcmV0',
      key_ops: ['verify'],
      x5c: [],
    });
    expect(clean).toEqual({ ...key, kid: 'k1', alg: 'ES256', use: 'sig' });
    expect(Object.keys(clean)).not.toContain('d');
    expect(asEcPublicJwk(key)).toEqual(key);
  });

  it('rejects what is not a P-256 public key with INVALID_ARGUMENT', () => {
    const bad: Record<string, unknown> = {
      null: null,
      array: [key],
      string: 'jwk',
      'wrong kty': { ...key, kty: 'OKP' },
      'wrong curve': { ...key, crv: 'P-384' },
      'missing y': { kty: 'EC', crv: 'P-256', x: key.x },
      'short x': { ...key, x: key.x.slice(0, 42) },
      'padded y': { ...key, y: `${key.y}=` },
      'numeric x': { ...key, x: 7 },
      'wrong alg': { ...key, alg: 'ES384' },
      'encryption key': { ...key, use: 'enc' },
      'kid not a string': { ...key, kid: 7 },
    };
    for (const [why, value] of Object.entries(bad)) {
      expect(() => asEcPublicJwk(value), why).toThrowError(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
    }
  });

  it('compares curve and point only', () => {
    expect(publicJwkEquals(key, { ...key, kid: 'other', alg: 'ES256', use: 'sig' })).toBe(true);
    expect(publicJwkEquals(key, vectors.ec[1]!.key)).toBe(false);
  });
});

describe('signers built from key pairs', () => {
  it('webCryptoSigner exports only the public key and uses the thumbprint as kid', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const signer = await webCryptoSigner(pair);
    expect(signer.alg).toBe('ES256');
    expect(Object.keys(signer.publicJwk).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y']);
    expect(signer.kid).toBe(await jwkThumbprint(signer.publicJwk));
    const named = await webCryptoSigner(pair, 'issuer-2026');
    expect(named.kid).toBe('issuer-2026');
    const signature = await named.sign(new TextEncoder().encode('data'));
    expect(signature).toHaveLength(64);
    expect(await webCryptoProvider.verifyEs256(named.publicJwk, new TextEncoder().encode('data'), signature)).toBe(
      true,
    );
  });

  it('refuses key pairs that cannot sign ES256', async () => {
    const rsa = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    );
    expect(await codeOf(() => webCryptoSigner(rsa))).toBe('INVALID_ARGUMENT');
    const verifyOnly = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ]);
    expect(
      await codeOf(() => webCryptoSigner({ privateKey: verifyOnly.publicKey, publicKey: verifyOnly.publicKey })),
    ).toBe('INVALID_ARGUMENT');
  });

  it('generateSigner and importSigner use the default provider unless told otherwise', async () => {
    const generated = await generateSigner();
    expect(generated.alg).toBe('ES256');
    const seeded = keyFromSeed(new TextEncoder().encode('default-provider'));
    const viaNoble = await importSigner(seeded, { crypto: nobleCryptoProvider() });
    const viaWebCrypto = await importSigner(seeded);
    expect(publicJwkEquals(viaNoble.publicJwk, viaWebCrypto.publicJwk)).toBe(true);
    expect(viaNoble.kid).toBe(viaWebCrypto.kid);
  });
});
