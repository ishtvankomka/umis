import { randomFillSync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  UmisError,
  base64urlDecode,
  base64urlEncode,
  bytesEqual,
  getDefaultCrypto,
  hexEncode,
  publicJwkEquals,
  randomBytes,
  randomId,
  setDefaultCrypto,
  signJws,
  utf8Encode,
  verifyJws,
  webCryptoProvider,
  type CryptoProvider,
  type EcPrivateJwk,
} from '../src/index.js';
import { keyFromSeed, nobleCryptoProvider } from '../src/noble.js';

const TYP = 'umis-test+jwt';
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const seed = (text: string): Uint8Array => utf8Encode(text);
/** Base64url text of `length` bytes that all equal `value`. */
const filled = (length: number, value: number): string => base64urlEncode(new Uint8Array(length).fill(value));

async function codeOf(run: () => Promise<unknown> | unknown): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  setDefaultCrypto(webCryptoProvider);
});

describe('Expo Go simulation: no globalThis.crypto', () => {
  it('lets the noble provider generate, sign and verify with an injected random source', async () => {
    const noble = nobleCryptoProvider({ getRandomValues: (array) => randomFillSync(array) });
    vi.stubGlobal('crypto', undefined);
    expect(globalThis.crypto).toBeUndefined();

    const signer = await noble.generateSigner();
    const token = await signJws({ header: { typ: TYP }, payload: { sub: 'holder' }, signer });
    const decoded = await verifyJws(token, { typ: TYP, key: signer.publicJwk, crypto: noble });
    expect(decoded.payload).toEqual({ sub: 'holder' });
    expect(await noble.sha256(utf8Encode('abc'))).toHaveLength(32);

    setDefaultCrypto(noble);
    expect(getDefaultCrypto()).toBe(noble);
    expect(randomId()).toHaveLength(22);
    const viaDefault = await verifyJws(token, { typ: TYP, key: signer.publicJwk });
    expect(viaDefault.payload).toEqual({ sub: 'holder' });
  });

  it('makes the WebCrypto provider fail with CRYPTO_UNAVAILABLE instead of reaching for something else', async () => {
    const noble = nobleCryptoProvider({ getRandomValues: (array) => randomFillSync(array) });
    const signer = await noble.generateSigner();
    const data = utf8Encode('data');
    const signature = await signer.sign(data);
    vi.stubGlobal('crypto', undefined);

    expect(() => webCryptoProvider.getRandomValues(new Uint8Array(16))).toThrowError(
      expect.objectContaining({ code: 'CRYPTO_UNAVAILABLE' }),
    );
    expect(await codeOf(() => webCryptoProvider.sha256(data))).toBe('CRYPTO_UNAVAILABLE');
    expect(await codeOf(() => webCryptoProvider.verifyEs256(signer.publicJwk, data, signature))).toBe(
      'CRYPTO_UNAVAILABLE',
    );
    expect(await codeOf(() => webCryptoProvider.generateSigner())).toBe('CRYPTO_UNAVAILABLE');
    expect(await codeOf(() => webCryptoProvider.importSigner(keyFromSeed(seed('expo-go'))))).toBe('CRYPTO_UNAVAILABLE');
    expect(await codeOf(() => randomBytes(16))).toBe('CRYPTO_UNAVAILABLE');
  });

  it('keeps a noble provider without any random source able to sign and verify, but not to generate keys', async () => {
    const withSource = nobleCryptoProvider({ getRandomValues: (array) => randomFillSync(array) });
    const signer = await withSource.importSigner(keyFromSeed(seed('no-rng')));
    const data = utf8Encode('data');
    const bare = nobleCryptoProvider();
    vi.stubGlobal('crypto', undefined);

    expect(await codeOf(() => bare.generateSigner())).toBe('CRYPTO_UNAVAILABLE');
    expect(await codeOf(() => bare.getRandomValues(new Uint8Array(16)))).toBe('CRYPTO_UNAVAILABLE');
    expect(await bare.verifyEs256(signer.publicJwk, data, await signer.sign(data))).toBe(true);
  });

  it('refuses a random source that leaves the buffer untouched', async () => {
    const dead = nobleCryptoProvider({ getRandomValues: (array) => array });
    expect(await codeOf(() => dead.generateSigner())).toBe('CRYPTO_UNAVAILABLE');
    expect(await codeOf(() => dead.getRandomValues(new Uint8Array(32)))).toBe('CRYPTO_UNAVAILABLE');
  });

  it('never asks globalThis.crypto for bytes: generation uses the injected source, the rest needs none', async () => {
    let injectedDraws = 0;
    const noble = nobleCryptoProvider({
      getRandomValues: (array) => {
        injectedDraws++;
        return randomFillSync(array);
      },
    });
    const global = vi.spyOn(globalThis.crypto, 'getRandomValues');

    const generated = await noble.generateSigner();
    expect(injectedDraws).toBe(1);
    const imported = await noble.importSigner(keyFromSeed(seed('quiet')));
    const data = utf8Encode('data');
    const signature = await imported.sign(data);
    expect(await noble.verifyEs256(imported.publicJwk, data, signature)).toBe(true);
    expect(await noble.verifyEs256(generated.publicJwk, data, signature)).toBe(false);
    expect(injectedDraws).toBe(1);
    expect(global).not.toHaveBeenCalled();
  });
});

describe('the two providers agree', () => {
  it('signs deterministically with a low s, and WebCrypto verifies what noble signs and the reverse', async () => {
    const noble = nobleCryptoProvider();
    const signer = await noble.generateSigner();
    const data = utf8Encode('the same bytes every time');
    const first = await signer.sign(data);
    const second = await signer.sign(data);
    expect(first).toHaveLength(64);
    expect(bytesEqual(first, second)).toBe(true);
    expect(BigInt(`0x${hexEncode(first.subarray(32))}`)).toBeLessThanOrEqual(P256_ORDER / 2n);
    expect(bytesEqual(first, await signer.sign(utf8Encode('other bytes')))).toBe(false);
    expect(await webCryptoProvider.verifyEs256(signer.publicJwk, data, first)).toBe(true);

    const native = await webCryptoProvider.generateSigner();
    expect(await noble.verifyEs256(native.publicJwk, data, await native.sign(data))).toBe(true);
    expect(await noble.verifyEs256(native.publicJwk, data, first)).toBe(false);
  });

  it('hashes alike', async () => {
    const data = utf8Encode('abc');
    const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    expect(hexEncode(await nobleCryptoProvider().sha256(data))).toBe(expected);
    expect(hexEncode(await webCryptoProvider.sha256(data))).toBe(expected);
  });

  it('derives the same signer from the same private JWK', async () => {
    const jwk = keyFromSeed(seed('same-key'));
    const a = await nobleCryptoProvider().importSigner(jwk);
    const b = await webCryptoProvider.importSigner(jwk);
    expect(publicJwkEquals(a.publicJwk, b.publicJwk)).toBe(true);
    expect(a.kid).toBe(b.kid);
  });
});

describe('keyFromSeed', () => {
  it('is deterministic, pinned, and consistent as a key pair', async () => {
    const jwk = keyFromSeed(seed('umis-test-seed-1'));
    expect(keyFromSeed(seed('umis-test-seed-1'))).toEqual(jwk);
    expect(jwk).toMatchObject({
      kty: 'EC',
      crv: 'P-256',
      x: 'Jnzht7-CrR57Pv3Y30xmOrGDTnVCO_fV_8uhS6fTkhA',
      y: 'deP7cDnM17IAqN1f_RAhqlMUDqEzJ6kIvTA9hEKmFH8',
    });
    expect(base64urlDecode(jwk.d)).toHaveLength(32);
    const other = keyFromSeed(seed('umis-test-seed-2'));
    expect(other.x).toBe('MZq9yozojC-9yEQW_wyGG5vAUobOsGKvLtFtMeXhdjQ');
    expect(other.d).not.toBe(jwk.d);
    // WebCrypto refuses a private JWK whose x and y do not belong to d, so a successful import is an independent check.
    expect(await webCryptoProvider.importSigner(jwk)).toMatchObject({ publicJwk: { x: jwk.x, y: jwk.y } });
  });
});

describe.each<[string, CryptoProvider]>([
  ['webcrypto', webCryptoProvider],
  ['noble', nobleCryptoProvider()],
])('importSigner on the %s provider', (_name, provider) => {
  const good = keyFromSeed(seed('import-me'));
  const other = keyFromSeed(seed('someone-else'));

  it('signs with the imported key', async () => {
    const signer = await provider.importSigner(good);
    const data = utf8Encode('data');
    expect(await provider.verifyEs256(signer.publicJwk, data, await signer.sign(data))).toBe(true);
    expect(signer.publicJwk).not.toHaveProperty('d');
  });

  it('refuses a JWK that is not a consistent P-256 private key: INVALID_ARGUMENT', async () => {
    const bad: Record<string, unknown> = {
      'x and y of another key': { ...good, x: other.x, y: other.y },
      'private scalar of another key': { ...good, d: other.d },
      'no private part': { kty: 'EC', crv: 'P-256', x: good.x, y: good.y },
      'zero scalar': { ...good, d: filled(32, 0x00) },
      'scalar of 31 bytes': { ...good, d: good.d.slice(0, 41) },
      'scalar not below the group order': { ...good, d: filled(32, 0xff) },
      'wrong curve': { ...good, crv: 'P-384' },
      'wrong key type': { ...good, kty: 'OKP' },
      null: null,
    };
    for (const [why, jwk] of Object.entries(bad)) {
      expect(await codeOf(() => provider.importSigner(jwk as EcPrivateJwk)), why).toBe('INVALID_ARGUMENT');
    }
  });
});

describe('randomness helpers and the default provider', () => {
  it('returns random bytes and identifiers of the requested size', () => {
    expect(randomBytes(0)).toHaveLength(0);
    const a = randomBytes(16);
    const b = randomBytes(16);
    expect(a).toHaveLength(16);
    expect(bytesEqual(a, b)).toBe(false);
    expect(randomBytes(65_536)).toHaveLength(65_536);
    expect(randomId()).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(randomId(32)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomId()).not.toBe(randomId());
    for (const n of [-1, 1.5, Number.NaN, 65_537]) {
      expect(() => randomBytes(n), String(n)).toThrowError(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
    }
  });

  it('uses the provider it is given, and the one set as default otherwise', () => {
    const calls: number[] = [];
    const counting = nobleCryptoProvider({
      getRandomValues: (array) => {
        calls.push(array.length);
        return randomFillSync(array);
      },
    });
    expect(getDefaultCrypto()).toBe(webCryptoProvider);
    randomBytes(24, counting);
    setDefaultCrypto(counting);
    randomBytes(20);
    expect(calls).toEqual([24, 20]);
    expect(() => setDefaultCrypto({ name: 'half' } as unknown as CryptoProvider)).toThrowError(
      expect.objectContaining({ code: 'INVALID_ARGUMENT' }),
    );
    expect(getDefaultCrypto()).toBe(counting);
  });

  it('reuses imported verification keys in the WebCrypto provider and keeps at most 256', async () => {
    const importKey = vi.spyOn(crypto.subtle, 'importKey');
    const data = utf8Encode('x');
    const first = await webCryptoProvider.generateSigner();
    const signature = await first.sign(data);
    expect(await webCryptoProvider.verifyEs256(first.publicJwk, data, signature)).toBe(true);
    const afterFirst = importKey.mock.calls.length;
    expect(await webCryptoProvider.verifyEs256(first.publicJwk, data, signature)).toBe(true);
    expect(importKey.mock.calls.length).toBe(afterFirst);

    for (let i = 0; i < 256; i++) {
      const signer = await webCryptoProvider.generateSigner();
      expect(await webCryptoProvider.verifyEs256(signer.publicJwk, data, await signer.sign(data))).toBe(true);
    }
    const beforeAgain = importKey.mock.calls.length;
    expect(await webCryptoProvider.verifyEs256(first.publicJwk, data, signature)).toBe(true);
    expect(importKey.mock.calls.length).toBe(beforeAgain + 1);
  });
});
