import { readFileSync, readdirSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  TYP,
  UmisError,
  base64urlDecode,
  jwkThumbprint,
  signJws,
  utf8Encode,
  verifyJws,
  webCryptoProvider,
} from '@umis/core';
import { nobleCryptoProvider } from '@umis/core/noble';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createKeyStore } from '../src/index.js';
import * as secureStore from './mocks/expo-secure-store.js';

type SecureEnvironmentMock = typeof import('./mocks/expo-secure-environment.js');

const DATA = utf8Encode('eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ');
const noble = nobleCryptoProvider();
const loadsOfHardwareModule = (): number | undefined =>
  (globalThis as { __umisSecureEnvironmentLoads?: number }).__umisSecureEnvironmentLoads;

beforeEach(() => {
  secureStore.reset();
});

// This group runs first and nothing before it imports the hardware stand-in, so the counter tells whether the code did.
describe('Expo Go', () => {
  it('never loads the hardware module', async () => {
    const store = createKeyStore('expo_go');
    const signer = await store.create('holder-1', { requireBiometric: false });
    await signer.sign(DATA);
    await (await store.get('holder-1'))!.sign(DATA);
    await store.remove('holder-1');
    expect(loadsOfHardwareModule()).toBeUndefined();
  });
});

describe('software keys', () => {
  const store = createKeyStore('expo_go');

  it('make signatures that verify with WebCrypto and with @noble, are found again and are removed', async () => {
    const signer = await store.create('holder-1', { requireBiometric: false });
    expect(signer).toMatchObject({ alg: 'ES256', protection: 'software', attestation: 'none' });
    expect(signer.kid).toBe(await jwkThumbprint(signer.publicJwk));
    expect(signer.publicJwk).toEqual({
      kty: 'EC',
      crv: 'P-256',
      x: signer.publicJwk.x,
      y: signer.publicJwk.y,
      kid: signer.kid,
      alg: 'ES256',
      use: 'sig',
    });

    const signature = await signer.sign(DATA);
    expect(signature).toHaveLength(64);
    for (const provider of [webCryptoProvider, noble]) {
      expect(await provider.verifyEs256(signer.publicJwk, DATA, signature)).toBe(true);
      expect(await provider.verifyEs256(signer.publicJwk, utf8Encode('other'), signature)).toBe(false);
    }
    const jws = await signJws({ header: { typ: TYP.event, kid: signer.kid }, payload: { n: 1 }, signer });
    await expect(verifyJws(jws, { typ: TYP.event, key: signer.publicJwk })).resolves.toBeDefined();

    const found = await store.get('holder-1');
    expect(found?.publicJwk).toEqual(signer.publicJwk);
    expect(await webCryptoProvider.verifyEs256(signer.publicJwk, DATA, await found!.sign(DATA))).toBe(true);

    await store.remove('holder-1');
    expect(await store.get('holder-1')).toBeNull();
    await expect(signer.sign(DATA)).rejects.toMatchObject({ code: 'KEY_NOT_FOUND' }); // a removed key signs no more
    await expect(store.remove('holder-1')).resolves.toBeUndefined();
  });

  it('keep the private key only in the secret store, written for this device and nowhere else', async () => {
    const consoles = (['log', 'info', 'warn', 'error', 'debug'] as const).map((level) => vi.spyOn(console, level));
    const signer = await store.create('holder-1', { requireBiometric: false });
    await signer.sign(DATA);
    await store.get('holder-1');

    const stored = secureStore.dump();
    expect(Object.keys(stored)).toEqual(['umis.key.holder-1']);
    const record = JSON.parse(stored['umis.key.holder-1']!);
    expect(record).toMatchObject({ v: 1, kind: 'software', requireBiometric: false });
    expect(base64urlDecode(record.jwk.d)).toHaveLength(32);
    expect(record.jwk).toMatchObject({ x: signer.publicJwk.x, y: signer.publicJwk.y });

    expect(Object.keys(signer.publicJwk)).not.toContain('d');
    expect(JSON.stringify({ ...signer })).not.toContain(record.jwk.d);
    for (const spy of consoles) expect(spy).not.toHaveBeenCalled();
    consoles.forEach((spy) => spy.mockRestore());

    const writes = secureStore.calls.filter((call) => call.op === 'set');
    expect(writes).toHaveLength(1);
    expect(writes[0]!.options).toEqual({ keychainAccessible: secureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
  });

  it('are made under valid aliases only, and a key is never replaced', async () => {
    for (const bad of ['', 'a b', 'a.b', 'a/b', '../k', 'x'.repeat(65), 5, undefined]) {
      await expect(store.create(bad as string, { requireBiometric: false })).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
      });
      await expect(store.get(bad as string)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
      await expect(store.remove(bad as string)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    }
    expect(secureStore.dump()).toEqual({});

    const longest = await store.create(`${'a'.repeat(30)}_${'B'.repeat(33)}`, { requireBiometric: false });
    expect(longest.protection).toBe('software');
    const first = await store.create('k-1', { requireBiometric: false });
    await expect(store.create('k-1', { requireBiometric: false })).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    expect((await store.get('k-1'))?.kid).toBe(first.kid);
    for (const bad of [undefined, {}, { requireBiometric: 'yes' }, { requireBiometric: true, prompt: '' }]) {
      await expect(store.create('k-2', bad as never)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    }
    expect(() => createKeyStore('browser' as never)).toThrow(UmisError);
  });
});

describe('the confirmation of software keys', () => {
  it('is asked before every signature, with the text of the key, and before the secret is read', async () => {
    const asked: Array<{ prompt: string; readsOfTheKey: number }> = [];
    const readsOfTheKey = (): number =>
      secureStore.calls.filter((call) => call.op === 'get' && call.key === 'umis.key.guarded').length;
    const store = createKeyStore('expo_go', {
      prompt: 'Confirm with Face ID',
      authenticate: async (prompt) => {
        asked.push({ prompt, readsOfTheKey: readsOfTheKey() });
        return true;
      },
    });
    const signer = await store.create('guarded', { requireBiometric: true, prompt: 'Open the door' });
    expect(asked).toEqual([]); // making the key asks nothing

    const before = readsOfTheKey();
    await signer.sign(DATA);
    await signer.sign(DATA);
    expect(asked).toEqual([
      { prompt: 'Open the door', readsOfTheKey: before },
      { prompt: 'Open the door', readsOfTheKey: before + 1 },
    ]);

    await (await store.get('guarded'))!.sign(DATA); // a key found again asks with the text of the store
    expect(asked.at(-1)?.prompt).toBe('Confirm with Face ID');

    const open = await store.create('open', { requireBiometric: false });
    await open.sign(DATA);
    expect(asked).toHaveLength(3);
  });

  it('refuses to sign unless the person was recognised', async () => {
    let answer: unknown = true;
    const store = createKeyStore('expo_go', { authenticate: async () => answer as boolean });
    const signer = await store.create('guarded', { requireBiometric: true });

    for (const refusal of [false, undefined, null, 0, 'yes']) {
      answer = refusal;
      await expect(signer.sign(DATA)).rejects.toMatchObject({ code: 'USER_CANCELLED' });
    }
    answer = true;
    expect(await webCryptoProvider.verifyEs256(signer.publicJwk, DATA, await signer.sign(DATA))).toBe(true);

    const failing = createKeyStore('expo_go', {
      authenticate: async () => {
        throw new Error('no biometrics enrolled');
      },
    });
    await expect((await failing.get('guarded'))!.sign(DATA)).rejects.toMatchObject({ code: 'USER_CANCELLED' });
  });

  it('needs the authenticate function of createKeyStore, to make such a key and to sign with it', async () => {
    const plain = createKeyStore('expo_go');
    await expect(plain.create('guarded', { requireBiometric: true })).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    expect(secureStore.dump()).toEqual({});

    await createKeyStore('expo_go', { authenticate: async () => true }).create('guarded', { requireBiometric: true });
    await expect((await plain.get('guarded'))!.sign(DATA)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });
});

describe('the module graph', () => {
  const read = (directory: string, extension: string): Array<{ file: string; text: string }> =>
    readdirSync(directory)
      .filter((file) => file.endsWith(extension) && !file.endsWith('.d.ts'))
      .map((file) => ({ file, text: readFileSync(join(directory, file), 'utf8') }));
  const packageRoot = fileURLToPath(new URL('..', import.meta.url));

  it('reaches the hardware module through one dynamic import and imports no other Expo module than the two of Expo Go', () => {
    for (const files of [read(join(packageRoot, 'src'), '.ts'), read(join(packageRoot, 'dist'), '.js')]) {
      expect(files.length).toBeGreaterThanOrEqual(5);
      const statics = new Set<string>();
      const dynamics: string[] = [];
      for (const { file, text } of files) {
        for (const match of text.matchAll(/\bfrom\s+'([^']+)'/g)) statics.add(match[1]!);
        // a `typeof import('…')` is a type and leaves no trace in the compiled code
        for (const match of text.matchAll(/(?<!typeof\s+)\bimport\(\s*'([^']+)'\s*\)/g))
          dynamics.push(`${file.replace(/\.(ts|js)$/, '')}: ${match[1]}`);
      }
      const expo = [...statics].filter((specifier) => /^(expo|@animo-id)/.test(specifier)).sort();
      expect(expo).toEqual(['expo-crypto', 'expo-secure-store']);
      expect(dynamics).toEqual(['hardware-keys: @animo-id/expo-secure-environment']);
    }
  });
});

describe('hardware keys', () => {
  let hardware: SecureEnvironmentMock;
  beforeAll(async () => {
    hardware = await import('./mocks/expo-secure-environment.js');
  });
  beforeEach(() => {
    hardware.reset();
  });

  const publicKeyOf = async (alias: string) =>
    webcrypto.subtle.exportKey('jwk', hardware.keys.get(alias)!.pair.publicKey);

  it('turn the compressed public key into the key of the signer and keep only a note in the secret store', async () => {
    const store = createKeyStore('dev_client');
    for (let n = 0; n < 12; n++) {
      const signer = await store.create(`hw-${n}`, { requireBiometric: n % 2 === 0 });
      const exported = await publicKeyOf(`hw-${n}`);
      expect(signer).toMatchObject({ alg: 'ES256', protection: 'hardware', attestation: 'none' });
      expect(signer.publicJwk).toEqual({
        kty: 'EC',
        crv: 'P-256',
        x: exported.x,
        y: exported.y,
        kid: signer.kid,
        alg: 'ES256',
        use: 'sig',
      });
      expect(signer.kid).toBe(await jwkThumbprint({ kty: 'EC', crv: 'P-256', x: exported.x!, y: exported.y! }));
    }

    const generated = hardware.calls.filter((call) => call.fn === 'generateKeypair');
    expect(generated[0]).toMatchObject({
      keyId: 'hw-0',
      args: {
        minimumKeyStorage: 'trustedEnvironment',
        userAuthentication: { methods: ['biometric'], invalidateOnBiometricChange: true, validitySeconds: 0 },
      },
    });
    expect(generated[1]).toMatchObject({ keyId: 'hw-1', args: { userAuthentication: false } });

    const stored = secureStore.dump();
    expect(Object.keys(stored).sort()).toEqual(Array.from({ length: 12 }, (_, n) => `umis.keymeta.hw-${n}`).sort());
    expect(JSON.parse(stored['umis.keymeta.hw-0']!)).toEqual({ v: 1, kind: 'hardware', requireBiometric: true });
    expect(JSON.parse(stored['umis.keymeta.hw-1']!)).toEqual({ v: 1, kind: 'hardware', requireBiometric: false });
    expect(Object.values(stored).join('')).not.toContain('"d"');
  });

  it('sign through the module, and the signatures verify whichever half of the curve order s is in', async () => {
    const store = createKeyStore('dev_client');
    const signer = await store.create('hw-1', { requireBiometric: true, prompt: 'Open the door' });

    for (const highS of [false, true]) {
      hardware.state.highS = highS;
      for (let n = 0; n < 6; n++) {
        const signature = await signer.sign(DATA);
        if (highS) expect(hardware.hasHighS(signature)).toBe(true);
        expect(signature).toHaveLength(64);
        for (const provider of [webCryptoProvider, noble]) {
          expect(await provider.verifyEs256(signer.publicJwk, DATA, signature)).toBe(true);
          expect(await provider.verifyEs256(signer.publicJwk, utf8Encode('other'), signature)).toBe(false);
        }
        const jws = await signJws({ header: { typ: TYP.event, kid: signer.kid }, payload: { n }, signer });
        await expect(verifyJws(jws, { typ: TYP.event, key: signer.publicJwk })).resolves.toBeDefined();
      }
    }
    const signs = hardware.calls.filter((call) => call.fn === 'sign');
    expect(signs.length).toBeGreaterThanOrEqual(24);
    expect(signs[0]).toMatchObject({ keyId: 'hw-1', args: { prompt: { title: 'Open the door' } } });
  });

  it('leave the confirmation to the hardware', async () => {
    const authenticate = vi.fn(async () => true);
    const store = createKeyStore('dev_client', { authenticate });
    const signer = await store.create('hw-1', { requireBiometric: true });
    await signer.sign(DATA);
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('are found again and removed together with their note, and a key the hardware lost is gone', async () => {
    const store = createKeyStore('dev_client', { prompt: 'Confirm it is you' });
    const signer = await store.create('hw-1', { requireBiometric: false });
    const found = await store.get('hw-1');
    expect(found).toMatchObject({ protection: 'hardware', kid: signer.kid, publicJwk: signer.publicJwk });
    await found!.sign(DATA);
    expect(hardware.calls.filter((call) => call.fn === 'sign').at(-1)?.args).toEqual({
      prompt: { title: 'Confirm it is you' },
    });
    await expect(store.create('hw-1', { requireBiometric: false })).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });

    await store.remove('hw-1');
    expect(hardware.keys.size).toBe(0);
    expect(secureStore.dump()).toEqual({});
    expect(await store.get('hw-1')).toBeNull();
    await expect(store.remove('hw-1')).resolves.toBeUndefined();

    const lost = await store.create('hw-2', { requireBiometric: false });
    hardware.keys.delete('hw-2');
    expect(await store.get('hw-2')).toBeNull();
    await expect(lost.sign(DATA)).rejects.toMatchObject({ code: 'KEY_NOT_FOUND' });
    await store.remove('hw-2');
    expect(secureStore.dump()).toEqual({});
  });

  it('are never asked for twice at the same time', async () => {
    const signer = await createKeyStore('dev_client').create('hw-1', { requireBiometric: true });
    await Promise.all([signer.sign(DATA), signer.sign(DATA), signer.sign(DATA)]);
    expect(hardware.calls.filter((call) => call.fn === 'sign')).toHaveLength(3);
    expect(hardware.state.mostActive).toBe(1);
  });

  it('report what went wrong with the codes of the SDK', async () => {
    const signer = await createKeyStore('dev_client').create('hw-1', { requireBiometric: true });
    const cases: Array<[string, string]> = [
      ['UserAuthenticationCanceledError', 'USER_CANCELLED'],
      ['UserAuthenticationFailedError', 'USER_CANCELLED'],
      ['UserAuthenticationLockedOutError', 'USER_CANCELLED'],
      ['KeyNotFoundError', 'KEY_NOT_FOUND'],
      ['KeyInvalidatedError', 'KEY_NOT_FOUND'],
      ['SecureEnvironmentError', 'CRYPTO_UNAVAILABLE'],
    ];
    for (const [name, code] of cases) {
      hardware.state.signError = hardware.failure(name);
      await expect(signer.sign(DATA)).rejects.toMatchObject({ code });
    }
    hardware.state.signError = undefined;
    await expect(signer.sign(DATA)).resolves.toHaveLength(64);
  });

  it('fall back to a software key where the device has no secure hardware', async () => {
    hardware.state.supported = false; // the iOS Simulator has no Secure Enclave
    const store = createKeyStore('dev_client', { authenticate: async () => true });
    const signer = await store.create('hw-1', { requireBiometric: true });
    expect(signer.protection).toBe('software');
    expect(hardware.keys.size).toBe(0);
    expect(hardware.calls.map((call) => call.fn)).not.toContain('generateKeypair');
    expect(Object.keys(secureStore.dump())).toEqual(['umis.key.hw-1']);
    expect(await webCryptoProvider.verifyEs256(signer.publicJwk, DATA, await signer.sign(DATA))).toBe(true);
    expect((await store.get('hw-1'))?.protection).toBe('software');
    await store.remove('hw-1');
    expect(secureStore.dump()).toEqual({});

    // a fallback never makes a key that should ask for a confirmation but cannot
    const mute = createKeyStore('dev_client');
    await expect(mute.create('hw-2', { requireBiometric: true })).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    expect(secureStore.dump()).toEqual({});
  });

  it('fall back when the module cannot make the key, and delete a key that could not be finished', async () => {
    const store = createKeyStore('dev_client');

    hardware.state.generateError = hardware.failure('SecureEnvironmentNotSupportedError');
    expect((await store.create('hw-1', { requireBiometric: false })).protection).toBe('software');
    hardware.state.generateError = undefined;

    hardware.state.publicKeyError = hardware.failure('SecureEnvironmentError');
    expect((await store.create('hw-2', { requireBiometric: false })).protection).toBe('software');
    expect(hardware.keys.size).toBe(0);
    hardware.state.publicKeyError = undefined;

    secureStore.failWhen((call) =>
      call.op === 'set' && call.key.startsWith('umis.keymeta.') ? new Error('keychain locked') : undefined,
    );
    expect((await store.create('hw-3', { requireBiometric: false })).protection).toBe('software');
    expect(hardware.keys.size).toBe(0);
    expect(Object.keys(secureStore.dump()).sort()).toEqual(
      ['hw-1', 'hw-2', 'hw-3'].map((alias) => `umis.key.${alias}`),
    );
  });

  it('fall back to a software key when the optional module is not installed', async () => {
    vi.resetModules();
    vi.doMock('@animo-id/expo-secure-environment', () => {
      throw new Error('Cannot find module');
    });
    try {
      const fresh = await import('../src/index.js');
      const freshStore = await import('./mocks/expo-secure-store.js');
      const signer = await fresh.createKeyStore('dev_client').create('hw-1', { requireBiometric: false });
      expect(signer.protection).toBe('software');
      expect(Object.keys(freshStore.dump())).toEqual(['umis.key.hw-1']);
    } finally {
      vi.doUnmock('@animo-id/expo-secure-environment');
      vi.resetModules();
    }
  });
});
