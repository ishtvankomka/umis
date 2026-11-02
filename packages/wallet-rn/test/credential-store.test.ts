import { VCT } from '@umis/core';
import type { StoredCredential } from '@umis/wallet';
import { beforeEach, describe, expect, it } from 'vitest';
import { createCredentialStore } from '../src/index.js';
import type { CredentialStore } from '../src/index.js';
import * as secureStore from './mocks/expo-secure-store.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * A credential of about `size` characters, the way an issued SD-JWT VC with its disclosures looks to the store. A
 * different `shift` changes every character of the body, so that pieces of two versions cannot be mistaken for each other.
 */
function credential(id: string, size = 6_000, label = 'Посвідчення члена: Підрядник А', shift = 0): StoredCredential {
  const body = Array.from({ length: size }, (_, i) => ALPHABET[(i * 7 + id.length + shift) % 64]).join('');
  return {
    id,
    sdJwtVc: `${body}~`,
    vct: VCT.orgMember,
    issuer: 'https://issuer.example/org-a',
    keyAlias: `key-${id}`,
    receivedAt: 1_793_750_400,
    label,
  };
}

const keysOf = (id: string): string[] =>
  Object.keys(secureStore.dump()).filter((key) => key.startsWith(`umis.cred.${id}.`));

/** The keys that the stored credential `id` occupies, worked out from its count record: `<n>` or `<n>b`. */
function keysHeld(id: string): string[] {
  const match = /^(\d+)(b?)$/.exec(secureStore.dump()[`umis.cred.${id}.n`] ?? '');
  const pieces = Array.from({ length: Number(match?.[1]) }, (_, n) => `umis.cred.${id}.${match?.[2]}${n}`);
  return [`umis.cred.${id}.n`, ...pieces].sort();
}

/** Small pieces, so that a credential of a few hundred characters has many of them and a failure prints little. */
const SMALL = { chunkChars: 200 };

/** A fresh store that holds `stored` in the first (`'a'`) or the second (`'b'`) set of pieces. */
async function storeHolding(stored: StoredCredential, set: 'a' | 'b'): Promise<CredentialStore> {
  secureStore.reset();
  const store = createCredentialStore(SMALL);
  if (set === 'b') await store.put(credential(stored.id, 500, 'Раніше', 5)); // the next put goes to the second set
  await store.put(stored);
  expect(secureStore.dump()[`umis.cred.${stored.id}.n`]?.endsWith('b')).toBe(set === 'b');
  return store;
}

const SHAPES = [
  ['as many pieces', 700, 700],
  ['fewer pieces', 900, 100],
  ['more pieces', 100, 900],
] as const;

/** Calls `check` once for every write of a replacement: with the stored credential in either set and in each shape. */
async function everyWriteOfAReplacement(
  check: (cut: {
    store: CredentialStore;
    stored: StoredCredential;
    replacement: StoredCredential;
    k: number;
    where: string;
  }) => Promise<void>,
): Promise<void> {
  for (const [shape, storedSize, replacementSize] of SHAPES) {
    for (const set of ['a', 'b'] as const) {
      const stored = credential('cred-1', storedSize);
      const replacement = credential('cred-1', replacementSize, 'Нова назва', 11);

      const rehearsal = await storeHolding(stored, set);
      secureStore.calls.length = 0;
      await rehearsal.put(replacement);
      const writes = secureStore.calls.filter((call) => call.op === 'set').length; // the pieces and the count
      expect(writes).toBeGreaterThanOrEqual(2);

      for (let k = 0; k < writes; k++) {
        const where = `${shape}, stored in set ${set}, write ${k + 1} of ${writes}`;
        await check({ store: await storeHolding(stored, set), stored, replacement, k, where });
      }
    }
  }
}

beforeEach(() => {
  secureStore.reset();
});

describe('the credential store', () => {
  it('cuts a 6 KiB credential with Cyrillic text into pieces that each fit one stored value', async () => {
    const store = createCredentialStore();
    const original = credential('cred-oleh-0001');
    await store.put(original);

    const stored = secureStore.dump();
    const pieces = keysOf('cred-oleh-0001').filter((key) => !key.endsWith('.n'));
    expect(pieces.length).toBeGreaterThanOrEqual(4);
    for (const key of pieces) expect(Buffer.byteLength(stored[key]!)).toBeLessThan(2_048);
    expect(pieces.sort((a, b) => a.length - b.length || a.localeCompare(b))).toEqual(
      pieces.map((_, n) => `umis.cred.cred-oleh-0001.${n}`),
    );
    expect(stored['umis.cred.cred-oleh-0001.n']).toBe(String(pieces.length));
    expect(JSON.parse(stored['umis.creds.index']!)).toEqual(['cred-oleh-0001']);
    for (const key of pieces.slice(0, -1)) expect(stored[key]).toHaveLength(1_800);

    // chunks first, then their number, then the index; every value is kept for this device only while it is unlocked
    const writes = secureStore.calls.filter((call) => call.op === 'set');
    expect(writes.map((call) => call.key)).toEqual([
      ...pieces.map((_, n) => `umis.cred.cred-oleh-0001.${n}`),
      'umis.cred.cred-oleh-0001.n',
      'umis.creds.index',
    ]);
    for (const call of writes) {
      expect(call.options?.keychainAccessible).toBe(secureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY);
    }

    expect(await store.get('cred-oleh-0001')).toEqual(original);
    expect(await store.list()).toEqual([original]);
  });

  it('lists in the order of storing, removes index first and leaves nothing behind', async () => {
    const store = createCredentialStore();
    const [first, second, third] = [credential('cred-1', 3_000), credential('cred-2', 500), credential('cred-3')];
    for (const item of [first, second, third]) await store.put(item);
    expect(await store.list()).toEqual([first, second, third]);

    secureStore.calls.length = 0;
    await store.remove('cred-1');
    const changes = secureStore.calls.filter((call) => call.op !== 'get').map((call) => `${call.op} ${call.key}`);
    expect(changes[0]).toBe('set umis.creds.index');
    expect(changes[1]).toBe('delete umis.cred.cred-1.n');
    expect(changes.slice(2).every((change) => /^delete umis\.cred\.cred-1\.\d+$/.test(change))).toBe(true);

    expect(keysOf('cred-1')).toEqual([]);
    expect(await store.get('cred-1')).toBeNull();
    expect(await store.list()).toEqual([second, third]);
    await expect(store.remove('cred-1')).resolves.toBeUndefined();
    await expect(store.remove('unknown')).resolves.toBeUndefined();
  });

  it('leaves the index and the earlier credentials as they were when a write fails', async () => {
    const store = createCredentialStore();
    const first = credential('cred-1');
    const second = credential('cred-2');
    await store.put(first);
    const indexBefore = secureStore.dump()['umis.creds.index'];

    // the pieces are written, the number of pieces is not
    secureStore.failWhen((call) =>
      call.op === 'set' && call.key === 'umis.cred.cred-2.n' ? new Error('keychain locked') : undefined,
    );
    await expect(store.put(second)).rejects.toThrow('keychain locked');
    expect(secureStore.dump()['umis.creds.index']).toBe(indexBefore);
    expect(await store.list()).toEqual([first]);
    expect(await store.get('cred-2')).toBeNull();
    expect(keysOf('cred-2')).toEqual([]);

    // the pieces and their number are written, the index is not
    secureStore.failWhen((call) =>
      call.op === 'set' && call.key === 'umis.creds.index' ? new Error('keychain locked') : undefined,
    );
    await expect(store.put(second)).rejects.toThrow('keychain locked');
    expect(secureStore.dump()['umis.creds.index']).toBe(indexBefore);
    expect(await store.list()).toEqual([first]);
    expect(await store.get('cred-2')).toBeNull();
    expect(keysOf('cred-2')).toEqual([]);

    secureStore.failWhen(undefined);
    await store.put(second);
    expect(await store.list()).toEqual([first, second]);
  });

  it('replaces a credential with the same id in the other set of pieces and drops the old pieces', async () => {
    const store = createCredentialStore();
    await store.put(credential('cred-1', 6_000));
    expect(keysOf('cred-1').length).toBeGreaterThanOrEqual(6); // four or more pieces and their number
    expect(secureStore.dump()['umis.cred.cred-1.n']).toMatch(/^[0-9]+$/); // the first set: umis.cred.<id>.<n>

    // the second set: umis.cred.<id>.b<n>, and the count says so
    const replacement = credential('cred-1', 400, 'Нова назва', 11);
    await store.put(replacement);
    expect(secureStore.dump()['umis.cred.cred-1.n']).toBe('1b');
    expect(keysOf('cred-1').sort()).toEqual(['umis.cred.cred-1.b0', 'umis.cred.cred-1.n']);
    expect(await store.list()).toEqual([replacement]);
    expect(JSON.parse(secureStore.dump()['umis.creds.index']!)).toEqual(['cred-1']);

    // and back to the first one
    const third = credential('cred-1', 3_000, 'Третя версія', 23);
    await store.put(third);
    expect(keysOf('cred-1').some((key) => /\.b\d+$/.test(key))).toBe(false);
    expect(keysOf('cred-1').sort()).toEqual(keysHeld('cred-1'));
    expect(await store.get('cred-1')).toEqual(third);

    // removing clears whichever set holds the credential
    await store.put(replacement);
    expect(secureStore.dump()['umis.cred.cred-1.n']).toBe('1b');
    await store.remove('cred-1');
    expect(keysOf('cred-1')).toEqual([]);
    expect(await store.get('cred-1')).toBeNull();
  });

  it('keeps the stored credential when any write of its replacement fails', async () => {
    await everyWriteOfAReplacement(async ({ store, stored, replacement, k, where }) => {
      const before = secureStore.dump();
      let seen = 0;
      secureStore.failWhen((call) => (call.op === 'set' && seen++ === k ? new Error('write failed') : undefined));
      await expect(store.put(replacement), where).rejects.toThrow('write failed');
      secureStore.failWhen(undefined);

      expect(await store.get('cred-1'), where).toEqual(stored);
      expect(await store.list(), where).toEqual([stored]);
      expect(secureStore.dump(), where).toEqual(before); // nothing of the replacement is left
    });
  });

  it('keeps the stored credential when the app is cut short during its replacement', async () => {
    await everyWriteOfAReplacement(async ({ store, stored, replacement, k, where }) => {
      let seen = 0;
      let cut = false;
      // from write number k on nothing reaches the store, so no clean-up can run either
      secureStore.failWhen((call) => {
        if (call.op === 'set' && seen++ === k) cut = true;
        return cut ? new Error('app stopped') : undefined;
      });
      await expect(store.put(replacement), where).rejects.toThrow('app stopped');
      secureStore.failWhen(undefined); // the app starts again

      expect(await store.get('cred-1'), where).toEqual(stored);
      expect(await store.list(), where).toEqual([stored]);

      // storing the replacement again works and leaves one set of pieces and nothing else
      await store.put(replacement);
      expect(await store.get('cred-1'), where).toEqual(replacement);
      expect(keysOf('cred-1').sort(), where).toEqual(keysHeld('cred-1'));
    });
  });

  it('has replaced a credential once its count is written, whatever happens to the old pieces', async () => {
    const store = createCredentialStore(SMALL);
    const stored = credential('cred-1', 900);
    const replacement = credential('cred-1', 100, 'Нова назва', 11);
    await store.put(stored);

    // the old pieces cannot be deleted: the put still succeeds and the replacement is what is stored
    secureStore.failWhen((call) => (call.op === 'delete' ? new Error('keychain locked') : undefined));
    await expect(store.put(replacement)).resolves.toBeUndefined();
    secureStore.failWhen(undefined);
    expect(await store.get('cred-1')).toEqual(replacement);
    expect(await store.list()).toEqual([replacement]);

    // the count lands and the store still reports an error: the replacement stands, whole, and the old pieces go
    secureStore.reset();
    await store.put(stored);
    secureStore.failAfterWhen((call) =>
      call.op === 'set' && call.key.endsWith('.n') ? new Error('disk full') : undefined,
    );
    await expect(store.put(replacement)).rejects.toThrow('disk full');
    secureStore.failAfterWhen(undefined);
    expect(await store.get('cred-1')).toEqual(replacement);
    expect(secureStore.dump()['umis.cred.cred-1.n']).toMatch(/^[0-9]+b$/); // the second set holds it
    expect(keysOf('cred-1').sort()).toEqual(keysHeld('cred-1')); // and nothing else is left of the old one

    // the same, but the count cannot be read back: nothing is deleted, so the replacement is not lost
    secureStore.reset();
    await store.put(stored);
    let landed = false;
    secureStore.failAfterWhen((call) => {
      if (call.op !== 'set' || !call.key.endsWith('.n')) return undefined;
      landed = true;
      return new Error('disk full');
    });
    secureStore.failWhen((call) =>
      landed && call.op === 'get' && call.key.endsWith('.n') ? new Error('keychain locked') : undefined,
    );
    await expect(store.put(replacement)).rejects.toThrow('disk full');
    secureStore.failAfterWhen(undefined);
    secureStore.failWhen(undefined);
    expect(await store.get('cred-1')).toEqual(replacement);
  });

  it('refuses ids, credentials and options that are not valid, and stores nothing for them', async () => {
    const store = createCredentialStore();
    const valid = credential('cred-1', 100);
    const invalid: unknown[] = [
      { ...valid, id: '' },
      { ...valid, id: 'a.b' },
      { ...valid, id: 'x'.repeat(65) },
      { ...valid, sdJwtVc: '' },
      { ...valid, vct: undefined },
      { ...valid, receivedAt: '1793750400' },
      { ...valid, receivedAt: Number.NaN },
      { ...valid, label: 5 },
      'cred-1',
      null,
    ];
    for (const bad of invalid) {
      await expect(store.put(bad as StoredCredential)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    }
    for (const bad of ['', 'a.b', '../x', 'x'.repeat(65), 5]) {
      await expect(store.get(bad as string)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
      await expect(store.remove(bad as string)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    }
    expect(secureStore.dump()).toEqual({});

    for (const chunkChars of [0, 127, 2_048, 1_800.5, Number.NaN]) {
      expect(() => createCredentialStore({ chunkChars })).toThrowError(
        expect.objectContaining({ code: 'INVALID_ARGUMENT' }),
      );
    }
    for (const namespace of ['', 'a.b', 'a/b', 'x'.repeat(33)]) {
      expect(() => createCredentialStore({ namespace })).toThrowError(
        expect.objectContaining({ code: 'INVALID_ARGUMENT' }),
      );
    }

    // only the fields of a credential are kept
    await store.put({ ...valid, unexpected: 'field' } as StoredCredential);
    expect(await store.get('cred-1')).toEqual(valid);
  });

  it('keeps every credential when several are stored at the same time', async () => {
    const store = createCredentialStore();
    const items = Array.from({ length: 8 }, (_, n) => credential(`cred-${n}`, 2_500 + n));
    await Promise.all(items.map((item) => store.put(item)));
    expect((await store.list()).map((item) => item.id)).toEqual(items.map((item) => item.id));

    await Promise.all([store.remove('cred-2'), store.put(credential('cred-9', 100)), store.remove('cred-5')]);
    expect((await store.list()).map((item) => item.id)).toEqual([
      'cred-0',
      'cred-1',
      'cred-3',
      'cred-4',
      'cred-6',
      'cred-7',
      'cred-9',
    ]);
  });

  it('refuses a damaged credential instead of returning it, and still lists the others', async () => {
    const store = createCredentialStore();
    const [a, b, c] = [credential('cred-a', 4_000), credential('cred-b', 4_000), credential('cred-c', 100)];
    for (const item of [a, b, c]) await store.put(item);

    secureStore.plant('umis.cred.cred-b.1', 'AAAA'); // a piece from somewhere else
    await expect(store.get('cred-b')).rejects.toMatchObject({ code: 'MALFORMED' });
    expect(await store.list()).toEqual([a, c]);

    await store.remove('cred-b');
    expect(keysOf('cred-b')).toEqual([]);
    expect(await store.list()).toEqual([a, c]);

    // a missing piece, an impossible number of pieces and the pieces of another credential
    await store.put(b);
    secureStore.plant('umis.cred.cred-b.n', '7');
    await expect(store.get('cred-b')).rejects.toMatchObject({ code: 'MALFORMED' });
    secureStore.plant('umis.cred.cred-b.n', '4000000');
    secureStore.calls.length = 0;
    await expect(store.get('cred-b')).rejects.toMatchObject({ code: 'MALFORMED' });
    expect(secureStore.calls.length).toBeLessThan(5);
    const dump = secureStore.dump();
    secureStore.plant('umis.cred.cred-b.n', dump['umis.cred.cred-a.n']!);
    for (const key of Object.keys(dump).filter((k) => /^umis\.cred\.cred-a\.\d+$/.test(k))) {
      secureStore.plant(key.replace('cred-a', 'cred-b'), dump[key]!);
    }
    await expect(store.get('cred-b')).rejects.toMatchObject({ code: 'MALFORMED' });
  });

  it('keeps the credentials of a namespace apart from those of another', async () => {
    const plain = createCredentialStore();
    const other = createCredentialStore({ namespace: 'second-profile', chunkChars: 500 });
    const item = credential('cred-1', 1_200);
    await other.put(item);

    expect(await plain.list()).toEqual([]);
    expect(await other.get('cred-1')).toEqual(item);
    const keys = Object.keys(secureStore.dump());
    expect(keys).toContain('second-profile.creds.index');
    expect(keys).toContain('second-profile.cred.cred-1.n');
    expect(keys.every((key) => key.startsWith('second-profile.'))).toBe(true);
    expect(keys.filter((key) => /\.cred\.cred-1\.\d+$/.test(key)).length).toBeGreaterThanOrEqual(3);
  });

  it('refuses a credential that the single index value could not list, and leaves the others alone', async () => {
    const store = createCredentialStore();
    const ids = Array.from({ length: 40 }, (_, n) => `${'c'.repeat(60)}-${String(n).padStart(3, '0')}`);
    let stored = 0;
    for (const id of ids) {
      try {
        await store.put(credential(id, 50));
        stored += 1;
      } catch (error) {
        expect(error).toMatchObject({ code: 'INVALID_ARGUMENT' });
        expect(keysOf(id)).toEqual([]);
        break;
      }
    }
    expect(stored).toBeGreaterThan(20);
    expect(stored).toBeLessThan(ids.length);
    expect((await store.list()).map((item) => item.id)).toEqual(ids.slice(0, stored));
  });
});
