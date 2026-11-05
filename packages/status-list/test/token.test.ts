import {
  LIMITS,
  TYP,
  UmisError,
  decodeJwsUnverified,
  generateSigner,
  signJws,
  webCryptoProvider,
  type CryptoProvider,
  type Signer,
} from '@umis/core';
import type { FlateStreamHandler } from 'fflate';
import { describe, expect, it, vi } from 'vitest';
import {
  STATUS,
  buildStatusListToken,
  checkStatus,
  createStatusList,
  createStatusListCache,
  decodeLst,
  encodeLst,
  parseStatusListToken,
  statusListFromValues,
  verifyStatusListToken,
} from '../src/index.js';

/** Every byte the inflater hands out, counted by a pass-through wrapper around fflate's streaming inflater. */
const inflation = vi.hoisted(() => ({ bytes: 0 }));

vi.mock('fflate', async (importOriginal) => {
  const fflate = await importOriginal<typeof import('fflate')>();
  class MeteredUnzlib extends fflate.Unzlib {
    constructor(ondata: FlateStreamHandler) {
      super((chunk, final) => {
        inflation.bytes += chunk.length;
        ondata(chunk, final);
      });
    }
  }
  return { ...fflate, Unzlib: MeteredUnzlib };
});

const URI = 'https://issuer.example/status/1';
const NOW = 1_793_750_400;
const DAY = 86_400;
const SIZE = 131_072;

const INVALID = { ok: false, reason: 'STATUS_LIST_INVALID' };
const STALE = { ok: false, reason: 'STATUS_LIST_STALE' };

async function codeOf(run: () => unknown): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

/** Deterministic pseudo-random numbers in [0, 1), so that a failing case can be reproduced. */
function mulberry32(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

/** `size` entries of which `count` distinct random ones are revoked, or also suspended with `bits` 2. */
function randomStatuses(size: number, count: number, seed: number, bits: 1 | 2 = 2): Uint8Array {
  const next = mulberry32(seed);
  const values = new Uint8Array(size);
  for (let placed = 0; placed < count;) {
    const idx = Math.floor(next() * size);
    if (values[idx] === 0) {
      values[idx] = bits === 2 && next() < 0.5 ? STATUS.SUSPENDED : STATUS.INVALID;
      placed += 1;
    }
  }
  return values;
}

/** Signs an arbitrary payload under an arbitrary `typ`, so that only the rules under test can reject it. */
function forge(signer: Signer, typ: string, payload: object): Promise<string> {
  return signJws({ header: { typ }, payload, signer });
}

/** The default WebCrypto provider with a counter on signature checks. */
function countingProvider(): { provider: CryptoProvider; verifications: () => number } {
  let count = 0;
  const provider: CryptoProvider = {
    name: 'counting',
    getRandomValues: (array) => webCryptoProvider.getRandomValues(array),
    sha256: (data) => webCryptoProvider.sha256(data),
    verifyEs256: (key, data, signature) => {
      count += 1;
      return webCryptoProvider.verifyEs256(key, data, signature);
    },
    generateSigner: (opts) => webCryptoProvider.generateSigner(opts),
    importSigner: (jwk, opts) => webCryptoProvider.importSigner(jwk, opts),
  };
  return { provider, verifications: () => count };
}

describe('status list tokens', () => {
  it('builds, verifies and reads back a 131 072-entry two-bit list with 1 000 set entries', async () => {
    const signer = await generateSigner();
    const values = randomStatuses(SIZE, 1_000, 20_261_102);
    const token = await buildStatusListToken({ signer, uri: URI, bits: 2, values, iat: NOW });

    const result = await verifyStatusListToken(token, {
      keys: [signer.publicJwk],
      expectedUri: URI,
      now: NOW + 60,
      maxAgeSeconds: DAY,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.ageSeconds).toBe(60);
    expect(result.list).toMatchObject({ uri: URI, iat: NOW, bits: 2, size: SIZE });
    expect(values.filter((value, idx) => result.list.get(idx) !== value)).toHaveLength(0);

    const parsed = parseStatusListToken(token);
    expect(values.filter((value, idx) => parsed.get(idx) !== value)).toHaveLength(0);
  });

  it('rejects a list with the wrong sub, key or typ or an iat from the future as invalid', async () => {
    const signer = await generateSigner();
    const other = await generateSigner();
    const values = randomStatuses(4_096, 40, 1);
    const token = await buildStatusListToken({ signer, uri: URI, bits: 2, values, iat: NOW });
    const base = { keys: [signer.publicJwk], expectedUri: URI, now: NOW, maxAgeSeconds: DAY };

    expect((await verifyStatusListToken(token, base)).ok).toBe(true);
    expect(await verifyStatusListToken(token, { ...base, expectedUri: 'https://issuer.example/status/2' })).toEqual(
      INVALID,
    );
    // Another issuer's key, and another key that claims the same kid.
    expect(await verifyStatusListToken(token, { ...base, keys: [other.publicJwk] })).toEqual(INVALID);
    expect(await verifyStatusListToken(token, { ...base, keys: [{ ...other.publicJwk, kid: signer.kid }] })).toEqual(
      INVALID,
    );
    expect(await verifyStatusListToken(token, { ...base, keys: [] })).toEqual(INVALID);

    const payload = {
      sub: URI,
      iat: NOW,
      status_list: { bits: 2, lst: encodeLst(statusListFromValues(values, 2).toBytes()) },
    };
    expect((await verifyStatusListToken(await forge(signer, TYP.statusList, payload), base)).ok).toBe(true);
    expect(await verifyStatusListToken(await forge(signer, 'JWT', payload), base)).toEqual(INVALID);
    expect(parseStatusListToken(await forge(signer, TYP.statusList, payload)).size).toBe(4_096);
    expect(await codeOf(async () => parseStatusListToken(await forge(signer, 'JWT', payload)))).toBe(
      'STATUS_LIST_INVALID',
    );
    expect(await verifyStatusListToken(await forge(signer, TYP.statusList, { ...payload, sub: 7 }), base)).toEqual(
      INVALID,
    );
    expect(
      await verifyStatusListToken(
        await forge(signer, TYP.statusList, { ...payload, status_list: { bits: 3, lst: payload.status_list.lst } }),
        base,
      ),
    ).toEqual(INVALID);

    const future = (iat: number) => buildStatusListToken({ signer, uri: URI, bits: 2, values, iat });
    expect((await verifyStatusListToken(await future(NOW + LIMITS.defaultSkewS), base)).ok).toBe(true);
    expect(await verifyStatusListToken(await future(NOW + LIMITS.defaultSkewS + 1), base)).toEqual(INVALID);
    expect(await verifyStatusListToken('not a token', base)).toEqual(INVALID);
  });

  it('accepts an age equal to S, rejects S + 1 and an expired list, and carries ttl and exp', async () => {
    const signer = await generateSigner();
    const exp = NOW + 200_000;
    const token = await buildStatusListToken({
      signer,
      uri: URI,
      bits: 1,
      values: randomStatuses(2_048, 20, 3, 1),
      iat: NOW,
      ttlSeconds: 3_600,
      exp,
    });
    const verifyAt = (now: number, extra: { maxAgeSeconds?: number; skewSeconds?: number } = {}) =>
      verifyStatusListToken(token, {
        keys: [signer.publicJwk],
        expectedUri: URI,
        now,
        maxAgeSeconds: DAY,
        ...extra,
      });

    const atS = await verifyAt(NOW + DAY);
    expect(atS.ok && atS.ageSeconds).toBe(DAY);
    expect(await verifyAt(NOW + DAY + 1)).toEqual(STALE);

    // exp: the token is usable until exp + skew (10 s by default), exclusive.
    const wide = { maxAgeSeconds: 1_000_000 };
    expect((await verifyAt(exp + LIMITS.defaultSkewS - 1, wide)).ok).toBe(true);
    expect(await verifyAt(exp + LIMITS.defaultSkewS, wide)).toEqual(STALE);
    expect((await verifyAt(exp - 1, { ...wide, skewSeconds: 0 })).ok).toBe(true);
    expect(await verifyAt(exp, { ...wide, skewSeconds: 0 })).toEqual(STALE);

    const parsed = parseStatusListToken(token);
    expect(parsed.ttl).toBe(3_600);
    expect(parsed.exp).toBe(exp);
    const bare = parseStatusListToken(
      await buildStatusListToken({ signer, uri: URI, bits: 1, values: new Uint8Array(8), iat: NOW }),
    );
    expect(Object.keys(bare).sort()).toEqual(['bits', 'get', 'iat', 'size', 'uri']);
  });

  it('writes the issuer it is given as iss, and no iss without one', async () => {
    const signer = await generateSigner();
    const build = (changes: { issuer?: string }) =>
      buildStatusListToken({ signer, uri: URI, bits: 1, values: new Uint8Array(8), iat: NOW, ...changes });
    const named = decodeJwsUnverified(await build({ issuer: 'https://issuer.example' }));
    expect(named.payload).toMatchObject({ iss: 'https://issuer.example', sub: URI });
    expect(Object.hasOwn(decodeJwsUnverified(await build({})).payload, 'iss')).toBe(false);
  });

  // Compressing the 64 MiB bomb alone takes several seconds on a slow CI runner, hence the explicit timeout.
  it('stops inflating a decompression bomb soon after the cap instead of materialising it', { timeout: 60_000 }, async () => {
    const bomb = encodeLst(new Uint8Array(64 * 1_048_576));
    expect(bomb.length).toBeLessThan(100_000);
    inflation.bytes = 0;
    expect(await codeOf(() => decodeLst(bomb))).toBe('STATUS_LIST_INVALID');
    // Small steps stop within about one step (some 1 MiB of output) past the cap; inflating the stream in one push
    // would hand out all 64 MiB before the cap could stop it.
    expect(inflation.bytes).toBeGreaterThan(LIMITS.statusListMaxBytes);
    expect(inflation.bytes).toBeLessThan(4 * LIMITS.statusListMaxBytes);
  });

  it('refuses a list that inflates beyond 1 MiB, in the codec and inside a signed token', async () => {
    const signer = await generateSigner();
    const atLimit = new Uint8Array(LIMITS.statusListMaxBytes);
    const beyond = new Uint8Array(LIMITS.statusListMaxBytes + 1);

    expect(decodeLst(encodeLst(atLimit))).toHaveLength(LIMITS.statusListMaxBytes);
    expect(await codeOf(() => decodeLst(encodeLst(beyond)))).toBe('STATUS_LIST_INVALID');
    expect(await codeOf(() => decodeLst(encodeLst(new Uint8Array(100)), 99))).toBe('STATUS_LIST_INVALID');

    const base = { keys: [signer.publicJwk], expectedUri: URI, now: NOW, maxAgeSeconds: DAY };
    const within = await forge(signer, TYP.statusList, {
      sub: URI,
      iat: NOW,
      status_list: { bits: 1, lst: encodeLst(atLimit) },
    });
    expect((await verifyStatusListToken(within, base)).ok).toBe(true);
    const oversized = await forge(signer, TYP.statusList, {
      sub: URI,
      iat: NOW,
      status_list: { bits: 1, lst: encodeLst(beyond) },
    });
    expect(await verifyStatusListToken(oversized, base)).toEqual(INVALID);
    expect(await codeOf(() => parseStatusListToken(oversized))).toBe('STATUS_LIST_INVALID');
  });

  it('reports VALID, REVOKED and SUSPENDED by status and OUT_OF_RANGE for every index outside the list', async () => {
    const signer = await generateSigner();
    const token = await buildStatusListToken({
      signer,
      uri: URI,
      bits: 2,
      values: Uint8Array.from([0, 1, 2, 3]),
      iat: NOW,
    });
    const list = parseStatusListToken(token);
    expect(list.size).toBe(4);

    const at = (idx: number, uri = URI) => checkStatus({ uri, idx }, list);
    expect([0, 1, 2, 3].map((idx) => at(idx))).toEqual(['VALID', 'REVOKED', 'SUSPENDED', 'REVOKED']);
    for (const idx of [4, 5, 131_072, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      expect(at(idx), `index ${idx}`).toBe('OUT_OF_RANGE');
    }
    // A reference that names another list is never answered by this one.
    expect(at(0, 'https://issuer.example/status/2')).toBe('OUT_OF_RANGE');
    expect(await codeOf(() => list.get(4))).toBe('INVALID_ARGUMENT');

    // 4-bit lists from other issuers: every type above SUSPENDED is treated as revoked.
    const wide = parseStatusListToken(
      await forge(signer, TYP.statusList, {
        sub: URI,
        iat: NOW,
        status_list: { bits: 4, lst: encodeLst(Uint8Array.from([0x10, 0x32, 0xf4])) },
      }),
    );
    expect(wide.size).toBe(6);
    expect([0, 1, 2, 3, 4, 5].map((idx) => checkStatus({ uri: URI, idx }, wide))).toEqual([
      'VALID',
      'REVOKED',
      'SUSPENDED',
      'REVOKED',
      'REVOKED',
      'REVOKED',
    ]);
  });

  it('verifies a cached token once and reuses it only under the keys it was verified with', async () => {
    const signer = await generateSigner();
    const other = await generateSigner();
    const token = await buildStatusListToken({
      signer,
      uri: URI,
      bits: 2,
      values: randomStatuses(2_048, 20, 5),
      iat: NOW,
    });
    const { provider, verifications } = countingProvider();
    const cache = createStatusListCache();
    const base = { keys: [signer.publicJwk], expectedUri: URI, now: NOW, maxAgeSeconds: DAY, cache, crypto: provider };

    const first = await verifyStatusListToken(token, base);
    const second = await verifyStatusListToken(token, { ...base, now: NOW + 5 });
    expect(first.ok && second.ok).toBe(true);
    expect(verifications()).toBe(1);
    expect(second.ok && first.ok && second.list === first.list).toBe(true);
    expect(second.ok && second.ageSeconds).toBe(5);

    // A hit still goes through the sub, age and exp rules.
    expect(await verifyStatusListToken(token, { ...base, now: NOW + DAY + 1 })).toEqual(STALE);
    expect(await verifyStatusListToken(token, { ...base, expectedUri: 'https://issuer.example/status/2' })).toEqual(
      INVALID,
    );
    // Extra keys do not matter, a different key set does: the entry is not trusted for another issuer.
    expect((await verifyStatusListToken(token, { ...base, keys: [signer.publicJwk, other.publicJwk] })).ok).toBe(true);
    expect(verifications()).toBe(1);
    expect(await verifyStatusListToken(token, { ...base, keys: [{ ...other.publicJwk, kid: signer.kid }] })).toEqual(
      INVALID,
    );
    expect(await verifyStatusListToken(token, { ...base, keys: [] })).toEqual(INVALID);

    // An entry this module did not verify itself is never taken on trust.
    const foreign = createStatusListCache();
    foreign.set(token, parseStatusListToken(token));
    const forged = { ...base, cache: foreign, crypto: provider };
    expect(await verifyStatusListToken(token, { ...forged, keys: [{ ...other.publicJwk, kid: signer.kid }] })).toEqual(
      INVALID,
    );
    const before = verifications();
    expect((await verifyStatusListToken(token, forged)).ok).toBe(true);
    expect(verifications()).toBe(before + 1);
  });

  it('evicts the least recently used token when the cache is full', async () => {
    const signer = await generateSigner();
    const listOf = async (n: number) =>
      parseStatusListToken(
        await buildStatusListToken({ signer, uri: `${URI}/${n}`, bits: 1, values: new Uint8Array(8), iat: NOW }),
      );
    const a = await listOf(1);
    const b = await listOf(2);
    const c = await listOf(3);
    const cache = createStatusListCache(2);
    cache.set('a', a);
    cache.set('b', b);
    expect(cache.get('a')).toBe(a);
    cache.set('c', c);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe(a);
    expect(cache.get('c')).toBe(c);
    expect(() => createStatusListCache(0)).toThrow(UmisError);
  });

  it('refuses arguments that cannot describe a status list', async () => {
    const signer = await generateSigner();
    const build = (changes: Record<string, unknown>) =>
      buildStatusListToken({ signer, uri: URI, bits: 2, values: new Uint8Array(8), iat: NOW, ...changes });

    for (const changes of [
      { bits: 4 },
      { bits: 3 },
      { uri: '' },
      { iat: -1 },
      { iat: 1.5 },
      { exp: NOW },
      { ttlSeconds: 0 },
      { issuer: '' },
      { values: new Uint8Array(0) },
      { values: Uint8Array.from([0, 4]) },
      { values: [0, 1] },
    ]) {
      expect(await codeOf(() => build(changes)), JSON.stringify(changes)).toBe('INVALID_ARGUMENT');
    }

    const list = createStatusList(10, 2);
    list.set(9, STATUS.SUSPENDED);
    expect(list.get(9)).toBe(STATUS.SUSPENDED);
    expect(list.toBytes()).toHaveLength(3);
    for (const run of [() => list.set(10, 1), () => list.set(0, 4), () => list.get(-1), () => createStatusList(0, 1)]) {
      expect(await codeOf(run)).toBe('INVALID_ARGUMENT');
    }

    const token = await build({});
    const base = { keys: [signer.publicJwk], expectedUri: URI, maxAgeSeconds: DAY };
    for (const now of [Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(await codeOf(() => verifyStatusListToken(token, { ...base, now }))).toBe('INVALID_ARGUMENT');
    }
    expect(await codeOf(() => verifyStatusListToken(token, { ...base, now: NOW, maxAgeSeconds: -1 }))).toBe(
      'INVALID_ARGUMENT',
    );
  });
});
