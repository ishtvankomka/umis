import { VCT, decodeFrame, encodeFrame } from '@umis/core';
import type { Frame, ReasonCode } from '@umis/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { createMemoryReplayStore, memberCacheEntryFromCredential, verifyAtCheckpoint } from '../src/index.js';
import {
  AT,
  ISSUER_A,
  ISSUER_V,
  LIST_V,
  buildWorld,
  doorContext,
  entryFor,
  expectAccept,
  expectReject,
  forgeJws,
  fullQr,
  oneWayQr,
  oneWayToken,
  statusList,
  warehouseContext,
  type World,
} from './fixtures.js';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});

describe('one-way QR at a low-class door', () => {
  it('accepts a resident through all nine steps, with the claims of the member cache', async () => {
    const result = await verifyAtCheckpoint(await oneWayQr(w), await doorContext(w));
    expectAccept(result);
    expect(result.channel).toBe('qr_oneway');
    expect(result.at).toBe(AT);
    expect(result.issuer).toBe(ISSUER_V);
    expect(result.vct).toBe(VCT.orgMember);
    expect(result.credentialRef).toBe('cred-andriy-0001');
    expect(result.claims?.org?.id).toBe('coworking-v');
    expect(result.claims?.display?.name).toBe('Андрій');
    expect(result.statusListAgeSeconds).toBe(602);
    expect(result.pointId).toBe('door-1');
    expect(result.policyVersion).toBe(1);
    // the credential was verified when it entered the cache, so step 3 does not run; no authority is asked for
    expect(result.trace[2]).toMatchObject({ step: 3, name: 'issuer_signature', ok: true, skipped: true });
    expect(result.trace[7]).toMatchObject({ step: 8, name: 'authority', ok: true, skipped: true });
  });

  it('accepts a token once: the same frame again is a replay, a new counter is a new token', async () => {
    const ctx = await doorContext(w);
    const qr = await oneWayQr(w);
    expectAccept(await verifyAtCheckpoint(qr, ctx));
    expectReject(await verifyAtCheckpoint(qr, ctx), 'REPLAY');
    expectAccept(await verifyAtCheckpoint(await oneWayQr(w, { ctr: 2 }), ctx));
  });

  it('spends a token that passed the binding even when a later step rejects it', async () => {
    const qr = await oneWayQr(w);
    const revoked = await statusList(w.issuerV, LIST_V, { iat: AT - 600, revoked: [1] });
    const ctx = await doorContext(w, { statusLists: new Map([[LIST_V, { token: revoked, fetchedAt: AT - 600 }]]) });
    expectReject(await verifyAtCheckpoint(qr, ctx), 'STATUS_REVOKED');
    expectReject(await verifyAtCheckpoint(qr, ctx), 'REPLAY');
    // another verifier has not seen it
    expectAccept(await verifyAtCheckpoint(qr, await doorContext(w)));
  });

  it('accepts a header that carries a key id and ignores it', async () => {
    expectAccept(await verifyAtCheckpoint(await oneWayQr(w, { kid: true }), await doorContext(w)));
  });

  it('rejects the audience of another organisation', async () => {
    const qr = await oneWayQr(w, { aud: ISSUER_A });
    expectReject(await verifyAtCheckpoint(qr, await doorContext(w)), 'AUDIENCE_MISMATCH');
  });

  it('allows a token 30 seconds to live and rejects 31', async () => {
    const ctx = await doorContext(w);
    expectAccept(await verifyAtCheckpoint(await oneWayQr(w, { ttl: 30, ctr: 1 }), ctx));
    expectReject(await verifyAtCheckpoint(await oneWayQr(w, { ttl: 31, ctr: 2 }), ctx), 'PRESENTATION_TOO_LONG_LIVED');
    // a policy may ask for less than the profile allows
    const strict = await doorContext(w);
    strict.policy.oneWayTokenMaxAgeSeconds = 20;
    expectReject(await verifyAtCheckpoint(await oneWayQr(w, { ttl: 21 }), strict), 'PRESENTATION_TOO_LONG_LIVED');
  });

  it('rejects a token at exp plus the skew and accepts it one second before', async () => {
    const qr = await oneWayQr(w, { iat: AT - 40 }); // exp = AT - 10, skew 10
    expectReject(await verifyAtCheckpoint(qr, await doorContext(w)), 'PRESENTATION_EXPIRED');
    expectAccept(await verifyAtCheckpoint(qr, await doorContext(w, { now: AT - 1 })));
  });

  it('rejects a token made in the future beyond the skew and accepts one within it', async () => {
    expectReject(await verifyAtCheckpoint(await oneWayQr(w, { iat: AT + 11 }), await doorContext(w)), 'CLOCK_SKEW');
    expectAccept(await verifyAtCheckpoint(await oneWayQr(w, { iat: AT + 10 }), await doorContext(w)));
  });

  it('rejects a reference that the member cache does not hold', async () => {
    const qr = await oneWayQr(w, { credRef: 'cred-nobody-0001' });
    const result = await verifyAtCheckpoint(qr, await doorContext(w));
    expectReject(result, 'UNKNOWN_CREDENTIAL_REF');
    expect(result.credentialRef).toBeUndefined();
    expect(result.claims).toBeUndefined();
  });

  it('rejects a token that the holder key of the credential did not sign', async () => {
    const result = await verifyAtCheckpoint(await oneWayQr(w, { holder: w.ivan }), await doorContext(w));
    expectReject(result, 'HOLDER_BINDING_INVALID');
    // the cache vouches for the credential, so what it holds is shown even though the proof failed
    expect(result.credentialRef).toBe('cred-andriy-0001');
  });

  it('rejects the one-way channel under a medium policy', async () => {
    const roleAuthority = await memberCacheEntryFromCredential(w.olehCredential, w.crypto);
    const ctx = warehouseContext(w, {
      memberCache: new Map([[roleAuthority.credRef, roleAuthority]]),
      audiences: [ISSUER_A],
    });
    const qr = await oneWayQr(w, { holder: w.oleh, credRef: roleAuthority.credRef, aud: ISSUER_A });
    expectReject(await verifyAtCheckpoint(qr, ctx), 'CHANNEL_NOT_ALLOWED');
  });

  it('holds the cached credential to the registry, the status list and its own expiry', async () => {
    const qr = await oneWayQr(w);
    const entry = entryFor(w.issuerV, ISSUER_V, 'Коворкінг В', [VCT.orgMember], LIST_V);
    expectReject(await verifyAtCheckpoint(qr, await doorContext(w, { trusted: [] })), 'ISSUER_UNTRUSTED');
    expectReject(
      await verifyAtCheckpoint(qr, await doorContext(w, { trusted: [{ ...entry, status: 'suspended' }] })),
      'ISSUER_SUSPENDED',
    );
    expectReject(
      await verifyAtCheckpoint(qr, await doorContext(w, { trusted: [{ ...entry, vcts: [VCT.roleAuthority] }] })),
      'ISSUER_VCT_NOT_ALLOWED',
    );
    expectReject(await verifyAtCheckpoint(qr, await doorContext(w, { statusLists: new Map() })), 'STATUS_LIST_MISSING');

    const stale = await doorContext(w);
    const cached = [...stale.memberCache!.values()][0]!;
    stale.memberCache = new Map([[cached.credRef, { ...cached, exp: AT - 100 }]]);
    expectReject(await verifyAtCheckpoint(qr, stale), 'CREDENTIAL_EXPIRED');
  });

  it('asks the policy for claims that the cache lacks', async () => {
    const ctx = await doorContext(w);
    ctx.policy.requestedClaims = ['org', 'display', 'authority'];
    expectReject(await verifyAtCheckpoint(await oneWayQr(w), ctx), 'CLAIM_MISSING');
  });

  it('cannot give an amount to a policy that names an authority', async () => {
    const named = { action: 'open_door', resource: 'main', unit: 'pcs' };
    for (const authority of [
      { ...named, amountSource: 'request' as const },
      { ...named, amountSource: 'fixed' as const, fixedAmount: 1 },
    ]) {
      const ctx = await doorContext(w);
      ctx.policy.authority = authority;
      const result = await verifyAtCheckpoint(await oneWayQr(w), ctx);
      expectReject(result, 'AUTHORITY_MISSING');
      expect(result.trace[7]).toMatchObject({ name: 'authority', ok: false, reason: 'AUTHORITY_MISSING' });
    }
  });

  it('rejects tokens that are not well formed, each with one reason', async () => {
    const ctx = async () => await doorContext(w);
    const good = { cred_ref: 'cred-andriy-0001', aud: ISSUER_V, iat: AT - 3, exp: AT + 27, ctr: 1 };
    const header = { alg: 'ES256', typ: 'umis-ow+jwt' };
    const cases: Array<[string, object, object, string]> = [
      ['a foreign type', { alg: 'ES256', typ: 'JWT' }, good, 'UNSUPPORTED_FORMAT'],
      ['an embedded key', { ...header, jwk: w.andriy.publicJwk }, good, 'MALFORMED'],
      ['a critical header', { ...header, crit: ['exp'] }, good, 'MALFORMED'],
      ['an exp before the iat', header, { ...good, exp: good.iat - 1 }, 'MALFORMED'],
      ['a missing counter', header, { ...good, ctr: undefined }, 'MALFORMED'],
      ['a reference that is a number', header, { ...good, cred_ref: 7 }, 'MALFORMED'],
      ['a negative counter', header, { ...good, ctr: -1 }, 'MALFORMED'],
    ];
    for (const [name, head, body, reason] of cases) {
      const qr = encodeFrame({ kind: 'oneway', tokens: [await forgeJws(w.andriy, head, body)] });
      const result = await verifyAtCheckpoint(qr, await ctx());
      expect([name, result.reasons]).toEqual([name, [reason]]);
      expectReject(result, reason as ReasonCode);
    }
  });

  it('refuses the other kinds of frame at a checkpoint', async () => {
    const token = await oneWayToken(w);
    for (const kind of ['request', 'response', 'mutual_reply'] as const) {
      const frame: Frame = { kind, tokens: [token] };
      expectReject(await verifyAtCheckpoint(frame, await doorContext(w)), 'UNSUPPORTED_FORMAT');
    }
    expectReject(await verifyAtCheckpoint('hello', await doorContext(w)), 'UNSUPPORTED_FORMAT');
  });
});

describe('full QR and Bluetooth presentations at a door', () => {
  it('accepts a presentation with the holder own nonce once', async () => {
    const ctx = await doorContext(w);
    const qr = await fullQr(w);
    const result = await verifyAtCheckpoint(qr, ctx);
    expectAccept(result);
    expect(result.channel).toBe('qr_full');
    expect(result.claims?.org?.name).toBe('Коворкінг В');
    expect(result.claims?.sub).toBe('p_cred-andriy-0001');
    expect(result.trace[2]!.skipped).toBeUndefined(); // the issuer signature is checked in full
    expectReject(await verifyAtCheckpoint(qr, ctx), 'REPLAY');
  });

  it('binds the presentation to this verifier and to the time', async () => {
    const ctx = async () => await doorContext(w);
    expectReject(await verifyAtCheckpoint(await fullQr(w, { aud: ISSUER_A }), await ctx()), 'AUDIENCE_MISMATCH');
    expectAccept(await verifyAtCheckpoint(await fullQr(w, { iat: AT - 30 }), await ctx()));
    expectReject(await verifyAtCheckpoint(await fullQr(w, { iat: AT - 31 }), await ctx()), 'PRESENTATION_EXPIRED');
    expectReject(await verifyAtCheckpoint(await fullQr(w, { iat: AT + 11 }), await ctx()), 'CLOCK_SKEW');
    expectReject(await verifyAtCheckpoint(await fullQr(w, { nonce: 'short' }), await ctx()), 'NONCE_MISMATCH');
  });

  it('asks for the claims of the policy', async () => {
    const result = await verifyAtCheckpoint(await fullQr(w, { disclose: ['org'] }), await doorContext(w));
    expectReject(result, 'CLAIM_MISSING');
  });

  it('treats a Frame object as the Bluetooth channel, which the door policy must list', async () => {
    const frame: Frame = decodeFrame(await fullQr(w));
    expectReject(await verifyAtCheckpoint(frame, await doorContext(w)), 'CHANNEL_NOT_ALLOWED');

    const open = await doorContext(w);
    open.policy.channels = ['qr_oneway', 'qr_full', 'ble'];
    const result = await verifyAtCheckpoint(frame, open);
    expectAccept(result);
    expect(result.channel).toBe('ble');
  });

  it('holds a presentation to the issuer of the policy', async () => {
    const ctx = await doorContext(w, { selfIssuer: ISSUER_A });
    expectReject(await verifyAtCheckpoint(await fullQr(w), ctx), 'ISSUER_UNTRUSTED');
    const other = await doorContext(w);
    other.policy.accepted = [{ vct: VCT.roleAuthority, issuers: 'self' }];
    expectReject(await verifyAtCheckpoint(await fullQr(w), other), 'VCT_NOT_ALLOWED');
  });
});

describe('the in-memory replay store', () => {
  it('answers true once per id and false afterwards', async () => {
    const store = createMemoryReplayStore();
    expect(await store.checkAndRemember('a', 100)).toBe(true);
    expect(await store.checkAndRemember('a', 100)).toBe(false);
    expect(await store.checkAndRemember('b', 100)).toBe(true);
    expect(store.size()).toBe(2);
  });

  it('forgets an id after its time and not before, by the clock it was given', async () => {
    let now = 50;
    const store = createMemoryReplayStore({ now: () => now });
    expect(await store.checkAndRemember('a', 100)).toBe(true);
    now = 100; // at the instant itself the id is still remembered
    expect(await store.checkAndRemember('a', 100)).toBe(false);
    now = 101;
    expect(store.size()).toBe(0);
    expect(await store.checkAndRemember('a', 200)).toBe(true);
  });

  it('refuses new ids when it is full of ids that have not expired, and recovers when they do', async () => {
    let now = 0;
    const store = createMemoryReplayStore({ max: 2, now: () => now });
    expect(await store.checkAndRemember('a', 10)).toBe(true);
    expect(await store.checkAndRemember('b', 20)).toBe(true);
    expect(await store.checkAndRemember('c', 30)).toBe(false);
    expect(await store.checkAndRemember('a', 10)).toBe(false);
    now = 11; // a has expired
    expect(await store.checkAndRemember('c', 30)).toBe(true);
    expect(store.size()).toBe(2);
  });

  it('takes its time from the decisions that use it when it has no clock', async () => {
    const store = createMemoryReplayStore({ max: 1 });
    const first = await doorContext(w, { replay: store });
    expectAccept(await verifyAtCheckpoint(await oneWayQr(w, { ctr: 1 }), first));
    // the first token is gone from the store once a decision is made after it expired, so the store has room again
    const later = await doorContext(w, { replay: store, now: AT + 1_000 });
    expectAccept(await verifyAtCheckpoint(await oneWayQr(w, { ctr: 2, iat: AT + 997 }), later));
    expect(store.size()).toBe(1);
  });

  it('rejects instead of forgetting when a verifier is flooded', async () => {
    const full = createMemoryReplayStore({ max: 1 });
    expect(await full.checkAndRemember('other', AT + 1_000)).toBe(true);
    const result = await verifyAtCheckpoint(await oneWayQr(w), await doorContext(w, { replay: full }));
    expectReject(result, 'REPLAY');
  });

  it('is used with arguments that make sense', () => {
    expect(() => createMemoryReplayStore({ max: 0 })).toThrow();
    expect(() => createMemoryReplayStore({ max: 1.5 })).toThrow();
  });
});
