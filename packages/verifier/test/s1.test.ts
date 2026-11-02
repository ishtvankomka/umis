import {
  TYP,
  VCT,
  decodeFrame,
  decodePresentationRequest,
  verifyJws,
  type AuthorityRequest,
  type ReasonCode,
} from '@umis/core';
import { nobleCryptoProvider } from '@umis/core/noble';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { DEFAULT_REQUEST_TTL_S, createRequestFrame, verifyPresentation, verifyResponseQr } from '../src/index.js';
import {
  AT,
  DAY,
  IDX,
  ISSUER_A,
  LIST_A,
  NOW,
  OLEH_AUTHORITY,
  T0,
  TEN_TONNES,
  VERIFIER_B,
  answer,
  ask,
  buildWorld,
  credential,
  expectAccept,
  expectReject,
  presentation,
  verdictOf,
  warehouseContext,
  type World,
} from './fixtures.js';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe('a request for a power of authority', () => {
  it('asks for the delegation whenever it asks for authority, with a fresh nonce and a short life', async () => {
    const { qr, pending } = await ask(w, { claims: ['org', 'role'] });
    const frame = decodeFrame(qr);
    expect(frame.kind).toBe('request');
    const { header, payload } = decodePresentationRequest(frame.tokens[0]!);
    expect(header.typ).toBe(TYP.request);
    expect(payload).toMatchObject({ v: 1, aud: VERIFIER_B, iat: NOW, authority: TEN_TONNES });
    expect(payload.exp - payload.iat).toBe(DEFAULT_REQUEST_TTL_S);
    expect(payload.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(payload.claims).toEqual(['org', 'role', 'authority', 'delegation']);
    expect(payload.vct).toEqual([VCT.orgMember, VCT.roleAuthority]);
    expect(pending).toMatchObject({ nonce: payload.nonce, aud: VERIFIER_B, iat: NOW, exp: NOW + 60, mutual: false });
    expect(pending.claims).toEqual(payload.claims);
    await verifyJws(frame.tokens[0]!, { typ: TYP.request, key: w.deviceB.publicJwk, crypto: w.crypto });

    const other = await ask(w);
    expect(other.pending.nonce).not.toBe(pending.nonce);
  });

  it('keeps a request within the longest life and refuses nonsense', async () => {
    const longest = await ask(w, { ttlSeconds: 120 });
    expect(longest.pending.exp - longest.pending.iat).toBe(120);
    for (const bad of [{ ttlSeconds: 121 }, { ttlSeconds: 0 }, { claims: [] }, { audience: '' }, { now: Number.NaN }]) {
      await expect(ask(w, bad as never)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    }
  });

  it('can be shown over Bluetooth as a frame', async () => {
    const { frame, pending } = await createRequestFrame({
      deviceSigner: w.deviceB,
      audience: VERIFIER_B,
      claims: ['org'],
      now: NOW,
      crypto: w.crypto,
    });
    expect(frame.kind).toBe('request');
    const reply = { kind: 'response' as const, tokens: [await presentation(w, w.olehCredential, w.oleh, pending)] };
    const result = await verifyResponseQr(reply, pending, warehouseContext(w, { policy: policyWithoutAuthority() }));
    expectAccept(result);
    expect(result.channel).toBe('ble');
  });

  it('is not answered over Bluetooth at a checkpoint whose policy does not list it', async () => {
    const { pending } = await createRequestFrame({
      deviceSigner: w.deviceB,
      audience: VERIFIER_B,
      claims: ['org'],
      now: NOW,
      crypto: w.crypto,
    });
    const reply = { kind: 'response' as const, tokens: [await presentation(w, w.olehCredential, w.oleh, pending)] };
    const policy = policyWithoutAuthority();
    policy.channels = ['qr_reverse'];
    expectReject(await verifyResponseQr(reply, pending, warehouseContext(w, { policy })), 'CHANNEL_NOT_ALLOWED');
  });

  it('names each claim once and refuses a name that is not a claim', async () => {
    const { pending } = await ask(w, { claims: ['org', 'org', 'authority'] });
    expect(pending.claims).toEqual(['org', 'authority', 'delegation']);
    await expect(ask(w, { claims: ['org', 'passport'] as never })).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    const custom = await ask(w, { vct: [VCT.roleAuthority] });
    expect(custom.pending.vct).toEqual([VCT.roleAuthority]);
  });
});

function policyWithoutAuthority() {
  const policy = warehouseContext(w).policy;
  delete policy.authority;
  policy.requestedClaims = ['org'];
  return policy;
}

describe('the power of authority across organisations', () => {
  it('accepts ten tonnes against a limit of ten, through all nine steps', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const result = await verifyResponseQr(reply, pending, warehouseContext(w));
    expectAccept(result);
    expect(result.channel).toBe('qr_reverse');
    expect(result.issuer).toBe(ISSUER_A);
    expect(result.vct).toBe(VCT.roleAuthority);
    expect(result.credentialRef).toBe('cred-oleh-0001');
    expect(result.authority).toEqual({
      requested: TEN_TONNES,
      matched: OLEH_AUTHORITY[0],
      usedInPeriod: 0,
    });
    expect(result.authority!.matched!.limit.amount).toBe(10);
    expect(result.delegation).toEqual({ depth: 0 });
    expect(result.claims).toMatchObject({
      org: { id: 'contractor-a' },
      role: { code: 'crew_lead' },
      sub: 'p_cred-oleh-0001',
    });
    expect(result.statusListAgeSeconds).toBe(AT - (NOW - 600));
    expect(result.pointId).toBe('gate-1');
    expect(result.policyVersion).toBe(3);
  });

  it('rejects ten tonnes against the eight of the delegate and shows the limit to the operator', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.ivanCredential, w.ivan, pending);
    const result = await verifyResponseQr(reply, pending, warehouseContext(w));
    expectReject(result, 'AUTHORITY_LIMIT_EXCEEDED');
    expect(result.authority!.matched!.limit.amount).toBe(8);
    expect(result.authority!.requested.amount).toBe(10);
    expect(result.delegation).toEqual({ depth: 1, parentId: 'cred-oleh-0001' });
    expect(result.claims?.role?.code).toBe('crew_member');
    expect(result.trace[7]).toMatchObject({ name: 'authority', ok: false, reason: 'AUTHORITY_LIMIT_EXCEEDED' });
    expect(result.trace[8]).toMatchObject({ name: 'decision', ok: false, skipped: true });

    const eight = await ask(w, { authority: { ...TEN_TONNES, amount: 8 } });
    const accepted = await verifyResponseQr(
      await answer(w, w.ivanCredential, w.ivan, eight.pending),
      eight.pending,
      warehouseContext(w),
    );
    expectAccept(accepted);
    expect(accepted.authority!.matched!.limit.amount).toBe(8);
  });

  it('draws the line exactly at the limit', async () => {
    const check = async (amount: number): Promise<ReasonCode> => {
      const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount } });
      const reply = await answer(w, w.olehCredential, w.oleh, pending);
      return (await verifyResponseQr(reply, pending, warehouseContext(w))).reasons[0]!;
    };
    expect(await check(10)).toBe('OK');
    expect(await check(0)).toBe('OK');
    expect(await check(10.000001)).toBe('AUTHORITY_LIMIT_EXCEEDED');
    expect(await check(11)).toBe('AUTHORITY_LIMIT_EXCEEDED');
  });

  it('matches action, resource, unit and object exactly', async () => {
    const check = async (request: AuthorityRequest): Promise<ReasonCode> => {
      const { pending } = await ask(w, { authority: request });
      const reply = await answer(w, w.olehCredential, w.oleh, pending);
      return (await verifyResponseQr(reply, pending, warehouseContext(w))).reasons[0]!;
    };
    expect(await check({ ...TEN_TONNES, unit: 'kg' })).toBe('AUTHORITY_MISSING');
    expect(await check({ ...TEN_TONNES, unit: 'T' })).toBe('AUTHORITY_MISSING');
    expect(await check({ ...TEN_TONNES, resource: 'cement' })).toBe('AUTHORITY_MISSING');
    expect(await check({ ...TEN_TONNES, action: 'ship_materials' })).toBe('AUTHORITY_MISSING');
    expect(await check({ ...TEN_TONNES, object: 'bridge-02' })).toBe('AUTHORITY_MISSING');
    expect(await check({ ...TEN_TONNES, object: 'bridge-01' })).toBe('OK');
  });

  it('rejects an authority that has expired', async () => {
    const expired = await credential({
      issuer: w.issuerA,
      iss: ISSUER_A,
      holder: w.oleh,
      jti: 'cred-oleh-0002',
      idx: IDX.spare,
      listUri: LIST_A,
      claims: {
        org: { id: 'contractor-a', name: 'Підрядник А' },
        role: { code: 'crew_lead', name: 'Керівник бригади' },
        authority: [{ ...OLEH_AUTHORITY[0]!, valid_until: AT - 1 }],
        delegation: { depth: 0, max_depth: 1 },
      },
      crypto: w.crypto,
    });
    const { pending } = await ask(w);
    const result = await verifyResponseQr(await answer(w, expired, w.oleh, pending), pending, warehouseContext(w));
    expectReject(result, 'AUTHORITY_EXPIRED');
    expect(result.authority!.matched!.valid_until).toBe(AT - 1);
  });

  it('checks the amount of the policy when the policy fixes it, and asks for one when it does not', async () => {
    const options = (nonce: string) => ({
      channel: 'qr_reverse' as const,
      aud: VERIFIER_B,
      nonce,
      maxAgeSeconds: 120,
      replayKey: (n: string) => `test:${n}`,
      replayExpiresAt: AT + 120,
    });
    const fixed = (amount: number) => {
      const ctx = warehouseContext(w);
      ctx.policy.authority = {
        action: 'receive_materials',
        resource: 'rebar',
        unit: 't',
        amountSource: 'fixed',
        fixedAmount: amount,
      };
      return ctx;
    };
    const { pending } = await ask(w);
    const oleh = await presentation(w, w.olehCredential, w.oleh, pending);
    expectAccept(await verifyPresentation(oleh, fixed(10), options(pending.nonce)));

    const second = await ask(w);
    const ivan = await presentation(w, w.ivanCredential, w.ivan, second.pending);
    const wanted = await verifyPresentation(ivan, fixed(10), options(second.pending.nonce));
    expectReject(wanted, 'AUTHORITY_LIMIT_EXCEEDED');
    expect(wanted.authority!.requested).toEqual({ ...TEN_TONNES });

    const third = await ask(w);
    const unasked = await presentation(w, w.olehCredential, w.oleh, third.pending);
    expectReject(
      await verifyPresentation(unasked, warehouseContext(w), options(third.pending.nonce)),
      'AUTHORITY_MISSING',
    );
  });
});

describe('binding the answer to the request', () => {
  it('accepts an answer once', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const ctx = warehouseContext(w);
    expectAccept(await verifyResponseQr(reply, pending, ctx));
    expectReject(await verifyResponseQr(reply, pending, ctx), 'REPLAY');
  });

  it('rejects an answer to another request, another audience, or another time', async () => {
    const { pending } = await ask(w);
    const other = await ask(w);
    const ctx = () => warehouseContext(w);
    const to = (options: Parameters<typeof answer>[4]) => answer(w, w.olehCredential, w.oleh, pending, options);

    expectReject(await verifyResponseQr(await to({ nonce: other.pending.nonce }), pending, ctx()), 'NONCE_MISMATCH');
    expectReject(
      await verifyResponseQr(await to({ aud: 'urn:umis:verifier:warehouse-c' }), pending, ctx()),
      'AUDIENCE_MISMATCH',
    );
    expectReject(await verifyResponseQr(await to({ iat: NOW - 11 }), pending, ctx()), 'CLOCK_SKEW');
    expectReject(await verifyResponseQr(await to({ iat: NOW + 71 }), pending, ctx()), 'CLOCK_SKEW');
    // the request lives until NOW + 60, and a skew of 10 seconds is allowed
    expectAccept(await verifyResponseQr(await to({ iat: NOW - 10 }), pending, ctx()));
  });

  it('rejects an answer once the request is closed', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending, { iat: NOW + 50 });
    expectAccept(await verifyResponseQr(reply, pending, warehouseContext(w, { now: NOW + 69 })));
    const closed = await verifyResponseQr(reply, pending, warehouseContext(w, { now: NOW + 70 }));
    expectReject(closed, 'PRESENTATION_EXPIRED');
  });

  it('wants the kind of frame that the request calls for', async () => {
    const { pending } = await ask(w);
    const asReply = await answer(w, w.olehCredential, w.oleh, pending, { kind: 'mutual_reply' });
    expectReject(await verifyResponseQr(asReply, pending, warehouseContext(w)), 'UNSUPPORTED_FORMAT');
    expectReject(await verifyResponseQr('UMIS1O:ABC.', pending, warehouseContext(w)), 'MALFORMED');
  });

  it('wants the claims that were asked for, not the ones that the policy lists', async () => {
    const { pending } = await ask(w, { claims: ['org', 'role', 'authority', 'display'] });
    const reply = await answer(w, w.olehCredential, w.oleh, pending, {
      disclose: ['org', 'role', 'authority', 'delegation'],
    });
    expectReject(await verifyResponseQr(reply, pending, warehouseContext(w)), 'CLAIM_MISSING');
  });

  it('wants a credential type that was asked for', async () => {
    const { pending } = await ask(w, { vct: [VCT.orgMember] });
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    expectReject(await verifyResponseQr(reply, pending, warehouseContext(w)), 'VCT_NOT_ALLOWED');
  });

  it('refuses a record of a request that is not one', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    expectReject(
      await verifyResponseQr(reply, { ...pending, nonce: undefined } as never, warehouseContext(w)),
      'MALFORMED',
    );
    expectReject(await verifyResponseQr(reply, null as never, warehouseContext(w)), 'MALFORMED');
  });
});

describe('trust only through the registry of the verifier', () => {
  const answered = async () => {
    const { pending } = await ask(w);
    return { pending, reply: await answer(w, w.olehCredential, w.oleh, pending) };
  };

  it('rejects an issuer that the registry does not list, shows nothing of the credential, and rejects before the key', async () => {
    const { pending, reply } = await answered();
    const result = await verifyResponseQr(reply, pending, warehouseContext(w, { trusted: [] }));
    expectReject(result, 'ISSUER_UNTRUSTED');
    expect(result.issuer).toBeUndefined();
    expect(result.vct).toBeUndefined();
    expect(result.credentialRef).toBeUndefined();
    expect(result.claims).toBeUndefined();
    expect(result.trace[0]!.ok).toBe(true);
    expect(result.trace[1]).toMatchObject({ ok: false, reason: 'ISSUER_UNTRUSTED' });
  });

  it('rejects an issuer that is listed for other credential types only', async () => {
    const { pending, reply } = await answered();
    const trusted = [{ ...w.entryA, vcts: [VCT.orgMember] }];
    expectReject(await verifyResponseQr(reply, pending, warehouseContext(w, { trusted })), 'ISSUER_VCT_NOT_ALLOWED');
  });

  it('rejects an issuer that is suspended, revoked or past its time in the registry', async () => {
    const { pending, reply } = await answered();
    for (const entry of [
      { ...w.entryA, status: 'suspended' as const },
      { ...w.entryA, status: 'revoked' as const },
      { ...w.entryA, validUntil: AT - 1 },
    ]) {
      expectReject(
        await verifyResponseQr(reply, pending, warehouseContext(w, { trusted: [entry] })),
        'ISSUER_SUSPENDED',
      );
    }
    const upToToday = { ...w.entryA, validUntil: AT };
    expectAccept(await verifyResponseQr(reply, pending, warehouseContext(w, { trusted: [upToToday] })));
  });

  it('does not accept an issuer that the policy of this checkpoint does not name', async () => {
    const { pending, reply } = await answered();
    const naming = (issuers: string[]) => {
      const ctx = warehouseContext(w);
      ctx.policy.accepted = [{ vct: VCT.roleAuthority, issuers }];
      return ctx;
    };
    const elsewhere = await verifyResponseQr(reply, pending, naming(['https://issuer.example/someone-else']));
    expectReject(elsewhere, 'ISSUER_UNTRUSTED');
    expect(elsewhere.trace[6]).toMatchObject({ name: 'policy', ok: false, reason: 'ISSUER_UNTRUSTED' });
    expectAccept(await verifyResponseQr(reply, pending, naming([ISSUER_A])));
  });
});

describe('offline and in any runtime', () => {
  it('uses no network: a stub of fetch that throws is never called', async () => {
    const stub = vi.fn(() => {
      throw new Error('network access in an offline decision');
    });
    vi.stubGlobal('fetch', stub);

    const { pending } = await ask(w);
    const ctx = warehouseContext(w);
    expectAccept(await verifyResponseQr(await answer(w, w.olehCredential, w.oleh, pending), pending, ctx));
    const second = await ask(w);
    expectReject(
      await verifyResponseQr(await answer(w, w.ivanCredential, w.ivan, second.pending), second.pending, ctx),
      'AUTHORITY_LIMIT_EXCEEDED',
    );
    expectReject(
      await verifyResponseQr(
        await answer(w, w.olehCredential, w.oleh, second.pending),
        second.pending,
        warehouseContext(w, { statusLists: new Map() }),
      ),
      'STATUS_LIST_MISSING',
    );
    expect(stub).not.toHaveBeenCalled();
  });

  it('decides the same with the noble crypto provider', async () => {
    const noble = nobleCryptoProvider();
    const world = await buildWorld(noble);
    const { pending } = await ask(world);
    const ctx = () => warehouseContext(world, { crypto: noble });
    expectAccept(
      await verifyResponseQr(await answer(world, world.olehCredential, world.oleh, pending), pending, ctx()),
    );
    const other = await ask(world);
    const result = await verifyResponseQr(
      await answer(world, world.ivanCredential, world.ivan, other.pending),
      other.pending,
      ctx(),
    );
    expectReject(result, 'AUTHORITY_LIMIT_EXCEEDED');
    expect(verdictOf(result).step).toBe(8);
  });

  it('keeps the time of the credential within its own lifetime', async () => {
    const lastSecond = T0 + 90 * DAY - 1;
    const { pending } = await ask(w, { now: lastSecond });
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const expired = await verifyResponseQr(reply, pending, warehouseContext(w, { now: lastSecond + 12 }));
    expectReject(expired, 'CREDENTIAL_EXPIRED');
    expect(expired.trace[3]).toMatchObject({ name: 'holder_binding', ok: true });
    expect(expired.trace[4]).toMatchObject({ name: 'validity', ok: false, reason: 'CREDENTIAL_EXPIRED' });
  });
});
