import {
  MUTUAL_AUD,
  TYP,
  VCT,
  decodeFrame,
  decodeJwsUnverified,
  encodeFrame,
  parseSdJwt,
  presentCredential,
  randomId,
  signPresentationRequest,
  verifyJws,
} from '@umis/core';
import type { DisclosableClaim, ParsedRequest, PresentationRequestPayloadV1, Signer } from '@umis/core';
import { DEFAULT_POLICIES } from '@umis/policy';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  createRequestFrame,
  createRequestQr,
  verifyCounterparty,
  verifyResponseQr,
  type CreateRequestInput,
} from '../src/index.js';
import {
  AT,
  IDX,
  ISSUER_A,
  ISSUER_B,
  LIST_A,
  NOW,
  VERIFIER_B,
  WALLET_OLEH,
  answer,
  buildWorld,
  expectAccept,
  expectReject,
  mutualContextA,
  mutualContextB,
  readMutualInit,
  statusList,
  type World,
} from './fixtures.js';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});

const CLAIMS: DisclosableClaim[] = ['org', 'role', 'display'];

/** Oleh opens an exchange: his request and his own presentation in one frame. */
function opening(over: Partial<CreateRequestInput> = {}) {
  return createRequestQr({
    deviceSigner: w.deviceB,
    audience: WALLET_OLEH,
    claims: CLAIMS,
    now: NOW,
    mutual: { sdJwtVc: w.olehCredential, disclose: CLAIMS, holderSigner: w.oleh },
    crypto: w.crypto,
    ...over,
  });
}

/** A mutual_init frame put together by hand, for openings that no honest wallet would make. */
async function handmade(o: {
  requestSigner?: Signer;
  requestNonce?: string;
  proofNonce?: string;
  proofAud?: string;
  mutual?: boolean;
  disclose?: DisclosableClaim[];
}): Promise<ParsedRequest> {
  const requestNonce = o.requestNonce ?? randomId(16, w.crypto);
  const payload: PresentationRequestPayloadV1 = {
    v: 1,
    nonce: requestNonce,
    aud: WALLET_OLEH,
    iat: NOW,
    exp: NOW + 60,
    vct: [VCT.orgMember, VCT.roleAuthority],
    claims: CLAIMS,
    ...(o.mutual === false ? {} : { mutual: true }),
  };
  const jws = await signPresentationRequest(payload, o.requestSigner ?? w.oleh);
  const counter = await presentCredential({
    credential: w.olehCredential,
    disclose: o.disclose ?? CLAIMS,
    kb: { signer: w.oleh, aud: o.proofAud ?? MUTUAL_AUD, nonce: o.proofNonce ?? requestNonce, iat: NOW },
    crypto: w.crypto,
  });
  return readMutualInit(encodeFrame({ kind: 'mutual_init', tokens: [jws, counter] }));
}

describe('the opening of a mutual exchange', () => {
  it('carries the request and the presentation of the opener, both made with the opener’s key', async () => {
    const { qr, pending } = await opening();
    const frame = decodeFrame(qr);
    expect(frame.kind).toBe('mutual_init');
    expect(frame.tokens).toHaveLength(2);
    expect(pending).toMatchObject({ aud: WALLET_OLEH, mutual: true, iat: NOW, exp: NOW + 60 });

    const request = await verifyJws<PresentationRequestPayloadV1>(frame.tokens[0]!, {
      typ: TYP.request,
      key: w.oleh.publicJwk,
      crypto: w.crypto,
    });
    expect(request.payload).toMatchObject({ mutual: true, nonce: pending.nonce, aud: WALLET_OLEH });

    const counter = await parseSdJwt(frame.tokens[1]!, w.crypto);
    expect(counter.kbJwt!.payload).toMatchObject({ aud: MUTUAL_AUD, nonce: pending.nonce, iat: NOW });
    expect(Object.keys(counter.claims).sort()).toEqual(['display', 'org', 'role']);
  });

  it('is not a mutual exchange unless the opener says so with a presentation of its own', async () => {
    const plain = await createRequestQr({
      deviceSigner: w.deviceB,
      audience: WALLET_OLEH,
      claims: CLAIMS,
      now: NOW,
      crypto: w.crypto,
    });
    expect(decodeFrame(plain.qr).kind).toBe('request');
    expect(plain.pending.mutual).toBe(false);
  });
});

describe('the other side reading the opener', () => {
  it('accepts the opener and learns who it is and which role it holds', async () => {
    const { qr } = await opening();
    const result = await verifyCounterparty(readMutualInit(qr), mutualContextB(w));
    expectAccept(result);
    expect(result.channel).toBe('qr_reverse');
    expect(result.issuer).toBe(ISSUER_A);
    expect(result.vct).toBe(VCT.roleAuthority);
    expect(result.claims).toMatchObject({
      org: { id: 'contractor-a' },
      role: { code: 'crew_lead' },
      display: { name: 'Олег' },
    });
    expect(result.trace[7]).toMatchObject({ name: 'authority', ok: true, skipped: true });
    expect(result.trace[2]!.skipped).toBeUndefined();
  });

  it('accepts an opener once', async () => {
    const { qr } = await opening();
    const ctx = mutualContextB(w);
    expectAccept(await verifyCounterparty(readMutualInit(qr), ctx));
    expectReject(await verifyCounterparty(readMutualInit(qr), ctx), 'REPLAY');
  });

  it('holds the presentation of the opener to 30 seconds and the request to its own life', async () => {
    const { qr } = await opening();
    expectAccept(await verifyCounterparty(readMutualInit(qr), mutualContextB(w, { now: NOW + 30 })));
    expectReject(
      await verifyCounterparty(readMutualInit(qr), mutualContextB(w, { now: NOW + 31 })),
      'PRESENTATION_EXPIRED',
    );

    const brief = await opening({ ttlSeconds: 15 });
    expectAccept(await verifyCounterparty(readMutualInit(brief.qr), mutualContextB(w, { now: NOW + 24 })));
    expectReject(
      await verifyCounterparty(readMutualInit(brief.qr), mutualContextB(w, { now: NOW + 25 })),
      'PRESENTATION_EXPIRED',
    );
  });

  it('rejects a request that was made in the future beyond the skew', async () => {
    const { qr } = await opening({ now: AT + 11 });
    expectReject(await verifyCounterparty(readMutualInit(qr), mutualContextB(w)), 'CLOCK_SKEW');
    const near = await opening({ now: AT + 10 });
    expectAccept(await verifyCounterparty(readMutualInit(near.qr), mutualContextB(w)));
  });

  it('believes nothing that the wallet derived from the frame, only the signed text', async () => {
    const { qr } = await opening();
    const read = readMutualInit(qr);
    const doctored: ParsedRequest = {
      ...read,
      nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
      aud: VERIFIER_B,
      iat: 0,
      exp: Number.MAX_SAFE_INTEGER,
      claims: ['display'],
      vct: [],
      mutual: false,
      signatureVerified: false,
    };
    expectAccept(await verifyCounterparty(doctored, mutualContextB(w)));
  });

  it('rejects a request that was signed by a key other than the one the presentation is bound to', async () => {
    const forged = await handmade({ requestSigner: w.deviceB });
    expect(forged.signatureVerified).toBe(true);
    const result = await verifyCounterparty(forged, mutualContextB(w));
    expectReject(result, 'HOLDER_BINDING_INVALID');
    expect(result.trace[3]).toMatchObject({ name: 'holder_binding', ok: false });

    const byDelegate = await handmade({ requestSigner: w.ivan });
    expectReject(await verifyCounterparty(byDelegate, mutualContextB(w)), 'HOLDER_BINDING_INVALID');
  });

  it('rejects a presentation that was made for another request', async () => {
    const mismatched = await handmade({ proofNonce: randomId(16, w.crypto) });
    expectReject(await verifyCounterparty(mismatched, mutualContextB(w)), 'NONCE_MISMATCH');
  });

  it('rejects a presentation that was made for a verifier and not for an exchange', async () => {
    const taken = await handmade({ proofAud: VERIFIER_B });
    expectReject(await verifyCounterparty(taken, mutualContextB(w)), 'AUDIENCE_MISMATCH');
  });

  it('rejects a request that does not call itself mutual', async () => {
    const plain = await handmade({ mutual: false });
    expectReject(await verifyCounterparty(plain, mutualContextB(w)), 'MALFORMED');
  });

  it('rejects what is not a mutual opening', async () => {
    const { qr } = await opening();
    const read = readMutualInit(qr);
    expectReject(await verifyCounterparty({ ...read, kind: 'request' }, mutualContextB(w)), 'UNSUPPORTED_FORMAT');
    const noProof: ParsedRequest = { ...read };
    delete noProof.counterPresentation;
    expectReject(await verifyCounterparty(noProof, mutualContextB(w)), 'MALFORMED');
    expectReject(await verifyCounterparty({ ...read, jws: 7 as never }, mutualContextB(w)), 'MALFORMED');
    expectReject(await verifyCounterparty({ ...read, jws: 'a.b.c' }, mutualContextB(w)), 'MALFORMED');
    expectReject(await verifyCounterparty(null as never, mutualContextB(w)), 'MALFORMED');
    expectReject(await verifyCounterparty(undefined as never, mutualContextB(w)), 'MALFORMED');
  });

  it('holds the opener to the policy of this side', async () => {
    const { qr } = await opening();
    const read = () => readMutualInit(qr);
    expectReject(await verifyCounterparty(read(), mutualContextB(w, { trusted: [] })), 'ISSUER_UNTRUSTED');

    const revoked = await statusList(w.issuerA, LIST_A, { iat: NOW - 600, revoked: [IDX.oleh] });
    const lists = new Map([[LIST_A, { token: revoked, fetchedAt: NOW - 300 }]]);
    expectReject(await verifyCounterparty(read(), mutualContextB(w, { statusLists: lists })), 'STATUS_REVOKED');

    const members = mutualContextB(w);
    members.policy.accepted = [{ vct: VCT.orgMember, issuers: 'registry' }];
    expectReject(await verifyCounterparty(read(), members), 'VCT_NOT_ALLOWED');

    const reticent = await opening({
      mutual: { sdJwtVc: w.olehCredential, disclose: ['org', 'role'], holderSigner: w.oleh },
    });
    expectReject(await verifyCounterparty(readMutualInit(reticent.qr), mutualContextB(w)), 'CLAIM_MISSING');

    expectReject(await verifyCounterparty(read(), mutualContextB(w), { channel: 'qr_oneway' }), 'CHANNEL_NOT_ALLOWED');
  });

  it('does not take authority without its chain from an opener who shows it', async () => {
    const { qr } = await opening({
      mutual: { sdJwtVc: w.ivanCredential, disclose: ['org', 'role', 'display', 'authority'], holderSigner: w.ivan },
    });
    expectReject(await verifyCounterparty(readMutualInit(qr), mutualContextB(w)), 'DELEGATION_UNDISCLOSED');
  });

  it('looks at the parent of a delegate who opens an exchange, although no amount is asked for', async () => {
    const open = () =>
      opening({
        mutual: {
          sdJwtVc: w.ivanCredential,
          disclose: ['org', 'role', 'display', 'authority', 'delegation'],
          holderSigner: w.ivan,
        },
      });
    const { qr } = await open();
    const accepted = await verifyCounterparty(readMutualInit(qr), mutualContextB(w));
    expectAccept(accepted);
    expect(accepted.delegation).toEqual({ depth: 1, parentId: 'cred-oleh-0001' });

    const revoked = await statusList(w.issuerA, LIST_A, { iat: NOW - 600, revoked: [IDX.oleh] });
    const lists = new Map([[LIST_A, { token: revoked, fetchedAt: NOW - 300 }]]);
    const again = await open();
    expectReject(
      await verifyCounterparty(readMutualInit(again.qr), mutualContextB(w, { statusLists: lists })),
      'PARENT_REVOKED',
    );
  });

  it('never uses the member cache of the context', async () => {
    const { qr } = await opening();
    const ctx = mutualContextB(w, { memberCache: new Map() });
    expectAccept(await verifyCounterparty(readMutualInit(qr), ctx));
    expect(ctx.memberCache).toBeDefined();
  });
});

describe('the opener reading the answer', () => {
  it('accepts the answer of the other side, whose role it learns', async () => {
    const { pending } = await opening();
    const reply = await answer(w, w.mariiaCredential, w.mariia, pending);
    expect(decodeFrame(reply).kind).toBe('mutual_reply');
    const result = await verifyResponseQr(reply, pending, mutualContextA(w));
    expectAccept(result);
    expect(result.issuer).toBe(ISSUER_B);
    expect(result.vct).toBe(VCT.orgMember);
    expect(result.claims).toMatchObject({
      org: { id: 'supplier-b' },
      role: { code: 'warehouse_manager' },
      display: { name: 'Марія' },
    });
  });

  it('accepts the answer once', async () => {
    const { pending } = await opening();
    const reply = await answer(w, w.mariiaCredential, w.mariia, pending);
    const ctx = mutualContextA(w);
    expectAccept(await verifyResponseQr(reply, pending, ctx));
    expectReject(await verifyResponseQr(reply, pending, ctx), 'REPLAY');
  });

  it('does not take the answer to another exchange, another audience or an ordinary response', async () => {
    const { pending } = await opening();
    const other = await opening();
    const ctx = () => mutualContextA(w);
    const reply = (options: Parameters<typeof answer>[4]) => answer(w, w.mariiaCredential, w.mariia, pending, options);

    expectReject(await verifyResponseQr(await reply({ nonce: other.pending.nonce }), pending, ctx()), 'NONCE_MISMATCH');
    expectReject(await verifyResponseQr(await reply({ aud: VERIFIER_B }), pending, ctx()), 'AUDIENCE_MISMATCH');
    expectReject(await verifyResponseQr(await reply({ kind: 'response' }), pending, ctx()), 'UNSUPPORTED_FORMAT');
  });

  it('holds the other side to the policy of the opener', async () => {
    const { pending } = await opening();
    const reply = await answer(w, w.mariiaCredential, w.mariia, pending);
    expectReject(await verifyResponseQr(reply, pending, mutualContextA(w, { trusted: [] })), 'ISSUER_UNTRUSTED');
    const policy = structuredClone(DEFAULT_POLICIES.mutual_medium);
    policy.accepted = [{ vct: VCT.roleAuthority, issuers: 'registry' }];
    expectReject(await verifyResponseQr(reply, pending, mutualContextA(w, { policy })), 'VCT_NOT_ALLOWED');
  });
});

describe('an exchange over Bluetooth', () => {
  it('uses the frame as it is, in both directions', async () => {
    const { frame, pending } = await createRequestFrame({
      deviceSigner: w.deviceB,
      audience: WALLET_OLEH,
      claims: CLAIMS,
      now: NOW,
      mutual: { sdJwtVc: w.olehCredential, disclose: CLAIMS, holderSigner: w.oleh },
      crypto: w.crypto,
    });
    expect(frame.kind).toBe('mutual_init');
    const [jws, counterPresentation] = frame.tokens as [string, string];
    const { payload } = decodeJwsUnverified<PresentationRequestPayloadV1>(jws);
    const request: ParsedRequest = {
      ...payload,
      kind: 'mutual_init',
      jws,
      signatureVerified: true,
      counterPresentation,
    };
    const there = await verifyCounterparty(request, mutualContextB(w), { channel: 'ble' });
    expectAccept(there);
    expect(there.channel).toBe('ble');

    const back = await verifyResponseQr(
      decodeFrame(await answer(w, w.mariiaCredential, w.mariia, pending)),
      pending,
      mutualContextA(w),
    );
    expectAccept(back);
    expect(back.channel).toBe('ble');
  });
});
