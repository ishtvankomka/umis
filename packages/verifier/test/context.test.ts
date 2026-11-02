import { UmisError, VCT, createMemoryJournal, signEvent, verifyEvent, verifyJournal } from '@umis/core';
import type { VerificationResult, VerifierContext } from '@umis/core';
import { createMemoryLedger } from '@umis/policy';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  createDecisionEvent,
  createMemoryReplayStore,
  deserializeVerifierContext,
  serializeVerifierContext,
  verifyAtCheckpoint,
  verifyResponseQr,
  type SerializedVerifierContextV1,
} from '../src/index.js';
import {
  AT,
  ISSUER_A,
  ISSUER_B,
  LIST_A,
  NOW,
  TEN_TONNES,
  answer,
  ask,
  buildWorld,
  doorContext,
  expectAccept,
  expectReject,
  oneWayQr,
  warehouseContext,
  type World,
} from './fixtures.js';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});

/** The document as a station would keep it: through JSON text and back. */
const viaJson = (ctx: VerifierContext): SerializedVerifierContextV1 =>
  JSON.parse(JSON.stringify(serializeVerifierContext(ctx))) as SerializedVerifierContextV1;

/** What two decisions must have in common to count as the same decision (the timings differ). */
const essence = (result: VerificationResult) => ({
  decision: result.decision,
  reasons: result.reasons,
  channel: result.channel,
  at: result.at,
  issuer: result.issuer,
  vct: result.vct,
  credentialRef: result.credentialRef,
  claims: result.claims,
  delegation: result.delegation,
  authority: result.authority,
  statusListAgeSeconds: result.statusListAgeSeconds,
  pointId: result.pointId,
  policyVersion: result.policyVersion,
  trace: result.trace.map(({ step, name, ok, reason, skipped }) => ({ step, name, ok, reason, skipped })),
});

describe('a context kept as JSON', () => {
  it('holds data and nothing else', () => {
    const document = serializeVerifierContext(warehouseContext(w));
    expect(Object.keys(document).sort()).toEqual([
      'audiences',
      'now',
      'pointId',
      'policy',
      'policyVersion',
      'selfIssuer',
      'statusLists',
      'trusted',
      'v',
    ]);
    const text = JSON.stringify(document);
    expect(text).not.toContain('"d"'); // no private key material of any kind
    expect(document.statusLists).toEqual([{ uri: LIST_A, token: w.listA, fetchedAt: NOW - 300 }]);
  });

  it('is a copy: changing it changes nothing in the context', () => {
    const ctx = warehouseContext(w);
    const document = serializeVerifierContext(ctx);
    document.policy.maxStatusAgeSeconds = 1;
    document.trusted[0]!.status = 'revoked';
    document.audiences.push('urn:umis:verifier:other');
    expect(ctx.policy.maxStatusAgeSeconds).toBe(86_400);
    expect(ctx.trusted[0]!.status).toBe('active');
    expect(ctx.audiences).toEqual(['urn:umis:verifier:warehouse-b']);
  });

  it('comes back to the same document, in a stable order', async () => {
    const door = await doorContext(w);
    const once = viaJson(door);
    const again = serializeVerifierContext(deserializeVerifierContext(once, { replay: createMemoryReplayStore() }));
    expect(again).toEqual(once);

    const reversed = warehouseContext(w, {
      statusLists: new Map([
        ['https://issuer.example/status/z', { token: 'z', fetchedAt: 1 }],
        ['https://issuer.example/status/a', { token: 'a', fetchedAt: 2 }],
      ]),
    });
    const order = serializeVerifierContext(reversed).statusLists.map((list) => list.uri);
    expect(order).toEqual(['https://issuer.example/status/a', 'https://issuer.example/status/z']);
  });

  it('decides the same as the context it came from, accepting and rejecting', async () => {
    const original = () => warehouseContext(w, { ledger: createMemoryLedger() });
    const restored = () => {
      const { ledger } = original();
      return {
        ...deserializeVerifierContext(viaJson(original()), { replay: createMemoryReplayStore() }),
        ledger,
        crypto: w.crypto,
      };
    };

    const scenes = [
      { cred: w.olehCredential, holder: w.oleh, amount: 10 },
      { cred: w.ivanCredential, holder: w.ivan, amount: 10 },
      { cred: w.ivanCredential, holder: w.ivan, amount: 8 },
      { cred: w.olehCredential, holder: w.ivan, amount: 5 },
    ];
    for (const scene of scenes) {
      const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount: scene.amount } });
      const reply = await answer(w, scene.cred, scene.holder, pending);
      const left = await verifyResponseQr(reply, pending, original());
      const right = await verifyResponseQr(reply, pending, restored());
      expect(essence(right)).toEqual(essence(left));
    }
  });

  it('serves a door with its member cache the same way', async () => {
    const original = await doorContext(w);
    const restored = deserializeVerifierContext(viaJson(original), { replay: createMemoryReplayStore() });
    restored.crypto = w.crypto;
    expect(restored.memberCache!.size).toBe(1);
    const qr = await oneWayQr(w);
    const left = await verifyAtCheckpoint(qr, original);
    const right = await verifyAtCheckpoint(qr, restored);
    expectAccept(right);
    expect(essence(right)).toEqual(essence(left));
  });

  it('lets a recorded situation be decided at another instant', async () => {
    const document = viaJson(warehouseContext(w));
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const replay = () => createMemoryReplayStore();
    const crypto = w.crypto;

    expect(deserializeVerifierContext(document, { replay: replay() }).now).toBe(AT);
    expectAccept(
      await verifyResponseQr(reply, pending, { ...deserializeVerifierContext(document, { replay: replay() }), crypto }),
    );
    const later = deserializeVerifierContext(document, { replay: replay(), now: NOW + 120 });
    expect(later.now).toBe(NOW + 120);
    expectReject(await verifyResponseQr(reply, pending, { ...later, crypto }), 'PRESENTATION_EXPIRED');
  });

  it('is refused with MALFORMED when it is not a context', () => {
    const base = () => viaJson(warehouseContext(w));
    const refuse = (change: (document: Record<string, unknown>) => void) => {
      const document = base() as unknown as Record<string, unknown>;
      change(document);
      try {
        deserializeVerifierContext(document as never, { replay: createMemoryReplayStore() });
      } catch (error) {
        expect(error).toBeInstanceOf(UmisError);
        expect((error as UmisError).code).toBe('MALFORMED');
        return;
      }
      throw new Error('a context that is not valid was accepted');
    };

    refuse((d) => (d.v = 2));
    refuse((d) => delete d.v);
    refuse((d) => (d.now = 'now'));
    refuse((d) => (d.now = Number.NaN));
    refuse((d) => (d.audiences = 'urn:umis:verifier:warehouse-b'));
    refuse((d) => (d.audiences = [7]));
    refuse((d) => delete d.policy);
    refuse((d) => ((d.policy as Record<string, unknown>).maxStatusAgeSeconds = -5));
    refuse((d) => ((d.policy as Record<string, unknown>).riskClass = 'extreme'));
    refuse((d) => (d.trusted = {}));
    refuse((d) => ((d.trusted as unknown[])[0] = { issuer: 'https://issuer.example/x' }));
    refuse((d) => (d.trusted as unknown[]).push((d.trusted as unknown[])[0]));
    refuse((d) => (d.statusLists = [{ uri: LIST_A }]));
    refuse((d) => (d.statusLists as unknown[]).push((d.statusLists as unknown[])[0]));
    refuse((d) => (d.policyVersion = -1));
    refuse((d) => (d.pointId = ''));
    refuse((d) => (d.memberCache = [{ credRef: 'x' }]));
    expect(() => deserializeVerifierContext(null as never, { replay: createMemoryReplayStore() })).toThrow(UmisError);
    expect(() => deserializeVerifierContext([] as never, { replay: createMemoryReplayStore() })).toThrow(UmisError);
  });

  it('is refused when a member appears twice', async () => {
    const document = viaJson(await doorContext(w));
    document.memberCache!.push(document.memberCache![0]!);
    expect(() => deserializeVerifierContext(document, { replay: createMemoryReplayStore() })).toThrow(/appears twice/);
  });
});

describe('the record of a decision', () => {
  it('has what an audit needs and none of what the credential said', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const result = await verifyResponseQr(reply, pending, warehouseContext(w));
    expectAccept(result);

    const event = createDecisionEvent(result, { iss: ISSUER_B, seq: 1, chk: 'gate-1' });
    expect(event).toMatchObject({
      iss: ISSUER_B,
      seq: 1,
      iat: AT,
      chk: 'gate-1',
      ch: 'qr_reverse',
      dec: 'accept',
      rsn: ['OK'],
      vct: VCT.roleAuthority,
      ciss: ISSUER_A,
      cref: 'cred-oleh-0001',
      sla: AT - (NOW - 600),
      pv: 3,
    });
    expect(event.lat).toBeGreaterThanOrEqual(0);

    const text = JSON.stringify(event);
    for (const secret of ['Олег', 'crew_lead', 'Підрядник', 'p_cred-oleh', 'bridge-01', 'rebar']) {
      expect(text).not.toContain(secret);
    }
  });

  it('records a rejection with its one reason, and the credential only when it was identified', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.ivanCredential, w.ivan, pending);
    const exceeded = await verifyResponseQr(reply, pending, warehouseContext(w));
    expectReject(exceeded, 'AUTHORITY_LIMIT_EXCEEDED');
    const known = createDecisionEvent(exceeded, { iss: ISSUER_B, seq: 2, chk: 'gate-1' });
    expect(known).toMatchObject({ dec: 'reject', rsn: ['AUTHORITY_LIMIT_EXCEEDED'], cref: 'cred-ivan-0001' });

    const second = await ask(w);
    const unknown = await verifyResponseQr(
      await answer(w, w.olehCredential, w.oleh, second.pending),
      second.pending,
      warehouseContext(w, { trusted: [] }),
    );
    expectReject(unknown, 'ISSUER_UNTRUSTED');
    const blank = createDecisionEvent(unknown, { iss: ISSUER_B, seq: 3, chk: 'gate-1', pv: 4 });
    expect(blank).toMatchObject({ dec: 'reject', rsn: ['ISSUER_UNTRUSTED'], pv: 4 });
    expect(blank).not.toHaveProperty('ciss');
    expect(blank).not.toHaveProperty('cref');
    expect(blank).not.toHaveProperty('vct');
  });

  it('is signed with the key of the verifier and chained in a journal that can be checked', async () => {
    const journal = createMemoryJournal();
    const jws: string[] = [];
    for (let seq = 1; seq <= 4; seq++) {
      const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount: seq * 3 } });
      const reply = await answer(w, w.olehCredential, w.oleh, pending);
      const result = await verifyResponseQr(reply, pending, warehouseContext(w));
      const event = createDecisionEvent(result, { iss: ISSUER_B, seq, chk: 'gate-1' });
      journal.append(event);
      jws.push(await signEvent(event, w.deviceB));
    }
    expect(verifyJournal(journal.entries())).toEqual({ ok: true });
    const events = await Promise.all(jws.map((token) => verifyEvent(token, w.deviceB.publicJwk, w.crypto)));
    expect(events.map((event) => event.dec)).toEqual(['accept', 'accept', 'accept', 'reject']);
    expect(events.map((event) => event.rsn[0])).toEqual(['OK', 'OK', 'OK', 'AUTHORITY_LIMIT_EXCEEDED']);
    expect(events).toEqual(journal.entries().map((entry) => entry.event));
    await expect(verifyEvent(jws[0]!, w.oleh.publicJwk, w.crypto)).rejects.toBeInstanceOf(UmisError);
  });

  it('refuses arguments that make no sense', async () => {
    const { pending } = await ask(w);
    const result = await verifyResponseQr(
      await answer(w, w.olehCredential, w.oleh, pending),
      pending,
      warehouseContext(w),
    );
    const bad = [
      { iss: '', seq: 1, chk: 'gate-1' },
      { iss: ISSUER_B, seq: 0, chk: 'gate-1' },
      { iss: ISSUER_B, seq: 1.5, chk: 'gate-1' },
      { iss: ISSUER_B, seq: -2, chk: 'gate-1' },
      { iss: ISSUER_B, seq: 1, chk: '' },
    ];
    for (const input of bad) {
      expect(() => createDecisionEvent(result, input)).toThrow(UmisError);
    }
  });
});
