import { ledgerKey, periodWindow } from '@umis/core';
import type { AuthorityItem, AuthorityLedger, Signer, VerificationResult, VerifierContext } from '@umis/core';
import { createMemoryLedger } from '@umis/policy';
import { beforeAll, describe, expect, it } from 'vitest';
import { verifyResponseQr } from '../src/index.js';
import {
  AT,
  IDX,
  ISSUER_A,
  LIST_A,
  NOW,
  OLEH_AUTHORITY,
  T0,
  TEN_TONNES,
  answer,
  ask,
  buildWorld,
  credential,
  expectAccept,
  expectReject,
  statusList,
  warehouseContext,
  type World,
} from './fixtures.js';

const HOUR = 3_600;

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});

interface Booking {
  cred?: string;
  holder?: Signer;
  ctx?: Partial<VerifierContext>;
  /** The time the request is made; the decision follows two seconds later. */
  at?: number;
}

/** The holder answers a request for `amount` tonnes and the warehouse decides with the context it is given. */
async function book(amount: number, o: Booking = {}): Promise<VerificationResult> {
  const at = o.at ?? NOW;
  // the status list is as fresh as the request, whatever day the test lives on
  const token = await statusList(w.issuerA, LIST_A, { iat: at - 600 });
  const { pending } = await ask(w, { now: at, authority: { ...TEN_TONNES, amount } });
  const reply = await answer(w, o.cred ?? w.olehCredential, o.holder ?? w.oleh, pending);
  const fresh = new Map([[LIST_A, { token, fetchedAt: at - 300 }]]);
  return verifyResponseQr(reply, pending, warehouseContext(w, { now: at + 2, statusLists: fresh, ...o.ctx }));
}

const olehKey = ledgerKey({ iss: ISSUER_A, jti: 'cred-oleh-0001', req: TEN_TONNES });
const thisShift = periodWindow('shift', AT);

/** A credential of the Oleh key with one authority item of this period and limit. */
function rootOf(
  jti: string,
  item: Partial<AuthorityItem['limit']>,
  over: Partial<AuthorityItem> = {},
): Promise<string> {
  const base = OLEH_AUTHORITY[0]!;
  return credential({
    issuer: w.issuerA,
    iss: ISSUER_A,
    holder: w.oleh,
    jti,
    idx: IDX.spare,
    listUri: LIST_A,
    claims: {
      org: { id: 'contractor-a', name: 'Підрядник А' },
      role: { code: 'crew_lead', name: 'Керівник бригади' },
      authority: [{ ...base, ...over, limit: { ...base.limit, ...item } }],
      delegation: { depth: 0, max_depth: 1 },
    },
    crypto: w.crypto,
  });
}

describe('the budget of a shift', () => {
  it('adds up what was accepted: 6 and 4 tonnes of ten, and not one more', async () => {
    const ledger = createMemoryLedger();
    const ctx = { ledger };

    const first = await book(6, { ctx });
    expectAccept(first);
    expect(first.authority).toMatchObject({ requested: { amount: 6 }, usedInPeriod: 0 });

    const second = await book(4, { ctx });
    expectAccept(second);
    expect(second.authority!.usedInPeriod).toBe(6);

    const third = await book(1, { ctx });
    expectReject(third, 'AUTHORITY_PERIOD_EXCEEDED');
    expect(third.authority).toMatchObject({ requested: { amount: 1 }, usedInPeriod: 10 });
    expect(third.authority!.matched!.limit).toEqual({ amount: 10, unit: 't', per: 'shift' });
    expect(third.trace[7]).toMatchObject({ name: 'authority', ok: false, reason: 'AUTHORITY_PERIOD_EXCEEDED' });

    expect(await ledger.used(olehKey, thisShift)).toBe(10);
    // nothing is left to take, but nothing is also asked for
    expectAccept(await book(0, { ctx }));
  });

  it('draws the line at the limit exactly', async () => {
    const ledger = createMemoryLedger();
    expectAccept(await book(9.5, { ctx: { ledger } }));
    expectReject(await book(0.5000001, { ctx: { ledger } }), 'AUTHORITY_PERIOD_EXCEEDED');
    expectAccept(await book(0.5, { ctx: { ledger } }));
  });

  it('books nothing for a decision that is rejected, whatever the reason', async () => {
    const ledger = createMemoryLedger();
    const ctx = { ledger };
    expectReject(await book(11, { ctx }), 'AUTHORITY_LIMIT_EXCEEDED');

    const revoked = await statusList(w.issuerA, LIST_A, { iat: NOW - 600, revoked: [IDX.oleh] });
    const lists = new Map([[LIST_A, { token: revoked, fetchedAt: NOW - 300 }]]);
    expectReject(await book(5, { ctx: { ledger, statusLists: lists } }), 'STATUS_REVOKED');
    expectReject(await book(5, { ctx: { ledger, trusted: [] } }), 'ISSUER_UNTRUSTED');
    expectReject(await book(5, { holder: w.ivan, ctx }), 'HOLDER_BINDING_INVALID');
    expect(await ledger.used(olehKey, thisShift)).toBe(0);

    // an amount that is not a quantity is over every limit and is never booked
    for (const amount of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount: 5 } });
      const reply = await answer(w, w.olehCredential, w.oleh, pending);
      const odd = { ...pending, authority: { ...TEN_TONNES, amount } };
      expectReject(await verifyResponseQr(reply, odd, warehouseContext(w, { ledger })), 'AUTHORITY_LIMIT_EXCEEDED');
    }
    expect(await ledger.used(olehKey, thisShift)).toBe(0);

    // a replayed answer does not book twice either
    const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount: 5 } });
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const shared = warehouseContext(w, { ledger });
    expectAccept(await verifyResponseQr(reply, pending, shared));
    expectReject(await verifyResponseQr(reply, pending, shared), 'REPLAY');
    expect(await ledger.used(olehKey, thisShift)).toBe(5);
  });

  it('is one budget for the holder of a power and for the delegate who got part of it', async () => {
    const ledger = createMemoryLedger();
    const ctx = { ledger };
    expectAccept(await book(6, { ctx }));

    // the delegate may take 8 in a shift at most, and 6 of the shared budget are gone
    const over = await book(3, { cred: w.ivanCredential, holder: w.ivan, ctx });
    expectReject(over, 'AUTHORITY_PERIOD_EXCEEDED');
    expect(over.authority).toMatchObject({ usedInPeriod: 6 });
    expect(over.authority!.matched!.limit.amount).toBe(8);

    const fits = await book(2, { cred: w.ivanCredential, holder: w.ivan, ctx });
    expectAccept(fits);
    expect(fits.authority!.usedInPeriod).toBe(6);

    // and what the delegate took is gone from the budget of the parent
    expectReject(await book(3, { ctx }), 'AUTHORITY_PERIOD_EXCEEDED');
    expectAccept(await book(2, { ctx }));
    expect(await ledger.used(olehKey, thisShift)).toBe(10);
  });

  it('is a fresh budget in the next shift and not in the same one', async () => {
    const ledger = createMemoryLedger();
    const ctx = { ledger };
    expectAccept(await book(10, { ctx }));
    expectReject(await book(1, { ctx }), 'AUTHORITY_PERIOD_EXCEEDED');

    // 00:00 to 08:00 is one shift; the next begins at 08:00 and has its own total
    const lastMoment = T0 + 8 * HOUR - 30;
    expectReject(await book(1, { ctx, at: lastMoment }), 'AUTHORITY_PERIOD_EXCEEDED');
    const nextShift = await book(10, { ctx, at: T0 + 8 * HOUR + 60 });
    expectAccept(nextShift);
    expect(nextShift.authority!.usedInPeriod).toBe(0);
    expect(await ledger.used(olehKey, periodWindow('shift', T0 + 8 * HOUR + 60))).toBe(10);
    expect(await ledger.used(olehKey, thisShift)).toBe(10);
  });

  it('keeps separate budgets for separate credentials', async () => {
    const ledger = createMemoryLedger();
    const ctx = { ledger };
    const other = await rootOf('cred-oleh-0007', {});
    expectAccept(await book(10, { ctx }));
    expectAccept(await book(10, { ctx, cred: other }));
    expectReject(await book(1, { ctx, cred: other }), 'AUTHORITY_PERIOD_EXCEEDED');
  });
});

describe('periods other than a shift', () => {
  it('counts a day as a whole UTC day, and a week as the week from Monday', async () => {
    const day = await rootOf('cred-oleh-0010', { per: 'day' });
    const ledger = createMemoryLedger();
    const ctx = { ledger };
    expectAccept(await book(10, { ctx, cred: day, at: T0 + HOUR }));
    // 15 hours later it is still the same day, which is to say that the budget is spent
    expectReject(await book(1, { ctx, cred: day, at: T0 + 15 * HOUR }), 'AUTHORITY_PERIOD_EXCEEDED');
    expectAccept(await book(10, { ctx, cred: day, at: T0 + 24 * HOUR + 60 }));

    const week = await rootOf('cred-oleh-0011', { per: 'week' });
    const weeks = createMemoryLedger();
    // 2026-11-04 is a Wednesday: the week ends on the coming Monday, 2026-11-09 00:00 UTC
    expectAccept(await book(10, { ctx: { ledger: weeks }, cred: week, at: T0 + HOUR }));
    expectReject(
      await book(1, { ctx: { ledger: weeks }, cred: week, at: T0 + 4 * 24 * HOUR + 60 }),
      'AUTHORITY_PERIOD_EXCEEDED',
    );
    expectAccept(await book(10, { ctx: { ledger: weeks }, cred: week, at: T0 + 5 * 24 * HOUR + 60 }));
  });

  it('books nothing for a limit per operation, nor for a limit without a period', async () => {
    for (const per of ['operation', undefined] as const) {
      const cred = await credential({
        issuer: w.issuerA,
        iss: ISSUER_A,
        holder: w.oleh,
        jti: `cred-oleh-002${per === undefined ? 0 : 1}`,
        idx: IDX.spare,
        listUri: LIST_A,
        claims: {
          org: { id: 'contractor-a', name: 'Підрядник А' },
          role: { code: 'crew_lead', name: 'Керівник бригади' },
          authority: [
            {
              ...OLEH_AUTHORITY[0]!,
              limit: per === undefined ? { amount: 10, unit: 't' } : { amount: 10, unit: 't', per },
            },
          ],
          delegation: { depth: 0, max_depth: 1 },
        },
        crypto: w.crypto,
      });
      const ledger = createMemoryLedger();
      const first = await book(10, { cred, ctx: { ledger } });
      expectAccept(first);
      expect(first.authority!.usedInPeriod).toBeUndefined();
      expectAccept(await book(10, { cred, ctx: { ledger } }));
      expectReject(await book(11, { cred, ctx: { ledger } }), 'AUTHORITY_LIMIT_EXCEEDED');
    }
  });

  it('checks only the amount of the request when the checkpoint keeps no ledger', async () => {
    const first = await book(10, { ctx: { ledger: undefined } });
    expectAccept(first);
    expect(first.authority!.usedInPeriod).toBeUndefined();
    expectAccept(await book(10, { ctx: { ledger: undefined } }));
  });
});

/** A ledger whose every call takes a moment, so that decisions overlap if nothing keeps them apart. */
function slow(inner: AuthorityLedger, ms: number): AuthorityLedger & { peak: number } {
  const pause = () => new Promise<void>((resolve) => setTimeout(resolve, ms));
  let running = 0;
  const ledger = {
    peak: 0,
    async used(key: string, window: Parameters<AuthorityLedger['used']>[1]) {
      running += 1;
      ledger.peak = Math.max(ledger.peak, running);
      try {
        await pause();
        return await inner.used(key, window);
      } finally {
        running -= 1;
      }
    },
    async add(key: string, window: Parameters<AuthorityLedger['add']>[1], amount: number) {
      await pause();
      return inner.add(key, window, amount);
    },
  };
  return ledger;
}

describe('two scans at the same moment', () => {
  it('cannot spend the same remainder twice: five at once for four tonnes of ten, two are accepted', async () => {
    const inner = createMemoryLedger();
    const ledger = slow(inner, 5);
    const ctx = warehouseContext(w, { ledger });
    const attempts = await Promise.all(
      Array.from({ length: 5 }, async () => {
        const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount: 4 } });
        return { pending, reply: await answer(w, w.olehCredential, w.oleh, pending) };
      }),
    );
    const results = await Promise.all(attempts.map(({ pending, reply }) => verifyResponseQr(reply, pending, ctx)));

    const accepted = results.filter((result) => result.decision === 'accept');
    expect(accepted).toHaveLength(2);
    for (const result of results.filter((entry) => entry.decision === 'reject')) {
      expectReject(result, 'AUTHORITY_PERIOD_EXCEEDED');
    }
    expect(accepted.map((result) => result.authority!.usedInPeriod).sort()).toEqual([0, 4]);
    expect(await inner.used(olehKey, thisShift)).toBe(8);
  });

  it('lets decisions on other budgets go on at the same time', async () => {
    const inner = createMemoryLedger();
    const ledger = slow(inner, 20);
    const other = await rootOf('cred-oleh-0030', {});
    const ctx = warehouseContext(w, { ledger });
    const one = await ask(w, { authority: { ...TEN_TONNES, amount: 6 } });
    const two = await ask(w, { authority: { ...TEN_TONNES, amount: 6 } });
    const replyOne = await answer(w, w.olehCredential, w.oleh, one.pending);
    const replyTwo = await answer(w, other, w.oleh, two.pending);

    const results = await Promise.all([
      verifyResponseQr(replyOne, one.pending, ctx),
      verifyResponseQr(replyTwo, two.pending, ctx),
    ]);
    results.forEach(expectAccept);
    expect(ledger.peak).toBe(2);
  });

  it('does not hold the budget back after a failure', async () => {
    const inner = createMemoryLedger();
    let failures = 1;
    const flaky: AuthorityLedger = {
      used: (key, window) => inner.used(key, window),
      async add(key, window, amount) {
        if (failures-- > 0) throw new Error('the store was not reachable');
        return inner.add(key, window, amount);
      },
    };
    const ctx = { ledger: flaky };
    const failed = await book(4, { ctx });
    expect(failed.decision).toBe('reject');
    expect(failed.reasons).toEqual(['MALFORMED']);
    expect(await inner.used(olehKey, thisShift)).toBe(0);

    const second = await Promise.race([
      book(4, { ctx }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('the budget stayed locked')), 2_000)),
    ]);
    expectAccept(second);
    expect(await inner.used(olehKey, thisShift)).toBe(4);
  });
});
