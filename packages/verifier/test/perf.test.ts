import { beforeAll, describe, expect, it } from 'vitest';
import { createMemoryReplayStore, verifyAtCheckpoint, verifyResponseQr } from '../src/index.js';
import {
  AT,
  TEN_TONNES,
  answer,
  ask,
  buildWorld,
  doorContext,
  expectAccept,
  oneWayQr,
  verdictOf,
  warehouseContext,
  type World,
} from './fixtures.js';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});

const percentile = (sorted: number[], p: number): number =>
  sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)]!;

describe('the time a decision takes', () => {
  it('is measured for every step and adds up to no more than the whole', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const result = await verifyResponseQr(reply, pending, warehouseContext(w));
    expectAccept(result);
    expect(verdictOf(result).step).toBe(9);
    const steps = result.trace.reduce((sum, entry) => sum + entry.ms, 0);
    expect(steps).toBeGreaterThan(0);
    expect(steps).toBeLessThanOrEqual(result.timings.totalMs + 0.5);
  });

  it(
    'is below 50 ms in nineteen cases of twenty over a thousand decisions in a row',
    { timeout: 120_000 },
    async () => {
      // twenty different answers, each shown to a verifier that has not seen it; the work is the verifier’s own
      const samples = await Promise.all(
        Array.from({ length: 20 }, async (_, index) => {
          const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount: 1 + (index % 10) } });
          return {
            pending,
            reply: await answer(
              w,
              index % 3 === 0 ? w.ivanCredential : w.olehCredential,
              index % 3 === 0 ? w.ivan : w.oleh,
              pending,
            ),
          };
        }),
      );

      const wall: number[] = [];
      const inside: number[] = [];
      for (let n = 0; n < 1_000; n++) {
        const { pending, reply } = samples[n % samples.length]!;
        const ctx = warehouseContext(w);
        const started = performance.now();
        const result = await verifyResponseQr(reply, pending, ctx);
        wall.push(performance.now() - started);
        inside.push(result.timings.totalMs);
        expect(result.decision === 'accept' || result.reasons[0] === 'AUTHORITY_LIMIT_EXCEEDED').toBe(true);
      }
      wall.sort((a, b) => a - b);
      inside.sort((a, b) => a - b);
      expect(percentile(wall, 0.95)).toBeLessThan(50);
      expect(percentile(inside, 0.95)).toBeLessThan(50);
    },
  );
});

describe('what a checkpoint keeps in memory', () => {
  it(
    'forgets the scans that can no longer be presented: a thousand scans leave a few dozen ids',
    { timeout: 120_000 },
    async () => {
      const replay = createMemoryReplayStore();
      for (let n = 0; n < 1_000; n++) {
        const now = AT + n;
        const ctx = await doorContext(w, { now, replay });
        const qr = await oneWayQr(w, { iat: now - 3, ctr: n + 1 });
        expectAccept(await verifyAtCheckpoint(qr, ctx));
      }
      // a one-way token is remembered for its 30 seconds and the skew of 10: 41 ids at most
      expect(replay.size()).toBeLessThanOrEqual(41);
      expect(replay.size()).toBeGreaterThan(30);
    },
  );
});
