import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LIMITS } from '@umis/core';
import type { ReasonCode, VerificationResult } from '@umis/core';
import { createMemoryReplayStore, deserializeVerifierContext, verifyAtCheckpoint } from '@umis/verifier';
import type { SerializedVerifierContextV1 } from '@umis/verifier';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { describeEnvironment } from '../src/bench/env.js';
import { csvText, jsonText, ms4 } from '../src/bench/output.js';
import {
  BENCH_SCENARIOS,
  benchProblems,
  benchProvider,
  benchReport,
  measure,
  measureScenario,
  runBench,
} from '../src/bench/runner.js';
import type { BenchOptions, BenchReport } from '../src/bench/runner.js';
import * as scenarioModule from '../src/bench/scenarios.js';
import { isExpected, oneWayFrames, openScenario, outcomeOf } from '../src/bench/scenarios.js';
import type { Scenario } from '../src/bench/scenarios.js';
import { meanCi95, percentile, standardDeviation, tCritical95 } from '../src/bench/stats.js';
import { autonomyTimeline, revocationTimeline } from '../src/bench/timelines.js';
import { createDemoWorld } from '../src/index.js';

const HOUR = 3_600;
const START = 1_793_606_400;

/** A world that signs and verifies with WebCrypto, which keeps the long timelines short. */
const fastWorld = () => createDemoWorld({ crypto: benchProvider('webcrypto', 'umis') });

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe('percentile', () => {
  it('is the element at the rank ceil(p / 100 · n) of the sorted list', () => {
    const five = [15, 20, 35, 40, 50];
    expect([0, 5, 20, 30, 40, 50, 95, 100].map((p) => percentile(five, p))).toEqual([15, 15, 15, 20, 20, 35, 50, 50]);

    const hundred = Array.from({ length: 100 }, (_, i) => i + 1);
    expect([50, 95, 99, 100].map((p) => percentile(hundred, p))).toEqual([50, 95, 99, 100]);
    const thousand = Array.from({ length: 1_000 }, (_, i) => i + 1);
    expect([50, 95, 99].map((p) => percentile(thousand, p))).toEqual([500, 950, 990]);
    expect(percentile([7], 99)).toBe(7);
  });

  it('does not let floating point move a rank to the next element', () => {
    // 0.07 · 100 is 7.000000000000001, which a ceiling would turn into 8
    const hundred = Array.from({ length: 100 }, (_, i) => i + 1);
    const thousand = Array.from({ length: 1_000 }, (_, i) => i + 1);
    for (let p = 1; p <= 100; p++) {
      expect(percentile(hundred, p)).toBe(p);
      expect(percentile(thousand, p)).toBe(p * 10);
    }
  });

  it('refuses an empty list and a p outside 0 to 100', () => {
    expect(() => percentile([], 50)).toThrow(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
    for (const p of [-1, 100.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => percentile([1, 2, 3], p)).toThrow(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
    }
  });
});

describe('the confidence interval', () => {
  it('uses the t-distribution with n - 1 degrees of freedom', () => {
    // the 97.5 % points of Student's t
    const table: Array<[number, number]> = [
      [1, 12.7062],
      [2, 4.3027],
      [4, 2.7764],
      [9, 2.2622],
      [29, 2.0452],
      [30, 2.0423],
      [100, 1.984],
    ];
    for (const [df, expected] of table) expect(tCritical95(df)).toBeCloseTo(expected, 3);
    expect(() => tCritical95(0)).toThrow(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
    expect(() => tCritical95(2.5)).toThrow(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
  });

  it('is the mean plus and minus t · SD / √n of a fixed list', () => {
    expect(standardDeviation([2, 4, 4, 4, 5, 5, 7, 9])).toBeCloseTo(Math.sqrt(32 / 7), 10);

    // mean 14, SD √10, 4 degrees of freedom: 14 ± 2.7764 · √(10 / 5)
    const [low, high] = meanCi95([10, 12, 14, 16, 18])!;
    const half = 2.7764451 * Math.sqrt(2);
    expect(low).toBeCloseTo(14 - half, 3);
    expect(high).toBeCloseTo(14 + half, 3);

    // thirty equal repeats have no spread, and one repeat has no interval to give
    expect(meanCi95(Array.from({ length: 30 }, () => 3.5))).toEqual([3.5, 3.5]);
    expect(meanCi95([4.25])).toBeNull();
    expect(() => meanCi95([])).toThrow(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
  });
});

describe('the output formats', () => {
  it('writes CSV with RFC 4180 quoting and a line feed after every line', () => {
    const text = csvText(
      ['a', 'b'],
      [
        [1, 'x,y'],
        [2, 'say "hi"'],
        [3, 'two\nlines'],
        [4, 'plain'],
      ],
    );
    expect(text).toBe('a,b\n1,"x,y"\n2,"say ""hi"""\n3,"two\nlines"\n4,plain\n');
  });

  it('writes JSON indented by two spaces, and milliseconds with four decimals', () => {
    expect(jsonText({ a: [1] })).toBe('{\n  "a": [\n    1\n  ]\n}\n');
    expect(ms4(1.23456)).toBe('1.2346');
    expect(ms4(2)).toBe('2.0000');
  });
});

describe('the provider of a run', () => {
  it('draws its random bytes from the stream of the seed, with either implementation', () => {
    const draw = (kind: 'webcrypto' | 'noble', seed: string) =>
      benchProvider(kind, seed).getRandomValues(new Uint8Array(24));
    expect(draw('noble', 'umis')).toEqual(draw('noble', 'umis'));
    expect(draw('webcrypto', 'umis')).toEqual(draw('noble', 'umis'));
    expect(draw('noble', 'other')).not.toEqual(draw('noble', 'umis'));
    expect([benchProvider('noble', 'umis').name, benchProvider('webcrypto', 'umis').name]).toEqual([
      'noble',
      'webcrypto',
    ]);
    expect(() => benchProvider('md5' as 'noble', 'umis')).toThrow(
      expect.objectContaining({ code: 'INVALID_ARGUMENT' }),
    );
  });

  it.each(['webcrypto', 'noble'] as const)('signs and verifies a signature (%s)', async (kind) => {
    const provider = benchProvider(kind, 'umis');
    const signer = await provider.generateSigner();
    const data = new TextEncoder().encode('a presentation');
    expect(await provider.verifyEs256(signer.publicJwk, data, await signer.sign(data))).toBe(true);
    expect(
      await provider.verifyEs256(signer.publicJwk, new TextEncoder().encode('another'), await signer.sign(data)),
    ).toBe(false);
  });
});

describe('isExpected', () => {
  const stale = { decision: 'reject', reason: 'STATUS_LIST_STALE' };
  const exceeded = { decision: 'reject', reason: 'AUTHORITY_LIMIT_EXCEEDED' };
  const accepted = { decision: 'accept', reason: 'OK' };

  it('takes a reject only for the reason the scenario expects', () => {
    expect(isExpected(stale, 'AUTHORITY_LIMIT_EXCEEDED')).toBe(false);
    expect(isExpected(exceeded, 'AUTHORITY_LIMIT_EXCEEDED')).toBe(true);
    expect(isExpected(exceeded, 'accept')).toBe(false);
  });

  it('takes an accept only where an accept is expected, and only one that has no fault', () => {
    expect(isExpected(accepted, 'accept')).toBe(true);
    expect(isExpected(accepted, 'AUTHORITY_LIMIT_EXCEEDED')).toBe(false);
    expect(isExpected({ decision: 'accept', reason: 'relay_http_401' }, 'accept')).toBe(false);
  });
});

describe('the scenarios', () => {
  const N = 6;

  it.each(BENCH_SCENARIOS)(
    '%s: every presentation is different, is decided as expected and is a replay the second time',
    async (name) => {
      const world = await fastWorld();
      const scenario = await openScenario(name, world);
      expect(scenario.name).toBe(name);
      const prepared = await scenario.prepare(N);
      try {
        // a presentation that repeated another would be a replay in the one store of the repeat
        for (let i = 0; i < N; i++) {
          const decided = await prepared.verify(i);
          expect(decided.fault).toBeUndefined();
          expect(decided.results).toHaveLength(name === 'mutual' ? 2 : 1);
          expect(isExpected(outcomeOf(decided), scenario.expected), `${name} ${i}`).toBe(true);

          const sizes = prepared.chars(i);
          expect(sizes).toHaveLength(scenario.frames.length);
          scenario.frames.forEach((frame, k) => {
            expect(Number.isInteger(sizes[k])).toBe(true);
            expect(sizes[k]).toBeGreaterThan(0);
            if (frame.kind.startsWith('qr_')) expect(sizes[k]).toBeLessThanOrEqual(LIMITS.qrMaxChars);
          });
        }
        for (let i = 0; i < N; i++) {
          const outcome = outcomeOf(await prepared.verify(i));
          expect(outcome.decision).toBe('reject');
          if (scenario.expected === 'accept') expect(outcome.reason).toBe('REPLAY');
        }
      } finally {
        await prepared.release();
      }
    },
  );

  it('expects an acceptance from every scenario but the refused request of the warehouse', async () => {
    const world = await fastWorld();
    const expected = Object.fromEntries(
      await Promise.all(BENCH_SCENARIOS.map(async (name) => [name, (await openScenario(name, world)).expected])),
    );
    expect(expected).toEqual({
      'oneway-low': 'accept',
      'full-qr-low': 'accept',
      's1-accept': 'accept',
      's1-reject': 'AUTHORITY_LIMIT_EXCEEDED',
      mutual: 'accept',
      oid4vp: 'accept',
      gateway: 'accept',
    });
  });

  it('makes the one-way QR codes different by their counters, even where the signatures repeat themselves', async () => {
    // the noble implementation signs deterministically: only the counter can tell two codes made at one time apart
    const world = await createDemoWorld({ crypto: benchProvider('noble', 'umis') });
    const first = await oneWayFrames(world, START, 20, 1);
    const second = await oneWayFrames(world, START, 20, 21);
    expect(new Set([...first, ...second]).size).toBe(40);
    expect(await oneWayFrames(world, START, 20, 1)).toEqual(first);
  });

  it('refuses a scenario it does not have', async () => {
    await expect(openScenario('nowhere' as 'mutual', await fastWorld())).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
  });
});

describe('the network', () => {
  it('is not used by any scenario but the gateway, which talks to its relay on the loopback interface', async () => {
    const fetchStub = vi.fn(() => {
      throw new Error('the network is not available to the benchmark');
    });
    vi.stubGlobal('fetch', fetchStub);
    try {
      for (const name of BENCH_SCENARIOS.filter((scenario) => scenario !== 'gateway')) {
        const measured = await measureScenario(name, {
          n: 3,
          repeats: 1,
          warmup: 0,
          crypto: 'webcrypto',
          seed: 'umis',
        });
        expect(measured.summary.mismatches, name).toBe(0);
      }
      expect(fetchStub).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

const LOOPBACK_HOSTS = ['127.0.0.1', 'localhost', '[::1]'];

/**
 * A `fetch` that keeps invariant I-20 for the gateway scenario: it writes down the host of every request, forwards the
 * requests to the loopback interface and throws for any other host. With `refuseCommands` only the first request, the
 * one that opens the connection to the emulator, is forwarded; the stub answers each request after it with 401.
 */
function loopbackOnly(seen: string[], refuseCommands = false): typeof fetch {
  const real = globalThis.fetch;
  return (input, init) => {
    const { hostname } = new URL(input instanceof Request ? input.url : String(input));
    seen.push(hostname);
    if (!LOOPBACK_HOSTS.includes(hostname)) throw new Error(`I-20: network access to ${hostname}`);
    return refuseCommands && seen.length > 1 ? Promise.resolve(new Response('{}', { status: 401 })) : real(input, init);
  };
}

describe('the gateway scenario', () => {
  it('lets the loopback interface through and throws for every other host', () => {
    const seen: string[] = [];
    const stub = loopbackOnly(seen);
    expect(() => stub('https://lists.example.test/status/1')).toThrow('I-20: network access to lists.example.test');
    expect(() => stub('http://192.0.2.7:8089/rpc')).toThrow('I-20: network access to 192.0.2.7');
    expect(seen).toEqual(['lists.example.test', '192.0.2.7']);
  });

  it('counts a relay command that the relay does not obey as a mismatch, whatever the decision was', async () => {
    const seen: string[] = [];
    vi.stubGlobal('fetch', loopbackOnly(seen, true));
    try {
      const measured = await measureScenario('gateway', {
        n: 3,
        repeats: 1,
        warmup: 0,
        crypto: 'webcrypto',
        seed: 'umis',
      });
      expect(seen).toHaveLength(4);
      expect(measured.summary.mismatches).toBe(3);
      expect(measured.samples.map((sample) => [sample.decision, sample.reason])).toEqual(
        Array(3).fill(['accept', 'relay_http_401']),
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('counts no fault when the relay obeys every command, and reaches the loopback interface only (I-20)', async () => {
    const seen: string[] = [];
    vi.stubGlobal('fetch', loopbackOnly(seen));
    try {
      const measured = await measureScenario('gateway', {
        n: 3,
        repeats: 2,
        warmup: 1,
        crypto: 'webcrypto',
        seed: 'umis',
      });
      expect(measured.summary.mismatches).toBe(0);
      expect(measured.samples.map((sample) => sample.reason)).toEqual(Array(6).fill('OK'));
      expect(seen.length).toBeGreaterThan(0);
      expect(seen.filter((host) => !LOOPBACK_HOSTS.includes(host))).toEqual([]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('both providers', () => {
  it.each(BENCH_SCENARIOS)(
    '%s is decided as expected with the noble implementation too',
    async (name) => {
      const measured = await measureScenario(name, { n: 3, repeats: 1, warmup: 1, crypto: 'noble', seed: 'umis' });
      expect(measured.summary).toMatchObject({ scenario: name, n: 3, repeats: 1, mismatches: 0 });
      expect(measured.samples).toHaveLength(3);
    },
    60_000,
  );

  it('makes the same one-way QR codes from the same seed with the noble implementation', async () => {
    const make = async (seed: string) =>
      oneWayFrames(await createDemoWorld({ crypto: benchProvider('noble', seed) }), START, 4, 1);
    expect(await make('umis')).toEqual(await make('umis'));
    expect(await make('other')).not.toEqual(await make('umis'));
  });
});

describe('the measurement', () => {
  function result(decision: 'accept' | 'reject', reason: ReasonCode): VerificationResult {
    return { decision, reasons: [reason], channel: 'qr_oneway', at: START, timings: { totalMs: 0 }, trace: [] };
  }

  /** A scenario that refuses every fourth presentation and counts how often it is prepared and released. */
  function counting(verify?: (i: number) => never): {
    scenario: Scenario;
    calls: { prepare: number; release: number };
  } {
    const calls = { prepare: 0, release: 0 };
    const scenario: Scenario = {
      name: 'oneway-low',
      expected: 'accept',
      frames: [{ kind: 'qr_oneway', checked: true }],
      prepare: () => {
        calls.prepare += 1;
        return Promise.resolve({
          chars: () => [100],
          verify: (i) => {
            if (verify !== undefined) verify(i);
            return Promise.resolve({
              results: [i % 4 === 3 ? result('reject', 'REPLAY') : result('accept', 'OK')],
            });
          },
          release: () => {
            calls.release += 1;
            return Promise.resolve();
          },
        });
      },
    };
    return { scenario, calls };
  }

  it('makes new presentations for every repeat, keeps the measured ones and throws the warm-up away', async () => {
    const { scenario, calls } = counting();
    const measured = await measure(scenario, { n: 8, repeats: 3, warmup: 2 });

    expect(calls).toEqual({ prepare: 5, release: 5 });
    expect(measured.samples).toHaveLength(24);
    expect(new Set(measured.samples.map((sample) => sample.repeat))).toEqual(new Set([1, 2, 3]));
    expect(measured.samples.filter((sample) => sample.repeat === 2).map((sample) => sample.i)).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8,
    ]);
    expect(measured.summary).toMatchObject({ scenario: 'oneway-low', n: 8, repeats: 3, expected: 'accept' });
    for (const sample of measured.samples) expect(sample.ms).toBeGreaterThanOrEqual(0);
  });

  /**
   * A scenario on a pretend clock that `performance.now` reads: making the presentations and releasing them take a second
   * each, and the decision takes `decisionMs`.
   */
  function onPretendClock(decisionMs: number): Scenario {
    let clock = 0;
    vi.spyOn(performance, 'now').mockImplementation(() => clock);
    return {
      name: 'oneway-low',
      expected: 'accept',
      frames: [{ kind: 'qr_oneway', checked: true }],
      prepare: () => {
        clock += 1_000;
        return Promise.resolve({
          chars: () => [10],
          verify: () => {
            clock += decisionMs;
            return Promise.resolve({ results: [result('accept', 'OK')] });
          },
          release: () => {
            clock += 1_000;
            return Promise.resolve();
          },
        });
      },
    };
  }

  it('times the call that decides and nothing else: not the making of the presentations, not the bookkeeping', async () => {
    const measured = await measure(onPretendClock(5), { n: 4, repeats: 2, warmup: 1 });
    expect(measured.samples.map((sample) => sample.ms)).toEqual(Array(8).fill(5));
    expect(measured.summary).toMatchObject({ p50: 5, p95: 5, p99: 5, mean: 5, sd: 0, min: 5, max: 5, mismatches: 0 });
  });

  it('meets NFR-P1 with a p95 of exactly one second and misses it by a hair more (NFR-P1 is p95 <= 1 000 ms)', async () => {
    const exactly = await measure(onPretendClock(1_000), { n: 4, repeats: 2, warmup: 0 });
    expect(exactly.summary).toMatchObject({ p95: 1_000, nfrP1Pass: true });

    const over = await measure(onPretendClock(1_000.0001), { n: 4, repeats: 2, warmup: 0 });
    expect(over.summary.p95).toBeGreaterThan(1_000);
    expect(over.summary.nfrP1Pass).toBe(false);
  });

  it('counts a presentation that came to another decision, warm-up included, and does not average it away', async () => {
    const { scenario } = counting();
    const measured = await measure(scenario, { n: 8, repeats: 3, warmup: 2 });
    // two of every eight presentations are refused, in each of the five repeats
    expect(measured.summary.mismatches).toBe(10);
    expect(measured.samples.filter((sample) => sample.decision === 'reject')).toHaveLength(6);
    expect(measured.samples.filter((sample) => sample.decision === 'reject').every((s) => s.reason === 'REPLAY')).toBe(
      true,
    );
  });

  it('counts a fault outside the decision as a mismatch and says what it was', async () => {
    const faulty: Scenario = {
      name: 'gateway',
      expected: 'accept',
      frames: [{ kind: 'qr_oneway', checked: true }],
      prepare: () =>
        Promise.resolve({
          chars: () => [10],
          verify: () => Promise.resolve({ results: [result('accept', 'OK')], fault: 'relay_http_401' }),
          release: () => Promise.resolve(),
        }),
    };
    const measured = await measure(faulty, { n: 3, repeats: 1, warmup: 0 });
    expect(measured.summary.mismatches).toBe(3);
    expect(measured.samples.map((sample) => [sample.decision, sample.reason])).toEqual(
      Array(3).fill(['accept', 'relay_http_401']),
    );
  });

  it('releases a repeat even when the decision throws, and stops when asked', async () => {
    const boom = counting(() => {
      throw new Error('boom');
    });
    await expect(measure(boom.scenario, { n: 2, repeats: 1, warmup: 0 })).rejects.toThrow('boom');
    expect(boom.calls).toEqual({ prepare: 1, release: 1 });

    const stopped = counting();
    const controller = new AbortController();
    controller.abort();
    await expect(
      measure(stopped.scenario, { n: 2, repeats: 1, warmup: 0 }, { signal: controller.signal }),
    ).rejects.toMatchObject({ code: 'USER_CANCELLED' });
    expect(stopped.calls.prepare).toBe(0);
  });

  it('reports the mean of each step of the pipeline, in the order of the nine steps', async () => {
    const world = await fastWorld();
    const measured = await measure(await openScenario('oneway-low', world), { n: 5, repeats: 2, warmup: 1 });
    expect(measured.steps.map((step) => [step.step, step.name])).toEqual([
      [1, 'parse'],
      [2, 'issuer_trust'],
      [3, 'issuer_signature'],
      [4, 'holder_binding'],
      [5, 'validity'],
      [6, 'status'],
      [7, 'policy'],
      [8, 'authority'],
      [9, 'decision'],
    ]);
    expect(measured.steps.reduce((sum, step) => sum + step.meanMs, 0)).toBeGreaterThan(0);
    expect(measured.steps.every((step) => step.meanMs >= 0)).toBe(true);
  });
});

describe('the autonomy of a checkpoint on the simulated clock', () => {
  it.each([
    ['low', 72 * HOUR, 80],
    ['medium', 24 * HOUR, 30],
  ] as const)(
    'the %s class accepts at S and switches to STATUS_LIST_STALE at S + 1 s',
    async (riskClass, s, hours) => {
      const { rows, report } = await autonomyTimeline(await fastWorld(), riskClass);

      expect(report).toMatchObject({
        riskClass,
        maxStatusAgeS: s,
        periodS: 300,
        lastAcceptS: s,
        firstStaleS: s + 1,
        exact: true,
      });
      const at = (t: number) => rows.find((row) => row.t === t);
      expect(at(s)).toEqual({ t: s, ageS: s, decision: 'accept', reason: 'OK' });
      expect(at(s + 1)).toEqual({ t: s + 1, ageS: s + 1, decision: 'reject', reason: 'STATUS_LIST_STALE' });

      // a presentation every five minutes after the sync up to the horizon, and the second after S
      expect(rows).toHaveLength(hours * 12 + 1);
      expect(rows[0]).toMatchObject({ t: 300, ageS: 300, decision: 'accept' });
      expect(rows.filter((row) => row.t % 300 !== 0).map((row) => row.t)).toEqual([s + 1]);
      expect(rows.map((row) => row.t)).toEqual([...new Set(rows.map((row) => row.t))].sort((a, b) => a - b));
      for (const row of rows) {
        expect(row.ageS).toBe(row.t);
        if (row.t <= s) expect([row.decision, row.reason]).toEqual(['accept', 'OK']);
        else expect([row.decision, row.reason]).toEqual(['reject', 'STATUS_LIST_STALE']);
      }
    },
    60_000,
  );

  it('plays on the clock of the world and reads no wall clock', async () => {
    // a call of Date.now from the SDK or the testkit would show in the stack; the runner of the tests is not counted
    const origin: string[] = [];
    const real = Date.now.bind(Date);
    vi.spyOn(Date, 'now').mockImplementation(() => {
      origin.push(new Error().stack ?? '');
      return real();
    });
    const world = await fastWorld();
    await autonomyTimeline(world, 'low');
    await revocationTimeline(await fastWorld(), await fastWorld());
    expect(origin.filter((stack) => /\/packages\/[a-z-]+\/(src|dist)\//.test(stack))).toEqual([]);
    // and the clock of the world is where the timeline left it, nowhere near the real time
    expect(world.clock.now()).toBeGreaterThan(START);
    expect(world.clock.now()).toBeLessThan(START + 81 * HOUR);
  }, 60_000);
});

describe('the revocation timeline', () => {
  it('is seen online within Δ and offline within min(T; S)', async () => {
    const { rows, report } = await revocationTimeline(await fastWorld(), await fastWorld());

    expect(report).toMatchObject({
      refreshS: 600,
      maxStatusAgeS: 24 * HOUR,
      lifetimeS: 90 * 24 * HOUR,
      tauOnlineS: 599,
      tauOfflineS: 24 * HOUR,
      boundOnlineS: 600,
      boundOfflineS: 24 * HOUR,
      withinBounds: true,
    });
    expect(report.tauOnlineS).toBeLessThanOrEqual(report.boundOnlineS);
    expect(report.tauOfflineS).toBeLessThanOrEqual(report.boundOfflineS);

    expect(rows[0]).toEqual({ t: 0, online: 'OK', offline: 'OK' });
    for (const row of rows) {
      expect(row.online).toBe(row.t < 599 ? 'OK' : 'STATUS_REVOKED');
      expect(row.offline).toBe(row.t < 24 * HOUR ? 'OK' : 'STATUS_LIST_STALE');
    }
    // the offline verifier is still accepting a revoked credential just before its list goes stale
    expect(rows.find((row) => row.t === 24 * HOUR - 1)).toEqual({
      t: 24 * HOUR - 1,
      online: 'STATUS_REVOKED',
      offline: 'OK',
    });
  }, 60_000);

  it('wants two worlds that start together', async () => {
    const later = await createDemoWorld({ start: START + 60, crypto: benchProvider('webcrypto', 'umis') });
    await expect(revocationTimeline(await fastWorld(), later)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });

  it('says what is off in a report', () => {
    const summary = (scenario: string, expected: string, mismatches: number) => ({ scenario, expected, mismatches });
    const fine = {
      scenarios: [summary('oneway-low', 'accept', 0), summary('s1-reject', 'AUTHORITY_LIMIT_EXCEEDED', 0)],
      autonomy: {
        low: { riskClass: 'low', exact: true },
        medium: { riskClass: 'medium', exact: true },
      },
      revocation: { withinBounds: true },
    } as unknown as BenchReport;
    expect(benchProblems(fine)).toEqual([]);
    const off = {
      scenarios: [summary('oneway-low', 'accept', 2), summary('s1-reject', 'AUTHORITY_LIMIT_EXCEEDED', 1)],
      autonomy: { low: { riskClass: 'low', exact: false }, medium: { riskClass: 'medium', exact: true } },
      revocation: { withinBounds: false },
    } as unknown as BenchReport;
    expect(benchProblems(off)).toEqual([
      'oneway-low: 2 presentations were not accepted',
      's1-reject: 1 presentation was not rejected with AUTHORITY_LIMIT_EXCEEDED',
      'the low class does not switch to STATUS_LIST_STALE exactly at S + 1 s',
      'a revocation is seen later than its bound',
    ]);
  });
});

describe('the environment record', () => {
  it('describes the machine, the code and the options, and reads no environment variable', () => {
    vi.stubEnv('UMIS_BENCH_TEST_VALUE', 'a-value-that-must-not-be-recorded');
    const options = {
      scenarios: ['oneway-low', 'gateway'],
      n: 1_000,
      repeats: 30,
      warmup: 1,
      crypto: 'noble',
      seed: 'umis',
    };
    const env = describeEnvironment(options, 'noble');

    expect(env).toMatchObject({ v: 1, crypto: 'noble', node: { version: process.version }, options });
    expect(env.cpu.cores).toBeGreaterThan(0);
    expect(env.memoryBytes).toBeGreaterThan(0);
    expect(new Date(env.generatedAt).toISOString()).toBe(env.generatedAt);
    expect(env.git.commit === null || /^[0-9a-f]{40}$/.test(env.git.commit)).toBe(true);
    expect(Object.keys(env.packages)).toEqual(
      expect.arrayContaining(['@umis/core', '@umis/verifier', '@umis/gateway', '@umis/testkit']),
    );
    expect(env.packages['@umis/core']).toMatch(/^\d+\.\d+\.\d+/);
    expect(JSON.stringify(env)).not.toContain('a-value-that-must-not-be-recorded');
  });
});

describe('the options of a run', () => {
  let scratch: string;
  beforeAll(async () => {
    scratch = await mkdtemp(join(tmpdir(), 'umis-bench-options-'));
  });
  afterAll(async () => {
    await rm(scratch, { recursive: true, force: true });
  });

  it('refuses what it cannot run, before it writes anything', async () => {
    const out = join(scratch, 'never');
    const base: BenchOptions = {
      scenarios: ['oneway-low'],
      n: 5,
      repeats: 2,
      warmup: 0,
      crypto: 'webcrypto',
      seed: 'umis',
      out,
    };
    const bad: Array<Partial<BenchOptions>> = [
      { n: 0 },
      { n: 100_001 },
      { n: 1.5 },
      { repeats: 0 },
      { warmup: -1 },
      { crypto: 'md5' as 'noble' },
      { scenarios: [] },
      { scenarios: ['nowhere' as 'mutual'] },
      { seed: '' },
      { out: '' },
      { emitFrames: '' },
    ];
    for (const change of bad) {
      await expect(runBench({ ...base, ...change }), JSON.stringify(change)).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
      });
    }
    await expect(stat(out)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('a smoke run of every scenario', () => {
  const FILES = [
    'autonomy-low.csv',
    'autonomy-medium.csv',
    'env.json',
    'revocation.csv',
    'sizes.csv',
    'summary.json',
    ...BENCH_SCENARIOS.flatMap((name) => [`samples-${name}.csv`, `steps-${name}.csv`]),
  ].sort();

  let scratch: string;
  let out: string;
  let frames: string;
  let report: BenchReport;
  let returned: Awaited<ReturnType<typeof runBench>>;
  let again: string;
  const progress: string[] = [];

  const rowsOf = async (file: string): Promise<string[][]> =>
    (await readFile(join(out, file), 'utf8'))
      .trimEnd()
      .split('\n')
      .map((line) => line.split(','));

  beforeAll(async () => {
    scratch = await mkdtemp(join(tmpdir(), 'umis-bench-smoke-'));
    out = join(scratch, 'results');
    frames = join(scratch, 'frames', 'door.json');
    const options: BenchOptions = {
      scenarios: [...BENCH_SCENARIOS],
      n: 50,
      repeats: 3,
      warmup: 1,
      crypto: 'webcrypto',
      seed: 'umis',
      out,
      emitFrames: frames,
    };
    report = await benchReport(options, { progress: (line) => progress.push(line) });
    again = join(scratch, 'again');
    returned = await runBench({
      scenarios: ['oneway-low'],
      n: 10,
      repeats: 2,
      warmup: 0,
      crypto: 'webcrypto',
      seed: 'umis',
      out: again,
    });
  }, 180_000);
  afterAll(async () => {
    await rm(scratch, { recursive: true, force: true });
  });

  it('writes every file and nothing else', async () => {
    expect((await readdir(out)).sort()).toEqual(FILES);
    expect((await readdir(again)).sort()).toEqual(
      FILES.filter((file) => !/^(samples|steps)-/.test(file) || file.endsWith('-oneway-low.csv')),
    );
    expect(progress.some((line) => line.startsWith('gateway:'))).toBe(true);
  });

  it('summarises each scenario as asked, with no presentation decided otherwise than expected', () => {
    expect(report.ok).toBe(true);
    expect(report.scenarios.map((summary) => summary.scenario)).toEqual([...BENCH_SCENARIOS]);
    expect(returned.map((summary) => [summary.scenario, summary.n, summary.repeats, summary.mismatches])).toEqual([
      ['oneway-low', 10, 2, 0],
    ]);
    for (const summary of report.scenarios) {
      expect(summary, summary.scenario).toMatchObject({ n: 50, repeats: 3, mismatches: 0, nfrP1Pass: true });
      expect(summary.min).toBeGreaterThan(0);
      expect(summary.min).toBeLessThanOrEqual(summary.p50);
      expect(summary.p50).toBeLessThanOrEqual(summary.p95);
      expect(summary.p95).toBeLessThanOrEqual(summary.p99);
      expect(summary.p99).toBeLessThanOrEqual(summary.max);
      const [low, high] = summary.p95Ci95!;
      expect(low).toBeLessThanOrEqual(summary.p95Mean);
      expect(summary.p95Mean).toBeLessThanOrEqual(high);
      expect(summary.frameChars.p50).toBeGreaterThan(0);
      expect(summary.frameChars.max).toBeGreaterThanOrEqual(summary.frameChars.p50);
      expect(summary.frameChars.max).toBeLessThanOrEqual(LIMITS.qrMaxChars);
    }
  });

  it('stops s1-reject at the limit every time', async () => {
    const summary = report.scenarios.find((row) => row.scenario === 's1-reject');
    expect(summary).toMatchObject({ expected: 'AUTHORITY_LIMIT_EXCEEDED', mismatches: 0 });

    const [header, ...rows] = await rowsOf('samples-s1-reject.csv');
    expect(header).toEqual(['repeat', 'i', 'ms', 'decision', 'reason']);
    expect(rows).toHaveLength(150);
    expect(new Set(rows.map((row) => `${row[3]},${row[4]}`))).toEqual(new Set(['reject,AUTHORITY_LIMIT_EXCEEDED']));

    const accepted = await rowsOf('samples-s1-accept.csv');
    expect(new Set(accepted.slice(1).map((row) => `${row[3]},${row[4]}`))).toEqual(new Set(['accept,OK']));
  });

  it('numbers the repeats and the presentations, and the summary is what the samples say', async () => {
    for (const summary of report.scenarios) {
      const [, ...rows] = await rowsOf(`samples-${summary.scenario}.csv`);
      expect(rows).toHaveLength(150);
      expect(rows.map((row) => Number(row[0]))).toEqual(Array.from({ length: 150 }, (_, k) => Math.floor(k / 50) + 1));
      expect(rows.map((row) => Number(row[1]))).toEqual(Array.from({ length: 150 }, (_, k) => (k % 50) + 1));

      const all = rows.map((row) => Number(row[2])).sort((a, b) => a - b);
      expect(percentile(all, 50)).toBeCloseTo(summary.p50, 3);
      expect(percentile(all, 95)).toBeCloseTo(summary.p95, 3);
      expect(percentile(all, 99)).toBeCloseTo(summary.p99, 3);
      expect(all[all.length - 1]).toBeCloseTo(summary.max, 3);

      const p95s = [1, 2, 3].map((repeat) =>
        percentile(
          rows
            .filter((row) => Number(row[0]) === repeat)
            .map((row) => Number(row[2]))
            .sort((a, b) => a - b),
          95,
        ),
      );
      const [low, high] = meanCi95(p95s)!;
      expect(low).toBeCloseTo(summary.p95Ci95![0], 3);
      expect(high).toBeCloseTo(summary.p95Ci95![1], 3);
      expect(summary.p95Mean).toBeCloseTo((p95s[0]! + p95s[1]! + p95s[2]!) / 3, 3);
    }
  });

  it('gives the mean time of the nine steps, and the sizes of the texts', async () => {
    const [header, ...steps] = await rowsOf('steps-oneway-low.csv');
    expect(header).toEqual(['step', 'name', 'mean_ms']);
    expect(steps.map((row) => row[1])).toEqual([
      'parse',
      'issuer_trust',
      'issuer_signature',
      'holder_binding',
      'validity',
      'status',
      'policy',
      'authority',
      'decision',
    ]);

    const [sizesHeader, ...sizes] = await rowsOf('sizes.csv');
    expect(sizesHeader).toEqual(['scenario', 'frame', 'checked', 'count', 'min_chars', 'p50_chars', 'max_chars']);
    expect(sizes.map((row) => `${row[0]}:${row[1]}`)).toEqual([
      'oneway-low:qr_oneway',
      'full-qr-low:qr_full',
      's1-accept:qr_request',
      's1-accept:qr_response',
      's1-reject:qr_request',
      's1-reject:qr_response',
      'mutual:qr_mutual_init',
      'mutual:qr_mutual_reply',
      'oid4vp:qr_login_request',
      'oid4vp:post_body',
      'gateway:qr_oneway',
    ]);
    for (const row of sizes) expect(Number(row[3])).toBe(150);
  });

  it('records the autonomy to the second and the revocation', async () => {
    const low = await rowsOf('autonomy-low.csv');
    expect(low[0]).toEqual(['t', 'age_s', 'decision', 'reason']);
    expect(low).toContainEqual(['259200', '259200', 'accept', 'OK']);
    expect(low).toContainEqual(['259201', '259201', 'reject', 'STATUS_LIST_STALE']);
    expect(low).toHaveLength(1 + 961);
    const medium = await rowsOf('autonomy-medium.csv');
    expect(medium).toContainEqual(['86400', '86400', 'accept', 'OK']);
    expect(medium).toContainEqual(['86401', '86401', 'reject', 'STATUS_LIST_STALE']);

    const revocation = await rowsOf('revocation.csv');
    expect(revocation[0]).toEqual(['t', 'online', 'offline']);
    expect(revocation).toContainEqual(['599', 'STATUS_REVOKED', 'OK']);
    expect(revocation).toContainEqual(['86400', 'STATUS_REVOKED', 'STATUS_LIST_STALE']);

    expect(report.autonomy.low).toMatchObject({ exact: true, lastAcceptS: 259_200, firstStaleS: 259_201 });
    expect(report.autonomy.medium).toMatchObject({ exact: true, lastAcceptS: 86_400, firstStaleS: 86_401 });
    expect(report.revocation).toMatchObject({ withinBounds: true, tauOnlineS: 599, tauOfflineS: 86_400 });
  });

  it('keeps the report in summary.json and the record of the run in env.json', async () => {
    expect(JSON.parse(await readFile(join(out, 'summary.json'), 'utf8'))).toEqual(JSON.parse(JSON.stringify(report)));
    const env = JSON.parse(await readFile(join(out, 'env.json'), 'utf8')) as ReturnType<typeof describeEnvironment>;
    expect(env.crypto).toBe('webcrypto');
    expect(env.options).toEqual({
      scenarios: [...BENCH_SCENARIOS],
      n: 50,
      repeats: 3,
      warmup: 1,
      crypto: 'webcrypto',
      seed: 'umis',
    });
    expect(Object.keys(env)).not.toContain('env');
  });

  it('writes a replay file that a station can decide on: every payload is accepted once, then it is a replay', async () => {
    const file = JSON.parse(await readFile(frames, 'utf8')) as {
      v: number;
      now: number;
      context: SerializedVerifierContextV1;
      payloads: string[];
    };
    expect(file.v).toBe(1);
    expect(file.now).toBe(file.context.now);
    expect(file.payloads).toHaveLength(50);
    expect(new Set(file.payloads).size).toBe(50);

    const replay = createMemoryReplayStore();
    const ctx = deserializeVerifierContext(file.context, { replay });
    for (const payload of file.payloads) {
      const first = await verifyAtCheckpoint(payload, ctx);
      expect([first.decision, first.reasons]).toEqual(['accept', ['OK']]);
    }
    for (const payload of file.payloads) {
      const second = await verifyAtCheckpoint(payload, ctx);
      expect([second.decision, second.reasons]).toEqual(['reject', ['REPLAY']]);
    }

    // a station decides at its own time: the codes live for 30 seconds
    const late = deserializeVerifierContext(file.context, { replay: createMemoryReplayStore(), now: file.now + 600 });
    expect((await verifyAtCheckpoint(file.payloads[0]!, late)).reasons).toEqual(['PRESENTATION_EXPIRED']);
  });
});

describe('a run that finds a presentation decided otherwise than expected', () => {
  const options = (out: string): BenchOptions => ({
    scenarios: ['oneway-low'],
    n: 3,
    repeats: 1,
    warmup: 0,
    crypto: 'webcrypto',
    seed: 'umis',
    out,
  });
  let scratch: string;

  beforeAll(async () => {
    scratch = await mkdtemp(join(tmpdir(), 'umis-bench-mismatch-'));
  });
  afterAll(async () => {
    await rm(scratch, { recursive: true, force: true });
  });

  it('is failed by runBench with PROTOCOL once the files are written, and reported as not ok by benchReport', async () => {
    vi.spyOn(scenarioModule, 'isExpected').mockReturnValue(false);

    const failed = join(scratch, 'failed');
    await expect(runBench(options(failed))).rejects.toMatchObject({
      code: 'PROTOCOL',
      message: 'the benchmark failed: oneway-low: 3 presentations were not accepted',
    });
    const written = JSON.parse(await readFile(join(failed, 'summary.json'), 'utf8')) as BenchReport;
    expect(written.ok).toBe(false);
    expect(written.scenarios.map((row) => row.mismatches)).toEqual([3]);

    const reported = await benchReport(options(join(scratch, 'reported')));
    expect(reported.ok).toBe(false);
    expect(reported.scenarios.map((row) => row.mismatches)).toEqual([3]);
  }, 60_000); // both runs play the autonomy and revocation timelines, about 3 s each
});
