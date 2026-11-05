import type { VerificationResult } from '@umis/core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { measure } from '../src/bench/runner.js';
import type { Scenario } from '../src/bench/scenarios.js';
import { meanCi95 } from '../src/bench/stats.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const accepted: VerificationResult = {
  decision: 'accept',
  reasons: ['OK'],
  channel: 'qr_oneway',
  at: 0,
  timings: { totalMs: 0 },
  trace: [],
};

/**
 * A scenario whose decision number `i` of repeat `r` takes `times[r][i]` milliseconds of a pretend clock that
 * `performance.now` reads, so that the figures of every repeat are set by the test.
 */
function timed(times: readonly (readonly number[])[]): Scenario {
  let clock = 0;
  let round = -1;
  vi.spyOn(performance, 'now').mockImplementation(() => clock);
  return {
    name: 'oneway-low',
    expected: 'accept',
    frames: [{ kind: 'qr_oneway', checked: true }],
    prepare: () => {
      round += 1;
      const mine = times[round]!;
      return Promise.resolve({
        chars: () => [10],
        verify: (i) => {
          clock += mine[i]!;
          return Promise.resolve({ results: [accepted] });
        },
        release: () => Promise.resolve(),
      });
    },
  };
}

/** Repeats of `n` decisions that all take the same time: the p95 of a repeat is that time. */
const steady = (n: number, perRepeat: readonly number[]): number[][] => perRepeat.map((ms) => Array(n).fill(ms));

describe('the interval of the repeats', () => {
  it('does not exist for a single repeat', () => {
    expect(meanCi95([5])).toBeNull();
  });

  it('for two repeats is the mean plus and minus 12.706 · SD / √2 (t for one degree of freedom)', () => {
    const [low, high] = meanCi95([4, 6])!;
    // mean 5, SD √2, so the half width is 12.706 · √2 / √2
    expect(Math.abs(low - (5 - 12.706))).toBeLessThan(1e-3);
    expect(Math.abs(high - (5 + 12.706))).toBeLessThan(1e-3);
  });

  it('is null in the summary of a run of one repeat, which still gives the p95 of that repeat as its mean', async () => {
    const { summary } = await measure(timed(steady(20, [7])), { n: 20, repeats: 1, warmup: 0 });
    expect(summary.p95Ci95).toBeNull();
    expect(summary.p95Mean).toBe(7);
  });
});

describe('p95Mean', () => {
  it('is the mean of the p95 of the repeats, and the centre of the interval of that mean', async () => {
    // five repeats whose p95 is 10, 12, 14, 16 and 18 ms: mean 14, SD √10, so 14 ± 2.7764 · √10 / √5
    const { summary } = await measure(timed(steady(20, [10, 12, 14, 16, 18])), { n: 20, repeats: 5, warmup: 0 });
    expect(summary.p95Mean).toBe(14);
    const [low, high] = summary.p95Ci95!;
    expect(low).toBeLessThan(summary.p95Mean);
    expect(summary.p95Mean).toBeLessThan(high);
    expect((low + high) / 2).toBeCloseTo(summary.p95Mean, 3);
    expect(high - low).toBeCloseTo(2 * 2.7764451 * Math.sqrt(2), 3);
  });

  it('is another figure than p95, which is that of all the presentations together and can lie outside the interval', async () => {
    // thirty repeats of twenty decisions; a slow tail of three decisions of 100 ms is in ten of them, 1 ms is all else
    const slow = [...Array(17).fill(1), ...Array(3).fill(100)];
    const repeats = [...Array(10).fill(slow), ...Array(20).fill(Array(20).fill(1))];
    const { summary } = await measure(timed(repeats), { n: 20, repeats: 30, warmup: 0 });

    // the p95 of a slow repeat is 100 ms and that of the others 1 ms: ten of 100 and twenty of 1 have the mean 34
    expect(summary.p95Mean).toBe(34);
    // 570 of the 600 decisions took 1 ms, so the nearest-rank p95 of all of them is 1 ms, below the interval, as expected
    expect(summary.p95).toBe(1);
    const [low] = summary.p95Ci95!;
    expect(summary.p95).toBeLessThan(low);
  });
});
