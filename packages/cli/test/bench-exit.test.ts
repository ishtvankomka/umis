import { UmisError } from '@umis/core';
import { benchReport } from '@umis/testkit';
import type { AutonomyReport, BenchReport, RevocationReport, ScenarioSummary } from '@umis/testkit';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { bench } from '../src/commands/bench.js';

vi.mock('@umis/testkit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@umis/testkit')>();
  return { ...actual, benchReport: vi.fn() };
});

const summary = (scenario: ScenarioSummary['scenario'], extra: Partial<ScenarioSummary> = {}): ScenarioSummary => ({
  scenario,
  n: 10,
  repeats: 2,
  expected: 'accept',
  mismatches: 0,
  p50: 1,
  p95: 2,
  p99: 3,
  mean: 1.5,
  sd: 0.5,
  min: 0.9,
  max: 4,
  p95Ci95: [1.5, 2.5],
  nfrP1Pass: true,
  frameChars: { p50: 300, max: 310 },
  ...extra,
});

const timeline = (riskClass: 'low' | 'medium', exact = true): AutonomyReport => ({
  riskClass,
  policy: riskClass === 'low' ? 'door_low' : 'warehouse_medium',
  maxStatusAgeS: 100,
  horizonS: 3_600,
  periodS: 300,
  probes: 13,
  lastAcceptS: 100,
  firstStaleS: exact ? 101 : 105,
  exact,
});

const revocation: RevocationReport = {
  refreshS: 600,
  maxStatusAgeS: 100,
  lifetimeS: 1_000,
  revokedAtS: 1,
  tauOnlineS: 599,
  tauOfflineS: 100,
  boundOnlineS: 600,
  boundOfflineS: 100,
  withinBounds: true,
};

function report(parts: Partial<BenchReport> & { scenarios: ScenarioSummary[] }): BenchReport {
  const autonomy = parts.autonomy ?? { low: timeline('low'), medium: timeline('medium') };
  const rest = parts.revocation ?? revocation;
  const ok =
    parts.ok ??
    (parts.scenarios.every((row) => row.mismatches === 0) &&
      autonomy.low.exact &&
      autonomy.medium.exact &&
      rest.withinBounds);
  return { v: 1, autonomy, revocation: rest, ok, ...parts };
}

async function run(args: string[], signal?: AbortSignal): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await bench(args, { out: (line) => out.push(line), err: (line) => err.push(line) }, signal);
  return { code, out: out.join('\n'), err: err.join('\n') };
}

beforeEach(() => {
  vi.mocked(benchReport).mockReset();
});

describe('umis bench, with a report that is made up', () => {
  it('runs everything with the defaults of the protocol, in a folder named by the time', async () => {
    vi.mocked(benchReport).mockResolvedValue(report({ scenarios: [summary('oneway-low')] }));
    const controller = new AbortController();
    expect((await run([], controller.signal)).code).toBe(0);

    const [options, hooks] = vi.mocked(benchReport).mock.calls[0]!;
    expect(options).toMatchObject({
      scenarios: ['oneway-low', 'full-qr-low', 's1-accept', 's1-reject', 'mutual', 'oid4vp', 'gateway'],
      n: 1_000,
      repeats: 30,
      warmup: 1,
      crypto: 'webcrypto',
      seed: 'umis',
    });
    expect(options.out).toMatch(/^bench-results[\\/]\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$/);
    expect(options).not.toHaveProperty('emitFrames');
    expect(hooks?.signal).toBe(controller.signal);
  });

  it('ends with 2 when a presentation came to another decision, and says which', async () => {
    vi.mocked(benchReport).mockResolvedValue(
      report({
        scenarios: [
          summary('oneway-low'),
          summary('s1-reject', { mismatches: 3, expected: 'AUTHORITY_LIMIT_EXCEEDED' }),
        ],
      }),
    );
    const { code, out, err } = await run(['--out', 'x']);
    expect(code).toBe(2);
    expect(err).toBe('s1-reject: 3 of 30 presentations were not rejected with AUTHORITY_LIMIT_EXCEEDED');
    expect(out.split('\n').at(-1)).toBe('2 scenarios, NOT AS EXPECTED, NFR-P1 met by all');
  });

  it('ends with 2 when a timeline is off, and shows it', async () => {
    vi.mocked(benchReport).mockResolvedValue(
      report({
        scenarios: [summary('mutual')],
        autonomy: { low: timeline('low'), medium: timeline('medium', false) },
      }),
    );
    const { code, out } = await run(['--out', 'x']);
    expect(code).toBe(2);
    expect(out).toContain('autonomy medium: 13 presentations over 1 h, accepted up to S = 100 s (last 100)');
    expect(out).toContain('STATUS_LIST_STALE from 105 s: NOT exactly at S + 1 s');
  });

  it('reports a scenario that misses NFR-P1 and still ends with 0', async () => {
    vi.mocked(benchReport).mockResolvedValue(
      report({ scenarios: [summary('oneway-low'), summary('gateway', { p95: 1_200.5, nfrP1Pass: false })] }),
    );
    const { code, out } = await run(['--out', 'x']);
    expect(code).toBe(0);
    expect(out).toMatch(/gateway\s+accept\s+1\.000\s+1200\.500\s.*\sNOT MET$/m);
    expect(out.split('\n').at(-1)).toBe('2 scenarios, every presentation as expected, NFR-P1 not met by gateway');
  });

  it('hands the options on as they were given', async () => {
    vi.mocked(benchReport).mockResolvedValue(report({ scenarios: [summary('mutual'), summary('gateway')] }));
    await run([
      ...['--scenario', 'mutual, gateway,mutual'],
      ...['--n', '7', '--repeats', '3', '--warmup', '0', '--crypto', 'noble', '--seed', 's'],
      ...['--out', 'results-here', '--emit-frames', 'frames-there.json'],
    ]);
    expect(vi.mocked(benchReport).mock.calls[0]![0]).toEqual({
      scenarios: ['mutual', 'gateway'],
      n: 7,
      repeats: 3,
      warmup: 0,
      crypto: 'noble',
      seed: 's',
      out: 'results-here',
      emitFrames: 'frames-there.json',
    });
  });

  it('ends with 1 when the run is stopped, and with 64 when the SDK refuses the options', async () => {
    vi.mocked(benchReport).mockRejectedValueOnce(new UmisError('USER_CANCELLED', 'the benchmark was stopped'));
    const stopped = await run(['--out', 'x']);
    expect(stopped.code).toBe(1);
    expect(stopped.err).toBe('umis bench: the benchmark was stopped');

    vi.mocked(benchReport).mockRejectedValueOnce(
      new UmisError('INVALID_ARGUMENT', 'n is a whole number from 1 to 100000'),
    );
    const refused = await run(['--n', '100001', '--out', 'x']);
    expect(refused.code).toBe(64);
    expect(refused.err).toContain('n is a whole number from 1 to 100000');
  });
});
