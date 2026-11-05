import type { AutonomyReport, BenchReport, RevocationReport, ScenarioSummary } from '@umis/testkit';
import { bench } from '../src/commands/bench.js';

// Reports that are made up, for the tests of `umis bench` that must not run the benchmark.

export const summary = (
  scenario: ScenarioSummary['scenario'],
  extra: Partial<ScenarioSummary> = {},
): ScenarioSummary => ({
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
  p95Mean: 2,
  p95Ci95: [1.5, 2.5],
  nfrP1Pass: true,
  frameChars: { p50: 300, max: 310 },
  ...extra,
});

export const timeline = (riskClass: 'low' | 'medium', exact = true): AutonomyReport => ({
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

export const revocation: RevocationReport = {
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

export function report(parts: Partial<BenchReport> & { scenarios: ScenarioSummary[] }): BenchReport {
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

export async function run(args: string[], signal?: AbortSignal): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await bench(args, { out: (line) => out.push(line), err: (line) => err.push(line) }, signal);
  return { code, out: out.join('\n'), err: err.join('\n') };
}
