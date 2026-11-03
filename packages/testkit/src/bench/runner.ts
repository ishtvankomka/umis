import { join } from 'node:path';
import { UmisError, webCryptoProvider } from '@umis/core';
import type { CryptoProvider, ReasonCode, StepName } from '@umis/core';
import { serializeVerifierContext } from '@umis/verifier';
import { DECISION_DELAY_S } from '../hero.js';
import { deterministicCrypto } from '../random.js';
import { createDemoWorld } from '../world.js';
import { describeEnvironment } from './env.js';
import type { RecordedOptions } from './env.js';
import { csvText, jsonText, ms4, writeText } from './output.js';
import { BENCH_SCENARIOS, isExpected, oneWayFrames, openScenario, outcomeOf } from './scenarios.js';
import type { BenchScenario, Scenario } from './scenarios.js';
import { describe, meanCi95, percentile } from './stats.js';
import { autonomyTimeline, revocationTimeline } from './timelines.js';
import type { AutonomyReport, RevocationReport } from './timelines.js';

export { BENCH_SCENARIOS } from './scenarios.js';
export type { BenchScenario } from './scenarios.js';

export interface BenchOptions {
  scenarios: BenchScenario[];
  /** Presentations verified in one repeat. */
  n: number;
  /** Repeats that are measured. */
  repeats: number;
  /** Repeats that are run first and thrown away. */
  warmup: number;
  crypto: 'webcrypto' | 'noble';
  /** Fixes the keys, identifiers and salts; WebCrypto signatures stay random. */
  seed: string;
  /** The folder the results are written to. */
  out: string;
  /** Where to write a file of one-way QR codes of the door and the context to decide on them with. */
  emitFrames?: string;
}

export interface ScenarioSummary {
  scenario: BenchScenario;
  n: number;
  repeats: number;
  /** The decision every presentation of the scenario should come to: an accept, or a reject for this reason. */
  expected: 'accept' | ReasonCode;
  /** Presentations that came to another decision, the warm-up repeats included. */
  mismatches: number;
  /** Milliseconds over all the measured presentations. */
  p50: number;
  p95: number;
  p99: number;
  mean: number;
  sd: number;
  min: number;
  max: number;
  /** 95 % confidence interval of the mean of the p95 of the repeats (t-distribution, repeats - 1 degrees of freedom). */
  p95Ci95: [number, number];
  /** True when the p95 over all the measured presentations is at most one second (NFR-P1). */
  nfrP1Pass: boolean;
  /** Characters of the QR texts that the verifier was given. */
  frameChars: { p50: number; max: number };
}

/** Everything a run found: the scenarios, the autonomy of the door and the warehouse, and the revocation. */
export interface BenchReport {
  v: 1;
  scenarios: ScenarioSummary[];
  autonomy: { low: AutonomyReport; medium: AutonomyReport };
  revocation: RevocationReport;
  /** True when no presentation came to another decision and both timelines are as they must be. */
  ok: boolean;
}

export interface BenchHooks {
  /** Hears what the run is doing, one line at a time. */
  progress?: (line: string) => void;
  /** Stops the run between two repeats when aborted: it fails with USER_CANCELLED, and the files written so far stay. */
  signal?: AbortSignal;
}

/** NFR-P1: the p95 of the decision latency is at most this many milliseconds. */
export const NFR_P1_MS = 1_000;
/** The most presentations in one repeat: the replay store of a verifier holds 100 000 ids. */
export const MAX_N = 100_000;
const MAX_REPEATS = 10_000;
const MAX_WARMUP = 100;
/** A line of progress for every this many repeats. */
const PROGRESS_EVERY = 5;

const STEP_NAMES: readonly StepName[] = [
  'parse',
  'issuer_trust',
  'issuer_signature',
  'holder_binding',
  'validity',
  'status',
  'policy',
  'authority',
  'decision',
];

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

function whole(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw invalid(`${name} is a whole number from ${min} to ${max}`);
  }
  return value;
}

/** The options as the run uses them, or INVALID_ARGUMENT. */
function checked(o: BenchOptions): BenchOptions {
  if (typeof o !== 'object' || o === null) throw invalid('the options of the benchmark are missing');
  if (!Array.isArray(o.scenarios) || o.scenarios.length === 0) throw invalid('name at least one scenario');
  const scenarios: BenchScenario[] = [];
  for (const name of o.scenarios) {
    if (!(BENCH_SCENARIOS as readonly unknown[]).includes(name)) {
      throw invalid(`unknown scenario "${String(name).slice(0, 64)}" (one of ${BENCH_SCENARIOS.join(', ')})`);
    }
    if (!scenarios.includes(name)) scenarios.push(name);
  }
  if (o.crypto !== 'webcrypto' && o.crypto !== 'noble') throw invalid('crypto is "webcrypto" or "noble"');
  if (typeof o.seed !== 'string' || o.seed === '') throw invalid('the seed is a non-empty text');
  if (typeof o.out !== 'string' || o.out === '') throw invalid('out names the folder for the results');
  if (o.emitFrames !== undefined && (typeof o.emitFrames !== 'string' || o.emitFrames === '')) {
    throw invalid('emitFrames names the file for the QR codes');
  }
  return {
    scenarios,
    n: whole(o.n, 'n', 1, MAX_N),
    repeats: whole(o.repeats, 'repeats', 1, MAX_REPEATS),
    warmup: whole(o.warmup, 'warmup', 0, MAX_WARMUP),
    crypto: o.crypto,
    seed: o.seed,
    out: o.out,
    ...(o.emitFrames === undefined ? {} : { emitFrames: o.emitFrames }),
  };
}

/**
 * The provider a run signs and verifies with: WebCrypto, or the `@noble` implementation that stands in for the engine of
 * Expo Go. Both draw their random bytes (identifiers, nonces, salts) from the stream of `seed`, so two runs with the same
 * seed make the same keys and the same frames; the signatures of WebCrypto are made with a random nonce all the same.
 * The stream is predictable by design: the provider is for measurements, never for protecting anything.
 */
export function benchProvider(kind: BenchOptions['crypto'], seed: string): CryptoProvider {
  const stream = deterministicCrypto(seed);
  if (kind === 'noble') return { ...stream, name: 'noble' };
  if (kind === 'webcrypto') return { ...webCryptoProvider, name: 'webcrypto', getRandomValues: stream.getRandomValues };
  throw invalid('crypto is "webcrypto" or "noble"');
}

const r4 = (value: number): number => Math.round(value * 10_000) / 10_000;

function stopIfAsked(hooks: BenchHooks): void {
  if (hooks.signal?.aborted === true) throw new UmisError('USER_CANCELLED', 'the benchmark was stopped');
}

/** One timed presentation. */
interface Sample {
  repeat: number;
  i: number;
  ms: number;
  decision: 'accept' | 'reject';
  reason: string;
}

/** The measurements of one scenario. */
export interface Measured {
  summary: ScenarioSummary;
  samples: readonly Sample[];
  /** Mean milliseconds of every step of the pipeline, summed over the calls of a presentation. */
  steps: ReadonlyArray<{ step: number; name: StepName; meanMs: number }>;
  sizes: ReadonlyArray<{ kind: string; checked: boolean; chars: readonly number[] }>;
}

/**
 * Times a scenario that is open: `warmup` repeats that are thrown away, then `repeats` measured ones, each with `n` new
 * presentations made before the timing starts and a new replay store. The only thing timed is the call that decides on a
 * presentation. A presentation that comes to another decision than the scenario expects is counted, warm-up included.
 */
export async function measure(
  scenario: Scenario,
  o: Pick<BenchOptions, 'n' | 'repeats' | 'warmup'>,
  hooks: BenchHooks = {},
): Promise<Measured> {
  const name = scenario.name;
  const say = (line: string): void => hooks.progress?.(line);
  say(`${name}: ${o.warmup} warm-up and ${o.repeats} repeats of ${o.n} presentations`);

  const samples: Sample[] = [];
  const columns = scenario.frames.map(() => [] as number[]);
  const stepSums = new Float64Array(STEP_NAMES.length);
  const p95s: number[] = [];
  let mismatches = 0;

  const total = o.warmup + o.repeats;
  for (let round = 0; round < total; round++) {
    stopIfAsked(hooks);
    const measured = round >= o.warmup;
    const repeat = round - o.warmup + 1;
    const prepared = await scenario.prepare(o.n);
    try {
      const times: number[] = [];
      for (let i = 0; i < o.n; i++) {
        const started = performance.now();
        const decided = await prepared.verify(i);
        const elapsed = performance.now() - started;

        const outcome = outcomeOf(decided);
        if (!isExpected(outcome, scenario.expected)) mismatches += 1;
        if (!measured) continue;
        times.push(elapsed);
        samples.push({ repeat, i: i + 1, ms: elapsed, ...outcome });
        for (const result of decided.results) {
          for (const step of result.trace) stepSums[step.step - 1]! += step.ms;
        }
        const sizes = prepared.chars(i);
        columns.forEach((column, k) => column.push(sizes[k]!));
      }
      if (measured) {
        p95s.push(
          percentile(
            times.sort((a, b) => a - b),
            95,
          ),
        );
        if (repeat % PROGRESS_EVERY === 0 || repeat === o.repeats) say(`${name}: repeat ${repeat}/${o.repeats}`);
      }
    } finally {
      await prepared.release();
    }
  }

  const distribution = describe(samples.map((sample) => sample.ms));
  const [low, high] = meanCi95(p95s);
  const checkedChars = columns.filter((_, k) => scenario.frames[k]!.checked).flat();
  const sortedChars = [...checkedChars].sort((a, b) => a - b);
  const summary: ScenarioSummary = {
    scenario: name,
    n: o.n,
    repeats: o.repeats,
    expected: scenario.expected,
    mismatches,
    p50: r4(distribution.p50),
    p95: r4(distribution.p95),
    p99: r4(distribution.p99),
    mean: r4(distribution.mean),
    sd: r4(distribution.sd),
    min: r4(distribution.min),
    max: r4(distribution.max),
    p95Ci95: [r4(low), r4(high)],
    nfrP1Pass: distribution.p95 <= NFR_P1_MS,
    frameChars: { p50: percentile(sortedChars, 50), max: sortedChars[sortedChars.length - 1]! },
  };
  return {
    summary,
    samples,
    steps: STEP_NAMES.map((stepName, k) => ({ step: k + 1, name: stepName, meanMs: stepSums[k]! / samples.length })),
    sizes: scenario.frames.map((frame, k) => ({ ...frame, chars: columns[k]! })),
  };
}

/** Runs one scenario on a world of its own that is made with the provider of the options; see {@link measure}. */
export async function measureScenario(
  name: BenchScenario,
  o: Pick<BenchOptions, 'n' | 'repeats' | 'warmup' | 'crypto' | 'seed'>,
  hooks: BenchHooks = {},
): Promise<Measured> {
  const world = await createDemoWorld({ crypto: benchProvider(o.crypto, o.seed) });
  return measure(await openScenario(name, world), o, hooks);
}

/** One-way QR codes of the door with the context to decide on them, as a station replays them. */
async function writeFrames(file: string, o: BenchOptions): Promise<void> {
  const world = await createDemoWorld({ crypto: benchProvider(o.crypto, o.seed) });
  const at = world.clock.now();
  const payloads = await oneWayFrames(world, at, o.n, 1);
  world.clock.set(at + DECISION_DELAY_S.door);
  const context = world.context({ org: 'kovorking-v', policy: 'door_low' });
  await writeText(file, jsonText({ v: 1, now: context.now, context: serializeVerifierContext(context), payloads }));
}

function sizeRows(scenario: BenchScenario, sizes: Measured['sizes']): Array<Array<string | number>> {
  return sizes.map(({ kind, checked, chars }) => {
    const sorted = [...chars].sort((a, b) => a - b);
    return [
      scenario,
      kind,
      checked ? 1 : 0,
      sorted.length,
      sorted[0]!,
      percentile(sorted, 50),
      sorted[sorted.length - 1]!,
    ];
  });
}

/**
 * The whole benchmark: every scenario, the autonomy of the door and of the warehouse on a simulated clock, and the
 * revocation timeline. Files go to `o.out` as each part finishes (`env.json`, `samples-<scenario>.csv`,
 * `steps-<scenario>.csv`, `sizes.csv`, `autonomy-low.csv`, `autonomy-medium.csv`, `revocation.csv`) and `summary.json`
 * last. The report says whether the run is `ok`; this function does not throw for a presentation that came to another
 * decision or a timeline that is off.
 */
export async function benchReport(options: BenchOptions, hooks: BenchHooks = {}): Promise<BenchReport> {
  const o = checked(options);
  const say = (line: string): void => hooks.progress?.(line);
  const recorded: RecordedOptions = {
    scenarios: o.scenarios,
    n: o.n,
    repeats: o.repeats,
    warmup: o.warmup,
    crypto: o.crypto,
    seed: o.seed,
  };
  await writeText(
    join(o.out, 'env.json'),
    jsonText(describeEnvironment(recorded, benchProvider(o.crypto, o.seed).name)),
  );

  const scenarios: ScenarioSummary[] = [];
  const sizes: Array<Array<string | number>> = [];
  for (const name of o.scenarios) {
    stopIfAsked(hooks);
    const measured = await measureScenario(name, o, hooks);
    scenarios.push(measured.summary);
    await writeText(
      join(o.out, `samples-${name}.csv`),
      csvText(
        ['repeat', 'i', 'ms', 'decision', 'reason'],
        measured.samples.map((s) => [s.repeat, s.i, ms4(s.ms), s.decision, s.reason]),
      ),
    );
    await writeText(
      join(o.out, `steps-${name}.csv`),
      csvText(
        ['step', 'name', 'mean_ms'],
        measured.steps.map((s) => [s.step, s.name, ms4(s.meanMs)]),
      ),
    );
    sizes.push(...sizeRows(name, measured.sizes));
    await writeText(
      join(o.out, 'sizes.csv'),
      csvText(['scenario', 'frame', 'checked', 'count', 'min_chars', 'p50_chars', 'max_chars'], sizes),
    );
    say(
      `${name}: p95 ${measured.summary.p95} ms, ${measured.summary.mismatches} presentations not as expected` +
        (measured.summary.nfrP1Pass ? '' : ', NFR-P1 NOT met'),
    );
  }

  stopIfAsked(hooks);
  say('autonomy: a presentation every 5 minutes after the last sync, on the simulated clock');
  const crypto = (): CryptoProvider => benchProvider(o.crypto, o.seed);
  const door = await autonomyTimeline(await createDemoWorld({ crypto: crypto() }), 'low');
  const warehouse = await autonomyTimeline(await createDemoWorld({ crypto: crypto() }), 'medium');
  for (const [file, rows] of [
    ['autonomy-low.csv', door.rows],
    ['autonomy-medium.csv', warehouse.rows],
  ] as const) {
    await writeText(
      join(o.out, file),
      csvText(
        ['t', 'age_s', 'decision', 'reason'],
        rows.map((row) => [row.t, row.ageS, row.decision, row.reason]),
      ),
    );
  }

  stopIfAsked(hooks);
  say('revocation: an online and an offline verifier on the simulated clock');
  const revocation = await revocationTimeline(
    await createDemoWorld({ crypto: crypto() }),
    await createDemoWorld({ crypto: crypto() }),
  );
  await writeText(
    join(o.out, 'revocation.csv'),
    csvText(
      ['t', 'online', 'offline'],
      revocation.rows.map((row) => [row.t, row.online, row.offline]),
    ),
  );

  if (o.emitFrames !== undefined) {
    say(`frames: ${o.n} one-way QR codes of the door and their context`);
    await writeFrames(o.emitFrames, o);
  }

  const found = {
    scenarios,
    autonomy: { low: door.report, medium: warehouse.report },
    revocation: revocation.report,
  };
  const report: BenchReport = { v: 1, ...found, ok: benchProblems(found).length === 0 };
  await writeText(join(o.out, 'summary.json'), jsonText(report));
  return report;
}

/**
 * What is off in a report, one sentence each; nothing when every presentation came to the decision its scenario expects
 * and both timelines are as they must be.
 */
export function benchProblems(report: Pick<BenchReport, 'scenarios' | 'autonomy' | 'revocation'>): string[] {
  const problems: string[] = [];
  for (const row of report.scenarios) {
    if (row.mismatches > 0) {
      const wanted = row.expected === 'accept' ? 'accepted' : `rejected with ${row.expected}`;
      const count = row.mismatches === 1 ? '1 presentation was' : `${row.mismatches} presentations were`;
      problems.push(`${row.scenario}: ${count} not ${wanted}`);
    }
  }
  for (const timeline of [report.autonomy.low, report.autonomy.medium]) {
    if (!timeline.exact) {
      problems.push(`the ${timeline.riskClass} class does not switch to STATUS_LIST_STALE exactly at S + 1 s`);
    }
  }
  if (!report.revocation.withinBounds) problems.push('a revocation is seen later than its bound');
  return problems;
}

/**
 * Runs the benchmark and returns the summary of every scenario. The files are written as `benchReport` writes them, and
 * only then is the run judged: a presentation that came to another decision than its scenario expects, a switch to
 * STATUS_LIST_STALE that is not exactly at S + 1 s and a revocation seen later than its bound each fail the run with
 * PROTOCOL, and the files stay for a look at what happened. Use `benchReport` to have the report of such a run.
 */
export async function runBench(o: BenchOptions, hooks: BenchHooks = {}): Promise<ScenarioSummary[]> {
  const report = await benchReport(o, hooks);
  const problems = benchProblems(report);
  if (problems.length > 0) throw new UmisError('PROTOCOL', `the benchmark failed: ${problems.join('; ')}`);
  return report.scenarios;
}
