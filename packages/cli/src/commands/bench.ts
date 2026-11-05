import { access, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { BENCH_SCENARIOS, benchReport } from '@umis/testkit';
import type { BenchReport, BenchScenario, ScenarioSummary } from '@umis/testkit';
import { EXIT, UsageError, runCommand, table } from './common.js';
import type { CommandIo } from './common.js';

export const BENCH_USAGE = `usage: umis bench [options]

Measures how long a verifier takes to decide on a presentation, on the demo world. In every repeat n different
presentations are made first, which is not timed, and then decided one after the other with a new replay store; the time
of each decision is taken around the verify call. The first repeats (--warmup) are thrown away. The autonomy of the door
(80 hours) and of the warehouse (30 hours) and the revocation of a credential are played on a simulated clock.

scenarios:
  oneway-low   one-way QR code at the door, decided from the member cache
  full-qr-low  full presentation as a QR code at the door
  s1-accept    the warehouse asks for 10 t of rebar and Олег, who holds 10 t, is accepted
  s1-reject    the same request from Іван, who holds 8 t delegated: AUTHORITY_LIMIT_EXCEEDED
  mutual       both decisions of a mutual exchange
  oid4vp       OpenID4VP login, with the status lists fetched from memory
  gateway      the decision of the door and a signed relay command to an emulator over loopback HTTP

options:
  --scenario <list>     all (default), or scenario names separated by commas
  --n <count>           presentations in one repeat (default 1000)
  --repeats <count>     repeats that are measured (default 30)
  --warmup <count>      repeats that are run first and thrown away (default 1)
  --crypto <provider>   webcrypto (default), or noble, which stands in for the JavaScript engine of Expo Go
  --seed <text>         fixes keys, identifiers and salts (default umis); WebCrypto signatures stay random
  --out <dir>           where the results go (default bench-results/<UTC time>); the folder must be empty or new
  --emit-frames <file>  also write n one-way QR codes of the door with the context to decide on them, for a replay
  -h, --help            show this text

Files in --out: env.json, summary.json, samples-<scenario>.csv, steps-<scenario>.csv, sizes.csv, autonomy-low.csv,
autonomy-medium.csv and revocation.csv. Progress goes to standard error, the table of results to standard output.
Exit code 0 when every presentation is decided as expected and both timelines hold, 2 when one is not, 64 for a
mistake in the arguments.`;

const DEFAULTS = { n: 1_000, repeats: 30, warmup: 1, seed: 'umis' } as const;

function scenariosOf(text: string | undefined): BenchScenario[] {
  if (text === undefined) return [...BENCH_SCENARIOS];
  const chosen = new Set<BenchScenario>();
  for (const part of text.split(',')) {
    const name = part.trim();
    if (name === 'all') {
      for (const scenario of BENCH_SCENARIOS) chosen.add(scenario);
    } else if ((BENCH_SCENARIOS as readonly string[]).includes(name)) {
      chosen.add(name as BenchScenario);
    } else {
      throw new UsageError(`unknown scenario "${name.slice(0, 64)}" (all, or ${BENCH_SCENARIOS.join(', ')})`);
    }
  }
  return [...chosen];
}

function countOf(text: string | undefined, fallback: number, option: string): number {
  if (text === undefined) return fallback;
  const value = Number(text);
  if (text.trim() === '' || !Number.isInteger(value) || value < 0) {
    throw new UsageError(`${option} takes a whole number, for example ${fallback}`);
  }
  return value;
}

function cryptoOf(text: string | undefined): 'webcrypto' | 'noble' {
  if (text === undefined || text === 'webcrypto') return 'webcrypto';
  if (text === 'noble') return 'noble';
  throw new UsageError('--crypto is webcrypto or noble');
}

/** `bench-results/2026-11-03T08-00-00Z`: the folder for a run that names none. */
function defaultOut(): string {
  const stamp = new Date()
    .toISOString()
    .replace(/\.\d{3}Z$/, 'Z')
    .replaceAll(':', '-');
  return join('bench-results', stamp);
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** Results are not overwritten: a folder that holds anything, and a file that is there, are refused. */
async function checkTargets(out: string, frames: string | undefined): Promise<void> {
  const held = await readdir(out).catch(() => [] as string[]);
  if (held.length > 0) throw new UsageError(`${out} holds files already; give a new folder with --out`);
  if (frames !== undefined && (await exists(frames))) throw new UsageError(`${frames} exists already`);
}

const ms = (value: number): string => value.toFixed(3);

/** The rows that are not one decision timed alone, with what they time; a note under the table says it for each. */
const ROW_NOTES: Partial<Record<BenchScenario, string>> = {
  mutual: 'both decisions of the exchange, timed together',
  oid4vp: "provider decision only, the wallet's part and the HTTP round trip are excluded",
  gateway: 'decision plus signed relay command against a loopback emulator, connection set-up excluded',
};

/** Intervals of fewer repeats than this are for smoke runs only. */
const SMOKE_BELOW = DEFAULTS.repeats;
const SMOKE_NOTE = `intervals from fewer than ${SMOKE_BELOW} repeats are for smoke runs only; a full run uses ${SMOKE_BELOW} repeats`;

function resultsTable(rows: readonly ScenarioSummary[]): string {
  const body = rows.map((row) => [
    row.scenario,
    row.expected,
    ms(row.p50),
    ms(row.p95),
    ms(row.p95Mean),
    row.p95Ci95 === null ? 'n/a' : `${ms(row.p95Ci95[0])} .. ${ms(row.p95Ci95[1])}`,
    ms(row.p99),
    ms(row.mean),
    ms(row.sd),
    ms(row.max),
    `${row.frameChars.p50} / ${row.frameChars.max}`,
    String(row.mismatches),
    row.nfrP1Pass ? 'met' : 'NOT MET',
  ]);
  return table(
    [
      'SCENARIO',
      'EXPECTED',
      'P50',
      'P95',
      'P95 REP',
      'P95 CI95',
      'P99',
      'MEAN',
      'SD',
      'MAX',
      'QR CHARS',
      'MISMATCH',
      'NFR-P1',
    ],
    body,
    new Set([2, 3, 4, 6, 7, 8, 9, 10, 11]),
  );
}

/** What to print under the table: a note for each row that is not one decision alone, and the caveat on smoke runs. */
function tableNotes(rows: readonly ScenarioSummary[], repeats: number): string[] {
  const notes: string[] = [];
  for (const row of rows) {
    const note = ROW_NOTES[row.scenario];
    if (note !== undefined) notes.push(`${row.scenario}: ${note}`);
  }
  if (repeats < SMOKE_BELOW || rows.some((row) => row.p95Ci95 !== null && row.p95Ci95[0] < 0)) notes.push(SMOKE_NOTE);
  return notes;
}

function timelineLines(report: BenchReport): string[] {
  const lines: string[] = [];
  for (const timeline of [report.autonomy.low, report.autonomy.medium]) {
    const hours = Math.round(timeline.horizonS / 3_600);
    lines.push(
      `autonomy ${timeline.riskClass}: ${timeline.probes} presentations over ${hours} h, accepted up to S = ${timeline.maxStatusAgeS} s ` +
        `(last ${timeline.lastAcceptS ?? 'none'}), STATUS_LIST_STALE from ${timeline.firstStaleS ?? 'never'} s: ` +
        (timeline.exact ? 'exactly at S + 1 s' : 'NOT exactly at S + 1 s'),
    );
  }
  const revocation = report.revocation;
  lines.push(
    `revocation: online ${revocation.tauOnlineS ?? 'never'} s after the revocation (bound Δ = ${revocation.boundOnlineS} s), ` +
      `offline ${revocation.tauOfflineS ?? 'never'} s (bound min(T; S) = ${revocation.boundOfflineS} s): ` +
      (revocation.withinBounds ? 'within the bounds' : 'NOT within the bounds'),
  );
  return lines;
}

/**
 * `umis bench`: runs the benchmark, writes its files and prints a table with one row for every scenario (milliseconds of
 * the decision: median, 95th percentile of all the decisions, mean of the 95th percentiles of the repeats with its 95 %
 * interval, 99th percentile, mean, standard deviation and maximum; characters of the QR text; presentations decided
 * otherwise than expected; NFR-P1), notes under it for the rows that are not one decision alone and for intervals that
 * come from a smoke run, and a line for each timeline. Returns 0 when every presentation is as expected and both
 * timelines hold, 2 when not, 64 for a mistake in the arguments.
 */
export async function bench(args: readonly string[], io: CommandIo, signal?: AbortSignal): Promise<number> {
  return runCommand('bench', io, async () => {
    const { values } = parseArgs({
      args: [...args],
      allowPositionals: false,
      strict: true,
      options: {
        scenario: { type: 'string' },
        n: { type: 'string' },
        repeats: { type: 'string' },
        warmup: { type: 'string' },
        crypto: { type: 'string' },
        seed: { type: 'string' },
        out: { type: 'string' },
        'emit-frames': { type: 'string' },
        help: { type: 'boolean', short: 'h' },
      },
    });
    if (values.help === true) {
      io.out(BENCH_USAGE);
      return EXIT.ok;
    }

    const out = values.out ?? defaultOut();
    const emitFrames = values['emit-frames'];
    const scenarios = scenariosOf(values.scenario);
    const options = {
      scenarios,
      n: countOf(values.n, DEFAULTS.n, '--n'),
      repeats: countOf(values.repeats, DEFAULTS.repeats, '--repeats'),
      warmup: countOf(values.warmup, DEFAULTS.warmup, '--warmup'),
      crypto: cryptoOf(values.crypto),
      seed: values.seed ?? DEFAULTS.seed,
      out,
      ...(emitFrames === undefined ? {} : { emitFrames }),
    };
    await checkTargets(out, emitFrames);

    const report = await benchReport(options, {
      progress: (line) => io.err(`· ${line}`),
      ...(signal === undefined ? {} : { signal }),
    });

    io.out(
      `decision latency in milliseconds: ${options.n} presentations in each of ${options.repeats} repeats, ` +
        `${options.warmup} warm-up, crypto ${options.crypto}, seed ${options.seed}`,
    );
    io.out(resultsTable(report.scenarios));
    for (const note of tableNotes(report.scenarios, options.repeats)) io.out(note);
    io.out('');
    for (const line of timelineLines(report)) io.out(line);
    io.out(`results in ${out}`);

    const off = report.scenarios.filter((row) => row.mismatches > 0);
    for (const row of off) {
      io.err(
        `${row.scenario}: ${row.mismatches} of ${row.n * (row.repeats + options.warmup)} presentations were not ${
          row.expected === 'accept' ? 'accepted' : `rejected with ${row.expected}`
        }`,
      );
    }
    const late = report.scenarios.filter((row) => !row.nfrP1Pass).map((row) => row.scenario);
    io.out(
      `${report.scenarios.length} ${report.scenarios.length === 1 ? 'scenario' : 'scenarios'}, ` +
        (report.ok ? 'every presentation as expected' : 'NOT AS EXPECTED') +
        (late.length === 0 ? ', NFR-P1 met by all' : `, NFR-P1 not met by ${late.join(', ')}`),
    );
    return report.ok ? EXIT.ok : EXIT.rejected;
  });
}
