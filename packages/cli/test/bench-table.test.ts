import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { benchReport } from '@umis/testkit';
import type { BenchOptions, BenchReport } from '@umis/testkit';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { report, run, summary } from './bench-fixtures.js';

vi.mock('@umis/testkit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@umis/testkit')>();
  return { ...actual, benchReport: vi.fn() };
});

const actual = await vi.importActual<typeof import('@umis/testkit')>('@umis/testkit');

const NOTES = {
  mutual: 'mutual: both decisions of the exchange, timed together',
  oid4vp: "oid4vp: provider decision only, the wallet's part and the HTTP round trip are excluded",
  gateway: 'gateway: decision plus signed relay command against a loopback emulator, connection set-up excluded',
};
const SMOKE = 'intervals from fewer than 30 repeats are for smoke runs only; a full run uses 30 repeats';

/** The report of a run that decided everything as expected, with the lower end of every interval at `lower`. */
function reportOf(options: BenchOptions, lower = 1.5): BenchReport {
  const interval: [number, number] | null = options.repeats < 2 ? null : [lower, 2.5];
  return report({
    scenarios: options.scenarios.map((name) =>
      summary(name, { n: options.n, repeats: options.repeats, p95Mean: 2, p95Ci95: interval }),
    ),
  });
}

/** The cells of a table line: the columns are separated by two spaces or more. */
const cells = (line: string): string[] => line.trim().split(/\s{2,}/);

let folder: string;
beforeAll(async () => {
  folder = await mkdtemp(join(tmpdir(), 'umis-cli-bench-table-'));
});
afterAll(async () => {
  await rm(folder, { recursive: true, force: true });
});
beforeEach(() => {
  vi.mocked(benchReport).mockReset();
  vi.mocked(benchReport).mockImplementation((options) => Promise.resolve(reportOf(options)));
});

describe('the table of umis bench', () => {
  it('shows P95 REP, the mean of the p95 of the repeats, before the interval of that mean', async () => {
    const { out } = await run(['--scenario', 'oneway-low', '--n', '3', '--repeats', '2', '--out', 'x']);
    const lines = out.split('\n');
    expect(cells(lines[1]!)).toEqual([
      ...['SCENARIO', 'EXPECTED', 'P50', 'P95', 'P95 REP', 'P95 CI95', 'P99', 'MEAN', 'SD', 'MAX'],
      ...['QR CHARS', 'MISMATCH', 'NFR-P1'],
    ]);
    expect(cells(lines[3]!).slice(0, 7)).toEqual([
      'oneway-low',
      'accept',
      '1.000',
      '2.000',
      '2.000',
      '1.500 .. 2.500',
      '3.000',
    ]);
  });

  it('prints n/a where one repeat cannot give an interval, and summary.json holds null (a real run)', async () => {
    vi.mocked(benchReport).mockImplementation(actual.benchReport);
    const results = join(folder, 'one-repeat');
    const { code, out } = await run([
      ...['--scenario', 'oneway-low', '--n', '3', '--repeats', '1', '--warmup', '0'],
      ...['--out', results],
    ]);
    expect(code).toBe(0);
    const row = out.split('\n').find((line) => line.startsWith('oneway-low '))!;
    expect(cells(row)[5]).toBe('n/a');

    const text = await readFile(join(results, 'summary.json'), 'utf8');
    expect(text).toContain('"p95Ci95": null');
    const written = JSON.parse(text) as BenchReport;
    expect(written.scenarios[0]!.p95Mean).toBeGreaterThan(0);
  }, 60_000);

  it.each(Object.entries(NOTES))(
    'labels the %s row, and only that one, as not one decision alone',
    async (name, note) => {
      const { out } = await run(['--scenario', name, '--n', '3', '--repeats', '2', '--out', 'x']);
      const lines = out.split('\n');
      expect(lines).toContain(note);
      for (const other of Object.values(NOTES).filter((line) => line !== note)) expect(lines).not.toContain(other);
    },
  );

  it('has no note for a scenario that times one decision alone, and one note for each that does not', async () => {
    const alone = await run(['--scenario', 'oneway-low', '--n', '3', '--repeats', '2', '--out', 'x']);
    for (const note of Object.values(NOTES)) expect(alone.out.split('\n')).not.toContain(note);

    const all = await run(['--n', '3', '--repeats', '2', '--out', 'x']);
    const lines = all.out.split('\n');
    for (const note of Object.values(NOTES)) expect(lines.filter((line) => line === note)).toHaveLength(1);
  });

  it.each([
    [1, 1.5, true],
    [2, 1.5, true],
    [29, 1.5, true],
    [30, 1.5, false],
    [30, -0.15, true],
    [100, 0, false],
  ])('with %i repeats and a lower end of %d the smoke line is printed: %s', async (repeats, lower, printed) => {
    vi.mocked(benchReport).mockImplementation((options) => Promise.resolve(reportOf(options, lower)));
    const { out } = await run(['--scenario', 'oneway-low', '--n', '2', '--repeats', String(repeats), '--out', 'x']);
    expect(out.split('\n').includes(SMOKE)).toBe(printed);
  });
});
