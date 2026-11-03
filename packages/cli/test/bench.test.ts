import { spawn } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bench } from '../src/commands/bench.js';

const BIN = fileURLToPath(new URL('../dist/bin.js', import.meta.url));

let folder: string;
beforeAll(async () => {
  folder = await mkdtemp(join(tmpdir(), 'umis-cli-bench-'));
});
afterAll(async () => {
  await rm(folder, { recursive: true, force: true });
});

/** Runs the command inside this process. */
async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await bench(args, { out: (line) => out.push(line), err: (line) => err.push(line) });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

describe('umis bench', () => {
  it('measures the scenarios asked for, prints a table and writes the files', async () => {
    const out = join(folder, 'run');
    const frames = join(folder, 'door.json');
    const {
      code,
      out: shown,
      err,
    } = await run([
      ...['--scenario', 'oneway-low,oid4vp'],
      ...['--n', '20', '--repeats', '2', '--warmup', '1'],
      ...['--crypto', 'webcrypto', '--seed', 'cli-test', '--out', out, '--emit-frames', frames],
    ]);
    expect(code).toBe(0);

    // the table: one row per scenario, with the columns of the thesis
    const lines = shown.split('\n');
    expect(lines[0]).toBe(
      'decision latency in milliseconds: 20 presentations in each of 2 repeats, 1 warm-up, crypto webcrypto, seed cli-test',
    );
    expect(lines[1]?.split(/\s+/)).toEqual([
      ...['SCENARIO', 'EXPECTED', 'P50', 'P95', 'P95', 'CI95', 'P99', 'MEAN', 'SD', 'MAX'],
      ...['QR', 'CHARS', 'MISMATCH', 'NFR-P1'],
    ]);
    const rows = lines.filter((line) => /^(oneway-low|oid4vp) /.test(line)).map((line) => line.split(/\s+/));
    expect(rows.map((row) => row.slice(0, 2))).toEqual([
      ['oneway-low', 'accept'],
      ['oid4vp', 'accept'],
    ]);
    for (const row of rows) {
      expect(row.at(-1)).toBe('met');
      expect(row.at(-2)).toBe('0');
    }
    expect(shown).toContain('autonomy low: 961 presentations over 80 h');
    expect(shown).toContain('STATUS_LIST_STALE from 259201 s: exactly at S + 1 s');
    expect(shown).toContain('autonomy medium: 361 presentations over 30 h');
    expect(shown).toContain('revocation: online 599 s after the revocation (bound Δ = 600 s), offline 86400 s');
    expect(shown).toContain(`results in ${out}`);
    expect(lines.at(-1)).toBe('2 scenarios, every presentation as expected, NFR-P1 met by all');

    // progress goes to standard error, so that the table can be piped
    expect(err.split('\n')[0]).toBe('· oneway-low: 1 warm-up and 2 repeats of 20 presentations');
    expect(shown).not.toContain('· ');

    expect((await readdir(out)).sort()).toEqual([
      'autonomy-low.csv',
      'autonomy-medium.csv',
      'env.json',
      'revocation.csv',
      'samples-oid4vp.csv',
      'samples-oneway-low.csv',
      'sizes.csv',
      'steps-oid4vp.csv',
      'steps-oneway-low.csv',
      'summary.json',
    ]);
    const summary = JSON.parse(await readFile(join(out, 'summary.json'), 'utf8')) as {
      ok: boolean;
      scenarios: Array<{ scenario: string; n: number; repeats: number }>;
    };
    expect(summary.ok).toBe(true);
    expect(summary.scenarios.map((row) => [row.scenario, row.n, row.repeats])).toEqual([
      ['oneway-low', 20, 2],
      ['oid4vp', 20, 2],
    ]);
    const env = JSON.parse(await readFile(join(out, 'env.json'), 'utf8')) as { options: { seed: string } };
    expect(env.options.seed).toBe('cli-test');
    expect(JSON.parse(await readFile(frames, 'utf8'))).toMatchObject({ v: 1 });

    // results are not overwritten: not the folder, and not the replay file
    const again = await run(['--n', '5', '--repeats', '1', '--out', out]);
    expect(again.code).toBe(64);
    expect(again.err).toContain('holds files already');
    const clash = await run(['--n', '5', '--repeats', '1', '--out', join(folder, 'other'), '--emit-frames', frames]);
    expect(clash.code).toBe(64);
    expect(clash.err).toContain('exists already');
    expect(await readdir(folder)).not.toContain('other');
  }, 120_000);

  it('prints its usage', async () => {
    const { code, out } = await run(['--help']);
    expect(code).toBe(0);
    expect(out).toContain('usage: umis bench');
    for (const name of ['oneway-low', 'full-qr-low', 's1-accept', 's1-reject', 'mutual', 'oid4vp', 'gateway']) {
      expect(out).toContain(name);
    }
  });

  it('ends with 64 for a mistake in the arguments', async () => {
    const out = join(folder, 'mistakes');
    const cases: string[][] = [
      ['--scenario', 'nowhere'],
      ['--scenario', 'oneway-low,'],
      ['--n', 'many'],
      ['--n', '1.5'],
      ['--n', '-1'],
      ['--n', '0'], // the SDK refuses it
      ['--repeats', '0'],
      ['--crypto', 'md5'],
      ['--seed', ''],
      ['now'],
      ['--bogus'],
    ];
    for (const args of cases) {
      const result = await run([...args, '--out', out]);
      expect(result.code, args.join(' ')).toBe(64);
      expect(result.err).toContain('umis bench');
    }
    expect(await readdir(folder)).not.toContain('mistakes');
  });

  it('is part of the built tool', async () => {
    const run2 = (args: string[]) =>
      new Promise<{ status: number | null; stdout: string }>((resolve, reject) => {
        const child = spawn(process.execPath, [BIN, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
        let stdout = '';
        child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
        child.once('error', reject);
        child.once('close', (status) => resolve({ status, stdout }));
      });
    const help = await run2(['bench', '--help']);
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('usage: umis bench');
    expect((await run2(['--help'])).stdout).toContain('bench');
  }, 30_000);
});
