import { parseArgs } from 'node:util';
import { runHero } from '@umis/testkit';
import type { HeroStepResult } from '@umis/testkit';
import QRCode from 'qrcode';
import { EXIT, UsageError, runCommand, table } from './common.js';
import type { CommandIo } from './common.js';

export const DEMO_USAGE = `usage: umis demo [--steps 1,2,3,4] [--qr] [--json]

Runs the hero scenario on a demo world of three invented organisations: a contractor, a supplier and a coworking space.
Everything is decided in this process, on the demo's own clock, and the keys come from public seeds.

steps:
  1  Олег opens the door of the coworking space with a one-way QR code
  2  the supplier's warehouse checks the authority of Олег (10 t, accepted) and of Іван (8 t, refused for 10 t)
  3  Олег and Марія show each other their roles, one after the other
  4  Олег signs in to the contractor's intranet over OpenID4VP, answering a login QR code

options:
  --steps <list>  steps to run, comma-separated (default 1,2,3,4)
  --qr            also print the QR code that was checked in every row
  --json          print the results as JSON, with the frames, instead of a table
  -h, --help      show this text

Exit code 0 when every row is decided as the scenario expects, 2 when one is not, 64 for a mistake in the arguments.`;

type Step = 1 | 2 | 3 | 4;

function stepsOf(text: string | undefined): Step[] | undefined {
  if (text === undefined) return undefined;
  const steps = text.split(',').map((part) => {
    const step = Number(part.trim());
    if (part.trim() === '' || !Number.isInteger(step) || step < 1 || step > 4) {
      throw new UsageError('--steps takes step numbers separated by commas, for example 1,2,3,4');
    }
    return step as Step;
  });
  return steps;
}

function count(rows: number): string {
  return `${rows} ${rows === 1 ? 'result' : 'results'}`;
}

function asExpected(row: HeroStepResult): boolean {
  return (
    row.expected === undefined || (row.decision === row.expected.decision && row.reasons[0] === row.expected.reason)
  );
}

function report(rows: readonly HeroStepResult[]): string {
  const body = rows.map((row) => [
    `${row.step} ${row.name}`,
    row.actor,
    row.decision,
    row.reasons.join(', '),
    row.ms.toFixed(1),
    row.frameChars === undefined ? '' : String(row.frameChars),
  ]);
  return table(['STEP', 'ACTOR', 'DECISION', 'REASON', 'MS', 'QR CHARS'], body, new Set([4, 5]));
}

function jsonOf(rows: readonly HeroStepResult[]): string {
  const results = rows.map((row) => ({
    step: row.step,
    name: row.name,
    actor: row.actor,
    decision: row.decision,
    reason: row.reasons[0],
    reasons: row.reasons,
    ms: row.ms,
    frameChars: row.frameChars,
    frame: row.frame,
    expected: row.expected,
    asExpected: asExpected(row),
  }));
  return JSON.stringify({ ok: rows.every(asExpected), results }, null, 2);
}

/**
 * `umis demo`: runs the hero steps on the demo world and prints a row for every decision (step, actor, decision,
 * reason, milliseconds, characters of the QR text). Returns 0 when every row is as expected, 2 when one is not, 64 for
 * a mistake in the arguments.
 */
export async function demo(args: readonly string[], io: CommandIo): Promise<number> {
  return runCommand('demo', io, async () => {
    const { values } = parseArgs({
      args: [...args],
      allowPositionals: false,
      strict: true,
      options: {
        steps: { type: 'string' },
        qr: { type: 'boolean' },
        json: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
    });
    if (values.help === true) {
      io.out(DEMO_USAGE);
      return EXIT.ok;
    }
    if (values.json === true && values.qr === true)
      throw new UsageError('--json already carries the frames; drop --qr');

    const rows = await runHero({ steps: stepsOf(values.steps) });
    const ok = rows.every(asExpected);
    if (values.json === true) {
      io.out(jsonOf(rows));
      return ok ? EXIT.ok : EXIT.rejected;
    }

    io.out(report(rows));
    if (values.qr === true) {
      for (const row of rows) {
        if (row.frame === undefined) continue;
        io.out(`\n${row.step} ${row.name} · ${row.actor} · ${row.frame.length} characters`);
        io.out(await QRCode.toString(row.frame, { type: 'terminal', small: true, errorCorrectionLevel: 'L' }));
      }
    }
    const different = rows.filter((row) => !asExpected(row));
    io.out('');
    if (different.length === 0) {
      io.out(`${count(rows.length)}, all as the scenario expects`);
    } else {
      for (const row of different) {
        io.err(
          `${row.step} ${row.name}, ${row.actor}: expected ${row.expected?.decision} ${row.expected?.reason}, got ${row.decision} ${row.reasons.join(', ')}`,
        );
      }
      io.out(`${count(rows.length)}, ${different.length} not as the scenario expects`);
    }
    return ok ? EXIT.ok : EXIT.rejected;
  });
}
