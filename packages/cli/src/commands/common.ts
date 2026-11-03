import { readFile } from 'node:fs/promises';
import { UmisError } from '@umis/core';

/**
 * Where a command writes and reads. `out` takes what the command reports and `err` warnings and mistakes; each call
 * writes one line or one block of lines. `stdin` returns what was piped into the process, or `undefined` when nothing
 * is piped (a terminal), so that a command never waits for a person to type.
 */
export interface CommandIo {
  out(line: string): void;
  err(line: string): void;
  stdin?(): Promise<string | undefined>;
}

/** A mistake in the command line or in a file it names: the command ends with exit code 64. */
export class UsageError extends Error {}

/** How a command ends: 0 for success, 2 when the answer it was asked for is no, 64 for a mistake of the caller. */
export const EXIT = { ok: 0, internal: 1, rejected: 2, usage: 64 } as const;

/** The most a command reads from standard input: a frame or a credential is a few thousand characters. */
export const MAX_INPUT_CHARS = 1_048_576;

/** True for the error `node:util` `parseArgs` throws for a command line it cannot read. */
function isArgumentError(error: unknown): error is TypeError {
  return error instanceof TypeError && 'code' in error && String(error.code).startsWith('ERR_PARSE_ARGS');
}

/**
 * Runs the body of command `name` and returns its exit code. A {@link UsageError}, a command line that `parseArgs`
 * cannot read and an INVALID_ARGUMENT from the SDK end with 64 and a pointer to `--help`; any other error ends with 1.
 */
export async function runCommand(name: string, io: CommandIo, body: () => Promise<number>): Promise<number> {
  try {
    return await body();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (
      error instanceof UsageError ||
      isArgumentError(error) ||
      (error instanceof UmisError && error.code === 'INVALID_ARGUMENT')
    ) {
      io.err(`umis ${name}: ${message}`);
      io.err(`run "umis ${name} --help" for the options`);
      return EXIT.usage;
    }
    io.err(`umis ${name}: ${message}`);
    return EXIT.internal;
  }
}

/** Reads a text file that a command line names. */
export async function readTextFile(file: string, what: string): Promise<string> {
  try {
    return await readFile(file, 'utf8');
  } catch {
    throw new UsageError(`cannot read ${what} ${file}`);
  }
}

/** Reads a JSON file that a command line names. */
export async function readJsonFile(file: string, what: string): Promise<unknown> {
  const text = await readTextFile(file, what);
  try {
    return JSON.parse(text);
  } catch {
    throw new UsageError(`${what} ${file} is not JSON`);
  }
}

/**
 * The text a command works on: the one argument it was given, or what is piped in when the argument is `-` or missing.
 * Surrounding whitespace is dropped, which is what the end of a pipe adds.
 */
export async function inputText(positionals: readonly string[], io: CommandIo, what: string): Promise<string> {
  if (positionals.length > 1) throw new UsageError(`give ${what} as one argument, or pipe it in and give -`);
  const [given] = positionals;
  if (given !== undefined && given !== '-') return given.trim();
  const piped = await io.stdin?.();
  if (piped === undefined) throw new UsageError(`give ${what} as an argument, or pipe it in and give -`);
  const text = piped.trim();
  if (text === '') throw new UsageError('nothing was piped in');
  return text;
}

/** A number of seconds since the epoch given on a command line. */
export function epochSeconds(text: string, option: string): number {
  const value = Number(text);
  if (text.trim() === '' || !Number.isFinite(value) || value < 0) {
    throw new UsageError(`${option} takes a time in seconds since 1970-01-01, for example 1793606400`);
  }
  return value;
}

/** Left-aligned columns, except those in `right`, separated by two spaces. */
export function table(header: readonly string[], rows: readonly string[][], right: ReadonlySet<number>): string {
  const widths = header.map((title, column) => Math.max(title.length, ...rows.map((row) => row[column]?.length ?? 0)));
  const line = (cells: readonly string[]): string =>
    cells
      .map((cell, column) =>
        right.has(column) ? cell.padStart(widths[column] ?? 0) : cell.padEnd(widths[column] ?? 0),
      )
      .join('  ')
      .trimEnd();
  return [line(header), line(widths.map((width) => '-'.repeat(width))), ...rows.map(line)].join('\n');
}
