#!/usr/bin/env node
import { bench } from './commands/bench.js';
import { MAX_INPUT_CHARS, UsageError } from './commands/common.js';
import type { CommandIo } from './commands/common.js';
import { demo } from './commands/demo.js';
import { inspect } from './commands/inspect.js';
import { keygen } from './commands/keygen.js';
import { relayEmu } from './commands/relay-emu.js';
import { verify } from './commands/verify.js';

interface Command {
  summary: string;
  run(args: readonly string[], io: CommandIo, signal: AbortSignal): Promise<number>;
}

/** The commands of the tool, by name. */
const COMMANDS: Readonly<Record<string, Command>> = {
  demo: {
    summary: 'run the four steps of the hero scenario on a demo world, in this process',
    run: demo,
  },
  verify: {
    summary: 'decide whether a QR frame is accepted at a checkpoint (a demo or a saved context)',
    run: verify,
  },
  inspect: {
    summary: 'tell what a QR text, link or token is and decode it, without verifying',
    run: inspect,
  },
  keygen: {
    summary: 'make a P-256 signing key pair and print its public key and fingerprint',
    run: keygen,
  },
  'relay-emu': {
    summary: 'run an emulator of a Shelly Gen3 relay that obeys signed relay commands',
    run: relayEmu,
  },
  bench: {
    summary: 'measure the decision latency of the verifier and play the autonomy and revocation timelines',
    run: bench,
  },
};

function usage(): string {
  const width = Math.max(...Object.keys(COMMANDS).map((name) => name.length));
  return [
    'usage: umis <command> [options]',
    '',
    'commands:',
    ...Object.entries(COMMANDS).map(([name, command]) => `  ${name.padEnd(width)}  ${command.summary}`),
    '',
    'Run "umis <command> --help" for the options of a command.',
  ].join('\n');
}

/** Runs the command named first in `argv` and returns the exit code: 64 for a missing or unknown command. */
async function dispatch(argv: readonly string[], io: CommandIo, signal: AbortSignal): Promise<number> {
  const [name, ...rest] = argv;
  if (name === '--help' || name === '-h' || name === 'help') {
    io.out(usage());
    return 0;
  }
  if (name === undefined) {
    io.err(usage());
    return 64;
  }
  const command = Object.hasOwn(COMMANDS, name) ? COMMANDS[name] : undefined;
  if (command === undefined) {
    io.err(`umis: unknown command "${name.slice(0, 64)}"`);
    io.err(usage());
    return 64;
  }
  return command.run(rest, io, signal);
}

const stop = new AbortController();
process.once('SIGINT', () => stop.abort());
process.once('SIGTERM', () => stop.abort());

/** What was piped into the process, or `undefined` for a terminal, where nobody has piped anything. */
async function readStdin(): Promise<string | undefined> {
  if (process.stdin.isTTY) return undefined;
  process.stdin.setEncoding('utf8');
  let text = '';
  for await (const chunk of process.stdin) {
    text += chunk;
    if (text.length > MAX_INPUT_CHARS) throw new UsageError('the input piped in is longer than 1 MiB');
  }
  return text;
}

const io: CommandIo = {
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
  stdin: readStdin,
};

try {
  process.exitCode = await dispatch(process.argv.slice(2), io, stop.signal);
} catch (error) {
  io.err(`umis: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
