#!/usr/bin/env node
import { relayEmu } from './commands/relay-emu.js';
import type { CommandIo } from './commands/relay-emu.js';

interface Command {
  summary: string;
  run(args: readonly string[], io: CommandIo, signal: AbortSignal): Promise<number>;
}

/** The commands of the tool, by name. */
const COMMANDS: Readonly<Record<string, Command>> = {
  'relay-emu': {
    summary: 'run an emulator of a Shelly Gen3 relay that obeys signed relay commands',
    run: relayEmu,
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

const io: CommandIo = {
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
};

try {
  process.exitCode = await dispatch(process.argv.slice(2), io, stop.signal);
} catch (error) {
  io.err(`umis: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
