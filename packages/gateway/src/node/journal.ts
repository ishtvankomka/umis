import { mkdir, open, readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { UmisError, createMemoryJournal, verifyJournal } from '@umis/core';
import type { DecisionEventV1, Journal, JournalEntry } from '@umis/core';

type Verdict = { ok: true } | { ok: false; index: number };

/** The lines of the file as parsed JSON; a line that is not JSON stands as `null`, which no entry can be. */
async function readLines(path: string): Promise<unknown[]> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines.map((line) => {
    try {
      return JSON.parse(line) as unknown;
    } catch {
      return null;
    }
  });
}

/**
 * A decision journal in a file, one JSON object per line: `{"event":…,"prevHash":…,"hash":…}`. Each entry is chained to
 * the one before it by SHA-256 over the canonical form of its event (the chain of `createMemoryJournal`), so a line that
 * is edited, removed or moved breaks the chain from there on. `append` needs the next `seq` (1 for the first event,
 * one more than the last after that); appends are carried out one at a time. `verify` reads the file as it is on disk
 * and returns `{ok: true}` or the index of the first entry that breaks the chain. The file and its folder are created
 * when needed.
 *
 * Three guarantees hold: the file is created with mode 0600 (its owner alone may read and write it); every append is
 * synced to disk (`datasync`) before the call returns; and a file that does not verify makes `append` fail with
 * PROTOCOL and is never extended.
 */
export function createFileJournal(path: string): {
  append(e: DecisionEventV1): Promise<JournalEntry>;
  verify(): Promise<Verdict>;
} {
  if (typeof path !== 'string' || path === '')
    throw new UmisError('INVALID_ARGUMENT', 'path must name the journal file');

  let queue: Promise<unknown> = Promise.resolve();
  /** The chain as read from the file; it follows the file for as long as every append succeeds. */
  let chain: Journal | undefined;

  const inTurn = <T>(task: () => Promise<T>): Promise<T> => {
    const result = queue.then(task, task);
    queue = result.catch(() => undefined);
    return result;
  };

  async function load(): Promise<Journal> {
    const entries = (await readLines(path)) as JournalEntry[];
    const verdict = verifyJournal(entries);
    if (!verdict.ok) {
      throw new UmisError('PROTOCOL', `the journal file does not verify at entry ${verdict.index} and is not extended`);
    }
    const journal = createMemoryJournal();
    for (const entry of entries) journal.append(entry.event);
    return journal;
  }

  return {
    append(e) {
      return inTurn(async () => {
        chain ??= await load();
        const entry = chain.append(e);
        const line = `${JSON.stringify({ event: entry.event, prevHash: entry.prevHash, hash: entry.hash })}\n`;
        try {
          await mkdir(dirname(path), { recursive: true });
          const file = await open(path, 'a', 0o600);
          try {
            await file.appendFile(line);
            await file.datasync();
          } finally {
            await file.close();
          }
        } catch (error) {
          chain = undefined; // the chain in memory is ahead of the file: read the file again next time
          throw error;
        }
        return entry;
      });
    },
    verify() {
      return inTurn(async () => verifyJournal((await readLines(path)) as JournalEntry[]));
    },
  };
}
