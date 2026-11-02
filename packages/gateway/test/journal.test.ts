import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DecisionEventV1 } from '@umis/core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createFileJournal } from '../src/node/index.js';

const event = (seq: number, over: Partial<DecisionEventV1> = {}): DecisionEventV1 => ({
  iss: 'urn:umis:verifier:door-1',
  seq,
  iat: 1_793_754_000 + seq,
  chk: 'urn:umis:checkpoint:door-1',
  ch: 'qr_oneway',
  dec: 'accept',
  rsn: ['OK'],
  lat: 3.5,
  ...over,
});

let folder: string;
let path: string;
beforeEach(async () => {
  folder = await mkdtemp(join(tmpdir(), 'umis-journal-'));
  path = join(folder, 'decisions.jsonl');
});
afterEach(async () => {
  await rm(folder, { recursive: true, force: true });
});

const lines = async (): Promise<string[]> => (await readFile(path, 'utf8')).trimEnd().split('\n');

describe('file journal: a JSONL hash chain', () => {
  it('chains three events and verifies them; an edited line fails at its own index', async () => {
    const journal = createFileJournal(path);
    expect(await journal.verify()).toEqual({ ok: true }); // no file yet: an empty journal
    const first = await journal.append(event(1));
    const second = await journal.append(event(2, { dec: 'reject', rsn: ['REPLAY'] }));
    const third = await journal.append(event(3));
    expect(first.prevHash).toBe('0'.repeat(64));
    expect(second.prevHash).toBe(first.hash);
    expect(third.prevHash).toBe(second.hash);
    expect(await journal.verify()).toEqual({ ok: true });

    const written = await lines();
    expect(written).toHaveLength(3);
    expect(JSON.parse(written[1]!)).toEqual({
      event: event(2, { dec: 'reject', rsn: ['REPLAY'] }),
      prevHash: first.hash,
      hash: second.hash,
    });

    // someone turns the rejection of entry 1 into an accept
    written[1] = written[1]!.replace('"dec":"reject"', '"dec":"accept"').replace('"rsn":["REPLAY"]', '"rsn":["OK"]');
    await writeFile(path, `${written.join('\n')}\n`);
    expect(await journal.verify()).toEqual({ ok: false, index: 1 });
  });

  it('detects a removed line, a swapped pair and a line that is not JSON', async () => {
    const journal = createFileJournal(path);
    for (const seq of [1, 2, 3, 4]) await journal.append(event(seq));
    const original = await lines();

    await writeFile(path, `${[original[0], original[2], original[3]].join('\n')}\n`);
    expect(await journal.verify()).toEqual({ ok: false, index: 1 });
    await writeFile(path, `${[original[0], original[2], original[1], original[3]].join('\n')}\n`);
    expect(await journal.verify()).toEqual({ ok: false, index: 1 });
    await writeFile(path, `${[original[0], original[1], '{"event":', original[3]].join('\n')}\n`);
    expect(await journal.verify()).toEqual({ ok: false, index: 2 });
    await writeFile(path, `${original.join('\n')}\n`);
    expect(await journal.verify()).toEqual({ ok: true });
  });

  it('goes on from the file after a restart, in order, and never extends a file that does not verify', async () => {
    await createFileJournal(path).append(event(1));
    const restarted = createFileJournal(path);
    await expect(restarted.append(event(1))).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' }); // seq must follow
    const entry = await restarted.append(event(2));
    expect(entry.prevHash).toBe(JSON.parse((await lines())[0]!).hash);

    // concurrent appends are written one after the other
    const racing = createFileJournal(join(folder, 'racing.jsonl'));
    await Promise.all([1, 2, 3, 4, 5].map((seq) => racing.append(event(seq))));
    expect(await racing.verify()).toEqual({ ok: true });

    const damaged = (await lines()).map((line) => line.replace('"lat":3.5', '"lat":0.5'));
    await writeFile(path, `${damaged.join('\n')}\n`);
    await expect(createFileJournal(path).append(event(3))).rejects.toMatchObject({ code: 'PROTOCOL' });
    expect(await lines()).toHaveLength(2);
  });
});
