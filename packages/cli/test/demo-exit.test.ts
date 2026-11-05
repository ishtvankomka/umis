import { runHero } from '@umis/testkit';
import type { HeroStepResult } from '@umis/testkit';
import { describe, expect, it, vi } from 'vitest';
import { demo } from '../src/commands/demo.js';

// The rows of the hero scenario are made up here, so that a row can come out other than the scenario expects.
vi.mock('@umis/testkit', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@umis/testkit')>()),
  runHero: vi.fn(),
}));

const row = (over: Partial<HeroStepResult>): HeroStepResult => ({
  step: 2,
  name: 'Authority check',
  actor: 'Іван → Постачальник Б',
  decision: 'accept',
  reasons: ['OK'],
  ms: 1.5,
  ...over,
});

async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await demo(args, { out: (line) => out.push(line), err: (line) => err.push(line) });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

describe('umis demo: exit code 2', () => {
  it('ends with 2 when a row is not decided as the scenario expects, and says which', async () => {
    vi.mocked(runHero).mockResolvedValue([
      row({ step: 1, name: 'Access', expected: { decision: 'accept', reason: 'OK' } }),
      row({ expected: { decision: 'reject', reason: 'AUTHORITY_LIMIT_EXCEEDED' } }),
    ]);
    const table = await run([]);
    expect(table.code).toBe(2);
    expect(table.out).toContain('1 not as the scenario expects');
    expect(table.err).toContain('expected reject AUTHORITY_LIMIT_EXCEEDED, got accept OK');

    const json = await run(['--json']);
    expect(json.code).toBe(2);
    const parsed = JSON.parse(json.out) as { ok: boolean; results: Array<{ asExpected: boolean }> };
    expect(parsed.ok).toBe(false);
    expect(parsed.results.map((result) => result.asExpected)).toEqual([true, false]);
  });

  it('ends with 0 when every row is as expected or expects nothing', async () => {
    vi.mocked(runHero).mockResolvedValue([
      row({ step: 1, name: 'Access', expected: { decision: 'accept', reason: 'OK' } }),
      row({ decision: 'reject', reasons: ['AUTHORITY_LIMIT_EXCEEDED'] }),
    ]);
    expect((await run([])).code).toBe(0);
    expect((await run(['--json'])).code).toBe(0);
  });
});
