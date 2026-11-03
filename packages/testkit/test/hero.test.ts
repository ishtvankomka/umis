import { LIMITS } from '@umis/core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { authorityCheck } from '../src/hero.js';
import { createDemoWorld, runHero } from '../src/index.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('runHero', () => {
  it('decides steps 1 to 3 as the scenario says, without touching the network', async () => {
    // I-20: an offline decision opens no connection, so a fetch that is used fails the run
    const fetchStub = vi.fn(() => {
      throw new Error('the network is not available to the demo');
    });
    vi.stubGlobal('fetch', fetchStub);

    const rows = await runHero({ steps: [1, 2, 3] });

    expect(rows.map((row) => [row.step, row.name, row.actor, row.decision, row.reasons])).toEqual([
      [1, 'Access', 'Олег Бондар → Коворкінг В', 'accept', ['OK']],
      [2, 'Authority check', 'Олег Бондар → Постачальник Б', 'accept', ['OK']],
      [2, 'Authority check', 'Іван Мельник → Постачальник Б', 'reject', ['AUTHORITY_LIMIT_EXCEEDED']],
      [3, 'Mutual exchange', 'Олег Бондар → Постачальник Б', 'accept', ['OK']],
      [3, 'Mutual exchange', 'Марія Коваль → Підрядник А', 'accept', ['OK']],
    ]);
    expect(fetchStub).not.toHaveBeenCalled();

    // every frame fits a QR code, and the rows say what they expected
    for (const row of rows) {
      expect(row.frameChars).toBe(row.frame?.length);
      expect(row.frameChars).toBeGreaterThan(0);
      expect(row.frameChars).toBeLessThanOrEqual(LIMITS.qrMaxChars);
      expect(row.frame).toMatch(/^UMIS1[A-Z]:/);
      expect(row.ms).toBeGreaterThanOrEqual(0);
      expect({ decision: row.decision, reason: row.reasons[0] }).toEqual(row.expected);
    }
  });

  it('gives the same frames on every run', async () => {
    const first = await runHero();
    const second = await runHero();
    expect(second.map((row) => row.frame)).toEqual(first.map((row) => row.frame));
  });

  it('runs the steps asked for in their own order, and refuses a step it does not have', async () => {
    const rows = await runHero({ steps: [3, 1, 3] });
    expect(rows.map((row) => row.step)).toEqual([1, 3, 3]);
    await expect(runHero({ steps: [4] })).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });
});

describe('the authority check of the warehouse', () => {
  it('accepts up to the limit of the holder and refuses above it', async () => {
    // Олег holds 10 t per shift, Іван 8 t delegated from him
    const cases = [
      ['oleg', 10, 'accept', 'OK'],
      ['oleg', 11, 'reject', 'AUTHORITY_LIMIT_EXCEEDED'],
      ['ivan', 8, 'accept', 'OK'],
      ['ivan', 9, 'reject', 'AUTHORITY_LIMIT_EXCEEDED'],
    ] as const;
    for (const [holder, amount, decision, reason] of cases) {
      const world = await createDemoWorld();
      const { result } = await authorityCheck(world, { holder, amount });
      expect([holder, amount, result.decision, result.reasons]).toEqual([holder, amount, decision, [reason]]);
    }
  });
});
