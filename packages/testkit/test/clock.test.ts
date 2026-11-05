import { describe, expect, it } from 'vitest';
import { createSimClock } from '../src/clock.js';

const INVALID = expect.objectContaining({ code: 'INVALID_ARGUMENT' });

describe('the simulated clock', () => {
  it('starts at the time it is given and moves forward, and advance returns the new time', () => {
    const clock = createSimClock(1_000);
    expect(clock.now()).toBe(1_000);
    expect(clock.advance(2)).toBe(1_002);
    expect(clock.now()).toBe(1_002);
    expect(clock.advance(0)).toBe(1_002);
    expect(clock.advance(0.5)).toBe(1_002.5);
    expect(clock.now()).toBe(1_002.5);
  });

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, '2' as unknown as number])(
    'does not advance by %s: INVALID_ARGUMENT, and the time stays where it was',
    (step) => {
      const clock = createSimClock(500);
      clock.advance(10);
      expect(() => clock.advance(step)).toThrow(INVALID);
      expect(clock.now()).toBe(510);
    },
  );

  it('is put anywhere with set, backwards as well, and set refuses what is not a finite time', () => {
    const clock = createSimClock(1_000);
    clock.advance(60);
    clock.set(1_000);
    expect(clock.now()).toBe(1_000);
    clock.set(10);
    expect(clock.now()).toBe(10);

    expect(() => clock.set(Number.NaN)).toThrow(INVALID);
    expect(() => clock.set(Number.POSITIVE_INFINITY)).toThrow(INVALID);
    expect(clock.now()).toBe(10);
  });

  it('refuses a start that is not a finite number', () => {
    expect(() => createSimClock(Number.NaN)).toThrow(INVALID);
    expect(() => createSimClock(Number.POSITIVE_INFINITY)).toThrow(INVALID);
  });
});
