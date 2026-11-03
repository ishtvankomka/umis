import { UmisError } from '@umis/core';

/**
 * A clock that moves only when it is told to. Every time in the SDK is an input, so a scenario that spans days runs in
 * milliseconds: the clock is the single place where "now" comes from. All values are NumericDate seconds.
 */
export interface SimClock {
  /** The current simulated time. */
  now(): number;
  /** Moves the clock forward by `seconds` (zero or more) and returns the new time. */
  advance(seconds: number): number;
  /** Puts the clock at `t`, forwards or backwards. */
  set(t: number): void;
}

function finite(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new UmisError('INVALID_ARGUMENT', `${what} must be a finite number of seconds`);
  }
  return value;
}

/** A simulated clock that starts at `start`. */
export function createSimClock(start: number): SimClock {
  let current = finite(start, 'start');
  return {
    now: () => current,
    advance(seconds) {
      const step = finite(seconds, 'seconds');
      if (step < 0)
        throw new UmisError('INVALID_ARGUMENT', 'a clock advances by zero or more seconds; use set to go back');
      current += step;
      return current;
    },
    set(t) {
      current = finite(t, 't');
    },
  };
}
