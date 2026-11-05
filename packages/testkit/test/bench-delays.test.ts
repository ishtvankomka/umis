import { describe, expect, it } from 'vitest';
import { DECISION_DELAY_S } from '../src/hero.js';

describe('the decision delays of the simulated clock', () => {
  it('are 2 s at the door, 7 s for the authority check and 5 s for the login', () => {
    // seconds from the first thing made in an exchange to its decision: a scan takes 2 s and an answer 3 s. The
    // benchmark decides every presentation at its instant plus the delay of its scenario, and its protocol quotes them
    expect(DECISION_DELAY_S).toEqual({ door: 2, authority: 7, login: 5 });
  });
});
