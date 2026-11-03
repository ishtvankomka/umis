import { DEFAULT_POLICIES } from '@umis/policy';
import { verifyAtCheckpoint } from '@umis/verifier';
import { createOneWayQr } from '@umis/wallet';
import { describe, expect, it } from 'vitest';
import { credentialOf } from '../src/hero.js';
import { createDemoWorld } from '../src/index.js';
import type { DemoWorld } from '../src/index.js';

const HOUR = 3600;
const START = 1_793_606_400;

/** The door of Коворкінг В reads a one-way QR code that Олег shows `after` seconds after the lists were published. */
async function doorAfter(world: DemoWorld, after: number) {
  world.clock.set(START + after);
  const frame = await createOneWayQr({
    sdJwtVc: credentialOf(world, 'oleg', 'coworkingMember'),
    signer: world.people.oleg.holder,
    now: world.clock.now(),
    ctr: 1,
  });
  const result = await verifyAtCheckpoint(frame, world.context({ org: 'kovorking-v', policy: 'door_low' }));
  return [result.decision, result.reasons];
}

describe('autonomy of a checkpoint without a connection', () => {
  it('lets the door decide for 72 hours on the list it holds, to the second', async () => {
    const world = await createDemoWorld();
    expect(DEFAULT_POLICIES.door_low.maxStatusAgeSeconds).toBe(72 * HOUR);

    expect(await doorAfter(world, 71 * HOUR)).toEqual(['accept', ['OK']]);
    // I-7: an age equal to S passes, and one second more does not
    expect(await doorAfter(world, 72 * HOUR)).toEqual(['accept', ['OK']]);
    expect(await doorAfter(world, 72 * HOUR + 1)).toEqual(['reject', ['STATUS_LIST_STALE']]);
    expect(await doorAfter(world, 73 * HOUR)).toEqual(['reject', ['STATUS_LIST_STALE']]);
  });

  it('counts the age from the newest list the door holds', async () => {
    const world = await createDemoWorld();
    expect(await doorAfter(world, 73 * HOUR)).toEqual(['reject', ['STATUS_LIST_STALE']]);

    // lists published again at +72 h make the door accept at +73 h
    world.clock.set(START + 72 * HOUR);
    await world.publish();
    expect(await doorAfter(world, 73 * HOUR)).toEqual(['accept', ['OK']]);
  });
});
