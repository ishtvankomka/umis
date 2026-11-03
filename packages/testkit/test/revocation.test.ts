import { decodeCredential } from '@umis/core';
import type { VerificationResult } from '@umis/core';
import { DEFAULT_POLICIES } from '@umis/policy';
import { describe, expect, it } from 'vitest';
import { authorityCheck, credentialOf } from '../src/hero.js';
import { createDemoWorld } from '../src/index.js';
import type { DemoWorld } from '../src/index.js';

const HOUR = 3600;
const START = 1_793_606_400;
const REFRESH = 600; // Δ of the online policies

const outcome = (result: VerificationResult): [string, string[]] => [result.decision, result.reasons];

/** `holder` answers a request for `amount` tonnes at `at` seconds after the start of the world. */
async function askAt(world: DemoWorld, at: number, holder: 'oleg' | 'ivan', amount: number) {
  world.clock.set(START + at);
  return outcome((await authorityCheck(world, { holder, amount })).result);
}

describe('revocation', () => {
  it('reaches an online verifier at the next refresh and an offline one when its list is too old', async () => {
    // The world is deterministic, so a second one is the same world: it plays the checkpoint that never receives the
    // list published after the revocation, while the first one plays the checkpoint that does.
    const online = await createDemoWorld();
    const offline = await createDemoWorld();
    expect(offline.statusLists()).toEqual(online.statusLists());
    expect(DEFAULT_POLICIES.warehouse_medium.maxStatusAgeSeconds).toBe(24 * HOUR);

    expect(await askAt(online, 60, 'ivan', 8)).toEqual(['accept', ['OK']]);

    // revoke Іван, and publish the lists Δ later
    online.revoke(decodeCredential(credentialOf(online, 'ivan', 'delegated')).jti);
    online.clock.set(START + REFRESH);
    await online.publish();

    expect(await askAt(online, REFRESH, 'ivan', 8)).toEqual(['reject', ['STATUS_REVOKED']]);
    expect(await askAt(online, REFRESH, 'oleg', 10)).toEqual(['accept', ['OK']]);

    // the checkpoint that holds the old list keeps accepting while the list is younger than S (24 h at this policy) ...
    expect(await askAt(offline, REFRESH, 'ivan', 8)).toEqual(['accept', ['OK']]);
    expect(await askAt(offline, 23 * HOUR, 'ivan', 8)).toEqual(['accept', ['OK']]);
    // ... and stops accepting once it is older
    expect(await askAt(offline, 25 * HOUR, 'ivan', 8)).toEqual(['reject', ['STATUS_LIST_STALE']]);
    expect(await askAt(offline, 25 * HOUR, 'oleg', 10)).toEqual(['reject', ['STATUS_LIST_STALE']]);
  });

  it('takes the credentials delegated from a revoked one with it', async () => {
    const world = await createDemoWorld();
    world.revoke(decodeCredential(credentialOf(world, 'oleg', 'roleAuthority')).jti);
    world.clock.set(START + REFRESH);
    await world.publish();

    expect(await askAt(world, REFRESH, 'ivan', 8)).toEqual(['reject', ['STATUS_REVOKED']]);
    expect(await askAt(world, REFRESH, 'oleg', 10)).toEqual(['reject', ['STATUS_REVOKED']]);
  });

  it('knows only the credentials it issued, and revoked or suspended as statuses', async () => {
    const world = await createDemoWorld();
    expect(() => world.revoke('not-a-credential')).toThrow(/no credential/);
    expect(() => world.revoke(decodeCredential(credentialOf(world, 'ivan', 'delegated')).jti, 3 as 1)).toThrow(
      /revoked.*suspended/,
    );
  });
});
