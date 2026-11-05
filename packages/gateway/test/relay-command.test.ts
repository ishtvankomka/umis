import { createHash } from 'node:crypto';
import { TYP, base64urlEncode, decodeJwsUnverified, generateSigner, signJws, utf8Encode } from '@umis/core';
import type { EcPublicJwk, ReplayStore, Signer } from '@umis/core';
import { createMemoryReplayStore } from '@umis/verifier';
import { beforeAll, describe, expect, it } from 'vitest';
import { shellySwitchSetBody, signRelayCommand, verifyRelayCommand } from '../src/index.js';

const NOW = 1_793_750_400;
const RELAY = 'http://127.0.0.1:8089';
const BODY = shellySwitchSetBody({ rpcId: 1, switchId: 0, on: true, toggleAfter: 3, src: 'umis-station-7' });

/** SHA-256 of the UTF-8 body as base64url, computed by Node itself rather than by the code under test. */
const bodyHash = (body: string): string => createHash('sha256').update(body, 'utf8').digest('base64url');

let station: Signer;
let other: Signer;
beforeAll(async () => {
  [station, other] = await Promise.all([generateSigner(), generateSigner()]);
});

function checks(over: Partial<Parameters<typeof verifyRelayCommand>[2]> = {}) {
  return { keys: [station.publicJwk], audiences: [RELAY], now: NOW, replay: createMemoryReplayStore(), ...over };
}

/** A command signed with the claims given, whatever the rules say, for the cases that signRelayCommand refuses to make. */
async function forged(claims: Record<string, unknown>, signer = station, typ: string = TYP.relayCommand) {
  const payload = { aud: RELAY, iat: NOW, exp: NOW + 10, jti: 'forged-jti', bh: bodyHash(BODY), ...claims };
  return signJws({ header: { typ }, payload, signer });
}

/** A command put together segment by segment, for headers that signJws never writes (another alg, no kid at all). */
async function assembled(header: object, payload: object, signer: Signer): Promise<string> {
  const segment = (value: object): string => base64urlEncode(utf8Encode(JSON.stringify(value)));
  const input = `${segment(header)}.${segment(payload)}`;
  return `${input}.${base64urlEncode(await signer.sign(utf8Encode(input)))}`;
}

/** The public key of a signer without its key id. */
function withoutKid(signer: Signer): EcPublicJwk {
  const jwk = { ...signer.publicJwk };
  delete jwk.kid;
  return jwk;
}

describe('relay command: signed, bound to the body, used once', () => {
  it('signs and verifies a command for one body, with the lifetime and identifiers of the profile', async () => {
    const jws = await signRelayCommand({
      signer: station,
      relayAud: RELAY,
      body: BODY,
      now: NOW,
      iss: 'umis-station-7',
    });
    const verdict = await verifyRelayCommand(jws, BODY, checks());
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;
    expect(verdict.payload).toMatchObject({
      iss: 'umis-station-7',
      aud: RELAY,
      iat: NOW,
      exp: NOW + 10,
      bh: bodyHash(BODY),
    });
    expect(verdict.payload.jti).toMatch(/^[A-Za-z0-9_-]{22}$/); // 16 random bytes

    const header = JSON.parse(atob(jws.split('.')[0]!.replaceAll('-', '+').replaceAll('_', '/')));
    expect(header).toMatchObject({ alg: 'ES256', typ: 'umis-relay-cmd+jwt' });
    // the lifetime is the signer's choice up to 30 s
    const long = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW, ttlSeconds: 30 });
    expect((await verifyRelayCommand(long, BODY, checks())).ok).toBe(true);
    await expect(
      signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW, ttlSeconds: 31 }),
    ).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
  });

  it('rejects a body that differs from the signed one by a single byte', async () => {
    const jws = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    const changed = BODY.replace('"toggle_after":3', '"toggle_after":9');
    expect(changed).toHaveLength(BODY.length);
    expect(await verifyRelayCommand(jws, changed, checks())).toEqual({ ok: false, reason: 'SIGNATURE_INVALID' });
    // whitespace is a byte too
    expect(await verifyRelayCommand(jws, `${BODY} `, checks())).toEqual({ ok: false, reason: 'SIGNATURE_INVALID' });
    expect((await verifyRelayCommand(jws, BODY, checks())).ok).toBe(true);
  });

  it('accepts a command once: the same one again is a replay, and a refused one is not used up', async () => {
    const replay = createMemoryReplayStore();
    const jws = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    // refused for its audience: this does not spend the jti
    expect(await verifyRelayCommand(jws, BODY, checks({ replay, audiences: ['http://other.example'] }))).toEqual({
      ok: false,
      reason: 'AUDIENCE_MISMATCH',
    });
    expect((await verifyRelayCommand(jws, BODY, checks({ replay }))).ok).toBe(true);
    expect(await verifyRelayCommand(jws, BODY, checks({ replay }))).toEqual({ ok: false, reason: 'REPLAY' });
    // another command for the same body is another command
    const next = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    expect((await verifyRelayCommand(next, BODY, checks({ replay }))).ok).toBe(true);

    // the store is asked once, for relay:<jti> until exp + skew, and only after every other check has passed
    const calls: Array<[string, number]> = [];
    const recorder: ReplayStore = {
      checkAndRemember: async (id, expiresAt) => {
        calls.push([id, expiresAt]);
        return true;
      },
    };
    const fresh = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    const elsewhere = checks({ replay: recorder, audiences: ['http://other.example'] });
    expect(await verifyRelayCommand(fresh, BODY, elsewhere)).toEqual({ ok: false, reason: 'AUDIENCE_MISMATCH' });
    expect(calls).toEqual([]);
    const verdict = await verifyRelayCommand(fresh, BODY, checks({ replay: recorder, skewSeconds: 7 }));
    if (!verdict.ok) throw new Error(`the command was refused: ${verdict.reason}`);
    expect(calls).toEqual([[`relay:${verdict.payload.jti}`, verdict.payload.exp + 7]]);
  });

  it('lets a replay store without a clock of its own forget the commands that have expired', async () => {
    // a full store that is never told the time keeps every id and refuses the next command as a replay
    const replay = createMemoryReplayStore({ max: 3 });
    for (let n = 0; n < 3; n += 1) {
      const jws = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
      expect((await verifyRelayCommand(jws, BODY, checks({ replay }))).ok).toBe(true);
    }
    expect(replay.size()).toBe(3);
    // at NOW + 100 the three ids are past exp + skew (NOW + 20): the verification tells the store, which forgets them
    const fourth = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW + 100 });
    expect(await verifyRelayCommand(fourth, BODY, checks({ replay, now: NOW + 100 }))).toMatchObject({ ok: true });
    expect(replay.size()).toBe(1);

    // a store with a clock of its own keeps working by that clock
    let clock = NOW;
    const timed = createMemoryReplayStore({ max: 3, now: () => clock });
    for (let n = 0; n < 3; n += 1) {
      const jws = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
      expect((await verifyRelayCommand(jws, BODY, checks({ replay: timed }))).ok).toBe(true);
    }
    clock = NOW + 100;
    const next = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW + 100 });
    expect(await verifyRelayCommand(next, BODY, checks({ replay: timed, now: NOW + 100 }))).toMatchObject({ ok: true });
    expect(timed.size()).toBe(1);
  });

  it('accepts the relay it names and no other', async () => {
    const jws = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    expect(await verifyRelayCommand(jws, BODY, checks({ audiences: ['http://127.0.0.1:8090'] }))).toEqual({
      ok: false,
      reason: 'AUDIENCE_MISMATCH',
    });
    expect(await verifyRelayCommand(jws, BODY, checks({ audiences: [] }))).toEqual({
      ok: false,
      reason: 'AUDIENCE_MISMATCH',
    });
    expect((await verifyRelayCommand(jws, BODY, checks({ audiences: ['urn:umis:relay:emu', RELAY] }))).ok).toBe(true);
  });

  it('allows a lifetime of 30 seconds and rejects 31, and keeps to the clock with the skew', async () => {
    expect((await verifyRelayCommand(await forged({ exp: NOW + 30 }), BODY, checks())).ok).toBe(true);
    expect(await verifyRelayCommand(await forged({ exp: NOW + 31, jti: 'j-31' }), BODY, checks())).toEqual({
      ok: false,
      reason: 'PRESENTATION_TOO_LONG_LIVED',
    });
    const jws = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    // expired: not before exp + skew (10 s) has passed
    expect((await verifyRelayCommand(jws, BODY, checks({ now: NOW + 19 }))).ok).toBe(true);
    const late = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    expect(await verifyRelayCommand(late, BODY, checks({ now: NOW + 20 }))).toEqual({
      ok: false,
      reason: 'PRESENTATION_EXPIRED',
    });
    // issued in the future beyond the skew
    const early = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW + 11 });
    expect(await verifyRelayCommand(early, BODY, checks())).toEqual({ ok: false, reason: 'CLOCK_SKEW' });
    expect(await verifyRelayCommand(early, BODY, checks({ skewSeconds: 11 }))).toMatchObject({ ok: true });
    // a clock that is not a number decides nothing
    expect(await verifyRelayCommand(jws, BODY, checks({ now: Number.NaN }))).toEqual({
      ok: false,
      reason: 'MALFORMED',
    });
  });

  it('trusts only the keys it is given, whatever key id the command names', async () => {
    const jws = await signRelayCommand({ signer: other, relayAud: RELAY, body: BODY, now: NOW });
    expect(await verifyRelayCommand(jws, BODY, checks())).toEqual({ ok: false, reason: 'SIGNATURE_INVALID' });
    expect(await verifyRelayCommand(jws, BODY, checks({ keys: [] }))).toEqual({
      ok: false,
      reason: 'SIGNATURE_INVALID',
    });
    // a trusted key without a key id verifies a command that names one, and the command's kid picks the key first
    const bare = { ...other.publicJwk };
    delete bare.kid;
    expect((await verifyRelayCommand(jws, BODY, checks({ keys: [station.publicJwk, bare] }))).ok).toBe(true);
    // a key id cannot make a key trusted
    const renamed = await signRelayCommand({
      signer: { ...other, kid: station.kid, sign: (d) => other.sign(d) },
      relayAud: RELAY,
      body: BODY,
      now: NOW,
    });
    expect(await verifyRelayCommand(renamed, BODY, checks())).toEqual({ ok: false, reason: 'SIGNATURE_INVALID' });
  });

  it('tries at most eight trusted keys, those the kid names first', async () => {
    const signers = await Promise.all(Array.from({ length: 9 }, () => generateSigner()));
    const ninth = signers[8]!;
    const firstEight = signers.slice(0, 8).map(withoutKid);
    const claims = { aud: RELAY, iat: NOW, exp: NOW + 10, jti: 'ninth-key', bh: bodyHash(BODY) };
    // no kid in the header and none on the keys: the ninth key in the list is never tried
    const anonymous = await assembled({ alg: 'ES256', typ: TYP.relayCommand }, claims, ninth);
    expect(decodeJwsUnverified(anonymous).header).not.toHaveProperty('kid');
    expect(await verifyRelayCommand(anonymous, BODY, checks({ keys: [...firstEight, withoutKid(ninth)] }))).toEqual({
      ok: false,
      reason: 'SIGNATURE_INVALID',
    });
    // the same command verifies when its key is among the first eight
    expect((await verifyRelayCommand(anonymous, BODY, checks({ keys: [withoutKid(ninth), ...firstEight] }))).ok).toBe(
      true,
    );
    // a key that the kid of the command names is tried first, wherever it stands in the list
    const named = await signRelayCommand({ signer: ninth, relayAud: RELAY, body: BODY, now: NOW });
    expect(decodeJwsUnverified(named).header.kid).toBe(ninth.publicJwk.kid);
    expect((await verifyRelayCommand(named, BODY, checks({ keys: [...firstEight, ninth.publicJwk] }))).ok).toBe(true);
  });

  it('turns text that is not a relay command into MALFORMED, and never throws', async () => {
    const jws = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    for (const text of ['', 'abc', 'a.b.c', `${jws}.x`, 'x'.repeat(5_000)]) {
      expect(await verifyRelayCommand(text, BODY, checks())).toEqual({ ok: false, reason: 'MALFORMED' });
    }
    // another kind of token signed by the same key is not a relay command
    expect(await verifyRelayCommand(await forged({}, station, TYP.event), BODY, checks())).toEqual({
      ok: false,
      reason: 'MALFORMED',
    });
    // claims of the wrong shape
    for (const claims of [{ aud: 7 }, { jti: '' }, { bh: 1 }, { iat: 'x' }, { exp: NOW }, { iss: 3 }]) {
      expect(await verifyRelayCommand(await forged(claims), BODY, checks())).toEqual({
        ok: false,
        reason: 'MALFORMED',
      });
    }
    expect(await verifyRelayCommand(jws, 42 as unknown as string, checks())).toEqual({
      ok: false,
      reason: 'MALFORMED',
    });
    expect(await verifyRelayCommand(jws, BODY, null as never)).toEqual({ ok: false, reason: 'MALFORMED' });
  });

  it('turns a command whose header names another algorithm into MALFORMED', async () => {
    const jws = await signRelayCommand({ signer: station, relayAud: RELAY, body: BODY, now: NOW });
    // the header of a valid command replaced, the payload and the signature kept
    const [, payload, signature] = jws.split('.');
    const header = base64urlEncode(utf8Encode(JSON.stringify({ alg: 'ES384', typ: TYP.relayCommand })));
    expect(await verifyRelayCommand(`${header}.${payload}.${signature}`, BODY, checks())).toEqual({
      ok: false,
      reason: 'MALFORMED',
    });
  });
});
