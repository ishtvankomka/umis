import { LIMITS } from '@umis/core';
import type { VerificationResult } from '@umis/core';
import { verifyAtCheckpoint } from '@umis/verifier';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createGateway, shellyRpcRelay } from '../src/index.js';
import { startShellyEmulator } from '../src/node/index.js';
import type { RelayEmulator } from '../src/node/index.js';
import { STATION_ISS, T0, buildDoor } from './fixtures.js';
import type { Door } from './fixtures.js';

// The real decision, observed: a test can tell whether a text was handed to the verifier at all.
vi.mock('@umis/verifier', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@umis/verifier')>();
  return { ...actual, verifyAtCheckpoint: vi.fn(actual.verifyAtCheckpoint) };
});

const NOW = T0 + 3_600;
let door: Door;
let emulator: RelayEmulator | undefined;
let clock = NOW;

beforeAll(async () => {
  door = await buildDoor();
});

afterEach(async () => {
  vi.mocked(verifyAtCheckpoint).mockClear();
  await emulator?.close();
  emulator = undefined;
});

async function relayAt() {
  clock = NOW;
  emulator = await startShellyEmulator({ port: 0, trust: [door.station.publicJwk], now: () => clock });
  return {
    emu: emulator,
    relay: shellyRpcRelay({
      url: `${emulator.url}/rpc`,
      signer: door.station,
      relayAud: emulator.url,
      iss: STATION_ISS,
    }),
  };
}

describe('gateway: decision, then relay', () => {
  it('opens the relay for an accepted one-way QR code and leaves it alone for a rejected one', async () => {
    const { emu, relay } = await relayAt();
    const decisions: VerificationResult[] = [];
    // a gate keeps one context, and with it one replay store, from scan to scan
    const held = door.context();
    const gateway = createGateway({
      context: () => held,
      relay,
      now: () => clock,
      onDecision: (r) => decisions.push(r),
    });

    const qr = await door.oneWayQr(NOW);
    const accepted = await gateway.handle(`  ${qr}\n`);
    expect(accepted.result).toMatchObject({ decision: 'accept', reasons: ['OK'], channel: 'qr_oneway', at: NOW });
    expect(accepted.result.claims?.display?.name).toBe('Андрій');
    expect(accepted.relay).toEqual({ ok: true, status: 200 });
    expect(emu.state()).toMatchObject({ on: true, until: NOW + 3, last: { iss: STATION_ISS } });
    const openedBy = emu.state().last;

    // the same code again is a replay: rejected, and the relay hears nothing
    clock = NOW + 5;
    expect(emu.state().on).toBe(false);
    const again = await gateway.handle(qr);
    expect(again.result).toMatchObject({ decision: 'reject', reasons: ['REPLAY'] });
    expect(again.relay).toBeUndefined();
    expect(emu.state()).toEqual({ on: false, last: openedBy });
    expect(decisions.map((d) => d.decision)).toEqual(['accept', 'reject']);

    // a code the door does not know: rejected before the relay as well
    const stranger = await door.oneWayQr(clock, 7);
    const unknown = createGateway({ context: () => door.context({ memberCache: new Map() }), relay, now: () => clock });
    const refused = await unknown.handle(stranger);
    expect(refused.result.reasons).toEqual(['UNKNOWN_CREDENTIAL_REF']);
    expect(refused.relay).toBeUndefined();
    expect(emu.state().last).toEqual(openedBy);
  });

  it('keeps the decision when the relay is down, slow or refuses, and still reports it', async () => {
    const down = shellyRpcRelay({
      url: 'http://127.0.0.1:1/rpc',
      signer: door.station,
      relayAud: 'http://127.0.0.1:1',
      fetch: () => Promise.reject(new Error('connection refused')),
    });
    const silent = shellyRpcRelay({
      url: 'http://127.0.0.1:1/rpc',
      signer: door.station,
      relayAud: 'http://127.0.0.1:1',
      fetch: () => new Promise<never>(() => undefined),
      timeoutMs: 40,
    });
    const refusing = shellyRpcRelay({
      url: 'http://127.0.0.1:1/rpc',
      signer: door.station,
      relayAud: 'http://127.0.0.1:1',
      fetch: async () => ({ status: 401, headers: { get: () => null }, text: async () => '{}' }),
    });
    const outcomes: unknown[] = [];
    for (const [index, relay] of [down, silent, refusing].entries()) {
      const gateway = createGateway({ context: () => door.context(), relay, now: () => NOW });
      const { result, relay: opened } = await gateway.handle(await door.oneWayQr(NOW, 100 + index));
      expect(result).toMatchObject({ decision: 'accept', reasons: ['OK'] });
      outcomes.push(opened);
    }
    expect(outcomes).toEqual([
      { ok: false, status: 0 },
      { ok: false, status: 0 },
      { ok: false, status: 401 },
    ]);
    // the client itself says why, in a few words
    await expect(down.open({ switchId: 0, seconds: 3, now: NOW })).resolves.toEqual({
      ok: false,
      status: 0,
      error: 'network error',
    });
    await expect(silent.open({ switchId: 0, seconds: 3, now: NOW })).resolves.toEqual({
      ok: false,
      status: 0,
      error: 'timeout',
    });
    await expect(refusing.open({ switchId: 0, seconds: 3, now: NOW })).resolves.toEqual({
      ok: false,
      status: 401,
      error: 'HTTP 401',
    });
  });

  it('turns away a text that is too long or not QR alphanumeric before it is decoded', async () => {
    const context = vi.fn(() => door.context());
    const seen: VerificationResult[] = [];
    const gateway = createGateway({ context, now: () => NOW, onDecision: (r) => seen.push(r) });

    const oversize = `UMIS1O:${'A'.repeat(LIMITS.qrMaxChars + 16)}`;
    const lowercase = `UMIS1O:${'a'.repeat(100)}.`;
    for (const text of [
      oversize,
      'A'.repeat(LIMITS.qrMaxChars + 17),
      lowercase,
      `UMIS1F:${'A'.repeat(50)}\u0000.`,
      'openid4vp://x',
      42 as never,
    ]) {
      const { result, relay } = await gateway.handle(text);
      expect(result).toMatchObject({ decision: 'reject', reasons: ['MALFORMED'], at: NOW });
      expect(result.trace).toHaveLength(9);
      expect(result.trace[0]).toMatchObject({ step: 1, name: 'parse', ok: false, reason: 'MALFORMED' });
      expect(result.trace.slice(1).every((step) => step.skipped === true)).toBe(true);
      expect(relay).toBeUndefined();
    }
    expect(verifyAtCheckpoint).not.toHaveBeenCalled();
    expect(context).not.toHaveBeenCalled();
    expect(seen).toHaveLength(6);
    expect(seen[0]?.channel).toBe('qr_oneway');
    expect(seen[1]?.channel).toBe('qr_full');

    // the limit is the gateway's to set, and a text within it goes to the verifier
    const small = createGateway({ context, now: () => NOW, maxInputChars: 20 });
    expect((await small.handle(await door.oneWayQr(NOW, 9))).result.reasons).toEqual(['MALFORMED']);
    expect(verifyAtCheckpoint).not.toHaveBeenCalled();
    const wide = createGateway({ context, now: () => NOW });
    expect((await wide.handle('UMIS1O:AAAA.')).result.reasons).toEqual(['MALFORMED']);
    expect(verifyAtCheckpoint).toHaveBeenCalledTimes(1);
    expect(context).toHaveBeenCalledTimes(1);
  });

  it('uses its own clock for the decision, the policy for how long to open, and an observer cannot change the outcome', async () => {
    const commands: Array<{ switchId: number; seconds: number; now: number }> = [];
    const relay = {
      open: async (call: { switchId: number; seconds: number; now: number }) => {
        commands.push(call);
        return { ok: true, status: 200 };
      },
    };
    const held = door.context({ now: 1 }); // a stale clock in the context
    const noisy = createGateway({
      context: async () => held,
      relay,
      switchId: 2,
      now: () => NOW,
      onDecision: () => {
        throw new Error('observer failed');
      },
    });
    const first = await noisy.handle(await door.oneWayQr(NOW, 1));
    expect(first.result).toMatchObject({ decision: 'accept', at: NOW });
    expect(commands).toEqual([{ switchId: 2, seconds: 3, now: NOW }]);

    const explicit = createGateway({
      context: () => held,
      relay,
      openSeconds: 5,
      now: () => NOW,
      onDecision: async () => Promise.reject(new Error('late')),
    });
    expect((await explicit.handle(await door.oneWayQr(NOW, 2))).relay).toEqual({ ok: true, status: 200 });
    expect(commands[1]).toEqual({ switchId: 0, seconds: 5, now: NOW });

    // an accepted decision without a relay has nothing to report about one; a context that cannot be built is an error
    const bare = createGateway({ context: () => held, now: () => NOW });
    expect(await bare.handle(await door.oneWayQr(NOW, 3))).toMatchObject({ result: { decision: 'accept' } });
    const broken = createGateway({ context: () => Promise.reject(new Error('store unavailable')), now: () => NOW });
    await expect(broken.handle(await door.oneWayQr(NOW, 4))).rejects.toMatchObject({ code: 'PROTOCOL' });
  });
});
