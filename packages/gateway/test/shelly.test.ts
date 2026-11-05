import { generateSigner } from '@umis/core';
import type { FetchLike, Signer } from '@umis/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { shellyRpcRelay } from '../src/index.js';
import { STATION_ISS, T0 } from './fixtures.js';

const RELAY_URL = 'http://127.0.0.1:1/rpc';
const RELAY_AUD = 'http://127.0.0.1:1';

let station: Signer;
beforeAll(async () => {
  station = await generateSigner();
});

/** A fetch that answers every request with `status` and `text`, and keeps the bodies it was sent. */
function answering(status: number, text: string): { fetch: FetchLike; bodies: string[] } {
  const bodies: string[] = [];
  return {
    bodies,
    fetch: async (_url, init) => {
      bodies.push(init?.body ?? '');
      return { status, headers: { get: () => null }, text: async () => text };
    },
  };
}

describe('Shelly RPC relay client', () => {
  it('reports a JSON-RPC error inside a 2xx answer as RPC error <code>', async () => {
    const relay = shellyRpcRelay({
      url: RELAY_URL,
      signer: station,
      relayAud: RELAY_AUD,
      fetch: answering(200, JSON.stringify({ id: 1, error: { code: -103, message: 'x' } })).fetch,
    });
    await expect(relay.open({ switchId: 0, seconds: 3, now: T0 })).resolves.toEqual({
      ok: false,
      status: 200,
      error: 'RPC error -103',
    });
  });

  it('sends as JSON-RPC src the src option, else iss, else umis-gateway', async () => {
    const sources: unknown[] = [];
    for (const names of [{ src: 'door-panel', iss: STATION_ISS }, { iss: STATION_ISS }, {}]) {
      const stub = answering(200, JSON.stringify({ id: 1, result: { was_on: false } }));
      const relay = shellyRpcRelay({
        url: RELAY_URL,
        signer: station,
        relayAud: RELAY_AUD,
        fetch: stub.fetch,
        ...names,
      });
      await expect(relay.open({ switchId: 0, seconds: 3, now: T0 })).resolves.toEqual({ ok: true, status: 200 });
      expect(stub.bodies).toHaveLength(1);
      sources.push((JSON.parse(stub.bodies[0]!) as { src?: unknown }).src);
    }
    expect(sources).toEqual(['door-panel', STATION_ISS, 'umis-gateway']);
  });
});
