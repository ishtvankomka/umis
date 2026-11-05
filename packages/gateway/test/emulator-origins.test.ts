import { generateSigner } from '@umis/core';
import type { Signer } from '@umis/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { startShellyEmulator } from '../src/node/index.js';
import { T0 } from './fixtures.js';

let station: Signer;
beforeAll(async () => {
  station = await generateSigner();
});

/** Starts an emulator with these CORS origins and closes it again: `started`, or the error that stopped it. */
const outcome = (cors: string[]): Promise<unknown> =>
  startShellyEmulator({ port: 0, trust: [station.publicJwk], now: () => T0, cors }).then(
    async (emulator) => {
      await emulator.close();
      return 'started';
    },
    (error: unknown) => error,
  );

describe('relay emulator: CORS origins', () => {
  it('refuses a wildcard anywhere in an origin, and an origin with a path, naming the origin', async () => {
    for (const origin of ['https://*.example.com', '*', 'https://a.example.com/path']) {
      const refused = await outcome([origin]);
      expect(refused, origin).toMatchObject({ code: 'INVALID_ARGUMENT' });
      expect((refused as Error).message, origin).toContain(`"${origin}"`);
    }
  });

  it('accepts exact origins, with or without a port', async () => {
    expect(await outcome(['https://admin.example.com', 'http://localhost:3000'])).toBe('started');
  });
});
