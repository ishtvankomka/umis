import { readFileSync } from 'node:fs';
import { base64urlDecode, decodeFrameBytes } from '@umis/core';
import type { PendingRequest, VerificationResult } from '@umis/core';
import {
  createMemoryReplayStore,
  deserializeVerifierContext,
  verifyAtCheckpoint,
  verifyCounterparty,
  verifyResponseQr,
} from '@umis/verifier';
import type { SerializedVerifierContextV1 } from '@umis/verifier';
import { verifyVpResponse } from '@umis/verifier/oid4vp';
import { parseRequestQr } from '@umis/wallet';
import { describe, expect, it } from 'vitest';
import { buildVectors } from '../scripts/gen-vectors.js';

const FILE = new URL('../../../test-vectors/umis-profile-v1.json', import.meta.url);

interface Entry {
  id: string;
  channel: string;
  check: string;
  context: string;
  now: number;
  encoding: string;
  input: string | Record<string, string>;
  request?: string;
  pending?: PendingRequest;
  nonce?: string;
  state?: string;
  audience?: string;
  expected: { decision: string; reasons: string[] };
}

interface Vectors {
  format: string;
  issuers: Array<{ issuer: string; jwks: { keys: Array<Record<string, unknown>> } }>;
  credentials: Array<{ id: string; vct: string; sdJwtVc: string }>;
  contexts: Record<string, SerializedVerifierContextV1>;
  presentations: Entry[];
}

const committed = readFileSync(FILE, 'utf8');
const vectors = JSON.parse(committed) as Vectors;

/** Decides an entry from what the file says, with the public functions of the packages and nothing else. */
async function decide(entry: Entry): Promise<VerificationResult> {
  const stored = vectors.contexts[entry.context];
  if (stored === undefined) throw new Error(`the entry ${entry.id} names a context the file does not have`);
  const ctx = deserializeVerifierContext(stored, { replay: createMemoryReplayStore(), now: entry.now });
  switch (entry.check) {
    case 'verifyAtCheckpoint':
      return verifyAtCheckpoint(entry.input as string, ctx);
    case 'verifyCounterparty':
      return verifyCounterparty(await parseRequestQr(entry.input as string, { now: entry.now }), ctx);
    case 'verifyResponseQr': {
      const frame =
        entry.encoding === 'frame-bytes-base64url'
          ? decodeFrameBytes(base64urlDecode(entry.input as string))
          : (entry.input as string);
      return verifyResponseQr(frame, entry.pending!, ctx);
    }
    case 'verifyVpResponse':
      return verifyVpResponse({
        body: entry.input as Record<string, string>,
        nonce: entry.nonce!,
        state: entry.state,
        audience: entry.audience!,
        trusted: ctx.trusted,
        fetchStatusList: (uri) => {
          const held = ctx.statusLists.get(uri);
          return held === undefined
            ? Promise.reject(new Error(`no status list at ${uri}`))
            : Promise.resolve(held.token);
        },
        now: ctx.now,
        policy: ctx.policy,
        replay: ctx.replay,
      });
    default:
      throw new Error(`unknown check "${entry.check}"`);
  }
}

function hasMember(value: unknown, name: string): boolean {
  if (Array.isArray(value)) return value.some((item) => hasMember(item, name));
  if (typeof value !== 'object' || value === null) return false;
  return Object.entries(value).some(([key, item]) => key === name || hasMember(item, name));
}

describe('test-vectors/umis-profile-v1.json', () => {
  it('is written again, byte for byte, by every run of the generator, and is the committed file', async () => {
    const first = await buildVectors();
    const second = await buildVectors();
    expect(second).toBe(first);
    expect(committed, 'the generator output differs: run pnpm -F @umis/testkit gen:vectors').toBe(first);
  });

  it('holds public keys only (I-17)', () => {
    expect(hasMember(vectors, 'd')).toBe(false);
    expect(vectors.issuers).toHaveLength(3);
    for (const issuer of vectors.issuers) {
      for (const key of issuer.jwks.keys)
        expect(Object.keys(key).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y']);
    }
  });

  it('has a credential of each type and a presentation for each channel', () => {
    expect(vectors.format).toBe('umis-test-vectors/v1');
    expect(new Set(vectors.credentials.map((credential) => credential.vct)).size).toBe(2);
    expect(new Set(vectors.presentations.map((entry) => entry.channel))).toEqual(
      new Set(['qr_oneway', 'qr_full', 'qr_reverse', 'ble', 'oid4vp']),
    );
  });

  it.each(vectors.presentations.map((entry) => [entry.id, entry] as const))(
    'is decided as recorded: %s',
    async (_id, entry) => {
      const result = await decide(entry);
      expect({ decision: result.decision, reasons: result.reasons }).toEqual(entry.expected);
    },
  );
});
