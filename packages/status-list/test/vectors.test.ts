import { readFileSync } from 'node:fs';
import { UmisError, hexDecode, hexEncode, type EcPublicJwk } from '@umis/core';
import { describe, expect, it } from 'vitest';
import {
  checkStatus,
  decodeLst,
  encodeLst,
  parseStatusListToken,
  statusListFromValues,
  verifyStatusListToken,
  type StatusBits,
} from '../src/index.js';

interface Vectors {
  packing: Array<{ bits: StatusBits; statuses: number[]; packedHex: string; lst: string }>;
  rejectLst: Array<{ lst: string; reason: string }>;
  signed: {
    uri: string;
    publicKey: EcPublicJwk;
    jws: { header: string; payload: string; signature: string };
    claims: { iat: number; exp: number; ttl: number; bits: StatusBits; size: number };
    revoked: number[];
    suspended: number[];
    verify: Array<{ now: number; maxAgeSeconds: number; outcome: string; ageSeconds?: number }>;
  };
}

const vectors = JSON.parse(
  readFileSync(new URL('../../../test-vectors/token-status-list.json', import.meta.url), 'utf8'),
) as Vectors;

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

describe('Token Status List vectors', () => {
  it('packs the draft examples least significant bits first and reads the draft lst back', () => {
    for (const { bits, statuses, packedHex, lst } of vectors.packing) {
      const packed = hexDecode(packedHex);
      const list = statusListFromValues(Uint8Array.from(statuses), bits);
      expect(hexEncode(list.toBytes())).toBe(packedHex);
      expect(list.bits).toBe(bits);
      expect(list.size).toBe(statuses.length);
      expect(statuses.map((_, idx) => list.get(idx))).toEqual(statuses);

      expect(decodeLst(lst)).toEqual(packed);
      // Encoders differ in their output, so the round trip is compared on the bytes, not on the text.
      expect(decodeLst(encodeLst(packed))).toEqual(packed);
    }
  });

  it('refuses every malformed lst of the vector file', () => {
    for (const { lst, reason } of vectors.rejectLst) {
      expect(
        codeOf(() => decodeLst(lst)),
        reason,
      ).toBe('STATUS_LIST_INVALID');
    }
  });

  it('parses and verifies the signed example under each freshness case', async () => {
    const { uri, publicKey, jws, claims, revoked, suspended, verify } = vectors.signed;
    const token = [jws.header, jws.payload, jws.signature].join('.');

    const parsed = parseStatusListToken(token);
    expect(parsed).toMatchObject({ uri, ...claims });
    for (let idx = 0; idx < claims.size; idx++) {
      const expected = revoked.includes(idx) ? 'REVOKED' : suspended.includes(idx) ? 'SUSPENDED' : 'VALID';
      expect(checkStatus({ uri, idx }, parsed), `index ${idx}`).toBe(expected);
    }
    expect(checkStatus({ uri, idx: claims.size }, parsed)).toBe('OUT_OF_RANGE');

    for (const { now, maxAgeSeconds, outcome, ageSeconds } of verify) {
      const result = await verifyStatusListToken(token, { keys: [publicKey], expectedUri: uri, now, maxAgeSeconds });
      if (outcome === 'ok') {
        expect(result.ok, `now ${now}`).toBe(true);
        expect(result.ok && result.ageSeconds).toBe(ageSeconds);
      } else {
        expect(result, `now ${now}`).toEqual({ ok: false, reason: outcome });
      }
    }
  });
});
