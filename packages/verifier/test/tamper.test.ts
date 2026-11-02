import {
  base64urlDecode,
  base64urlEncode,
  decodeFrame,
  encodeFrame,
  generateSigner,
  utf8Decode,
  utf8Encode,
} from '@umis/core';
import type { AuthorityItem, Frame, ReasonCode, Signer, VerificationResult, VerifierContext } from '@umis/core';
import { createMemoryLedger } from '@umis/policy';
import { beforeAll, describe, expect, it } from 'vitest';
import { verifyAtCheckpoint, verifyResponseQr } from '../src/index.js';
import {
  DAY,
  IDX,
  ISSUER_A,
  LIST_A,
  NOW,
  OLEH_AUTHORITY,
  answer,
  ask,
  buildWorld,
  credential,
  doorContext,
  expectAccept,
  expectReject,
  forgeJws,
  fullQr,
  oneWayQr,
  presentation,
  verdictOf,
  warehouseContext,
  type AnswerOptions,
  type World,
} from './fixtures.js';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});

type Edit = (parts: string[]) => string[] | Promise<string[]>;

/** Oleh answers a fresh request for ten tonnes; `edit` changes the parts of the presentation (`jwt~disclosure~…~kb`). */
async function edited(edit: Edit, o: { cred?: string; holder?: Signer } & AnswerOptions = {}) {
  const { pending } = await ask(w);
  const token = await presentation(w, o.cred ?? w.olehCredential, o.holder ?? w.oleh, pending, o);
  const parts = await edit(token.split('~'));
  // a frame object, because the QR text of a response cannot be made without a key-binding proof
  const reply: Frame = { kind: 'response', tokens: [parts.join('~')] };
  return verifyResponseQr(reply, pending, warehouseContext(w));
}

/** A rejection that a fault of the verifier’s own causes: the exception is reported as malformed at the step it hit. */
function failedAt(result: VerificationResult, reason: ReasonCode, step: number): void {
  const verdict = verdictOf(result, { fault: true });
  expect(result.decision).toBe('reject');
  expect([verdict.reason, verdict.step]).toEqual([reason, step]);
}

const decodeDisclosure = (text: string): [string, string, unknown] =>
  JSON.parse(utf8Decode(base64urlDecode(text))) as [string, string, unknown];
const encodeDisclosure = (value: unknown): string => base64urlEncode(utf8Encode(JSON.stringify(value)));
const disclosureIndex = (parts: string[], name: string): number =>
  parts.findIndex((part, index) => index > 0 && index < parts.length - 1 && decodeDisclosure(part)[1] === name);

/** One member of the three parts of a compact JWS, decoded, changed and put back without re-signing. */
function reencode(jws: string, part: 0 | 1, change: (json: Record<string, unknown>) => void): string {
  const segments = jws.split('.');
  const json = JSON.parse(utf8Decode(base64urlDecode(segments[part]!))) as Record<string, unknown>;
  change(json);
  segments[part] = base64urlEncode(utf8Encode(JSON.stringify(json)));
  return segments.join('.');
}

describe('a presentation that was changed on the way', () => {
  it('is rejected when a disclosure was changed to raise the limit', async () => {
    const result = await edited((parts) => {
      const at = disclosureIndex(parts, 'authority');
      const [salt, name, value] = decodeDisclosure(parts[at]!);
      const raised = (value as AuthorityItem[]).map((item) => ({ ...item, limit: { ...item.limit, amount: 1_000 } }));
      return parts.map((part, index) => (index === at ? encodeDisclosure([salt, name, raised]) : part));
    });
    expectReject(result, 'MALFORMED');
    expect(result.claims).toBeUndefined();
  });

  it('is rejected when a disclosure is added that the issuer never listed', async () => {
    const invented = encodeDisclosure(['c2FsdHNhbHRzYWx0c2FsdA', 'display', { name: 'Директор' }]);
    const result = await edited((parts) => [...parts.slice(0, -1), invented, parts[parts.length - 1]!]);
    expectReject(result, 'MALFORMED');
  });

  it('is rejected when a disclosure is shown twice', async () => {
    const result = await edited((parts) => [...parts.slice(0, -1), parts[1]!, parts[parts.length - 1]!]);
    expectReject(result, 'MALFORMED');
  });

  it('cannot have the delegation taken out after the holder signed it', async () => {
    const result = await edited((parts) => parts.filter((_, index) => index !== disclosureIndex(parts, 'delegation')));
    expectReject(result, 'HOLDER_BINDING_INVALID');
    expect(result.trace[3]).toMatchObject({ name: 'holder_binding', ok: false });
  });

  it('is rejected with the key-binding proof of another presentation', async () => {
    const other = await ask(w);
    const proof = (await presentation(w, w.olehCredential, w.oleh, other.pending, { disclose: ['org'] }))
      .split('~')
      .pop()!;
    const result = await edited((parts) => [...parts.slice(0, -1), proof]);
    expectReject(result, 'HOLDER_BINDING_INVALID');
  });

  it('is rejected when the proof was made by a key other than the holder’s', async () => {
    expectReject(await edited((parts) => parts, { kbSigner: w.ivan }), 'HOLDER_BINDING_INVALID');
    const stranger = await generateSigner({ crypto: w.crypto });
    expectReject(await edited((parts) => parts, { kbSigner: stranger }), 'HOLDER_BINDING_INVALID');
  });

  it('is rejected without any proof', async () => {
    const result = await edited((parts) => [...parts.slice(0, -1), '']);
    expectReject(result, 'HOLDER_BINDING_INVALID');
  });

  it('is rejected when the proof is not a key-binding token', async () => {
    const result = await edited(async (parts) => {
      const forged = await forgeJws(
        w.oleh,
        { alg: 'ES256', typ: 'JWT' },
        { iat: NOW + 1, aud: 'x', nonce: 'y', sd_hash: 'z' },
      );
      return [...parts.slice(0, -1), forged];
    });
    expectReject(result, 'HOLDER_BINDING_INVALID');
  });

  it('is rejected when the issuer signature was altered by a single character', async () => {
    const result = await edited((parts) => {
      const [header, payload, signature] = parts[0]!.split('.') as [string, string, string];
      const flipped = signature[10] === 'A' ? 'B' : 'A';
      return [
        [header, payload, `${signature.slice(0, 10)}${flipped}${signature.slice(11)}`].join('.'),
        ...parts.slice(1),
      ];
    });
    expectReject(result, 'SIGNATURE_INVALID');
    // nothing the credential claims is shown when its signature does not hold
    expect(result.claims).toBeUndefined();
    expect(result.issuer).toBeUndefined();
    expect(result.credentialRef).toBeUndefined();
  });

  it('is rejected when the lifetime was prolonged in the signed part', async () => {
    const result = await edited((parts) => [
      reencode(parts[0]!, 1, (payload) => {
        payload.exp = (payload.exp as number) + 365 * DAY;
      }),
      ...parts.slice(1),
    ]);
    expectReject(result, 'SIGNATURE_INVALID');
  });

  it('is rejected when the holder key in the credential was replaced by another', async () => {
    const result = await edited(
      (parts) => [
        reencode(parts[0]!, 1, (payload) => {
          payload.cnf = { jwk: w.ivan.publicJwk };
        }),
        ...parts.slice(1),
      ],
      { kbSigner: w.ivan },
    );
    expectReject(result, 'SIGNATURE_INVALID');
  });

  it('is rejected when the header names another key of the issuer than the one that signed', async () => {
    const result = await edited((parts) => [
      reencode(parts[0]!, 0, (header) => {
        header.kid = w.issuerB.kid;
      }),
      ...parts.slice(1),
    ]);
    expectReject(result, 'ISSUER_KEY_UNKNOWN');
  });

  it('is rejected when a stranger signed in the name of the issuer', async () => {
    const stranger = await generateSigner({ crypto: w.crypto });
    const forgery = await credential({
      issuer: stranger,
      iss: ISSUER_A,
      holder: w.oleh,
      jti: 'cred-oleh-9999',
      idx: IDX.spare,
      listUri: LIST_A,
      claims: {
        org: { id: 'contractor-a', name: 'Підрядник А' },
        role: { code: 'crew_lead', name: 'Керівник бригади' },
        authority: OLEH_AUTHORITY,
        delegation: { depth: 0, max_depth: 1 },
      },
      crypto: w.crypto,
    });
    expectReject(await edited((parts) => parts, { cred: forgery }), 'ISSUER_KEY_UNKNOWN');

    // with the key id of the real issuer in the header, the signature is what gives it away
    const pretended = await edited(
      (parts) => [
        reencode(parts[0]!, 0, (header) => {
          header.kid = w.issuerA.kid;
        }),
        ...parts.slice(1),
      ],
      { cred: forgery },
    );
    expectReject(pretended, 'SIGNATURE_INVALID');
  });

  it('is not what a credential that is not an SD-JWT VC looks like', async () => {
    const payload = { iss: ISSUER_A, vct: 'x' };
    for (const header of [
      { alg: 'ES256', typ: 'JWT' },
      { alg: 'none', typ: 'dc+sd-jwt' },
      { alg: 'HS256', typ: 'dc+sd-jwt' },
    ]) {
      const result = await edited(async () => [await forgeJws(w.issuerA, header, payload), '']);
      expect(result.decision).toBe('reject');
      expect(['MALFORMED', 'UNSUPPORTED_FORMAT']).toContain(result.reasons[0]);
      verdictOf(result);
    }
  });
});

describe('one-way tokens that were changed on the way', () => {
  it('are rejected when the payload was changed after the holder signed it', async () => {
    const door = () => doorContext(w);
    const qr = await oneWayQr(w);
    expectAccept(await verifyAtCheckpoint(qr, await door()));

    const frame = decodeFrame(await oneWayQr(w, { ctr: 5 }));
    const changed = reencode(frame.tokens[0]!, 1, (payload) => {
      payload.exp = (payload.exp as number) + 600;
      payload.ctr = 6;
    });
    const result = await verifyAtCheckpoint(encodeFrame({ kind: 'oneway', tokens: [changed] }), await door());
    expectReject(result, 'HOLDER_BINDING_INVALID');
  });
});

describe('input that is not a frame at all', () => {
  /** A small deterministic generator, so that a failure can be repeated. */
  function generator(seed: number): () => number {
    let state = seed >>> 0;
    return () => {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      return state / 2 ** 32;
    };
  }
  const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:~_abcdef=';

  const prefixes = async (): Promise<string[]> => {
    const samples = [await oneWayQr(w), await fullQr(w)];
    const { qr } = await ask(w);
    samples.push(qr);
    return ['', 'UMIS1', ...samples.map((text) => text.slice(0, text.indexOf(':') + 1))];
  };

  it('is rejected with one reason and never throws: 300 strings made at random', async () => {
    const next = generator(2026_11_02);
    const { pending } = await ask(w);
    const starts = await prefixes();
    for (let n = 0; n < 300; n++) {
      const length = Math.floor(next() * 400);
      let body = starts[Math.floor(next() * starts.length)]!;
      for (let i = 0; i < length; i++) body += ALPHABET[Math.floor(next() * ALPHABET.length)];
      const asked = await verifyResponseQr(body, pending, warehouseContext(w));
      expect(asked.decision).toBe('reject');
      verdictOf(asked);
      const door = await verifyAtCheckpoint(body, await doorContext(w));
      expect(door.decision).toBe('reject');
      verdictOf(door);
    }
  });

  it('is rejected when a valid frame is cut short, at every length that is tried', async () => {
    const { pending } = await ask(w);
    const qr = await answer(w, w.olehCredential, w.oleh, pending);
    const step = Math.max(1, Math.floor(qr.length / 120));
    for (let length = 0; length < qr.length; length += step) {
      const result = await verifyResponseQr(qr.slice(0, length), pending, warehouseContext(w));
      expect(result.decision).toBe('reject');
      verdictOf(result);
    }
    expectAccept(await verifyResponseQr(qr, pending, warehouseContext(w)));
  });

  it('gives a verdict in the right shape when characters of a valid frame are replaced', async () => {
    const next = generator(7);
    const { pending } = await ask(w);
    const qr = await answer(w, w.olehCredential, w.oleh, pending);
    for (let n = 0; n < 200; n++) {
      const at = 7 + Math.floor(next() * (qr.length - 7));
      const replacement = ALPHABET[Math.floor(next() * ALPHABET.length)]!;
      const mutated = `${qr.slice(0, at)}${replacement}${qr.slice(at + 1)}`;
      verdictOf(await verifyResponseQr(mutated, pending, warehouseContext(w)));
    }
  });

  it('is rejected when it is no frame object either', async () => {
    const { pending } = await ask(w);
    const odd: unknown[] = [
      undefined,
      null,
      42,
      true,
      [],
      {},
      { kind: 'response' },
      { kind: 'response', tokens: 'x' },
      { kind: 'response', tokens: [1] },
      { kind: 'response', tokens: [] },
      { kind: 'response', tokens: ['a', 'b'] },
      { kind: 'nonsense', tokens: ['a'] },
      { kind: 7, tokens: ['a'] },
      { kind: 'oneway', tokens: ['a', 'b'] },
    ];
    for (const input of odd) {
      const result = await verifyResponseQr(input as Frame, pending, warehouseContext(w));
      expect(result.decision).toBe('reject');
      verdictOf(result);
      const door = await verifyAtCheckpoint(input as Frame, await doorContext(w));
      expect(door.decision).toBe('reject');
      verdictOf(door);
    }
  });
});

describe('a context that cannot be decided with', () => {
  const bad = async (over: Partial<VerifierContext>) => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    return verifyResponseQr(reply, pending, warehouseContext(w, over));
  };

  it('rejects a clock that is not a number, a negative skew and a missing part', async () => {
    for (const over of [
      { now: Number.NaN },
      { now: Number.POSITIVE_INFINITY },
      { skewSeconds: -1 },
      { skewSeconds: Number.NaN },
      { replay: undefined as never },
      { replay: {} as never },
      { statusLists: undefined as never },
      { trusted: undefined as never },
      { audiences: undefined as never },
      { policy: undefined as never },
      { policy: null as never },
    ]) {
      const result = await bad(over);
      expectReject(result, 'MALFORMED');
      expect(result.trace[0]).toMatchObject({ step: 1, ok: false, reason: 'MALFORMED' });
    }
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    for (const ctx of [null, undefined, 'context', 7, {}]) {
      const result = await verifyResponseQr(reply, pending, ctx as never);
      expectReject(result, 'MALFORMED');
    }
  });

  it('rejects when a store fails, and does not accept on a failure', async () => {
    const failing = () => Promise.reject(new Error('the disk is full'));
    failedAt(await bad({ replay: { checkAndRemember: failing } }), 'MALFORMED', 4);

    // an answer from the store that is not a plain yes counts as "seen before"
    const notBoolean = await bad({ replay: { checkAndRemember: () => Promise.resolve('yes' as never) } });
    expectReject(notBoolean, 'REPLAY');

    failedAt(await bad({ ledger: { used: failing, add: failing } }), 'MALFORMED', 8);

    const ledger = createMemoryLedger();
    const booking = await bad({ ledger: { used: (key, window) => ledger.used(key, window), add: failing } });
    failedAt(booking, 'MALFORMED', 9);
    expect(booking.trace[8]).toMatchObject({ name: 'decision', ok: false, reason: 'MALFORMED' });
  });

  it('rejects when the crypto provider fails', async () => {
    const broken = {
      ...w.crypto,
      verifyEs256: () => Promise.reject(new Error('no key store')),
      sha256: () => Promise.reject(new Error('no key store')),
    };
    const result = await bad({ crypto: broken });
    expect(result.decision).toBe('reject');
    verdictOf(result, { fault: true });
  });

  it('rejects when the registry holds nonsense', async () => {
    const result = await bad({ trusted: [null as never, 7 as never, { issuer: ISSUER_A } as never] });
    expect(result.decision).toBe('reject');
    verdictOf(result, { fault: true });
  });

  it('reports the time of the verifier, and rejects a presentation from its future', async () => {
    const { pending } = await ask(w);
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const behind = await verifyResponseQr(reply, pending, warehouseContext(w, { now: NOW - 20 }));
    expectReject(behind, 'CLOCK_SKEW');
    expect(behind.at).toBe(NOW - 20);
  });
});
