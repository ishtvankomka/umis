import { deflateSync } from 'fflate';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  FRAME_KINDS,
  FRAME_KIND_CODE,
  FRAME_PREFIX,
  LIMITS,
  TYP,
  UmisError,
  VCT,
  base45Encode,
  base64urlDecode,
  base64urlEncode,
  classifyQr,
  concatBytes,
  decodeFrame,
  decodeFrameBytes,
  decodePresentationRequest,
  encodeFrame,
  encodeFrameBytes,
  frameKindOf,
  generateSigner,
  signJws,
  signPresentationRequest,
  varintEncode,
  verifyJws,
  webCryptoProvider,
  type Frame,
  type FrameKind,
  type PresentationRequestPayloadV1,
  type QrKind,
  type Signer,
} from '../src/index.js';
import { inflateCapped } from '../src/frame.js';
import { NOW, VERIFIER, buildWorld, codeOf, forgeJws, presentWith, segment, type World } from './fixtures.js';

const NONCE = base64urlEncode(Uint8Array.from({ length: 16 }, (_, i) => i + 1));
const ONE_WAY = {
  cred_ref: 'cred-oleh-0001',
  aud: 'https://issuer.example/contractor-a',
  iat: NOW,
  exp: NOW + 30,
  ctr: 7,
};
const QR_ALPHANUMERIC = /^[0-9A-Z $%*+\-./:]+$/;

/** Reproducible pseudo-random bytes (xorshift32), so that a failing case can be replayed. */
function pseudoRandom(length: number, seed = 0x2545f491): Uint8Array {
  const out = new Uint8Array(length);
  let state = seed;
  for (let i = 0; i < length; i++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    out[i] = state & 0xff;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// building frames by hand, so that a container can be wrong in exactly one respect
// ---------------------------------------------------------------------------------------------------------------

const byte = (value: number): Uint8Array => Uint8Array.of(value);
const bytesOf = (text: string): Uint8Array => base64urlDecode(text);
const lengthPrefixed = (bytes: Uint8Array): Uint8Array => concatBytes(varintEncode(bytes.length), bytes);

/** `u8 1 ‖ 3 segments` for a compact JWS. */
function packedJws(token: string): Uint8Array {
  return concatBytes(byte(1), ...token.split('.').map((part) => lengthPrefixed(bytesOf(part))));
}

/** `u8 2 ‖ issuer JWT ‖ d ‖ disclosures ‖ u8 hasKb ‖ KB-JWT` for an SD-JWT with a key-binding JWT. */
function packedSdJwt(token: string, hasKeyBinding = 1): Uint8Array {
  const pieces = token.split('~');
  const keyBinding = pieces[pieces.length - 1]!;
  const disclosures = pieces.slice(1, -1);
  return concatBytes(
    byte(2),
    ...pieces[0]!.split('.').map((part) => lengthPrefixed(bytesOf(part))),
    varintEncode(disclosures.length),
    ...disclosures.map((disclosure) => lengthPrefixed(bytesOf(disclosure))),
    byte(hasKeyBinding),
    ...keyBinding.split('.').map((part) => lengthPrefixed(bytesOf(part))),
  );
}

/** `u8 0x01 ‖ varint n ‖ n × (varint len ‖ packedToken)`. */
function container(...packed: Uint8Array[]): Uint8Array {
  return concatBytes(byte(1), varintEncode(packed.length), ...packed.map(lengthPrefixed));
}

const textOf = (kind: FrameKind, body: Uint8Array): string =>
  `${FRAME_PREFIX[kind]}${base45Encode(deflateSync(body, { level: 9 }))}.`;
const bytesFrame = (kind: FrameKind, body: Uint8Array): Uint8Array =>
  concatBytes(byte(FRAME_KIND_CODE[kind]), deflateSync(body, { level: 9 }));

/** The code of the failure of decoding `body` as a frame of `kind`, from its text and from its bytes. */
async function decodeFailure(kind: FrameKind, body: Uint8Array): Promise<[string | undefined, string | undefined]> {
  return [
    await codeOf(() => decodeFrame(textOf(kind, body))),
    await codeOf(() => decodeFrameBytes(bytesFrame(kind, body))),
  ];
}

// ---------------------------------------------------------------------------------------------------------------
// the frames of a real exchange
// ---------------------------------------------------------------------------------------------------------------

let world: World;
let oneWay: string;
let request: string;
let mutualRequest: string;
let olehPresentation: string;
let ivanPresentation: string;
let framesByKind: Record<FrameKind, Frame>;

const REQUEST_PAYLOAD: PresentationRequestPayloadV1 = {
  v: 1,
  nonce: NONCE,
  aud: VERIFIER,
  iat: NOW + 100,
  exp: NOW + 160,
  vct: [VCT.roleAuthority],
  claims: ['org', 'role', 'authority', 'delegation'],
  authority: { action: 'receive_materials', resource: 'rebar', amount: 10, unit: 't', object: 'bridge-01' },
  policy: { id: 'warehouse-b', v: 3, risk: 'medium' },
  verifier: { name: 'Склад Б', org: 'Підрядник А' },
};

beforeAll(async () => {
  world = await buildWorld(webCryptoProvider);
  oneWay = await signJws({ header: { typ: TYP.oneWay }, payload: ONE_WAY, signer: world.oleh });
  const verifierKey = await generateSigner({ crypto: webCryptoProvider });
  request = await signPresentationRequest(REQUEST_PAYLOAD, verifierKey);
  mutualRequest = await signPresentationRequest({ ...REQUEST_PAYLOAD, mutual: true }, world.oleh);
  olehPresentation = await presentWith(world, world.olehCredential, world.oleh, { nonce: NONCE });
  ivanPresentation = await presentWith(world, world.ivanCredential, world.ivan, { nonce: NONCE });
  framesByKind = {
    oneway: { kind: 'oneway', tokens: [oneWay] },
    full: { kind: 'full', tokens: [olehPresentation] },
    request: { kind: 'request', tokens: [request] },
    response: { kind: 'response', tokens: [olehPresentation] },
    mutual_init: { kind: 'mutual_init', tokens: [mutualRequest, olehPresentation] },
    mutual_reply: { kind: 'mutual_reply', tokens: [ivanPresentation] },
  };
});

describe('frames of every kind', () => {
  it.each(FRAME_KINDS)('%s: the text and the bytes give the tokens back exactly', (kind) => {
    const frame = framesByKind[kind];
    const text = encodeFrame(frame);
    expect(text.startsWith(FRAME_PREFIX[kind])).toBe(true);
    expect(text.endsWith('.')).toBe(true);
    expect(text).toMatch(QR_ALPHANUMERIC);
    expect(text.length).toBeLessThanOrEqual(LIMITS.qrMaxChars);
    expect(frameKindOf(text)).toBe(kind);
    expect(decodeFrame(text)).toEqual(frame);
    expect(decodeFrame(`  \r\n${text}\n `)).toEqual(frame); //                          whitespace around a scan is ignored

    const bytes = encodeFrameBytes(frame);
    expect(bytes[0]).toBe(FRAME_KIND_CODE[kind]);
    expect(decodeFrameBytes(bytes)).toEqual(frame);
    expect(encodeFrame(frame)).toBe(text); //                                           the encoding is deterministic
  });

  it('keeps an SD-JWT with no disclosure at all, and one with every claim disclosed', async () => {
    const bare = await presentWith(world, world.olehCredential, world.oleh, { nonce: NONCE }, []);
    const everything = await presentWith(world, world.ivanCredential, world.ivan, { nonce: NONCE }, [
      'org',
      'org_unit',
      'role',
      'authority',
      'delegation',
      'display',
    ]);
    for (const token of [bare, everything]) {
      expect(decodeFrame(encodeFrame({ kind: 'response', tokens: [token] })).tokens).toEqual([token]);
      expect(decodeFrameBytes(encodeFrameBytes({ kind: 'full', tokens: [token] })).tokens).toEqual([token]);
    }
    expect(bare.split('~')).toHaveLength(2);
  });

  it('fits the response of Олег and of Іван, the full frame and the mutual exchange into one QR code', () => {
    const sizes = {
      oleh: encodeFrame(framesByKind.response).length,
      ivan: encodeFrame({ kind: 'response', tokens: [ivanPresentation] }).length,
      full: encodeFrame(framesByKind.full).length,
      mutualInit: encodeFrame(framesByKind.mutual_init).length,
      mutualReply: encodeFrame(framesByKind.mutual_reply).length,
      oneWay: encodeFrame(framesByKind.oneway).length,
    };
    for (const size of Object.values(sizes)) expect(size).toBeLessThanOrEqual(LIMITS.qrMaxChars);
    expect(sizes.oleh).toBeLessThan(2_300); //          about 1.8 k: the cnf key carries its four coordinates only
    expect(sizes.oneWay).toBeLessThan(500);
    expect(sizes.mutualInit).toBeLessThan(2_800);
    expect(sizes.full).toBe(sizes.oleh); //             the same token in a slot of the same kind of content
  });

  it('is not misled by a frame that holds another kind of content', async () => {
    const swapped = encodeFrame(framesByKind.oneway).replace(FRAME_PREFIX.oneway, FRAME_PREFIX.full);
    expect(await codeOf(() => decodeFrame(swapped))).toBe('MALFORMED');
    const fromRequest = encodeFrame(framesByKind.request).replace(FRAME_PREFIX.request, FRAME_PREFIX.mutual_init);
    expect(await codeOf(() => decodeFrame(fromRequest))).toBe('MALFORMED');
  });
});

describe('what a frame is not', () => {
  const text = (): string => encodeFrame(framesByKind.response);

  it('does not belong to UMIS when the prefix is not one of the six', async () => {
    for (const other of [
      '',
      '   ',
      'hello',
      'UMIS2O:ABC.',
      'UMIS1X:ABC.',
      'umis1o:ABC.',
      'UMIS1:ABC.',
      'https://example.com/',
    ]) {
      expect(await codeOf(() => decodeFrame(other))).toBe('UNSUPPORTED_FORMAT');
      expect(frameKindOf(other)).toBeUndefined();
    }
    expect(await codeOf(() => decodeFrame(undefined as unknown as string))).toBe('UNSUPPORTED_FORMAT');
    expect(await codeOf(() => decodeFrameBytes(Uint8Array.of(0, 1, 2)))).toBe('UNSUPPORTED_FORMAT');
    expect(await codeOf(() => decodeFrameBytes(Uint8Array.of(7, 1, 2)))).toBe('UNSUPPORTED_FORMAT');
    expect(await codeOf(() => decodeFrameBytes(new Uint8Array(0)))).toBe('UNSUPPORTED_FORMAT');
    expect(await codeOf(() => decodeFrameBytes('UMIS1O:' as unknown as Uint8Array))).toBe('MALFORMED');
  });

  it('is malformed with a lowercase character, a character outside the alphabet or no terminator', async () => {
    const valid = text();
    const body = valid.slice(FRAME_PREFIX.response.length, -1);
    const at = 20;
    for (const replacement of ['a', 'z', '#', '"', 'Д', '\u0000']) {
      const damaged = `${FRAME_PREFIX.response}${body.slice(0, at)}${replacement}${body.slice(at + 1)}.`;
      expect(await codeOf(() => decodeFrame(damaged))).toBe('MALFORMED');
    }
    expect(await codeOf(() => decodeFrame(valid.slice(0, -1)))).toBe('MALFORMED'); //  no terminator
    expect(await codeOf(() => decodeFrame(`${valid}.`))).toBe('MALFORMED'); //          two terminators: '.' is not base45
    expect(await codeOf(() => decodeFrame(`${valid}A`))).toBe('MALFORMED');
    expect(await codeOf(() => decodeFrame(`${FRAME_PREFIX.oneway}.`))).toBe('MALFORMED'); // nothing inside
    expect(await codeOf(() => decodeFrame(`${FRAME_PREFIX.oneway}0.`))).toBe('MALFORMED'); // a base45 length of 1 modulo 3
    expect(await codeOf(() => decodeFrame(`${FRAME_PREFIX.oneway}:::.`))).toBe('MALFORMED'); // a triplet above 65 535
  });

  it('is malformed when it is cut anywhere, in text as in bytes', async () => {
    const valid = encodeFrame(framesByKind.oneway);
    for (let length = FRAME_PREFIX.oneway.length; length < valid.length; length++) {
      const code = await codeOf(() => decodeFrame(valid.slice(0, length)));
      expect(code, `text cut to ${length}`).toBe('MALFORMED');
    }
    const bytes = encodeFrameBytes(framesByKind.oneway);
    for (let length = 1; length < bytes.length; length++) {
      const code = await codeOf(() => decodeFrameBytes(bytes.subarray(0, length)));
      expect(code, `bytes cut to ${length}`).toBe('MALFORMED');
    }
  });

  it('never fails with anything but a UMIS error, however it is damaged', async () => {
    let state = 12_345;
    const next = (bound: number): number => {
      state = (Math.imul(state, 1_103_515_245) + 12_345) >>> 0;
      return (state >>> 8) % bound;
    };
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
    for (const kind of FRAME_KINDS) {
      const valid = encodeFrame(framesByKind[kind]);
      const bytes = encodeFrameBytes(framesByKind[kind]);
      for (let round = 0; round < 60; round++) {
        const position = FRAME_PREFIX[kind].length + next(valid.length - FRAME_PREFIX[kind].length - 1);
        const character = alphabet.charAt(next(alphabet.length));
        const variants = [
          valid.slice(0, position) + character + valid.slice(position + 1),
          valid.slice(0, position) + valid.slice(position + 1),
          valid.slice(0, position) + character + valid.slice(position),
        ];
        for (const variant of variants) {
          const outcome = await codeOf(() => decodeFrame(variant));
          expect([undefined, 'MALFORMED'], `${kind}: ${variant.slice(0, 40)}`).toContain(outcome);
        }
        const damaged = Uint8Array.from(bytes);
        const index = 1 + next(damaged.length - 1);
        damaged[index] = (damaged[index] ?? 0) ^ (1 << next(8));
        const outcome = await codeOf(() => decodeFrameBytes(damaged));
        expect([undefined, 'MALFORMED']).toContain(outcome);
      }
    }
  });
});

describe('the container of a frame', () => {
  const oneWayPacked = (): Uint8Array => packedJws(oneWay);
  const sdJwtPacked = (): Uint8Array => packedSdJwt(olehPresentation);

  it('is read back from a container built by hand', () => {
    expect(decodeFrame(textOf('oneway', container(oneWayPacked()))).tokens).toEqual([oneWay]);
    expect(decodeFrame(textOf('response', container(sdJwtPacked()))).tokens).toEqual([olehPresentation]);
    expect(decodeFrameBytes(bytesFrame('mutual_init', container(packedJws(request), sdJwtPacked()))).tokens).toEqual([
      request,
      olehPresentation,
    ]);
  });

  it('is malformed with a wrong version, a wrong count, a wrong slot type or no key-binding JWT', async () => {
    const cases: Array<[string, FrameKind, Uint8Array]> = [
      ['version 2', 'oneway', concatBytes(byte(2), container(oneWayPacked()).subarray(1))],
      ['count 2 in a one-way frame', 'oneway', container(oneWayPacked(), oneWayPacked())],
      ['count 0', 'oneway', container()],
      ['count 1 in a mutual-init frame', 'mutual_init', container(packedJws(request))],
      ['an SD-JWT in the slot of a JWS', 'oneway', container(sdJwtPacked())],
      ['a JWS in the slot of an SD-JWT', 'response', container(oneWayPacked())],
      ['the slots of a mutual-init frame in reverse', 'mutual_init', container(sdJwtPacked(), packedJws(request))],
      ['an unknown token type', 'oneway', container(concatBytes(byte(3), oneWayPacked().subarray(1)))],
      ['no key-binding JWT', 'response', container(packedSdJwt(olehPresentation, 0))],
      ['a key-binding flag of 2', 'response', container(packedSdJwt(olehPresentation, 2))],
    ];
    for (const [label, kind, body] of cases) {
      expect(await decodeFailure(kind, body), label).toEqual(['MALFORMED', 'MALFORMED']);
    }
  });

  it('is malformed with trailing bytes, in a token or after the last one', async () => {
    const inside = concatBytes(oneWayPacked(), byte(0));
    expect(await decodeFailure('oneway', container(inside))).toEqual(['MALFORMED', 'MALFORMED']);
    const after = concatBytes(container(oneWayPacked()), byte(0));
    expect(await decodeFailure('oneway', after)).toEqual(['MALFORMED', 'MALFORMED']);
    const afterSdJwt = concatBytes(container(sdJwtPacked()), byte(0));
    expect(await decodeFailure('response', afterSdJwt)).toEqual(['MALFORMED', 'MALFORMED']);
  });

  it('is malformed with lengths that lie, are not shortest or leave a segment empty', async () => {
    const jws = oneWayPacked();
    const declaredLonger = concatBytes(byte(1), byte(1), varintEncode(jws.length + 5), jws);
    expect(await decodeFailure('oneway', declaredLonger)).toEqual(['MALFORMED', 'MALFORMED']);
    const declaredShorter = concatBytes(byte(1), byte(1), varintEncode(jws.length - 1), jws);
    expect(await decodeFailure('oneway', declaredShorter)).toEqual(['MALFORMED', 'MALFORMED']);
    const countNotShortest = concatBytes(byte(1), Uint8Array.of(0x81, 0x00), lengthPrefixed(jws));
    expect(await decodeFailure('oneway', countNotShortest)).toEqual(['MALFORMED', 'MALFORMED']);
    const lengthNotShortest = concatBytes(
      byte(1),
      byte(1),
      Uint8Array.of(0x80 | (jws.length & 0x7f), 0x80 | ((jws.length >> 7) & 0x7f), 0x00), // three bytes where two do
      jws,
    );
    expect(await decodeFailure('oneway', lengthNotShortest)).toEqual(['MALFORMED', 'MALFORMED']);
    const emptySegment = concatBytes(byte(1), byte(0), byte(0), byte(0)); //             three segments of no bytes
    expect(await decodeFailure('oneway', container(emptySegment))).toEqual(['MALFORMED', 'MALFORMED']);
    expect(await decodeFailure('oneway', new Uint8Array(0))).toEqual(['MALFORMED', 'MALFORMED']);
    expect(await decodeFailure('oneway', byte(1))).toEqual(['MALFORMED', 'MALFORMED']);
  });
});

describe('the size of a frame', () => {
  it('stays within the capacity of a QR code on the way out: at the limit it passes, one step beyond it fails', () => {
    // A fixed signature keeps the sizes reproducible: a real one is random and compresses differently every time.
    const signature = base64urlEncode(pseudoRandom(64, 7));
    const frameWith = (padding: number): string => {
      const header = segment({ alg: 'ES256', typ: TYP.oneWay });
      const payload = segment({ ...ONE_WAY, pad: base64urlEncode(pseudoRandom(padding)) });
      return encodeFrame({ kind: 'oneway', tokens: [`${header}.${payload}.${signature}`] });
    };
    let largest = 0;
    for (let padding = 2_400; ; padding += 1) {
      let length: number;
      try {
        length = frameWith(padding).length;
      } catch (error) {
        expect(error).toBeInstanceOf(UmisError);
        expect((error as UmisError).code).toBe('INVALID_ARGUMENT');
        break;
      }
      expect(length).toBeLessThanOrEqual(LIMITS.qrMaxChars);
      largest = length;
    }
    expect(largest).toBeGreaterThanOrEqual(LIMITS.qrMaxChars - 8); //   a step of one more byte adds up to five characters
  });

  it('refuses a container beyond the cap for the bytes as well, although a BLE link has no QR limit', async () => {
    const token = await forgeJws(
      world.oleh,
      { alg: 'ES256', typ: TYP.oneWay },
      { pad: base64urlEncode(pseudoRandom(17_000)) },
    );
    expect(await codeOf(() => encodeFrameBytes({ kind: 'oneway', tokens: [token] }))).toBe('INVALID_ARGUMENT');
    const justUnder = await forgeJws(
      world.oleh,
      { alg: 'ES256', typ: TYP.oneWay },
      { pad: base64urlEncode(pseudoRandom(9_000)) },
    );
    const bytes = encodeFrameBytes({ kind: 'oneway', tokens: [justUnder] });
    expect(decodeFrameBytes(bytes).tokens).toEqual([justUnder]);
    expect(await codeOf(() => encodeFrame({ kind: 'oneway', tokens: [justUnder] }))).toBe('INVALID_ARGUMENT'); //  too long for a QR
  });

  it('is measured before anything is decoded: a scan longer than a QR code holds is malformed without being read', async () => {
    const token = await forgeJws(
      world.oleh,
      { alg: 'ES256', typ: TYP.oneWay },
      { pad: base64urlEncode(pseudoRandom(3_200)) },
    );
    const body = container(packedJws(token));
    const long = textOf('oneway', body);
    expect(long.length).toBeGreaterThan(LIMITS.qrMaxChars);
    expect(await codeOf(() => decodeFrame(long))).toBe('MALFORMED');
    expect(decodeFrameBytes(bytesFrame('oneway', body)).tokens).toEqual([token]); // the same content is sound in bytes
  });

  it('stops inflating at the cap: a container that inflates to 1 MiB is malformed and costs a bounded amount of memory', async () => {
    const MiB = 1024 * 1024;
    const bomb = deflateSync(new Uint8Array(MiB), { level: 9 });
    expect(bomb.length).toBeLessThan(2_048);
    expect(`${FRAME_PREFIX.oneway}${base45Encode(bomb)}.`.length).toBeLessThan(LIMITS.qrMaxChars);
    expect(await codeOf(() => decodeFrame(`${FRAME_PREFIX.oneway}${base45Encode(bomb)}.`))).toBe('MALFORMED');
    expect(await codeOf(() => decodeFrameBytes(concatBytes(byte(FRAME_KIND_CODE.oneway), bomb)))).toBe('MALFORMED');

    const stopped = inflateCapped(bomb, LIMITS.frameMaxBytes);
    expect(stopped.exceeded).toBe(true);
    if (stopped.exceeded) {
      // One 256-byte piece of input can expand to 264 192 bytes at most (DEFLATE expands 1 032 times at most).
      expect(stopped.produced).toBeGreaterThan(LIMITS.frameMaxBytes);
      expect(stopped.produced).toBeLessThanOrEqual(LIMITS.frameMaxBytes + 256 * 1_032);
    }

    // 32 MiB of zeros compress to about 32 KiB; reading them all would be 2 000 times the cap.
    const huge = inflateCapped(deflateSync(new Uint8Array(32 * MiB), { level: 9 }), LIMITS.frameMaxBytes);
    expect(huge.exceeded).toBe(true);
    if (huge.exceeded) expect(huge.produced).toBeLessThanOrEqual(LIMITS.frameMaxBytes + 256 * 1_032);
  });

  it('counts the cap in inflated bytes, inclusive', () => {
    const atCap = inflateCapped(deflateSync(new Uint8Array(LIMITS.frameMaxBytes), { level: 9 }), LIMITS.frameMaxBytes);
    expect(atCap.exceeded).toBe(false);
    if (!atCap.exceeded) expect(atCap.bytes).toHaveLength(LIMITS.frameMaxBytes);
    const pastCap = inflateCapped(
      deflateSync(new Uint8Array(LIMITS.frameMaxBytes + 1), { level: 9 }),
      LIMITS.frameMaxBytes,
    );
    expect(pastCap).toEqual({ exceeded: true, produced: LIMITS.frameMaxBytes + 1 });
  });

  it('refuses compressed data that no encoder of this package could have made', async () => {
    const tooLong = concatBytes(byte(FRAME_KIND_CODE.oneway), pseudoRandom(2 * LIMITS.frameMaxBytes + 1));
    expect(await codeOf(() => decodeFrameBytes(tooLong))).toBe('MALFORMED');
    expect(await codeOf(() => decodeFrameBytes(concatBytes(byte(FRAME_KIND_CODE.oneway), pseudoRandom(64))))).toBe(
      'MALFORMED',
    );
    expect(await codeOf(() => decodeFrameBytes(byte(FRAME_KIND_CODE.oneway)))).toBe('MALFORMED'); //                 no data
  });
});

describe('what a frame refuses to carry', () => {
  const fails = async (frame: unknown): Promise<string | undefined> => codeOf(() => encodeFrame(frame as Frame));
  const failsAsBytes = async (frame: unknown): Promise<string | undefined> =>
    codeOf(() => encodeFrameBytes(frame as Frame));

  it('does not carry a token in the wrong form for its slot, or the wrong number of tokens', async () => {
    const frames: unknown[] = [
      { kind: 'oneway', tokens: [] },
      { kind: 'oneway', tokens: [oneWay, oneWay] },
      { kind: 'mutual_init', tokens: [mutualRequest] },
      { kind: 'mutual_init', tokens: [olehPresentation, mutualRequest] },
      { kind: 'oneway', tokens: [olehPresentation] }, //                      an SD-JWT where a JWS belongs
      { kind: 'response', tokens: [oneWay] }, //                              a JWS where an SD-JWT belongs
      { kind: 'response', tokens: [world.olehCredential] }, //                an SD-JWT without a key-binding JWT
      { kind: 'response', tokens: [`${olehPresentation}~`] }, //              a trailing empty piece
      { kind: 'response', tokens: ['~~'] },
      { kind: 'oneway', tokens: [123] },
      { kind: 'oneway', tokens: [undefined] },
      { kind: 'oneway', tokens: 'not a list' },
      { kind: 'oneway' },
      { kind: 'beacon', tokens: [oneWay] },
      { tokens: [oneWay] },
      null,
      undefined,
      'UMIS1O:',
    ];
    for (const frame of frames) {
      expect(await fails(frame), JSON.stringify(frame)?.slice(0, 60)).toBe('INVALID_ARGUMENT');
      expect(await failsAsBytes(frame), JSON.stringify(frame)?.slice(0, 60)).toBe('INVALID_ARGUMENT');
    }
  });

  it('does not carry a segment whose base64url is not the canonical text of its bytes', async () => {
    const [header, payload, signature] = oneWay.split('.') as [string, string, string];
    const lastValue = signature.charAt(signature.length - 1);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const other = alphabet.charAt((alphabet.indexOf(lastValue) + 1) % 64);
    const forged = [
      `${header}.${payload}.${signature.slice(0, -1)}${other}`, //            stray bits after the last byte
      `${header}.${payload}.${signature}=`, //                                 padding
      `${header}.${payload}.${signature.slice(0, -2)}+/`, //                   the standard alphabet
      `${header}.${payload}.${signature.slice(0, -1)}`, //                     a length of 1 modulo 4 is not base64url
      `${header}..${signature}`, //                                            an empty segment
      `${header}.${payload}`, //                                               two segments
      `${header}.${payload}.${signature}.${signature}`, //                     four segments
      `${header}.${payload}. ${signature}`, //                                 a space
    ];
    for (const token of forged) {
      expect(await fails({ kind: 'oneway', tokens: [token] }), token.slice(-12)).toBe('INVALID_ARGUMENT');
    }

    const pieces = olehPresentation.split('~');
    const withDisclosure = (disclosure: string): string => [pieces[0], disclosure, pieces[pieces.length - 1]].join('~');
    expect(await fails({ kind: 'response', tokens: [withDisclosure('AB')] })).toBe('INVALID_ARGUMENT'); //  stray bits
    expect(await fails({ kind: 'response', tokens: [withDisclosure('A')] })).toBe('INVALID_ARGUMENT'); //   1 modulo 4
    expect(await fails({ kind: 'response', tokens: [withDisclosure('')] })).toBe('INVALID_ARGUMENT'); //    empty
    const canonical = withDisclosure('AA'); //                                                              one zero byte
    expect(decodeFrame(encodeFrame({ kind: 'response', tokens: [canonical] })).tokens).toEqual([canonical]);
  });

  it('does not carry a frame longer than a QR code can show, however well it compresses or not', async () => {
    const token = await forgeJws(
      world.oleh,
      { alg: 'ES256', typ: TYP.oneWay },
      { pad: base64urlEncode(pseudoRandom(4_000)) },
    );
    expect(await fails({ kind: 'oneway', tokens: [token] })).toBe('INVALID_ARGUMENT');
  });
});

// ---------------------------------------------------------------------------------------------------------------
// presentation requests
// ---------------------------------------------------------------------------------------------------------------

describe('presentation requests', () => {
  let signer: Signer;
  beforeAll(async () => {
    signer = await generateSigner({ crypto: webCryptoProvider, kid: 'device-warehouse-b' });
  });

  /** Signs a request that breaks the rules, which `signPresentationRequest` would refuse, with the header of a real one. */
  const forged = (payload: object, header: object = { alg: 'ES256', typ: TYP.request, kid: 'device-warehouse-b' }) =>
    forgeJws(signer, header, payload);
  const decodeFails = async (payload: object, header?: object): Promise<string | undefined> => {
    const jws = await forged(payload, header);
    return codeOf(() => decodePresentationRequest(jws));
  };
  const withPayload = (changes: Record<string, unknown>): Record<string, unknown> => {
    const copy: Record<string, unknown> = { ...REQUEST_PAYLOAD };
    for (const [name, value] of Object.entries(changes)) {
      if (value === undefined) delete copy[name];
      else copy[name] = value;
    }
    return copy;
  };

  it('is signed with the key of the requester and read back with every field', async () => {
    const jws = await signPresentationRequest(REQUEST_PAYLOAD, signer);
    const decoded = decodePresentationRequest(jws);
    expect(decoded.header).toEqual({ alg: 'ES256', typ: 'umis-req+jwt', kid: 'device-warehouse-b' });
    expect(decoded.payload).toEqual(REQUEST_PAYLOAD);
    const verified = await verifyJws(jws, { typ: TYP.request, key: signer.publicJwk });
    expect(verified.payload).toEqual(REQUEST_PAYLOAD);

    const minimal: PresentationRequestPayloadV1 = {
      v: 1,
      nonce: NONCE,
      aud: 'urn:umis:wallet:oleh',
      iat: NOW,
      exp: NOW + 1,
      vct: [VCT.orgMember],
      claims: ['org'],
    };
    expect(decodePresentationRequest(await signPresentationRequest(minimal, signer)).payload).toEqual(minimal);
    const mutual = decodePresentationRequest(await signPresentationRequest({ ...minimal, mutual: true }, world.oleh));
    expect(mutual.payload.mutual).toBe(true);
    expect(mutual.header.kid).toBe(world.oleh.kid);
  });

  it('lives for more than 0 and at most 120 seconds', async () => {
    const ttl = (seconds: number) => withPayload({ exp: REQUEST_PAYLOAD.iat + seconds });
    expect(await decodeFails(ttl(120))).toBeUndefined();
    expect(await decodeFails(ttl(1))).toBeUndefined();
    expect(await decodeFails(ttl(121))).toBe('MALFORMED');
    expect(await decodeFails(ttl(0))).toBe('MALFORMED');
    expect(await decodeFails(ttl(-5))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ iat: 'now' }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ exp: null }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ iat: undefined }))).toBe('MALFORMED');
    expect(
      await codeOf(() => signPresentationRequest({ ...REQUEST_PAYLOAD, exp: REQUEST_PAYLOAD.iat + 121 }, signer)),
    ).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => signPresentationRequest({ ...REQUEST_PAYLOAD, exp: REQUEST_PAYLOAD.iat }, signer))).toBe(
      'INVALID_ARGUMENT',
    );
  });

  it('carries a nonce of 16 random bytes in canonical base64url', async () => {
    const sixteen = base64urlEncode(pseudoRandom(16));
    const fifteen = base64urlEncode(pseudoRandom(15));
    expect(sixteen).toHaveLength(22);
    expect(await decodeFails(withPayload({ nonce: sixteen }))).toBeUndefined();
    expect(await decodeFails(withPayload({ nonce: base64urlEncode(pseudoRandom(32)) }))).toBeUndefined();
    expect(await decodeFails(withPayload({ nonce: fifteen }))).toBe('MALFORMED'); //                  20 characters
    expect(await decodeFails(withPayload({ nonce: sixteen.slice(0, 21) }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ nonce: `${'A'.repeat(21)}B` }))).toBe('MALFORMED'); //     stray bits
    expect(await decodeFails(withPayload({ nonce: `${sixteen.slice(0, 21)}+` }))).toBe('MALFORMED'); //  wrong alphabet
    expect(await decodeFails(withPayload({ nonce: `${sixteen}=` }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ nonce: '' }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ nonce: 12_345 }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ nonce: undefined }))).toBe('MALFORMED');
    expect(await codeOf(() => signPresentationRequest({ ...REQUEST_PAYLOAD, nonce: fifteen }, signer))).toBe(
      'INVALID_ARGUMENT',
    );
  });

  it('asks for UMIS claims only, and a request for authority asks for the delegation too', async () => {
    expect(await decodeFails(withPayload({ authority: undefined, claims: ['authority'] }))).toBeUndefined();
    expect(await decodeFails(withPayload({ claims: ['org', 'role', 'authority'] }))).toBe('MALFORMED'); // no delegation
    expect(await decodeFails(withPayload({ claims: ['org', 'role', 'delegation'] }))).toBe('MALFORMED'); // no authority
    expect(await decodeFails(withPayload({ claims: ['authority', 'delegation'] }))).toBeUndefined();
    expect(await decodeFails(withPayload({ authority: undefined, claims: ['org'] }))).toBeUndefined();
    expect(await decodeFails(withPayload({ claims: [] }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ claims: 'org' }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ claims: ['org', 'email'] }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ claims: ['org', 7] }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ claims: ['__proto__'] }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ claims: undefined }))).toBe('MALFORMED');
    expect(
      await codeOf(() => signPresentationRequest({ ...REQUEST_PAYLOAD, claims: ['org', 'authority'] }, signer)),
    ).toBe('INVALID_ARGUMENT');
  });

  it('names the credential types it accepts and the authority it asks about', async () => {
    expect(await decodeFails(withPayload({ vct: [] }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ vct: [''] }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ vct: VCT.orgMember }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ vct: undefined }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ aud: '' }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ aud: undefined }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ v: 2 }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ v: '1' }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ v: undefined }))).toBe('MALFORMED');
    for (const authority of [
      { action: 'receive_materials', resource: 'rebar', amount: -1, unit: 't' },
      { action: 'receive_materials', resource: 'rebar', amount: '10', unit: 't' },
      { action: 'receive_materials', resource: 'rebar', unit: 't' },
      { action: '', resource: 'rebar', amount: 1, unit: 't' },
      { action: 'receive_materials', resource: 'rebar', amount: 1 },
      { action: 'receive_materials', resource: 'rebar', amount: 1, unit: 't', object: '' },
      'ten tonnes',
      [],
    ]) {
      expect(await decodeFails(withPayload({ authority })), JSON.stringify(authority)).toBe('MALFORMED');
    }
    expect(
      await decodeFails(
        withPayload({ authority: { action: 'receive_materials', resource: 'rebar', amount: 0, unit: 't' } }),
      ),
    ).toBeUndefined();
  });

  it('keeps the optional policy, verifier and mutual members to their shapes', async () => {
    expect(await decodeFails(withPayload({ policy: { id: 'p', v: 0, risk: 'highest' } }))).toBeUndefined();
    for (const policy of [
      { id: 'p', v: -1, risk: 'low' },
      { id: 'p', v: 1.5, risk: 'low' },
      { id: 'p', v: '1', risk: 'low' },
      { id: 'p', v: 1, risk: 'extreme' },
      { id: 'p', v: 1 },
      { v: 1, risk: 'low' },
      'warehouse',
    ]) {
      expect(await decodeFails(withPayload({ policy })), JSON.stringify(policy)).toBe('MALFORMED');
    }
    expect(await decodeFails(withPayload({ verifier: { name: 'Склад Б' } }))).toBeUndefined();
    expect(await decodeFails(withPayload({ verifier: {} }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ verifier: { name: 'Склад Б', org: 5 } }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ mutual: 'yes' }))).toBe('MALFORMED');
    expect(await decodeFails(withPayload({ mutual: false }))).toBeUndefined();
  });

  it('is of the type umis-req+jwt, with a header of the usual members only', async () => {
    const payload = withPayload({});
    expect(await decodeFails(payload, { alg: 'ES256', typ: TYP.oneWay })).toBe('UNSUPPORTED_FORMAT');
    expect(await decodeFails(payload, { alg: 'ES256', typ: 'JWT' })).toBe('UNSUPPORTED_FORMAT');
    expect(await decodeFails(payload, { alg: 'ES256' })).toBe('UNSUPPORTED_FORMAT');
    expect(await decodeFails(payload, { alg: 'none', typ: TYP.request })).toBe('UNSUPPORTED_FORMAT');
    expect(await decodeFails(payload, { alg: 'ES256', typ: TYP.request, crit: ['exp'] })).toBe('MALFORMED');
    expect(await decodeFails(payload, { alg: 'ES256', typ: TYP.request, x5u: 'https://issuer.example/key' })).toBe(
      'MALFORMED',
    );
    expect(await decodeFails(payload, { alg: 'ES256', typ: TYP.request, jwk: signer.publicJwk })).toBeUndefined();
    expect(await codeOf(() => decodePresentationRequest('not a token'))).toBe('MALFORMED');
    expect(await codeOf(() => decodePresentationRequest(`${segment({})}.${segment({})}.${segment('x')}`))).toBe(
      'UNSUPPORTED_FORMAT',
    );
  });

  it('comes back as a clean copy: members the profile does not know are not passed on', async () => {
    const known = withPayload({ exp: REQUEST_PAYLOAD.iat + 30, authority: undefined, claims: ['org'] });
    const text = JSON.stringify({ ...known, injected: { admin: true } }).slice(0, -1) + ',"__proto__":{"admin":true}}';
    const jws = await forgeJws(signer, { alg: 'ES256', typ: TYP.request, kid: 'device-warehouse-b' }, text);
    const decoded = decodePresentationRequest(jws).payload;
    expect(Object.keys(decoded).sort()).toEqual([
      'aud',
      'claims',
      'exp',
      'iat',
      'nonce',
      'policy',
      'v',
      'vct',
      'verifier',
    ]);
    expect(Object.getPrototypeOf(decoded)).toBe(Object.prototype);
    expect((decoded as unknown as Record<string, unknown>).admin).toBeUndefined();

    const nested = withPayload({ authority: { action: 'a', resource: 'r', amount: 1, unit: 't', hidden: 1 } });
    expect(decodePresentationRequest(await forged(nested)).payload.authority).toEqual({
      action: 'a',
      resource: 'r',
      amount: 1,
      unit: 't',
    });
  });
});

// ---------------------------------------------------------------------------------------------------------------
// what a scanned QR code is
// ---------------------------------------------------------------------------------------------------------------

describe('classifying a scanned QR code', () => {
  it('names all nine kinds', () => {
    const expected: Array<[string, QrKind]> = [
      ['openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1', 'credential_offer'],
      [
        'openid4vp://authorize?client_id=urn%3Aumis%3Averifier%3Awarehouse-b&request_uri=https%3A%2F%2Fissuer.example%2Fr',
        'oid4vp_request',
      ],
      [encodeFrame(framesByKind.oneway), 'umis_oneway'],
      [encodeFrame(framesByKind.full), 'umis_full'],
      [encodeFrame(framesByKind.request), 'umis_request'],
      [encodeFrame(framesByKind.response), 'umis_response'],
      [encodeFrame(framesByKind.mutual_init), 'umis_mutual_init'],
      [encodeFrame(framesByKind.mutual_reply), 'umis_mutual_reply'],
      ['https://example.com/', 'unknown'],
    ];
    for (const [text, kind] of expected) expect(classifyQr(text), text.slice(0, 40)).toBe(kind);
    expect(new Set(expected.map(([, kind]) => kind)).size).toBe(9);
  });

  it('looks at the start of the text only, ignores white space around it and the case of a URI scheme', () => {
    expect(classifyQr('  \n openid4vp://authorize?x=1\r\n')).toBe('oid4vp_request');
    expect(classifyQr('OPENID4VP://AUTHORIZE?X=1')).toBe('oid4vp_request'); //                        QR alphanumeric mode is upper case
    expect(classifyQr('OPENID-CREDENTIAL-OFFER://?CREDENTIAL_OFFER_URI=HTTPS')).toBe('credential_offer');
    expect(classifyQr('UMIS1P:anything at all, it is not read')).toBe('umis_response');
    expect(classifyQr(`\t${FRAME_PREFIX.mutual_reply}`)).toBe('umis_mutual_reply');
  });

  it('does not take other text for a UMIS or OpenID code', () => {
    for (const text of [
      '',
      '   ',
      'umis1p:abc.',
      'UMIS2P:abc.',
      'UMIS1Z:abc.',
      'openid4vp:/authorize',
      'openid4vp:authorize',
      'x openid4vp://',
      'http://openid4vp://',
      'WIFI:T:WPA;S:net;;',
      'BEGIN:VCARD',
    ]) {
      expect(classifyQr(text), text).toBe('unknown');
    }
    expect(classifyQr(undefined as unknown as string)).toBe('unknown');
    expect(classifyQr(null as unknown as string)).toBe('unknown');
    expect(classifyQr(5 as unknown as string)).toBe('unknown');
  });
});
