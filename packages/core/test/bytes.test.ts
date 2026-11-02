import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  UmisError,
  base32Encode,
  base45Decode,
  base45Encode,
  base64urlDecode,
  base64urlEncode,
  bytesEqual,
  concatBytes,
  hexDecode,
  hexEncode,
  utf8Decode,
  utf8Encode,
  varintDecode,
  varintEncode,
} from '../src/index.js';

interface Base45Vectors {
  encode: Array<{ text: string; base45: string }>;
  decodeOnly: Array<{ base45: string; hex: string }>;
  reject: Array<{ base45: string; reason: string }>;
}

const base45Vectors = JSON.parse(
  readFileSync(new URL('../../../test-vectors/rfc9285-base45.json', import.meta.url), 'utf8'),
) as Base45Vectors;

/** The code of the UmisError that `run` throws; anything else is reported as such so the assertion shows it. */
function failureOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

/** Reproducible pseudo-random bytes (xorshift32), so that a failing length can be replayed. */
function sampleBytes(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let state = (seed * 2654435761) >>> 0 || 1;
  for (let i = 0; i < length; i++) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[i] = state & 0xff;
  }
  return out;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('base45 (RFC 9285)', () => {
  it('reproduces the RFC examples in both directions', () => {
    for (const { text, base45 } of base45Vectors.encode) {
      expect(base45Encode(utf8Encode(text))).toBe(base45);
      expect(utf8Decode(base45Decode(base45))).toBe(text);
    }
    for (const { base45, hex } of base45Vectors.decodeOnly) {
      expect(hexEncode(base45Decode(base45))).toBe(hex);
    }
  });

  it('round-trips every length up to 64 bytes and emits only QR alphanumeric characters', () => {
    for (let length = 0; length <= 64; length++) {
      const bytes = sampleBytes(length, length + 1);
      const text = base45Encode(bytes);
      expect(text).toMatch(/^[0-9A-Z $%*+\-./:]*$/);
      expect(bytesEqual(base45Decode(text), bytes)).toBe(true);
    }
  });

  it('rejects what the RFC forbids with MALFORMED', () => {
    for (const { base45, reason } of base45Vectors.reject) {
      expect(
        failureOf(() => base45Decode(base45)),
        reason,
      ).toBe('MALFORMED');
    }
  });
});

describe('base64url (RFC 4648 section 5)', () => {
  it('matches the platform encoder and uses the URL-safe alphabet', () => {
    for (let length = 0; length <= 64; length++) {
      const bytes = sampleBytes(length, 100 + length);
      const text = base64urlEncode(bytes);
      const reference = btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      expect(text).toBe(reference);
      expect(bytesEqual(base64urlDecode(text), bytes)).toBe(true);
    }
    const everyByte = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(base64urlEncode(everyByte)).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(bytesEqual(base64urlDecode(base64urlEncode(everyByte)), everyByte)).toBe(true);
  });

  it('accepts one text per byte string and rejects every other spelling with MALFORMED', () => {
    expect(hexEncode(base64urlDecode('QQ'))).toBe('41');
    expect(base64urlDecode('')).toHaveLength(0);
    const spellings: Record<string, string> = {
      padding: 'QQ==',
      'standard alphabet plus': 'Q+',
      'standard alphabet slash': 'QQ/A',
      'non-zero trailing bits after one byte': 'QR',
      'non-zero trailing bits after two bytes': 'QUJ',
      'length 1 modulo 4': 'QUJDR',
      'single character': 'Q',
      'leading space': ' QQ',
      'trailing newline': 'QQ\n',
      'non-ASCII character': 'QQé',
    };
    for (const [why, text] of Object.entries(spellings)) {
      expect(
        failureOf(() => base64urlDecode(text)),
        why,
      ).toBe('MALFORMED');
    }
  });
});

describe('varint (unsigned LEB128, at most three bytes)', () => {
  it('round-trips at the boundaries', () => {
    const cases: Array<[number, number[]]> = [
      [0, [0x00]],
      [127, [0x7f]],
      [128, [0x80, 0x01]],
      [16_383, [0xff, 0x7f]],
      [16_384, [0x80, 0x80, 0x01]],
      [2 ** 21 - 1, [0xff, 0xff, 0x7f]],
    ];
    for (const [value, encoded] of cases) {
      expect([...varintEncode(value)]).toEqual(encoded);
      const framed = Uint8Array.from([0xaa, ...encoded, 0xbb]);
      expect(varintDecode(framed, 1)).toEqual({ value, next: 1 + encoded.length });
    }
  });

  it('refuses values that do not fit and encodings that are cut off or too long', () => {
    for (const value of [2 ** 21, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(
        failureOf(() => varintEncode(value)),
        String(value),
      ).toBe('INVALID_ARGUMENT');
    }
    expect(failureOf(() => varintDecode(Uint8Array.of(0x80, 0x80, 0x80, 0x01), 0))).toBe('MALFORMED');
    expect(failureOf(() => varintDecode(Uint8Array.of(0x80), 0))).toBe('MALFORMED');
    expect(failureOf(() => varintDecode(new Uint8Array(0), 0))).toBe('MALFORMED');
    expect(failureOf(() => varintDecode(Uint8Array.of(0x01), 1))).toBe('MALFORMED');
  });
});

describe('base32, hex and byte helpers', () => {
  it('encodes the RFC 4648 section 10 vectors without padding', () => {
    const vectors: Array<[string, string]> = [
      ['', ''],
      ['f', 'MY'],
      ['fo', 'MZXQ'],
      ['foo', 'MZXW6'],
      ['foob', 'MZXW6YQ'],
      ['fooba', 'MZXW6YTB'],
      ['foobar', 'MZXW6YTBOI'],
    ];
    for (const [text, expected] of vectors) expect(base32Encode(utf8Encode(text))).toBe(expected);
  });

  it('writes lowercase hex, reads either case and rejects the rest', () => {
    expect(hexEncode(Uint8Array.of(0x00, 0x0f, 0xa5, 0xff))).toBe('000fa5ff');
    expect([...hexDecode('000FA5ff')]).toEqual([0x00, 0x0f, 0xa5, 0xff]);
    for (const text of ['abc', 'zz', '0x00', ' 00'])
      expect(
        failureOf(() => hexDecode(text)),
        text,
      ).toBe('MALFORMED');
  });

  it('concatenates and compares', () => {
    expect([...concatBytes(Uint8Array.of(1), new Uint8Array(0), Uint8Array.of(2, 3))]).toEqual([1, 2, 3]);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 0))).toBe(false);
  });
});

describe('UTF-8', () => {
  const invalid: Record<string, number[]> = {
    'byte that never occurs': [0xff],
    'stray continuation byte': [0x80],
    'overlong NUL': [0xc0, 0x80],
    'overlong three-byte form': [0xe0, 0x80, 0x80],
    'UTF-16 surrogate': [0xed, 0xa0, 0x80],
    'above U+10FFFF': [0xf4, 0x90, 0x80, 0x80],
    'truncated three-byte sequence': [0xe2, 0x82],
    'truncated four-byte sequence at the end': [0x61, 0xf0, 0x9f, 0x98],
  };
  const valid = [
    '',
    'plain ASCII',
    'Підрядник А',
    '€ and 日本語',
    '😀 outside the BMP',
    'a\u0000b',
    '﻿byte order mark kept',
  ];

  it('decodes strictly with TextDecoder and with the built-in fallback, with identical results', () => {
    for (const mode of ['TextDecoder', 'fallback'] as const) {
      if (mode === 'fallback') vi.stubGlobal('TextDecoder', undefined);
      for (const text of valid) expect(utf8Decode(new TextEncoder().encode(text)), `${mode}: ${text}`).toBe(text);
      for (const [why, bytes] of Object.entries(invalid)) {
        expect(
          failureOf(() => utf8Decode(Uint8Array.from(bytes))),
          `${mode}: ${why}`,
        ).toBe('MALFORMED');
      }
      vi.unstubAllGlobals();
    }
  });

  it('encodes with the built-in fallback exactly like TextEncoder, lone surrogates included', () => {
    const samples = [...valid, 'lone high \ud800 and low \udc00 surrogates', 'pair 😀 intact'];
    const expected = samples.map((text) => new TextEncoder().encode(text));
    vi.stubGlobal('TextEncoder', undefined);
    samples.forEach((text, index) => expect(bytesEqual(utf8Encode(text), expected[index]!), text).toBe(true));
  });
});
