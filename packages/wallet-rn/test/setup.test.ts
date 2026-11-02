import { randomFillSync } from 'node:crypto';
import { TextDecoder as NativeTextDecoder } from 'node:util';
import {
  UmisError,
  getDefaultCrypto,
  randomId,
  setDefaultCrypto,
  utf8Decode,
  utf8Encode,
  webCryptoProvider,
} from '@umis/core';
import { afterEach, describe, expect, it } from 'vitest';
import { installRnPolyfills, setupCrypto } from '../src/index.js';
import * as expoCrypto from './mocks/expo-crypto.js';

const globals = globalThis as Record<string, unknown>;
const saved = {
  crypto: Object.getOwnPropertyDescriptor(globalThis, 'crypto'),
  TextDecoder: Object.getOwnPropertyDescriptor(globalThis, 'TextDecoder'),
};

function replaceGlobal(name: 'crypto' | 'TextDecoder', value: unknown): void {
  Object.defineProperty(globalThis, name, { value, writable: true, configurable: true });
}

afterEach(() => {
  for (const name of ['crypto', 'TextDecoder'] as const) {
    const original = saved[name];
    if (original === undefined) delete globals[name];
    else Object.defineProperty(globalThis, name, original);
  }
  setDefaultCrypto(webCryptoProvider);
  expoCrypto.reset();
});

/** A random source that remembers how many bytes it was asked for. */
function countingSource(): { requests: number[]; getRandomValues: <T extends Uint8Array>(array: T) => T } {
  const requests: number[] = [];
  return {
    requests,
    getRandomValues: <T extends Uint8Array>(array: T): T => {
      requests.push(array.length);
      return randomFillSync(array);
    },
  };
}

describe('setupCrypto', () => {
  it('uses WebCrypto where the runtime has it and makes it the default', () => {
    const source = countingSource();
    const provider = setupCrypto({ getRandomValues: source.getRandomValues });
    expect(provider).toBe(webCryptoProvider);
    expect(getDefaultCrypto()).toBe(provider);
    expect(source.requests).toEqual([]);
  });

  it('uses @noble with the injected random source when the runtime has no crypto.subtle', async () => {
    replaceGlobal('crypto', undefined);
    const source = countingSource();
    const provider = setupCrypto({ getRandomValues: source.getRandomValues });
    expect(provider.name).toBe('noble');
    expect(getDefaultCrypto()).toBe(provider);

    // the SDK works end to end without any global: keys, signatures and identifiers all draw from the injected source
    const signer = await provider.generateSigner();
    const data = utf8Encode('header.payload');
    expect(await provider.verifyEs256(signer.publicJwk, data, await signer.sign(data))).toBe(true);
    expect(randomId(16)).toHaveLength(22);
    expect(source.requests).toEqual([48, 16]);
  });

  it('treats a global crypto that only fills random values as no WebCrypto', () => {
    const source = countingSource();
    replaceGlobal('crypto', { getRandomValues: source.getRandomValues });
    expect(setupCrypto({ getRandomValues: source.getRandomValues }).name).toBe('noble');
  });

  it('takes the random numbers of expo-crypto when none are given', () => {
    replaceGlobal('crypto', undefined);
    const provider = setupCrypto();
    provider.getRandomValues(new Uint8Array(16));
    expect(expoCrypto.requests).toEqual([16]);
  });
});

describe('installRnPolyfills', () => {
  it('adds a TextDecoder only when the runtime has none, and only once', () => {
    const native = globalThis.TextDecoder;
    installRnPolyfills();
    expect(globalThis.TextDecoder).toBe(native);

    replaceGlobal('TextDecoder', undefined);
    installRnPolyfills();
    const installed = globalThis.TextDecoder;
    expect(installed).toBeTypeOf('function');
    expect(installed).not.toBe(native);

    installRnPolyfills();
    expect(globalThis.TextDecoder).toBe(installed);
  });

  it('installs a UTF-8 decoder that rejects malformed input when asked to', () => {
    replaceGlobal('TextDecoder', undefined);
    installRnPolyfills();

    const strict = new TextDecoder('utf-8', { fatal: true });
    const text = 'Підрядник А — Коворкінг В 🚧';
    expect(strict.decode(utf8Encode(text))).toBe(text);
    expect(strict.decode(utf8Encode('я'.repeat(50_000) + '🚧'.repeat(10_000)))).toBe(
      'я'.repeat(50_000) + '🚧'.repeat(10_000),
    );
    const malformed = [[0xc0, 0x80], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xe2, 0x82], [0x80], [0xff]];
    for (const bytes of malformed) expect(() => strict.decode(Uint8Array.from(bytes))).toThrow(TypeError);
    expect(() => new TextDecoder('utf-16')).toThrow(RangeError);

    // without `fatal` one U+FFFD stands for each broken sequence; a leading byte order mark is dropped unless kept
    expect(new TextDecoder().decode(Uint8Array.of(0x61, 0xe2, 0x82, 0x62))).toBe('a�b');
    expect(new TextDecoder().decode(Uint8Array.of(0xef, 0xbb, 0xbf, 0x41))).toBe('A');
    expect(new TextDecoder('utf-8', { ignoreBOM: true }).decode(Uint8Array.of(0xef, 0xbb, 0xbf, 0x41))).toBe('﻿A');

    // the codec of the SDK reads through it, and keeps refusing overlong forms
    expect(utf8Decode(utf8Encode('Підрядник А'))).toBe('Підрядник А');
    expect(() => utf8Decode(Uint8Array.of(0xc0, 0x80))).toThrow(UmisError);
  });

  it('decodes like the decoder of the runtime on random byte sequences', () => {
    replaceGlobal('TextDecoder', undefined);
    installRnPolyfills();
    const Polyfill = globalThis.TextDecoder;

    // bytes at the edges of every range of Table 3-7 of the Unicode Standard
    const edges = [
      0x00, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xec, 0xed, 0xee, 0xef,
      0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xf8, 0xfe, 0xff,
    ];
    let state = 0x9e3779b9;
    const next = (): number => {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return state >>> 0;
    };
    const attempt = (decode: () => string): string | undefined => {
      try {
        return decode();
      } catch {
        return undefined;
      }
    };

    const mismatches: string[] = [];
    for (let run = 0; run < 30_000; run++) {
      const bytes = Uint8Array.from({ length: next() % 9 }, () => edges[next() % edges.length]!);
      for (const fatal of [false, true]) {
        const options = { fatal, ignoreBOM: true };
        const expected = attempt(() => new NativeTextDecoder('utf-8', options).decode(bytes));
        const actual = attempt(() => new Polyfill('utf-8', options).decode(bytes));
        if (actual !== expected)
          mismatches.push(`${fatal ? 'fatal' : 'lenient'} ${Buffer.from(bytes).toString('hex')}`);
      }
    }
    expect(mismatches).toEqual([]);
  });
});
