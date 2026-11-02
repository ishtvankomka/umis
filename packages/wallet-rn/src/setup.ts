import { setDefaultCrypto, webCryptoProvider } from '@umis/core';
import type { CryptoProvider } from '@umis/core';
import { nobleCryptoProvider } from '@umis/core/noble';
import * as ExpoCrypto from 'expo-crypto';

/** The parts of SubtleCrypto that the WebCrypto provider of the SDK calls. */
const SUBTLE_METHODS = ['digest', 'generateKey', 'importKey', 'exportKey', 'sign', 'verify'] as const;

function hasSubtleCrypto(): boolean {
  const subtle: unknown = (globalThis as { crypto?: { subtle?: unknown } }).crypto?.subtle;
  if (typeof subtle !== 'object' || subtle === null) return false;
  const methods = subtle as Record<string, unknown>;
  return SUBTLE_METHODS.every((name) => typeof methods[name] === 'function');
}

/**
 * Picks the cryptographic backend of this runtime and makes it the default of the SDK: WebCrypto where the runtime has
 * it, otherwise the audited @noble libraries with the random numbers of `getRandomValues` (expo-crypto unless given).
 * Call it once at app start, before any other call of the SDK.
 */
export function setupCrypto(opts: { getRandomValues?: <T extends Uint8Array>(a: T) => T } = {}): CryptoProvider {
  const provider = hasSubtleCrypto()
    ? webCryptoProvider
    : nobleCryptoProvider({ getRandomValues: opts.getRandomValues ?? ExpoCrypto.getRandomValues });
  setDefaultCrypto(provider);
  return provider;
}

const UTF8_LABELS: ReadonlySet<string> = new Set([
  'unicode-1-1-utf-8',
  'unicode11utf8',
  'unicode20utf8',
  'utf-8',
  'utf8',
  'x-unicode20utf8',
]);
const REPLACEMENT_CHARACTER = 0xfffd;
/** UTF-16 code units gathered before they are turned into text; keeps the argument list of `fromCharCode` short. */
const FLUSH_UNITS = 4_096;

/**
 * The UTF-8 decoder of the Encoding Standard (https://encoding.spec.whatwg.org/#utf-8-decoder). A malformed sequence
 * is an error: `fatal` throws a TypeError, otherwise one U+FFFD stands for each maximal invalid subpart.
 */
function decodeUtf8(bytes: Uint8Array, fatal: boolean, ignoreBom: boolean): string {
  let start = 0;
  if (!ignoreBom && bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) start = 3;

  let text = '';
  let units: number[] = [];
  const emit = (codePoint: number): void => {
    if (codePoint > 0xffff) {
      const offset = codePoint - 0x10000;
      units.push(0xd800 + (offset >> 10), 0xdc00 + (offset & 0x3ff));
    } else {
      units.push(codePoint);
    }
    if (units.length >= FLUSH_UNITS) {
      text += String.fromCharCode(...units);
      units = [];
    }
  };
  const fail = (): void => {
    if (fatal) throw new TypeError('The encoded data was not valid UTF-8');
    emit(REPLACEMENT_CHARACTER);
  };

  let codePoint = 0;
  let seen = 0;
  let needed = 0;
  let lower = 0x80;
  let upper = 0xbf;
  for (let i = start; i < bytes.length; i++) {
    const byte = bytes[i]!;
    if (needed === 0) {
      if (byte <= 0x7f) {
        emit(byte);
      } else if (byte >= 0xc2 && byte <= 0xdf) {
        needed = 1;
        codePoint = byte & 0x1f;
      } else if (byte >= 0xe0 && byte <= 0xef) {
        if (byte === 0xe0) lower = 0xa0;
        if (byte === 0xed) upper = 0x9f;
        needed = 2;
        codePoint = byte & 0x0f;
      } else if (byte >= 0xf0 && byte <= 0xf4) {
        if (byte === 0xf0) lower = 0x90;
        if (byte === 0xf4) upper = 0x8f;
        needed = 3;
        codePoint = byte & 0x07;
      } else {
        fail();
      }
      continue;
    }
    if (byte < lower || byte > upper) {
      codePoint = needed = seen = 0;
      lower = 0x80;
      upper = 0xbf;
      i -= 1; // the byte is not part of the broken sequence: it is read again as the start of the next one
      fail();
      continue;
    }
    lower = 0x80;
    upper = 0xbf;
    codePoint = (codePoint << 6) | (byte & 0x3f);
    seen += 1;
    if (seen === needed) {
      emit(codePoint);
      codePoint = needed = seen = 0;
    }
  }
  if (needed !== 0) fail();
  return text + String.fromCharCode(...units);
}

function bytesOf(input: unknown): Uint8Array {
  if (input === undefined) return new Uint8Array(0);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  throw new TypeError('The input must be an ArrayBuffer or a view of one');
}

/** `TextDecoder` for UTF-8, the only encoding the SDK reads. Streaming decoding is not offered. */
class Utf8TextDecoder {
  readonly encoding = 'utf-8';
  readonly fatal: boolean;
  readonly ignoreBOM: boolean;

  constructor(label: string = 'utf-8', options: { fatal?: boolean; ignoreBOM?: boolean } = {}) {
    if (!UTF8_LABELS.has(String(label).trim().toLowerCase())) {
      throw new RangeError(`The "${label}" encoding is not supported`);
    }
    this.fatal = Boolean(options?.fatal);
    this.ignoreBOM = Boolean(options?.ignoreBOM);
  }

  decode(input?: ArrayBuffer | ArrayBufferView, options?: { stream?: boolean }): string {
    if (options?.stream) throw new TypeError('Streaming decoding is not supported');
    return decodeUtf8(bytesOf(input), this.fatal, this.ignoreBOM);
  }
}

/**
 * Adds the globals the SDK and its dependencies read but that some React Native runtimes lack: a UTF-8 `TextDecoder`
 * that rejects malformed input when asked to (`fatal`). A runtime that has one keeps it, and calling this twice is the
 * same as calling it once. Call it before `setupCrypto`.
 */
export function installRnPolyfills(): void {
  if (typeof (globalThis as { TextDecoder?: unknown }).TextDecoder === 'function') return;
  Object.defineProperty(globalThis, 'TextDecoder', {
    value: Utf8TextDecoder,
    writable: true,
    configurable: true,
    enumerable: false,
  });
}
