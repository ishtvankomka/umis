import { UmisError } from './reasons.js';

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const BASE45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HEX = '0123456789abcdef';

/** Maps an ASCII code to its position in `alphabet`, -1 for every other code. */
function indexTable(alphabet: string): Int8Array {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) table[alphabet.charCodeAt(i)] = i;
  return table;
}

const BASE64URL_INDEX = indexTable(BASE64URL);
const BASE45_INDEX = indexTable(BASE45);

function malformed(message: string): never {
  throw new UmisError('MALFORMED', message);
}

// ---------------------------------------------------------------------------------------------------------------
// UTF-8
// ---------------------------------------------------------------------------------------------------------------

export function utf8Encode(s: string): Uint8Array {
  return typeof TextEncoder === 'function' ? new TextEncoder().encode(s) : encodeUtf8(s);
}

/** Strict UTF-8 decoding. Overlong forms, surrogates, code points above U+10FFFF and truncated sequences are MALFORMED. */
export function utf8Decode(b: Uint8Array): string {
  if (typeof TextDecoder !== 'function') return decodeUtf8(b);
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b);
  } catch (cause) {
    throw new UmisError('MALFORMED', 'invalid UTF-8', { cause });
  }
}

/** Encoder for runtimes without TextEncoder. Lone surrogates become U+FFFD, like the WHATWG encoder. */
function encodeUtf8(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 3);
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (next - 0xdc00);
        i += 1;
      } else {
        c = 0xfffd;
      }
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      c = 0xfffd;
    }
    if (c < 0x80) {
      out[o++] = c;
    } else if (c < 0x800) {
      out[o++] = 0xc0 | (c >> 6);
      out[o++] = 0x80 | (c & 0x3f);
    } else if (c < 0x10000) {
      out[o++] = 0xe0 | (c >> 12);
      out[o++] = 0x80 | ((c >> 6) & 0x3f);
      out[o++] = 0x80 | (c & 0x3f);
    } else {
      out[o++] = 0xf0 | (c >> 18);
      out[o++] = 0x80 | ((c >> 12) & 0x3f);
      out[o++] = 0x80 | ((c >> 6) & 0x3f);
      out[o++] = 0x80 | (c & 0x3f);
    }
  }
  return out.slice(0, o);
}

/** Decoder for runtimes without TextDecoder; accepts exactly the well-formed sequences of Unicode Table 3-7. */
function decodeUtf8(b: Uint8Array): string {
  const CHUNK = 4096;
  let result = '';
  let units: number[] = [];
  const flush = (): void => {
    result += String.fromCharCode(...units);
    units = [];
  };
  const continuation = (index: number, low = 0x80, high = 0xbf): number => {
    const byte = b[index];
    if (byte === undefined || byte < low || byte > high) malformed('invalid UTF-8');
    return byte & 0x3f;
  };
  let i = 0;
  while (i < b.length) {
    const lead = b[i]!;
    let codePoint: number;
    if (lead < 0x80) {
      codePoint = lead;
      i += 1;
    } else if (lead >= 0xc2 && lead <= 0xdf) {
      codePoint = ((lead & 0x1f) << 6) | continuation(i + 1);
      i += 2;
    } else if (lead >= 0xe0 && lead <= 0xef) {
      const low = lead === 0xe0 ? 0xa0 : 0x80;
      const high = lead === 0xed ? 0x9f : 0xbf;
      codePoint = ((lead & 0x0f) << 12) | (continuation(i + 1, low, high) << 6) | continuation(i + 2);
      i += 3;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      const low = lead === 0xf0 ? 0x90 : 0x80;
      const high = lead === 0xf4 ? 0x8f : 0xbf;
      codePoint =
        ((lead & 0x07) << 18) |
        (continuation(i + 1, low, high) << 12) |
        (continuation(i + 2) << 6) |
        continuation(i + 3);
      i += 4;
    } else {
      return malformed('invalid UTF-8');
    }
    if (codePoint >= 0x10000) {
      const offset = codePoint - 0x10000;
      units.push(0xd800 + (offset >> 10), 0xdc00 + (offset & 0x3ff));
    } else {
      units.push(codePoint);
    }
    if (units.length >= CHUNK) flush();
  }
  flush();
  return result;
}

// ---------------------------------------------------------------------------------------------------------------
// base64url (RFC 4648 §5)
// ---------------------------------------------------------------------------------------------------------------

/** Unpadded base64url. */
export function base64urlEncode(b: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    out +=
      BASE64URL.charAt(n >> 18) +
      BASE64URL.charAt((n >> 12) & 63) +
      BASE64URL.charAt((n >> 6) & 63) +
      BASE64URL.charAt(n & 63);
  }
  const rest = b.length - i;
  if (rest === 1) {
    const n = b[i]!;
    out += BASE64URL.charAt(n >> 2) + BASE64URL.charAt((n << 4) & 63);
  } else if (rest === 2) {
    const n = (b[i]! << 8) | b[i + 1]!;
    out += BASE64URL.charAt(n >> 10) + BASE64URL.charAt((n >> 4) & 63) + BASE64URL.charAt((n << 2) & 63);
  }
  return out;
}

/**
 * Canonical decoding only: no padding, no characters outside `A-Za-z0-9_-`, no length of 1 modulo 4 and no non-zero
 * bits after the last full byte, so that every byte string has exactly one accepted text.
 */
export function base64urlDecode(s: string): Uint8Array {
  if (typeof s !== 'string') return malformed('base64url input is not a string');
  if (s.length % 4 === 1) return malformed('base64url length is invalid');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const value = code < 128 ? BASE64URL_INDEX[code]! : -1;
    if (value < 0) return malformed('base64url contains a character outside the alphabet');
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) return malformed('base64url has non-zero trailing bits');
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// base45 (RFC 9285), base32 (RFC 4648 §6), hex
// ---------------------------------------------------------------------------------------------------------------

export function base45Encode(b: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 1 < b.length; i += 2) {
    const n = b[i]! * 256 + b[i + 1]!;
    out += BASE45.charAt(n % 45) + BASE45.charAt(Math.floor(n / 45) % 45) + BASE45.charAt(Math.floor(n / 2025));
  }
  if (i < b.length) {
    const n = b[i]!;
    out += BASE45.charAt(n % 45) + BASE45.charAt(Math.floor(n / 45));
  }
  return out;
}

export function base45Decode(s: string): Uint8Array {
  if (typeof s !== 'string') return malformed('base45 input is not a string');
  if (s.length % 3 === 1) return malformed('base45 length is invalid');
  const value = (index: number): number => {
    const code = s.charCodeAt(index);
    const v = code < 128 ? BASE45_INDEX[code]! : -1;
    if (v < 0) malformed('base45 contains a character outside the alphabet');
    return v;
  };
  const out = new Uint8Array(Math.floor(s.length / 3) * 2 + (s.length % 3 === 2 ? 1 : 0));
  let o = 0;
  let i = 0;
  for (; i + 2 < s.length; i += 3) {
    const n = value(i) + value(i + 1) * 45 + value(i + 2) * 2025;
    if (n > 0xffff) return malformed('base45 triplet exceeds 65535');
    out[o++] = n >> 8;
    out[o++] = n & 0xff;
  }
  if (i < s.length) {
    const n = value(i) + value(i + 1) * 45;
    if (n > 0xff) return malformed('base45 pair exceeds 255');
    out[o] = n;
  }
  return out;
}

/** Unpadded base32 with the RFC 4648 §6 alphabet. */
export function base32Encode(b: Uint8Array): string {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of b) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32.charAt((acc >> bits) & 31);
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32.charAt((acc << (5 - bits)) & 31);
  return out;
}

/** Lowercase hexadecimal. */
export function hexEncode(b: Uint8Array): string {
  let out = '';
  for (const byte of b) out += HEX.charAt(byte >> 4) + HEX.charAt(byte & 15);
  return out;
}

/** Accepts an even number of hexadecimal digits in either case. */
export function hexDecode(s: string): Uint8Array {
  if (typeof s !== 'string') return malformed('hex input is not a string');
  if (s.length % 2 !== 0) return malformed('hex length is odd');
  const digit = (index: number): number => {
    const code = s.charCodeAt(index);
    if (code >= 48 && code <= 57) return code - 48;
    if (code >= 97 && code <= 102) return code - 87;
    if (code >= 65 && code <= 70) return code - 55;
    return malformed('hex contains a character outside the alphabet');
  };
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = (digit(2 * i) << 4) | digit(2 * i + 1);
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// byte strings and varints
// ---------------------------------------------------------------------------------------------------------------

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Constant time for equal lengths; the length itself is not secret. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Unsigned LEB128 for 0 ≤ n < 2^21, which takes at most three bytes. */
export function varintEncode(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n >= 1 << 21) {
    throw new UmisError('INVALID_ARGUMENT', 'varint value must be an integer in [0, 2^21)');
  }
  if (n < 0x80) return Uint8Array.of(n);
  if (n < 0x4000) return Uint8Array.of((n & 0x7f) | 0x80, n >> 7);
  return Uint8Array.of((n & 0x7f) | 0x80, ((n >> 7) & 0x7f) | 0x80, n >> 14);
}

/** Reads one varint at `offset`; more than three bytes or a truncated input is MALFORMED. */
export function varintDecode(b: Uint8Array, offset: number): { value: number; next: number } {
  if (!Number.isInteger(offset) || offset < 0)
    throw new UmisError('INVALID_ARGUMENT', 'offset must be a non-negative integer');
  let value = 0;
  for (let i = 0; i < 3; i++) {
    const byte = b[offset + i];
    if (byte === undefined) return malformed('varint is truncated');
    value |= (byte & 0x7f) << (7 * i);
    if ((byte & 0x80) === 0) return { value, next: offset + i + 1 };
  }
  return malformed('varint is longer than three bytes');
}
