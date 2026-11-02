import { Inflate, deflateSync } from 'fflate';
import {
  base45Decode,
  base45Encode,
  base64urlDecode,
  base64urlEncode,
  concatBytes,
  varintDecode,
  varintEncode,
} from './bytes.js';
import { FRAME_KINDS, FRAME_KIND_CODE, FRAME_PREFIX, FRAME_TERMINATOR, LIMITS, type FrameKind } from './profile.js';
import { UmisError } from './reasons.js';

/** The tokens a UMIS frame carries, in slot order (see the slot table of each kind). */
export interface Frame {
  kind: FrameKind;
  tokens: string[];
}

type Slot = 'jws' | 'sdjwt';

/** What each kind carries: a compact JWS, or an SD-JWT with a key-binding JWT. */
const SLOTS: Readonly<Record<FrameKind, readonly Slot[]>> = {
  oneway: ['jws'],
  full: ['sdjwt'],
  request: ['jws'],
  response: ['sdjwt'],
  mutual_init: ['jws', 'sdjwt'],
  mutual_reply: ['sdjwt'],
};

const CONTAINER_VERSION = 0x01;
const TOKEN_JWS = 1;
const TOKEN_SDJWT = 2;
/**
 * Compressed input is fed to the decompressor in pieces of this size. DEFLATE cannot expand more than 1 032 times, so one
 * piece yields at most about 264 KB, and the cap is enforced after every piece.
 */
const INFLATE_PIECE_BYTES = 256;
/** A compressed frame of an admissible container cannot be longer than this, whatever the encoder. */
const MAX_COMPRESSED_BYTES = 2 * LIMITS.frameMaxBytes;

const invalid = (message: string, cause?: unknown): UmisError => new UmisError('INVALID_ARGUMENT', message, { cause });
const malformed = (message: string, cause?: unknown): UmisError => new UmisError('MALFORMED', message, { cause });

// ---------------------------------------------------------------------------------------------------------------
// producing
// ---------------------------------------------------------------------------------------------------------------

function segmentBytes(segment: string, what: string): Uint8Array {
  if (segment === '') throw invalid(`${what} is empty`);
  try {
    return base64urlDecode(segment);
  } catch (cause) {
    throw invalid(`${what} is not canonical base64url`, cause);
  }
}

/** Appends `varint length ‖ bytes` for each base64url segment. */
function pushSegments(out: Uint8Array[], segments: readonly string[], what: string): void {
  for (const segment of segments) {
    const bytes = segmentBytes(segment, what);
    out.push(varintEncode(bytes.length), bytes);
  }
}

function threeSegments(compact: string, what: string): string[] {
  const segments = compact.split('.');
  if (segments.length !== 3) throw invalid(`${what} is not a compact JWS`);
  return segments;
}

function packToken(token: unknown, slot: Slot): Uint8Array {
  if (typeof token !== 'string') throw invalid('a frame token must be a string');
  const out: Uint8Array[] = [];
  if (slot === 'jws') {
    if (token.includes('~')) throw invalid('this slot holds a compact JWS, not an SD-JWT');
    out.push(Uint8Array.of(TOKEN_JWS));
    pushSegments(out, threeSegments(token, 'the token'), 'a JWS segment');
    return concatBytes(...out);
  }
  const pieces = token.split('~');
  const keyBinding = pieces[pieces.length - 1] ?? '';
  if (pieces.length < 2 || keyBinding === '') throw invalid('this slot holds an SD-JWT with a key-binding JWT');
  const disclosures = pieces.slice(1, -1);
  out.push(Uint8Array.of(TOKEN_SDJWT));
  pushSegments(out, threeSegments(pieces[0] ?? '', 'the issuer JWT'), 'a JWS segment');
  out.push(varintEncode(disclosures.length));
  pushSegments(out, disclosures, 'a disclosure');
  out.push(Uint8Array.of(1));
  pushSegments(out, threeSegments(keyBinding, 'the key-binding JWT'), 'a JWS segment');
  return concatBytes(...out);
}

function buildContainer(f: Frame): Uint8Array {
  if (typeof f !== 'object' || f === null || !(FRAME_KINDS as readonly string[]).includes(f.kind)) {
    throw invalid('unknown frame kind');
  }
  const slots = SLOTS[f.kind];
  if (!Array.isArray(f.tokens) || f.tokens.length !== slots.length) {
    throw invalid(`a ${f.kind} frame carries ${slots.length} token(s)`);
  }
  const parts: Uint8Array[] = [Uint8Array.of(CONTAINER_VERSION), varintEncode(slots.length)];
  slots.forEach((slot, index) => {
    const packed = packToken(f.tokens[index], slot);
    parts.push(varintEncode(packed.length), packed);
  });
  const container = concatBytes(...parts);
  if (container.length > LIMITS.frameMaxBytes) throw invalid('the frame container exceeds the size limit');
  return container;
}

/**
 * The text of a frame, as shown in a QR code: the kind's prefix, the base45 of the raw-DEFLATE of the packed tokens,
 * and the terminator `.`. Every character is in the QR alphanumeric set. A frame longer than `LIMITS.qrMaxChars`, a
 * token that does not fit its slot and a segment that is not canonical base64url are INVALID_ARGUMENT.
 */
export function encodeFrame(f: Frame): string {
  const container = buildContainer(f);
  const text = FRAME_PREFIX[f.kind] + base45Encode(deflateSync(container, { level: 9 })) + FRAME_TERMINATOR;
  if (text.length > LIMITS.qrMaxChars) {
    throw invalid(`the frame has ${text.length} characters; a QR code holds at most ${LIMITS.qrMaxChars}`);
  }
  return text;
}

/** The bytes of a frame for a transport such as BLE: the kind's code, then the raw-DEFLATE of the packed tokens. */
export function encodeFrameBytes(f: Frame): Uint8Array {
  const container = buildContainer(f);
  return concatBytes(Uint8Array.of(FRAME_KIND_CODE[f.kind]), deflateSync(container, { level: 9 }));
}

// ---------------------------------------------------------------------------------------------------------------
// consuming
// ---------------------------------------------------------------------------------------------------------------

/**
 * Inflates raw DEFLATE data and stops as soon as the output passes `cap` bytes. The input goes in pieces, so the
 * amount produced before the stop is at most `cap` plus what one piece can expand to. Exported for the tests of the
 * limit; not part of the package surface.
 */
export function inflateCapped(
  data: Uint8Array,
  cap: number,
): { exceeded: false; bytes: Uint8Array } | { exceeded: true; produced: number } {
  const chunks: Uint8Array[] = [];
  let produced = 0;
  let exceeded = false;
  const decompressor = new Inflate((chunk) => {
    produced += chunk.length;
    if (produced > cap) exceeded = true;
    else chunks.push(chunk);
  });
  try {
    for (let offset = 0; offset < data.length && !exceeded; offset += INFLATE_PIECE_BYTES) {
      const end = Math.min(offset + INFLATE_PIECE_BYTES, data.length);
      decompressor.push(data.subarray(offset, end), end === data.length);
    }
  } catch (cause) {
    throw malformed('the frame is not valid DEFLATE data', cause);
  }
  if (exceeded) return { exceeded: true, produced };
  if (data.length === 0) throw malformed('the frame holds no data');
  return { exceeded: false, bytes: concatBytes(...chunks) };
}

function inflateContainer(compressed: Uint8Array): Uint8Array {
  if (compressed.length > MAX_COMPRESSED_BYTES) throw malformed('the frame is longer than any frame the encoder makes');
  const result = inflateCapped(compressed, LIMITS.frameMaxBytes);
  if (result.exceeded) throw malformed('the frame inflates beyond the size limit');
  return result.bytes;
}

/** A reader over a byte string that fails with MALFORMED instead of reading past the end. */
class Reader {
  private position = 0;

  constructor(private readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.position;
  }

  u8(): number {
    const value = this.bytes[this.position];
    if (value === undefined) throw malformed('the frame is truncated');
    this.position += 1;
    return value;
  }

  /** An unsigned LEB128 value in its shortest form. */
  varint(): number {
    const { value, next } = varintDecode(this.bytes, this.position);
    const shortest = value < 0x80 ? 1 : value < 0x4000 ? 2 : 3;
    if (next - this.position !== shortest) throw malformed('a length is not in its shortest form');
    this.position = next;
    return value;
  }

  take(length: number): Uint8Array {
    if (length > this.remaining) throw malformed('the frame is truncated');
    const out = this.bytes.subarray(this.position, this.position + length);
    this.position += length;
    return out;
  }
}

function readSegments(reader: Reader, count: number): string[] {
  const segments: string[] = [];
  for (let i = 0; i < count; i++) {
    const length = reader.varint();
    if (length === 0) throw malformed('a segment is empty');
    segments.push(base64urlEncode(reader.take(length)));
  }
  return segments;
}

function unpackToken(reader: Reader, slot: Slot): string {
  const type = reader.u8();
  let token: string;
  if (slot === 'jws') {
    if (type !== TOKEN_JWS) throw malformed('a token has the wrong type for its slot');
    token = readSegments(reader, 3).join('.');
  } else {
    if (type !== TOKEN_SDJWT) throw malformed('a token has the wrong type for its slot');
    const issuer = readSegments(reader, 3).join('.');
    const disclosures = readSegments(reader, reader.varint());
    if (reader.u8() !== 1) throw malformed('the SD-JWT of this slot carries a key-binding JWT');
    const keyBinding = readSegments(reader, 3).join('.');
    token = [issuer, ...disclosures, keyBinding].join('~');
  }
  if (reader.remaining !== 0) throw malformed('a token is followed by extra bytes');
  return token;
}

function readContainer(kind: FrameKind, container: Uint8Array): Frame {
  const slots = SLOTS[kind];
  const reader = new Reader(container);
  if (reader.u8() !== CONTAINER_VERSION) throw malformed('unknown container version');
  if (reader.varint() !== slots.length) throw malformed(`a ${kind} frame carries ${slots.length} token(s)`);
  const tokens = slots.map((slot) => unpackToken(new Reader(reader.take(reader.varint())), slot));
  if (reader.remaining !== 0) throw malformed('the container is followed by extra bytes');
  return { kind, tokens };
}

/** The kind announced by the prefix of a frame text, if any. Nothing else is looked at. */
export function frameKindOf(text: string): FrameKind | undefined {
  if (typeof text !== 'string') return undefined;
  const trimmed = text.trim();
  return FRAME_KINDS.find((kind) => trimmed.startsWith(FRAME_PREFIX[kind]));
}

/**
 * Reads the text of a frame. Surrounding whitespace is trimmed, the prefix selects the kind (UNSUPPORTED_FORMAT when
 * none matches), and from there everything is MALFORMED when wrong: a length above `LIMITS.qrMaxChars` (checked before
 * any decoding), a missing terminator, a character outside base45, DEFLATE data that is invalid or inflates beyond
 * `LIMITS.frameMaxBytes`, and a container whose tokens, lengths, count or types do not fit the kind. The container is
 * read to its last byte; bytes after the end of the DEFLATE stream itself are not reported by the decompressor and are
 * ignored, which cannot change the tokens, and every token is checked by its own signature.
 */
export function decodeFrame(text: string): Frame {
  const kind = frameKindOf(text);
  if (kind === undefined) throw new UmisError('UNSUPPORTED_FORMAT', 'not a UMIS frame');
  const trimmed = text.trim();
  if (trimmed.length > LIMITS.qrMaxChars) throw malformed('the frame is longer than a QR code can hold');
  if (!trimmed.endsWith(FRAME_TERMINATOR)) throw malformed('the frame has no terminator');
  const body = trimmed.slice(FRAME_PREFIX[kind].length, trimmed.length - FRAME_TERMINATOR.length);
  return readContainer(kind, inflateContainer(base45Decode(body)));
}

/** Reads the bytes of a frame from {@link encodeFrameBytes}; an unknown kind code is UNSUPPORTED_FORMAT. */
export function decodeFrameBytes(b: Uint8Array): Frame {
  if (!(b instanceof Uint8Array)) throw malformed('frame bytes expected');
  const kind = FRAME_KINDS.find((candidate) => FRAME_KIND_CODE[candidate] === b[0]);
  if (kind === undefined) throw new UmisError('UNSUPPORTED_FORMAT', 'not a UMIS frame');
  return readContainer(kind, inflateContainer(b.subarray(1)));
}
