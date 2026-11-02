import { LIMITS, UmisError, concatBytes } from '@umis/core';

/** Bytes in front of every chunk: the id of the message, the index of the chunk and the number of chunks. */
const HEADER_BYTES = 3;
/** The number of chunks of a message is one byte. */
const MAX_CHUNKS = 255;
/** The smallest chunk that holds a header and one byte of the frame. */
const MIN_MTU = HEADER_BYTES + 1;
const MAX_MTU = 65_535;

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);
const malformed = (message: string): UmisError => new UmisError('MALFORMED', message);

/** Checks the size of a chunk, header included. */
export function assertMtu(mtu: unknown): asserts mtu is number {
  if (typeof mtu !== 'number' || !Number.isInteger(mtu) || mtu < MIN_MTU || mtu > MAX_MTU) {
    throw invalid(`mtu is an integer from ${MIN_MTU} to ${MAX_MTU}`);
  }
}

/**
 * Cuts a frame into chunks that fit a link whose largest write is `mtu` bytes. Every chunk starts with the header
 * `[msgId, index, total]` (one byte each; `index` counts from 0) and carries at most `mtu - 3` bytes of the frame, so the
 * chunks of one frame are `ceil(length / (mtu - 3))` and never more than 255. A frame that is empty, longer than
 * `LIMITS.frameMaxBytes`, or too long for 255 chunks of this size is INVALID_ARGUMENT, and so is an `msgId` outside 0 to
 * 255. The sender gives each frame its own `msgId`, counting up and wrapping at 256.
 */
export function chunkFrame(frame: Uint8Array, mtu: number, msgId: number): Uint8Array[] {
  if (!(frame instanceof Uint8Array)) throw invalid('a frame is a byte array');
  assertMtu(mtu);
  if (!Number.isInteger(msgId) || msgId < 0 || msgId > 0xff) throw invalid('msgId is an integer from 0 to 255');
  if (frame.length === 0) throw invalid('a frame has at least one byte');

  const room = mtu - HEADER_BYTES;
  const limit = Math.min(LIMITS.frameMaxBytes, MAX_CHUNKS * room);
  if (frame.length > limit) {
    throw invalid(`a frame of ${frame.length} bytes is too long: at most ${limit} bytes go through an MTU of ${mtu}`);
  }
  const total = Math.ceil(frame.length / room);
  const chunks: Uint8Array[] = [];
  for (let index = 0; index < total; index++) {
    chunks.push(concatBytes(Uint8Array.of(msgId, index, total), frame.subarray(index * room, (index + 1) * room)));
  }
  return chunks;
}

interface Assembly {
  readonly msgId: number;
  readonly total: number;
  readonly parts: Uint8Array[];
  size: number;
}

/**
 * Puts the chunks of a frame back together. `push` takes the chunks of one message in the order they were made and
 * returns the frame with the last of them; until then it returns `undefined`. Anything that does not fit is MALFORMED and
 * the unfinished message is dropped, so the next chunk starts afresh: a chunk that is not a header with data, an index
 * that is not below the total, a first chunk that is not index 0, a chunk of another message, a changed total, an index
 * seen twice or one that skips a chunk, and a message that grows beyond `maxBytes` (`LIMITS.frameMaxBytes` by default,
 * which is also the most that can be asked for). The first chunk of a message with a new id replaces an unfinished
 * message without an error, because a sender that gave up starts over with a new id. `reset` drops the unfinished
 * message.
 */
export function createReassembler(o: { maxBytes?: number } = {}): {
  push(chunk: Uint8Array): Uint8Array | undefined;
  reset(): void;
} {
  if (typeof o !== 'object' || o === null) throw invalid('the options must be an object');
  const maxBytes = o.maxBytes ?? LIMITS.frameMaxBytes;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > LIMITS.frameMaxBytes) {
    throw invalid(`maxBytes is an integer from 1 to ${LIMITS.frameMaxBytes}`);
  }

  let current: Assembly | undefined;

  function accept(chunk: Uint8Array): Uint8Array | undefined {
    if (!(chunk instanceof Uint8Array)) throw malformed('a chunk is a byte array');
    if (chunk.length <= HEADER_BYTES) throw malformed('a chunk holds a header and at least one byte of the frame');
    const msgId = chunk[0]!;
    const index = chunk[1]!;
    const total = chunk[2]!;
    if (total === 0 || index >= total) throw malformed('the index of a chunk is out of range');

    if (current !== undefined && index === 0 && msgId !== current.msgId) current = undefined;
    if (current === undefined) {
      if (index !== 0) throw malformed('a message starts with its first chunk');
      current = { msgId, total, parts: [], size: 0 };
    } else {
      if (msgId !== current.msgId) throw malformed('a chunk belongs to another message');
      if (total !== current.total) throw malformed('the number of chunks changed within a message');
      if (index < current.parts.length) throw malformed('a chunk arrived twice');
      if (index > current.parts.length) throw malformed('a chunk is missing');
    }

    const data = chunk.subarray(HEADER_BYTES);
    if (current.size + data.length > maxBytes) throw malformed(`the message is longer than ${maxBytes} bytes`);
    current.parts.push(data.slice());
    current.size += data.length;
    if (current.parts.length < current.total) return undefined;

    const frame = concatBytes(...current.parts);
    current = undefined;
    return frame;
  }

  return {
    push(chunk) {
      try {
        return accept(chunk);
      } catch (error) {
        current = undefined;
        throw error;
      }
    },
    reset() {
      current = undefined;
    },
  };
}
