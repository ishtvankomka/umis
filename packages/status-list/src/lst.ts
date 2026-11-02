import { LIMITS, UmisError, base64urlDecode, base64urlEncode, concatBytes } from '@umis/core';
import { Unzlib, zlibSync } from 'fflate';

/**
 * Compressed bytes handed to the inflater at a time. A hostile stream can expand about a thousand-fold, so small steps
 * keep each burst of output small and let the size cap stop the work early.
 */
const STEP = 1_024;
/** The shortest zlib stream: 2 header bytes, an empty final block of 2 bytes and the 4-byte Adler-32 trailer. */
const MIN_ZLIB_BYTES = 8;
const ADLER_MODULUS = 65_521;
/** The longest run of bytes whose Adler-32 sums still fit in 32 bits before the modulo is taken. */
const ADLER_RUN = 5_552;

const invalid = (message: string, cause?: unknown): UmisError =>
  new UmisError('STATUS_LIST_INVALID', message, { cause });

/** The packed bytes of a status list as zlib (RFC 1950) at level 9, written as unpadded base64url. */
export function encodeLst(packed: Uint8Array): string {
  if (!(packed instanceof Uint8Array)) throw new UmisError('INVALID_ARGUMENT', 'the packed list must be a Uint8Array');
  return base64urlEncode(zlibSync(packed, { level: 9 }));
}

function adler32(parts: readonly Uint8Array[]): number {
  let a = 1;
  let b = 0;
  for (const part of parts) {
    for (let start = 0; start < part.length; start += ADLER_RUN) {
      const end = Math.min(start + ADLER_RUN, part.length);
      for (let i = start; i < end; i++) {
        a += part[i]!;
        b += a;
      }
      a %= ADLER_MODULUS;
      b %= ADLER_MODULUS;
    }
  }
  return ((b << 16) | a) >>> 0;
}

/**
 * Inverse of {@link encodeLst}. The text must be canonical unpadded base64url holding a complete zlib stream whose
 * checksum matches; the inflated size is capped at `maxBytes` (the profile limit by default) while inflating, so an
 * oversized or hostile list is refused without being materialised. Every failure is STATUS_LIST_INVALID.
 */
export function decodeLst(lst: string, maxBytes: number = LIMITS.statusListMaxBytes): Uint8Array {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new UmisError('INVALID_ARGUMENT', 'maxBytes must be a non-negative integer');
  }
  let compressed: Uint8Array;
  try {
    compressed = base64urlDecode(lst);
  } catch (cause) {
    throw invalid('lst is not canonical unpadded base64url', cause);
  }
  if (compressed.length < MIN_ZLIB_BYTES) throw invalid('lst is too short to be a zlib stream');

  const parts: Uint8Array[] = [];
  const progress = { total: 0, overflow: false };
  const inflater = new Unzlib((part) => {
    progress.total += part.length;
    if (progress.total > maxBytes) progress.overflow = true;
    else if (part.length > 0) parts.push(part);
  });
  try {
    for (let start = 0; start < compressed.length && !progress.overflow; start += STEP) {
      const end = Math.min(start + STEP, compressed.length);
      inflater.push(compressed.subarray(start, end), end === compressed.length);
    }
  } catch (cause) {
    throw invalid('lst is not a valid zlib stream', cause);
  }
  if (progress.overflow) throw invalid(`lst inflates to more than ${maxBytes} bytes`);

  // The inflater drops the Adler-32 trailer without comparing it.
  const trailer = new DataView(compressed.buffer, compressed.byteOffset + compressed.length - 4, 4).getUint32(0);
  if (adler32(parts) !== trailer) throw invalid('the zlib checksum of lst does not match');
  return parts.length === 1 ? parts[0]! : concatBytes(...parts);
}
