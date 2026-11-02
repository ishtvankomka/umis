import { LIMITS, UmisError } from '@umis/core';

/** Width of one status entry in bits. Token Status List allows 1, 2, 4 and 8. */
export type StatusBits = 1 | 2 | 4 | 8;

/** Status types of Token Status List draft-21 section 7.1. Values from 3 up are application-specific. */
export const STATUS = { VALID: 0, INVALID: 1, SUSPENDED: 2 } as const;

/**
 * A status list in the packed layout of the draft: entry 0 occupies the least significant bits of byte 0, entry 1 the
 * next `bits` bits, and so on. `get` and `set` throw INVALID_ARGUMENT outside `0 <= idx < size` and for a value that
 * does not fit in `bits` bits.
 */
export interface StatusList {
  readonly bits: StatusBits;
  readonly size: number;
  get(idx: number): number;
  set(idx: number, value: number): void;
  /** A copy of the packed bytes; the unused bits of the last byte are zero. */
  toBytes(): Uint8Array;
}

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

export function isStatusBits(value: unknown): value is StatusBits {
  return value === 1 || value === 2 || value === 4 || value === 8;
}

/** The entry at `idx` of a packed list. The caller has already checked that `idx` lies inside the list. */
export function readStatus(packed: Uint8Array, bits: StatusBits, idx: number): number {
  const offset = idx * bits;
  return (packed[offset >> 3]! >> (offset & 7)) & ((1 << bits) - 1);
}

function wrap(size: number, bits: StatusBits, packed: Uint8Array): StatusList {
  const largest = (1 << bits) - 1;
  const position = (idx: number): number => {
    if (!Number.isSafeInteger(idx) || idx < 0 || idx >= size)
      throw invalid(`status index ${String(idx)} is outside the list`);
    return idx;
  };
  return Object.freeze({
    bits,
    size,
    get: (idx: number): number => readStatus(packed, bits, position(idx)),
    set(idx: number, value: number): void {
      const offset = position(idx) * bits;
      if (!Number.isInteger(value) || value < 0 || value > largest) {
        throw invalid(`a ${bits}-bit status is an integer from 0 to ${largest}`);
      }
      const shift = offset & 7;
      packed[offset >> 3] = (packed[offset >> 3]! & ~(largest << shift)) | (value << shift);
    },
    toBytes: (): Uint8Array => packed.slice(),
  });
}

/** An all-VALID list of `size` entries. Its packed form never exceeds `LIMITS.statusListMaxBytes`. */
export function createStatusList(size: number, bits: StatusBits): StatusList {
  if (!isStatusBits(bits)) throw invalid('bits must be 1, 2, 4 or 8');
  const capacity = LIMITS.statusListMaxBytes * (8 / bits);
  if (!Number.isSafeInteger(size) || size < 1 || size > capacity) {
    throw invalid(`a ${bits}-bit status list holds 1 to ${capacity} entries`);
  }
  return wrap(size, bits, new Uint8Array(Math.ceil((size * bits) / 8)));
}

/** A list with one entry per element of `values`; every element must fit in `bits` bits. */
export function statusListFromValues(values: Uint8Array, bits: StatusBits): StatusList {
  if (!(values instanceof Uint8Array)) throw invalid('values must be a Uint8Array');
  const list = createStatusList(values.length, bits);
  const largest = (1 << bits) - 1;
  for (let idx = 0; idx < values.length; idx++) {
    const value = values[idx]!;
    if (value > largest) throw invalid(`status ${value} at index ${idx} does not fit in ${bits} bits`);
    if (value !== 0) list.set(idx, value);
  }
  return list;
}
