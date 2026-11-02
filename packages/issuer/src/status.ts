import { UmisError, randomBytes } from '@umis/core';
import type { CryptoProvider, StatusRef } from '@umis/core';
import { invalid, isRecord, isText, own } from './profile.js';

/** Uniform draws tried before the search for a free index turns into a scan. */
const RANDOM_DRAWS = 64;
/** A status list is far smaller than this (its token is capped at 1 MiB); the cap keeps the scan bounded. */
const MAX_LIST_SIZE = 2 ** 32;
/** Draws of random bytes allowed for one uniform number; a working random source needs two at the very most, on average. */
const MAX_BYTE_DRAWS = 128;

/** A uniformly distributed integer in `[0, size)`: random bytes read as a number, redrawn when they fall in the biased tail. */
function uniformBelow(size: number, crypto: CryptoProvider | undefined): number {
  let byteCount = 0;
  let range = 1;
  while (range < size) {
    range *= 256;
    byteCount += 1;
  }
  const usable = range - (range % size); // the largest multiple of `size` that fits in the range
  for (let attempt = 0; attempt < MAX_BYTE_DRAWS; attempt++) {
    let value = 0;
    for (const byte of randomBytes(byteCount, crypto)) value = value * 256 + byte;
    if (value < usable) return value % size;
  }
  throw new UmisError('CRYPTO_UNAVAILABLE', 'the random source does not deliver usable values');
}

/**
 * Picks a free index in a status list of `size` entries, uniformly and unpredictably, so that the position of a credential
 * says nothing about when it was issued or to whom. `isUsed` tells whether an index is taken. Up to 64 uniform indexes are
 * tried; if all are taken, the list is scanned linearly from a random start. A list with no free index is
 * INVALID_ARGUMENT.
 */
export function randomStatusIndex(size: number, isUsed: (idx: number) => boolean, crypto?: CryptoProvider): number {
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_LIST_SIZE) {
    throw invalid(`the size of a status list must be an integer from 1 to ${MAX_LIST_SIZE}`);
  }
  if (typeof isUsed !== 'function') throw invalid('isUsed must be a function');
  for (let draw = 0; draw < RANDOM_DRAWS; draw++) {
    const idx = uniformBelow(size, crypto);
    if (!isUsed(idx)) return idx;
  }
  const start = uniformBelow(size, crypto);
  for (let step = 0; step < size; step++) {
    const idx = (start + step) % size;
    if (!isUsed(idx)) return idx;
  }
  throw invalid('the status list has no free index');
}

/**
 * The credentials to revoke together with `root`: every descendant, whatever the depth, each once, nearest first
 * (breadth-first, in the order that `childrenOf` lists them). The root itself is not in the result. A credential that
 * can be reached twice, or a delegation that leads back to a credential already seen, does not repeat or loop.
 */
export function cascadeRevocation(i: {
  root: string;
  childrenOf: (jti: string) => ReadonlyArray<{ jti: string; status: StatusRef }>;
}): Array<{ jti: string; status: StatusRef }> {
  const request: unknown = i;
  if (!isRecord(request)) throw invalid('the cascade input must be an object');
  if (!isText(i.root)) throw invalid('root must be a non-empty string');
  if (typeof i.childrenOf !== 'function') throw invalid('childrenOf must be a function');

  const seen = new Set<string>([i.root]);
  const descendants: Array<{ jti: string; status: StatusRef }> = [];
  let level = [i.root];
  while (level.length > 0) {
    const next: string[] = [];
    for (const parent of level) {
      const children: unknown = i.childrenOf(parent);
      if (!Array.isArray(children)) throw invalid('childrenOf must return a list');
      for (const child of children as unknown[]) {
        const status = isRecord(child) ? own(child, 'status') : undefined;
        const jti = isRecord(child) ? own(child, 'jti') : undefined;
        const uri = isRecord(status) ? own(status, 'uri') : undefined;
        const idx = isRecord(status) ? own(status, 'idx') : undefined;
        if (!isText(jti) || !isText(uri) || typeof idx !== 'number' || !Number.isSafeInteger(idx) || idx < 0) {
          throw invalid(`childrenOf returned an entry without a jti and a status reference below ${parent}`);
        }
        if (seen.has(jti)) continue;
        seen.add(jti);
        descendants.push({ jti, status: { uri, idx } });
        next.push(jti);
      }
    }
    level = next;
  }
  return descendants;
}
