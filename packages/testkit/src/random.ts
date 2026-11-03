import { createHash } from 'node:crypto';
import { UmisError } from '@umis/core';
import type { CryptoProvider } from '@umis/core';
import { nobleCryptoProvider } from '@umis/core/noble';

const BLOCK_BYTES = 32;
const MAX_BLOCKS = 2 ** 32;

/**
 * The ES256 provider of the `@noble` libraries with a random source that repeats itself: the bytes it hands out are the
 * stream `SHA-256(seed ‖ counter) …` for counter = 0, 1, 2, … (counter as 4 bytes, big-endian), consumed in order across
 * calls. Signatures are RFC 6979 deterministic, so the same calls in the same order give the same keys, salts,
 * identifiers and signatures on every machine. That is what published test vectors and reproducible demo runs need.
 *
 * It is predictable by design: use it for vectors and demos, never to protect anything.
 */
export function deterministicCrypto(seed: string): CryptoProvider {
  if (typeof seed !== 'string' || seed === '') {
    throw new UmisError('INVALID_ARGUMENT', 'the seed of a deterministic provider is a non-empty string');
  }
  // `getRandomValues` is synchronous and the hash of a CryptoProvider is not, so the stream is hashed with the SHA-256
  // of the Node runtime, which this Node-only package can rely on.
  let counter = 0;
  let block: Uint8Array = new Uint8Array(0);
  let used = 0;

  const nextBlock = (): Uint8Array => {
    if (counter >= MAX_BLOCKS) throw new UmisError('CRYPTO_UNAVAILABLE', 'the deterministic stream is exhausted');
    const index = new Uint8Array(4);
    new DataView(index.buffer).setUint32(0, counter);
    counter += 1;
    return new Uint8Array(createHash('sha256').update(seed, 'utf8').update(index).digest());
  };

  const fill = <T extends Uint8Array>(array: T): T => {
    let written = 0;
    while (written < array.length) {
      if (used >= block.length) {
        block = nextBlock();
        used = 0;
      }
      const take = Math.min(array.length - written, BLOCK_BYTES - used);
      array.set(block.subarray(used, used + take), written);
      used += take;
      written += take;
    }
    return array;
  };

  return { ...nobleCryptoProvider({ getRandomValues: fill }), name: 'noble-deterministic' };
}
