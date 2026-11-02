// Stand-in for expo-crypto. It draws from the operating system, not from `globalThis.crypto`, which the tests remove to
// look like Expo Go, and it records how many bytes were asked for.
import { randomFillSync } from 'node:crypto';

export const requests: number[] = [];

export function reset(): void {
  requests.length = 0;
}

export function getRandomValues<T extends Uint8Array>(array: T): T {
  requests.push(array.length);
  randomFillSync(array);
  return array;
}
