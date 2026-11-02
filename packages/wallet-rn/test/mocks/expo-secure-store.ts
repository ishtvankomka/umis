// In-memory stand-in for expo-secure-store. It keeps the limits a caller has to live with (the alphabet of keys and
// the size of a value), yields to the event loop on every call so that concurrent callers really interleave, and
// records every call so that tests can see which options were passed.
import { TextEncoder } from 'node:util';

export type SecureStoreOptions = { keychainAccessible?: number };

export const AFTER_FIRST_UNLOCK = 0;
export const AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY = 1;
export const ALWAYS = 2;
export const WHEN_PASSCODE_SET_THIS_DEVICE_ONLY = 3;
export const ALWAYS_THIS_DEVICE_ONLY = 4;
export const WHEN_UNLOCKED = 5;
export const WHEN_UNLOCKED_THIS_DEVICE_ONLY = 6;

const KEY_PATTERN = /^[A-Za-z0-9._-]+$/;
/** The platform stores accept values of up to 2 048 bytes. */
export const MAX_VALUE_BYTES = 2_047;

export interface Call {
  op: 'get' | 'set' | 'delete';
  key: string;
  value?: string;
  options?: SecureStoreOptions;
}

const items = new Map<string, string>();
export const calls: Call[] = [];
let failure: ((call: Call) => Error | undefined) | undefined;
let lateFailure: ((call: Call) => Error | undefined) | undefined;

/** Empties the store and forgets the calls and the injected failures. */
export function reset(): void {
  items.clear();
  calls.length = 0;
  failure = undefined;
  lateFailure = undefined;
}

/** A copy of everything stored. */
export function dump(): Record<string, string> {
  return Object.fromEntries(items);
}

/** Makes every call for which `decide` returns an error fail with that error before it changes anything. */
export function failWhen(decide: ((call: Call) => Error | undefined) | undefined): void {
  failure = decide;
}

/** Makes every call for which `decide` returns an error do its work and then fail: a write that lands and still reports an error. */
export function failAfterWhen(decide: ((call: Call) => Error | undefined) | undefined): void {
  lateFailure = decide;
}

/** Overwrites a stored value without going through the size and failure checks. */
export function plant(key: string, value: string): void {
  items.set(key, value);
}

async function enter(call: Call): Promise<void> {
  if (!KEY_PATTERN.test(call.key)) throw new Error(`Invalid key: ${call.key}`);
  calls.push(call);
  await Promise.resolve();
  const error = failure?.(call);
  if (error !== undefined) throw error;
  await Promise.resolve();
}

function leave(call: Call): void {
  const error = lateFailure?.(call);
  if (error !== undefined) throw error;
}

export async function getItemAsync(key: string, options?: SecureStoreOptions): Promise<string | null> {
  await enter({ op: 'get', key, options });
  return items.get(key) ?? null;
}

export async function setItemAsync(key: string, value: string, options?: SecureStoreOptions): Promise<void> {
  const call: Call = { op: 'set', key, value, options };
  await enter(call);
  const size = new TextEncoder().encode(value).length;
  if (size > MAX_VALUE_BYTES) throw new Error(`Value of ${size} bytes is larger than the store accepts`);
  items.set(key, value);
  leave(call);
}

export async function deleteItemAsync(key: string, options?: SecureStoreOptions): Promise<void> {
  const call: Call = { op: 'delete', key, options };
  await enter(call);
  items.delete(key);
  leave(call);
}
