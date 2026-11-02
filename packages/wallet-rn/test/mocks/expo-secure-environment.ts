// Stand-in for @animo-id/expo-secure-environment. Keys are WebCrypto P-256 pairs that never leave this module; it
// answers like the real one (a compressed public key of 33 bytes, a raw signature of 64 bytes over SHA-256, errors that
// carry the name of their class) and can be told to misbehave.
import { webcrypto } from 'node:crypto';

// Evaluating this file is the proof that the module was loaded.
const marker = globalThis as { __umisSecureEnvironmentLoads?: number };
marker.__umisSecureEnvironmentLoads = (marker.__umisSecureEnvironmentLoads ?? 0) + 1;

const subtle = webcrypto.subtle;
const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export interface KeyEntry {
  pair: CryptoKeyPair;
  options: unknown;
}

export interface Call {
  fn: string;
  keyId?: string;
  args?: unknown;
}

export const state = {
  supported: true,
  generateError: undefined as Error | undefined,
  publicKeyError: undefined as Error | undefined,
  signError: undefined as Error | undefined,
  /** Replaces every signature by the equivalent one with the large half of s. */
  highS: false,
  /** Signatures that are running at this moment, and the most there ever were at once. */
  active: 0,
  mostActive: 0,
};
export const keys = new Map<string, KeyEntry>();
export const calls: Call[] = [];

export function reset(): void {
  state.supported = true;
  state.generateError = undefined;
  state.publicKeyError = undefined;
  state.signError = undefined;
  state.highS = false;
  state.active = 0;
  state.mostActive = 0;
  keys.clear();
  calls.length = 0;
}

/** An error whose `name` is that of the class the real module throws. */
export function failure(name: string): Error {
  const error = new Error(name);
  error.name = name;
  return error;
}

function entryOf(keyId: string): KeyEntry {
  const entry = keys.get(keyId);
  if (entry === undefined) throw failure('KeyNotFoundError');
  return entry;
}

/** s becomes ORDER - s when it is in the lower half: the same signature in the other of its two forms. */
export function withHighS(signature: Uint8Array): Uint8Array {
  const out = signature.slice();
  const s = BigInt(`0x${Buffer.from(signature.subarray(32)).toString('hex')}`);
  if (s * 2n >= ORDER) return out;
  out.set(Buffer.from((ORDER - s).toString(16).padStart(64, '0'), 'hex'), 32);
  return out;
}

/** True when s lies in the upper half of the curve order. */
export function hasHighS(signature: Uint8Array): boolean {
  return BigInt(`0x${Buffer.from(signature.subarray(32)).toString('hex')}`) * 2n > ORDER;
}

export function isSecureEnvironmentSupported(options?: { minimumKeyStorage?: string }): boolean {
  calls.push({ fn: 'isSecureEnvironmentSupported', args: options });
  return state.supported;
}

export async function generateKeypair(keyId: string, options?: unknown): Promise<void> {
  calls.push({ fn: 'generateKeypair', keyId, args: options });
  if (state.generateError !== undefined) throw state.generateError;
  if (keys.has(keyId)) throw failure('KeyAlreadyExistsError');
  const pair = (await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  keys.set(keyId, { pair, options });
}

export async function getPublicBytesForKeyId(keyId: string): Promise<Uint8Array> {
  calls.push({ fn: 'getPublicBytesForKeyId', keyId });
  if (state.publicKeyError !== undefined) throw state.publicKeyError;
  const raw = new Uint8Array(await subtle.exportKey('raw', entryOf(keyId).pair.publicKey)); // 0x04 ‖ x ‖ y
  const compressed = new Uint8Array(33);
  compressed[0] = 0x02 + (raw[64]! & 1);
  compressed.set(raw.subarray(1, 33), 1);
  return compressed;
}

export async function sign(keyId: string, message: Uint8Array, options?: unknown): Promise<Uint8Array> {
  calls.push({ fn: 'sign', keyId, args: options });
  state.active += 1;
  state.mostActive = Math.max(state.mostActive, state.active);
  try {
    await new Promise((resolve) => setTimeout(resolve, 1));
    if (state.signError !== undefined) throw state.signError;
    const signature = new Uint8Array(
      await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, entryOf(keyId).pair.privateKey, message),
    );
    return state.highS ? withHighS(signature) : signature;
  } finally {
    state.active -= 1;
  }
}

export async function deleteKey(keyId: string): Promise<void> {
  calls.push({ fn: 'deleteKey', keyId });
  entryOf(keyId);
  keys.delete(keyId);
}
