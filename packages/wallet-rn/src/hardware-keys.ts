import { p256 } from '@noble/curves/nist.js';
import { UmisError, base64urlEncode, jwkThumbprint } from '@umis/core';
import type { EcPublicJwk } from '@umis/core';
import { nobleCryptoProvider } from '@umis/core/noble';
import * as SecureStore from 'expo-secure-store';
import type { ManagedSigner } from './keystore.js';

type SecureEnvironment = typeof import('@animo-id/expo-secure-environment');

/** The secret store holds a note about each hardware key under `umis.keymeta.<alias>`; the key itself never leaves the hardware. */
const META_PREFIX = 'umis.keymeta.';
const STORE_OPTIONS = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };
/**
 * The weakest place the key may be: the Trusted Execution Environment of an Android device, or better (StrongBox is
 * taken where the device has it). The Secure Enclave of an iPhone is always used. Anything weaker counts as software.
 */
const MINIMUM_KEY_STORAGE = 'trustedEnvironment';
const COMPRESSED_POINT_BYTES = 33;
const SIGNATURE_BYTES = 64;

const noble = nobleCryptoProvider();

interface HardwareMeta {
  v: 1;
  kind: 'hardware';
  requireBiometric: boolean;
  /** Set on the note written before the key is generated and dropped once the key is complete. */
  pending?: true;
}

/**
 * The native module is an optional peer dependency: it is loaded here and nowhere else, and only on a development
 * build. The import sits inside `try`, which also lets Metro bundle an app that does not install the module.
 */
async function loadSecureEnvironment(): Promise<SecureEnvironment | undefined> {
  try {
    return await import('@animo-id/expo-secure-environment');
  } catch {
    return undefined;
  }
}

/**
 * Makes a key in the secure hardware. Resolves to `undefined` when the device cannot hold one, so that the caller makes a
 * software key instead: the module is not installed, the device has no Secure Enclave, StrongBox or Trusted Execution
 * Environment (the iOS Simulator), or the module refuses to generate the key (for instance because no biometrics are
 * enrolled for a key that needs them). Any other failure of the module is CRYPTO_UNAVAILABLE and makes no software key,
 * and a failure of the secret store is passed on; a key that was generated but not completed is deleted again.
 *
 * The note is written twice: marked `pending` before the key is generated and without the mark once the key is
 * complete. A key whose note is still pending was cut short, by the app being stopped or by a deletion that failed, and
 * is deleted the next time its alias is read or created, because the secret store cannot be listed.
 */
export async function createHardwareKey(
  alias: string,
  requireBiometric: boolean,
  prompt: string,
): Promise<ManagedSigner | undefined> {
  const secureEnvironment = await loadSecureEnvironment();
  if (secureEnvironment === undefined) return undefined;
  // A key left by a create that was cut short is deleted before another one is generated under its alias.
  const note = await SecureStore.getItemAsync(META_PREFIX + alias);
  if (note !== null && parseMeta(note).pending === true) await clearUnfinished(secureEnvironment, alias);
  let supported: boolean;
  try {
    supported = secureEnvironment.isSecureEnvironmentSupported({ minimumKeyStorage: MINIMUM_KEY_STORAGE });
  } catch (cause) {
    throw unavailable(cause);
  }
  if (!supported) return undefined;

  await writeMeta(alias, { v: 1, kind: 'hardware', requireBiometric, pending: true });
  try {
    await secureEnvironment.generateKeypair(alias, {
      minimumKeyStorage: MINIMUM_KEY_STORAGE,
      userAuthentication: requireBiometric
        ? { methods: ['biometric'], invalidateOnBiometricChange: true, validitySeconds: 0 }
        : false,
    });
  } catch {
    // No biometrics enrolled, no suitable storage after all, or another refusal: the module made no key.
    await SecureStore.deleteItemAsync(META_PREFIX + alias).catch(() => undefined);
    return undefined;
  }

  let signer: ManagedSigner;
  try {
    signer = await hardwareSigner(secureEnvironment, alias, prompt);
  } catch (cause) {
    await discardKey(secureEnvironment, alias);
    throw unavailable(cause);
  }
  try {
    await writeMeta(alias, { v: 1, kind: 'hardware', requireBiometric });
  } catch (error) {
    await discardKey(secureEnvironment, alias);
    throw error;
  }
  return signer;
}

/** The signer of a hardware key made earlier, or `null` when there is no note about one or the hardware lost the key. */
export async function getHardwareKey(alias: string, prompt: string): Promise<ManagedSigner | null> {
  const note = await SecureStore.getItemAsync(META_PREFIX + alias);
  if (note === null) return null;
  if (parseMeta(note).pending === true) {
    await clearUnfinished(await loadSecureEnvironment(), alias);
    return null;
  }
  const secureEnvironment = await requireSecureEnvironment();
  try {
    return await hardwareSigner(secureEnvironment, alias, prompt);
  } catch (cause) {
    if (nameOf(cause) === 'KeyNotFoundError') return null;
    throw translate(cause);
  }
}

export async function removeHardwareKey(alias: string): Promise<void> {
  const note = await SecureStore.getItemAsync(META_PREFIX + alias);
  if (note === null) return;
  const secureEnvironment = await requireSecureEnvironment();
  try {
    await secureEnvironment.deleteKey(alias);
  } catch (cause) {
    if (nameOf(cause) !== 'KeyNotFoundError') throw translate(cause);
  }
  await SecureStore.deleteItemAsync(META_PREFIX + alias);
}

/**
 * A key whose note is still pending was never completed. The module is asked to delete it and, whatever it answers (the
 * key may never have been generated), the note goes too and the alias is free again.
 */
async function clearUnfinished(secureEnvironment: SecureEnvironment | undefined, alias: string): Promise<void> {
  await secureEnvironment?.deleteKey(alias).catch(() => undefined);
  await SecureStore.deleteItemAsync(META_PREFIX + alias);
}

/** Deletes a key that was generated but not completed; its pending note stays until the key is gone. */
async function discardKey(secureEnvironment: SecureEnvironment, alias: string): Promise<void> {
  try {
    await secureEnvironment.deleteKey(alias);
  } catch (cause) {
    if (nameOf(cause) !== 'KeyNotFoundError') return;
  }
  await SecureStore.deleteItemAsync(META_PREFIX + alias).catch(() => undefined);
}

async function writeMeta(alias: string, meta: HardwareMeta): Promise<void> {
  await SecureStore.setItemAsync(META_PREFIX + alias, JSON.stringify(meta), STORE_OPTIONS);
}

async function requireSecureEnvironment(): Promise<SecureEnvironment> {
  const secureEnvironment = await loadSecureEnvironment();
  if (secureEnvironment === undefined) {
    throw new UmisError(
      'CRYPTO_UNAVAILABLE',
      'the key lives in the secure hardware, but @animo-id/expo-secure-environment is not available',
    );
  }
  return secureEnvironment;
}

async function hardwareSigner(
  secureEnvironment: SecureEnvironment,
  alias: string,
  prompt: string,
): Promise<ManagedSigner> {
  const compressed = await secureEnvironment.getPublicBytesForKeyId(alias);
  if (!(compressed instanceof Uint8Array) || compressed.length !== COMPRESSED_POINT_BYTES) {
    throw new UmisError('CRYPTO_UNAVAILABLE', 'the secure hardware returned a public key of the wrong shape');
  }
  const point = p256.Point.fromBytes(compressed).toBytes(false); // 0x04 ‖ x ‖ y, checked to lie on the curve
  const base = {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlEncode(point.subarray(1, 33)),
    y: base64urlEncode(point.subarray(33, 65)),
  } as const;
  const kid = await jwkThumbprint(base, noble);
  const publicJwk: EcPublicJwk = { ...base, kid, alg: 'ES256', use: 'sig' };
  return {
    alg: 'ES256',
    kid,
    publicJwk,
    protection: 'hardware',
    attestation: 'none',
    sign: (data) => signSerially(secureEnvironment, alias, prompt, data),
  };
}

// On iOS a second prompt cancels the one that is showing, so confirmations are asked one after the other.
let signing: Promise<unknown> = Promise.resolve();

function signSerially(
  secureEnvironment: SecureEnvironment,
  alias: string,
  prompt: string,
  data: Uint8Array,
): Promise<Uint8Array> {
  const run = signing.then(() => signInHardware(secureEnvironment, alias, prompt, data));
  signing = run.catch(() => undefined);
  return run;
}

async function signInHardware(
  secureEnvironment: SecureEnvironment,
  alias: string,
  prompt: string,
  data: Uint8Array,
): Promise<Uint8Array> {
  let signature: Uint8Array;
  try {
    // The module hashes the message with SHA-256 and returns r ‖ s. The signature is passed on as it is, whichever half
    // of the curve order s lies in: every verifier of this SDK accepts both.
    signature = await secureEnvironment.sign(alias, data, { prompt: { title: prompt } });
  } catch (cause) {
    throw translate(cause);
  }
  if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_BYTES) {
    throw new UmisError('CRYPTO_UNAVAILABLE', 'the secure hardware returned a signature of the wrong shape');
  }
  return signature;
}

function parseMeta(text: string): HardwareMeta {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    // Without the parser's error as the cause, as for key records: its message quotes part of the stored text.
    throw new UmisError('MALFORMED', 'the stored key note is not JSON');
  }
  const meta = value as Partial<HardwareMeta> | null;
  if (meta === null || typeof meta !== 'object' || meta.v !== 1 || meta.kind !== 'hardware') {
    throw new UmisError('MALFORMED', 'the stored key note has an unexpected shape');
  }
  const parsed: HardwareMeta = { v: 1, kind: 'hardware', requireBiometric: meta.requireBiometric === true };
  if (meta.pending === true) parsed.pending = true;
  return parsed;
}

/** The module's errors are told apart by name, which each of its error classes sets. */
function nameOf(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const name = (error as { name?: unknown }).name;
  return typeof name === 'string' ? name : undefined;
}

/** A failure of the module while a key is made, other than a refusal to generate it. */
function unavailable(cause: unknown): UmisError {
  if (cause instanceof UmisError && cause.code === 'CRYPTO_UNAVAILABLE') return cause;
  return new UmisError('CRYPTO_UNAVAILABLE', 'the secure hardware failed while the key was made', { cause });
}

function translate(cause: unknown): UmisError {
  if (cause instanceof UmisError) return cause;
  switch (nameOf(cause)) {
    case 'KeyNotFoundError':
    case 'KeyInvalidatedError':
      return new UmisError('KEY_NOT_FOUND', 'the hardware key is gone or was invalidated', { cause });
    case 'UserAuthenticationCanceledError':
    case 'UserAuthenticationFailedError':
    case 'UserAuthenticationLockedOutError':
    case 'UserAuthenticationUnavailableError':
      return new UmisError('USER_CANCELLED', 'the person did not confirm', { cause });
    default:
      return new UmisError('CRYPTO_UNAVAILABLE', 'the secure hardware failed', { cause });
  }
}
