import { UmisError } from '@umis/core';
import type { Signer } from '@umis/core';
import { createHardwareKey, getHardwareKey, removeHardwareKey } from './hardware-keys.js';
import { createSoftwareKey, getSoftwareKey, hasSoftwareKey, removeSoftwareKey } from './software-keys.js';

/** Where the private key lives: in the secure hardware of the phone, or in the operating system's secret store. */
export type KeyProtection = 'hardware' | 'software';

/** An ES256 signer that knows how its key is protected. Keys are never attested, so `attestation` is always `'none'`. */
export interface ManagedSigner extends Signer {
  readonly protection: KeyProtection;
  readonly attestation: 'none';
}

export interface KeyStore {
  /** Makes a new key under `alias`. An alias that is already taken is refused: a key is never replaced. */
  create(alias: string, o: { requireBiometric: boolean; prompt?: string }): Promise<ManagedSigner>;
  /** The signer of an existing key, or `null` when there is none under this alias. */
  get(alias: string): Promise<ManagedSigner | null>;
  /** Deletes the key. Removing an alias that does not exist is not an error. */
  remove(alias: string): Promise<void>;
}

/** What the person is asked when a key needs a confirmation and nobody gave a text. */
const DEFAULT_PROMPT = 'Confirm that it is you to use this credential';

const ALIAS_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

// The calls for one alias run one after the other: `create` checks that the alias is free and then makes the key, and
// `get` deletes a hardware key whose making was cut short, which must not be the one that a `create` is making.
const queues = new Map<string, Promise<unknown>>();

function exclusively<T>(alias: string, task: () => Promise<T>): Promise<T> {
  const run = (queues.get(alias) ?? Promise.resolve()).then(task);
  queues.set(
    alias,
    run.catch(() => undefined),
  );
  return run;
}

function checkAlias(alias: unknown): asserts alias is string {
  if (typeof alias !== 'string' || !ALIAS_PATTERN.test(alias)) {
    throw new UmisError('INVALID_ARGUMENT', 'a key alias is 1 to 64 characters of A-Z, a-z, 0-9, "_" and "-"');
  }
}

/**
 * Key store for the mobile app. In a development build (`dev_client`) new keys are made in the secure hardware when the
 * device has it, and in the secret store of the operating system otherwise; in Expo Go (`expo_go`) they are always in
 * the secret store, because native modules cannot be added there.
 *
 * `authenticate` shows the biometric prompt for software keys that need a confirmation; it resolves to `true` only when
 * the person was recognised. `prompt` is the text of every confirmation unless `create` is given another one.
 */
export function createKeyStore(
  runtime: 'expo_go' | 'dev_client',
  opts: {
    authenticate?: (prompt: string) => Promise<boolean>;
    prompt?: string;
  } = {},
): KeyStore {
  if (runtime !== 'expo_go' && runtime !== 'dev_client') {
    throw new UmisError('INVALID_ARGUMENT', 'the runtime is "expo_go" or "dev_client"');
  }
  const authenticate = opts.authenticate;
  if (authenticate !== undefined && typeof authenticate !== 'function') {
    throw new UmisError('INVALID_ARGUMENT', 'authenticate must be a function');
  }
  const storePrompt = textOption(opts.prompt, 'prompt') ?? DEFAULT_PROMPT;
  const hardwareAllowed = runtime === 'dev_client';

  return {
    async create(alias, o) {
      checkAlias(alias);
      if (typeof o !== 'object' || o === null || typeof o.requireBiometric !== 'boolean') {
        throw new UmisError('INVALID_ARGUMENT', 'requireBiometric must be true or false');
      }
      const { requireBiometric } = o;
      const prompt = textOption(o.prompt, 'prompt') ?? storePrompt;
      return exclusively(alias, async () => {
        if (await exists(alias, hardwareAllowed)) {
          throw new UmisError('INVALID_ARGUMENT', `a key named "${alias}" already exists`);
        }
        if (hardwareAllowed) {
          const hardware = await createHardwareKey(alias, requireBiometric, prompt);
          if (hardware !== undefined) return hardware;
        }
        return createSoftwareKey(alias, requireBiometric, { authenticate, prompt });
      });
    },

    async get(alias) {
      checkAlias(alias);
      return exclusively(alias, async () => {
        if (hardwareAllowed) {
          const hardware = await getHardwareKey(alias, storePrompt);
          if (hardware !== null) return hardware;
        }
        return getSoftwareKey(alias, { authenticate, prompt: storePrompt });
      });
    },

    async remove(alias) {
      checkAlias(alias);
      return exclusively(alias, async () => {
        if (hardwareAllowed) await removeHardwareKey(alias);
        await removeSoftwareKey(alias);
      });
    },
  };
}

async function exists(alias: string, hardwareAllowed: boolean): Promise<boolean> {
  if (await hasSoftwareKey(alias)) return true;
  return hardwareAllowed && (await getHardwareKey(alias, DEFAULT_PROMPT)) !== null;
}

function textOption(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value === '') {
    throw new UmisError('INVALID_ARGUMENT', `${name} must be a non-empty string`);
  }
  return value;
}
