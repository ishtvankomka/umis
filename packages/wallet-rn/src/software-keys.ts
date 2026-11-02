import { p256 } from '@noble/curves/nist.js';
import { UmisError, asEcPublicJwk, base64urlEncode, jwkThumbprint, randomBytes } from '@umis/core';
import type { EcPrivateJwk, EcPublicJwk } from '@umis/core';
import { nobleCryptoProvider } from '@umis/core/noble';
import * as SecureStore from 'expo-secure-store';
import type { ManagedSigner } from './keystore.js';

/** The secret store holds the record of a software key under `umis.key.<alias>`. */
const KEY_PREFIX = 'umis.key.';
/** Bytes of randomness that map into the P-256 scalar field with negligible bias. */
const SEED_BYTES = 48;
/** The key never leaves this device and is readable only while the device is unlocked. */
const STORE_OPTIONS = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };

// Signing and the RFC 7638 thumbprint go through the SDK's @noble provider: it needs no `globalThis.crypto`, which Expo
// Go does not have, and its curve takes no randomness from outside its arguments.
const noble = nobleCryptoProvider();

interface SoftwareRecord {
  v: 1;
  kind: 'software';
  requireBiometric: boolean;
  jwk: EcPrivateJwk;
}

/** How a key that needs a confirmation gets it. */
export interface Confirmation {
  authenticate: ((prompt: string) => Promise<boolean>) | undefined;
  prompt: string;
}

export async function createSoftwareKey(
  alias: string,
  requireBiometric: boolean,
  confirmation: Confirmation,
): Promise<ManagedSigner> {
  if (requireBiometric && confirmation.authenticate === undefined) {
    throw new UmisError(
      'INVALID_ARGUMENT',
      'a software key with requireBiometric needs the authenticate function of createKeyStore',
    );
  }
  const seed = randomBytes(SEED_BYTES);
  let secretKey: Uint8Array | undefined;
  try {
    secretKey = p256.utils.randomSecretKey(seed);
    const point = p256.getPublicKey(secretKey, false); // 0x04 ‖ x ‖ y
    const jwk: EcPrivateJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: base64urlEncode(point.subarray(1, 33)),
      y: base64urlEncode(point.subarray(33, 65)),
      d: base64urlEncode(secretKey),
    };
    // The provider derives the public point again with its own curve and refuses x and y that do not belong to d.
    const { kid, publicJwk } = await noble.importSigner(jwk);
    const record: SoftwareRecord = { v: 1, kind: 'software', requireBiometric, jwk };
    await SecureStore.setItemAsync(KEY_PREFIX + alias, JSON.stringify(record), STORE_OPTIONS);
    return softwareSigner(alias, publicJwk, kid, requireBiometric, confirmation);
  } finally {
    seed.fill(0);
    secretKey?.fill(0);
  }
}

export async function getSoftwareKey(alias: string, confirmation: Confirmation): Promise<ManagedSigner | null> {
  const record = await readRecord(alias);
  if (record === null) return null;
  const base = asEcPublicJwk({ kty: record.jwk.kty, crv: record.jwk.crv, x: record.jwk.x, y: record.jwk.y });
  const kid = await jwkThumbprint(base, noble);
  const publicJwk: EcPublicJwk = { ...base, kid, alg: 'ES256', use: 'sig' };
  return softwareSigner(alias, publicJwk, kid, record.requireBiometric, confirmation);
}

export async function hasSoftwareKey(alias: string): Promise<boolean> {
  return (await SecureStore.getItemAsync(KEY_PREFIX + alias)) !== null;
}

export async function removeSoftwareKey(alias: string): Promise<void> {
  await SecureStore.deleteItemAsync(KEY_PREFIX + alias);
}

/**
 * The signer keeps no secret: each signature reads the record, so the private key is released only after the
 * confirmation and a removed key can no longer sign.
 */
function softwareSigner(
  alias: string,
  publicJwk: EcPublicJwk,
  kid: string,
  requireBiometric: boolean,
  confirmation: Confirmation,
): ManagedSigner {
  return {
    alg: 'ES256',
    kid,
    publicJwk,
    protection: 'software',
    attestation: 'none',
    async sign(data: Uint8Array): Promise<Uint8Array> {
      if (requireBiometric) await confirm(confirmation);
      const record = await readRecord(alias);
      if (record === null || record.jwk.x !== publicJwk.x || record.jwk.y !== publicJwk.y) {
        throw new UmisError('KEY_NOT_FOUND', `the key "${alias}" is gone or was replaced`);
      }
      const signer = await noble.importSigner(record.jwk, { kid });
      return signer.sign(data);
    },
  };
}

/** Resolves only when the person was recognised; anything else, a rejection included, refuses the signature. */
async function confirm({ authenticate, prompt }: Confirmation): Promise<void> {
  if (authenticate === undefined) {
    throw new UmisError(
      'INVALID_ARGUMENT',
      'this key needs a biometric confirmation, but createKeyStore got no authenticate function',
    );
  }
  let confirmed: boolean;
  try {
    confirmed = (await authenticate(prompt)) === true;
  } catch (cause) {
    throw new UmisError('USER_CANCELLED', 'the confirmation failed', { cause });
  }
  if (!confirmed) throw new UmisError('USER_CANCELLED', 'the person did not confirm');
}

async function readRecord(alias: string): Promise<SoftwareRecord | null> {
  const text = await SecureStore.getItemAsync(KEY_PREFIX + alias);
  return text === null ? null : parseRecord(text);
}

function parseRecord(text: string): SoftwareRecord {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (cause) {
    throw new UmisError('MALFORMED', 'the stored key record is not JSON', { cause });
  }
  const record = value as Partial<SoftwareRecord> | null;
  const jwk = record?.jwk as Partial<EcPrivateJwk> | undefined;
  if (
    record === null ||
    typeof record !== 'object' ||
    record.v !== 1 ||
    record.kind !== 'software' ||
    typeof record.requireBiometric !== 'boolean' ||
    typeof jwk !== 'object' ||
    jwk === null ||
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    typeof jwk.x !== 'string' ||
    typeof jwk.y !== 'string' ||
    typeof jwk.d !== 'string'
  ) {
    throw new UmisError('MALFORMED', 'the stored key record has an unexpected shape');
  }
  return {
    v: 1,
    kind: 'software',
    requireBiometric: record.requireBiometric,
    jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d },
  };
}
