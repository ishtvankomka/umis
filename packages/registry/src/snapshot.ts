import {
  TYP,
  UmisError,
  signJws,
  verifyJws,
  type CryptoProvider,
  type EcPublicJwk,
  type Signer,
  type TrustedIssuerEntryV1,
} from '@umis/core';
import { z } from 'zod';
import { describeIssues, trustedIssuerEntrySchema } from './schema.js';

/** The signed content of a registry: the organisation that owns it (`iss`), a version, the issue time and the entries. */
export interface RegistrySnapshotV1 {
  iss: string;
  ver: number;
  iat: number;
  entries: TrustedIssuerEntryV1[];
}

const snapshotSchema = z.strictObject({
  iss: z.string().min(1),
  ver: z.number().int().nonnegative(),
  iat: z.number().nonnegative(),
  entries: z.array(trustedIssuerEntrySchema),
});

function checkSnapshot(value: unknown): { ok: true; snapshot: RegistrySnapshotV1 } | { ok: false; reason: string } {
  const parsed = snapshotSchema.safeParse(value);
  if (!parsed.success) return { ok: false, reason: describeIssues(parsed.error).join('; ') };
  const seen = new Set<string>();
  for (const { issuer } of parsed.data.entries) {
    if (seen.has(issuer)) return { ok: false, reason: `the issuer "${issuer}" has more than one entry` };
    seen.add(issuer);
  }
  return { ok: true, snapshot: parsed.data };
}

/**
 * Signs a registry snapshot as an ES256 JWS of type `umis-registry+jwt`. The snapshot is validated first
 * (`INVALID_ARGUMENT`): every entry must fit the schema and no issuer may appear twice.
 */
export async function signRegistry(s: RegistrySnapshotV1, signer: Signer): Promise<string> {
  const checked = checkSnapshot(s);
  if (!checked.ok) throw new UmisError('INVALID_ARGUMENT', `the registry snapshot is not valid: ${checked.reason}`);
  return signJws({ header: { typ: TYP.registry }, payload: checked.snapshot, signer });
}

/**
 * Verifies a registry snapshot against the keys of the organisation that owns it and returns its content. The JWS
 * failures of `verifyJws` pass through (`UNSUPPORTED_FORMAT` for a wrong type, `SIGNATURE_INVALID`,
 * `ISSUER_KEY_UNKNOWN`); a correctly signed snapshot that does not validate, or lists an issuer twice, is `MALFORMED`.
 * `version` is the snapshot's `ver`.
 */
export async function parseRegistry(
  jws: string,
  verifierJwk: EcPublicJwk | readonly EcPublicJwk[],
  crypto?: CryptoProvider,
): Promise<{ iss: string; version: number; iat: number; entries: TrustedIssuerEntryV1[] }> {
  const decoded = await verifyJws(jws, { typ: TYP.registry, key: verifierJwk, crypto });
  const checked = checkSnapshot(decoded.payload);
  if (!checked.ok) throw new UmisError('MALFORMED', `the signed registry snapshot is not valid: ${checked.reason}`);
  const { iss, ver, iat, entries } = checked.snapshot;
  return { iss, version: ver, iat, entries };
}
