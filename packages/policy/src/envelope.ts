import {
  TYP,
  UmisError,
  signJws,
  verifyJws,
  type CheckpointPolicyV1,
  type CryptoProvider,
  type EcPublicJwk,
  type Signer,
} from '@umis/core';
import { z } from 'zod';
import { describeIssues } from './schema.js';
import { validatePolicy } from './validate.js';

/** Payload of a signed policy: the owner organisation (`iss`), the policy id (`sub`), its version and issue time. */
export interface PolicyEnvelopeV1 {
  iss: string;
  sub: string;
  ver: number;
  iat: number;
  policy: CheckpointPolicyV1;
}

const envelopeSchema = z.strictObject({
  iss: z.string().min(1),
  sub: z.string().min(1),
  ver: z.number().int().nonnegative(),
  iat: z.number().nonnegative(),
  policy: z.unknown(),
});

function checkEnvelope(value: unknown): { ok: true; envelope: PolicyEnvelopeV1 } | { ok: false; reason: string } {
  const shell = envelopeSchema.safeParse(value);
  if (!shell.success) return { ok: false, reason: describeIssues(shell.error).join('; ') };
  const checked = validatePolicy(shell.data.policy);
  if (!checked.ok) return { ok: false, reason: `${checked.code}: ${checked.errors.join('; ')}` };
  const { iss, sub, ver, iat } = shell.data;
  return { ok: true, envelope: { iss, sub, ver, iat, policy: checked.policy } };
}

/**
 * Signs a policy envelope as an ES256 JWS of type `umis-policy+jwt`. The envelope and the policy in it are validated
 * first (`INVALID_ARGUMENT` when either is not acceptable), so a policy that breaks its class caps is never signed.
 */
export async function signPolicy(e: PolicyEnvelopeV1, signer: Signer): Promise<string> {
  const checked = checkEnvelope(e);
  if (!checked.ok) throw new UmisError('INVALID_ARGUMENT', `the policy envelope is not valid: ${checked.reason}`);
  return signJws({ header: { typ: TYP.policy }, payload: checked.envelope, signer });
}

/**
 * Verifies a signed policy against the owner's keys and validates the policy again. The JWS failures of
 * `verifyJws` pass through (`UNSUPPORTED_FORMAT` for a wrong type, `SIGNATURE_INVALID` for a payload that was
 * changed); a correctly signed envelope that does not validate is `MALFORMED`.
 */
export async function verifyPolicy(
  jws: string,
  keys: EcPublicJwk | readonly EcPublicJwk[],
  crypto?: CryptoProvider,
): Promise<PolicyEnvelopeV1> {
  const decoded = await verifyJws(jws, { typ: TYP.policy, key: keys, crypto });
  const checked = checkEnvelope(decoded.payload);
  if (!checked.ok) throw new UmisError('MALFORMED', `the signed policy envelope is not valid: ${checked.reason}`);
  return checked.envelope;
}
