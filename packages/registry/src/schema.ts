import { asEcPublicJwk, type EcPublicJwk, type TrustedIssuerEntryV1 } from '@umis/core';
import { z } from 'zod';

/** One readable line per validation issue: the path inside the document, then the message. */
export function describeIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => `${issue.path.map(String).join('.') || '(document)'}: ${issue.message}`);
}

function isPublicPoint(jwk: unknown): boolean {
  try {
    asEcPublicJwk(jwk);
    return true;
  } catch {
    return false;
  }
}

// A registry carries public keys only: a private member such as `d` is an unknown member and fails the schema.
const publicJwkSchema: z.ZodType<EcPublicJwk> = z
  .strictObject({
    kty: z.literal('EC'),
    crv: z.literal('P-256'),
    x: z.string(),
    y: z.string(),
    kid: z.string().min(1).optional(),
    alg: z.literal('ES256').optional(),
    use: z.literal('sig').optional(),
  })
  .refine(isPublicPoint, { message: 'x and y must be the base64url encoding of 32 bytes' });

/**
 * One trusted issuer: its identifier, display name, signing keys, the credential types it may issue, the status lists
 * it publishes and whether the verifier's organisation currently trusts it. Unknown members are rejected.
 */
export const trustedIssuerEntrySchema: z.ZodType<TrustedIssuerEntryV1> = z.strictObject({
  issuer: z.string().min(1),
  name: z.string().min(1),
  jwks: z.strictObject({ keys: z.array(publicJwkSchema) }),
  vcts: z.array(z.string().min(1)),
  statusLists: z.array(z.string().min(1)),
  validUntil: z.number().nonnegative().optional(),
  status: z.enum(['active', 'suspended', 'revoked']),
});
