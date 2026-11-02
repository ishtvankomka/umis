import { CHANNELS, DISCLOSABLE_CLAIMS, RISK_CLASSES, type CheckpointPolicyV1 } from '@umis/core';
import { z } from 'zod';

/** One readable line per validation issue: the path inside the document, then the message. */
export function describeIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => `${issue.path.map(String).join('.') || '(document)'}: ${issue.message}`);
}

const acceptedSchema = z.strictObject({
  vct: z.string().min(1).describe('Credential type (vct) URI.'),
  issuers: z
    .union([z.enum(['self', 'registry']), z.array(z.string().min(1)).min(1)])
    .describe(
      "'self' is the verifier's own issuer, 'registry' is any issuer of the trusted-issuer registry, a list names issuers by identifier.",
    ),
});

const authoritySchema = z.strictObject({
  action: z.string().min(1).describe('Action the credential must authorise.'),
  resource: z.string().min(1).describe('Resource the action applies to.'),
  unit: z.string().min(1).describe('Unit of the amount; compared as an exact string.'),
  amountSource: z
    .enum(['request', 'fixed'])
    .describe("'request' takes the amount from the presentation request, 'fixed' uses fixedAmount."),
  fixedAmount: z.number().positive().optional().describe("Amount to check when amountSource is 'fixed'."),
});

/**
 * The checkpoint policy document, `umis.policy.v1`. Unknown members are rejected. The schema covers the shape and the
 * rules between members of one policy; the limits of the risk class are applied by {@link validatePolicy}.
 */
export const checkpointPolicySchema: z.ZodType<CheckpointPolicyV1> = z
  .strictObject({
    schema: z.literal('umis.policy.v1').describe('Document identifier.'),
    riskClass: z
      .enum(RISK_CLASSES)
      .describe('Risk class. It caps the status age, the allowed channels and the biometric requirement.'),
    channels: z
      .array(z.enum(CHANNELS))
      .min(1)
      .describe('Channels the checkpoint accepts. The risk class limits them; qr_oneway exists only in the low class.'),
    maxStatusAgeSeconds: z
      .number()
      .int()
      .positive()
      .describe('S: the oldest status list, in seconds, that the checkpoint accepts.'),
    statusRefreshSeconds: z
      .number()
      .int()
      .positive()
      .describe('Delta: how often a status list is refreshed, in seconds. Not larger than S.'),
    oneWayTokenMaxAgeSeconds: z
      .number()
      .int()
      .nonnegative()
      .describe('Longest accepted lifetime of a one-way token, in seconds. At most 30.'),
    requireBiometric: z.boolean().describe('Whether the holder must pass a biometric check before presenting.'),
    accepted: z.array(acceptedSchema).min(1).describe('Credential types the checkpoint accepts and their issuers.'),
    requestedClaims: z
      .array(z.enum(DISCLOSABLE_CLAIMS).exclude(['delegation']))
      .describe(
        "Claims the verifier asks the holder to disclose. 'delegation' is never listed; it accompanies 'authority'.",
      ),
    authority: authoritySchema
      .optional()
      .describe('Power of authority to check. Needs authority among the requested claims.'),
    relay: z
      .strictObject({
        openSeconds: z.number().int().positive().describe('How long the relay stays switched on, in seconds.'),
      })
      .optional()
      .describe('Relay action after an accept.'),
  })
  .meta({
    title: 'UMIS checkpoint policy',
    description: 'What one verification point accepts, how fresh its status data must be and what it asks for.',
  })
  .refine((policy) => policy.statusRefreshSeconds <= policy.maxStatusAgeSeconds, {
    path: ['statusRefreshSeconds'],
    message: 'must not be larger than maxStatusAgeSeconds',
  })
  .refine((policy) => policy.authority === undefined || policy.requestedClaims.includes('authority'), {
    path: ['requestedClaims'],
    message: "must include 'authority' when the policy checks an authority",
  })
  .refine(
    (policy) =>
      policy.authority?.amountSource !== 'fixed' ||
      (policy.authority.fixedAmount !== undefined && policy.authority.fixedAmount > 0),
    { path: ['authority', 'fixedAmount'], message: "must be a positive number when amountSource is 'fixed'" },
  );

/** The JSON Schema (draft 2020-12) of {@link checkpointPolicySchema}, as committed in `schema/`. */
export const checkpointPolicyJsonSchema: Record<string, unknown> = z.toJSONSchema(checkpointPolicySchema, {
  target: 'draft-2020-12',
});
