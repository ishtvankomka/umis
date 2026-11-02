import { CLASS_CAPS, LIMITS, type Channel, type CheckpointPolicyV1 } from '@umis/core';
import { checkpointPolicySchema, describeIssues } from './schema.js';

/** `POLICY_INVALID`: the document is malformed or contradicts itself. `POLICY_CLASS_CAP_EXCEEDED`: it asks for more than its risk class allows. */
export type PolicyErrorCode = 'POLICY_INVALID' | 'POLICY_CLASS_CAP_EXCEEDED';

function classCapViolations(policy: CheckpointPolicyV1): string[] {
  const caps = CLASS_CAPS[policy.riskClass];
  const errors: string[] = [];
  for (const channel of policy.channels) {
    if (!caps.channels.includes(channel)) {
      errors.push(`channels: "${channel}" is not allowed in the ${policy.riskClass} risk class`);
    }
  }
  if (policy.maxStatusAgeSeconds > caps.maxStatusAgeS) {
    errors.push(
      `maxStatusAgeSeconds: ${policy.maxStatusAgeSeconds} is more than the ${caps.maxStatusAgeS} the ${policy.riskClass} risk class allows`,
    );
  }
  if (policy.oneWayTokenMaxAgeSeconds > LIMITS.oneWayMaxTtlS) {
    errors.push(
      `oneWayTokenMaxAgeSeconds: ${policy.oneWayTokenMaxAgeSeconds} is more than the ${LIMITS.oneWayMaxTtlS} seconds a one-way token may live`,
    );
  }
  if (caps.biometric && !policy.requireBiometric) {
    errors.push(`requireBiometric: the ${policy.riskClass} risk class requires a biometric check`);
  }
  return errors;
}

/**
 * Checks a policy document. A document that does not fit the schema, or contradicts itself (a refresh interval above
 * the maximum status age, an authority check without the claim, a fixed amount without a value), is `POLICY_INVALID`.
 * A well-formed document that goes beyond what its risk class allows (channels, maximum status age, one-way token
 * lifetime, biometric requirement) is `POLICY_CLASS_CAP_EXCEEDED`. The returned policy is a copy of the input.
 */
export function validatePolicy(
  doc: unknown,
): { ok: true; policy: CheckpointPolicyV1 } | { ok: false; code: PolicyErrorCode; errors: string[] } {
  const parsed = checkpointPolicySchema.safeParse(doc);
  if (!parsed.success) return { ok: false, code: 'POLICY_INVALID', errors: describeIssues(parsed.error) };
  const errors = classCapViolations(parsed.data);
  if (errors.length > 0) return { ok: false, code: 'POLICY_CLASS_CAP_EXCEEDED', errors };
  return { ok: true, policy: parsed.data };
}

/** Whether the policy accepts `channel`: it lists the channel and the policy's risk class allows it. */
export function isChannelAllowed(policy: CheckpointPolicyV1, channel: Channel): boolean {
  if (!Object.hasOwn(CLASS_CAPS, policy.riskClass)) return false;
  return policy.channels.includes(channel) && CLASS_CAPS[policy.riskClass].channels.includes(channel);
}
