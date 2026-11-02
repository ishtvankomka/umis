import { UmisError } from '@umis/core';
import type { DecisionEventV1, VerificationResult } from '@umis/core';

/**
 * The audit event of a decision, ready to be signed with `signEvent` or appended to a journal: who decided (`iss`), the
 * journal position (`seq`), when, at which checkpoint (`chk`), over which channel, the outcome and its reason, the
 * credential type, issuer and reference when the credential was identified, the latency in milliseconds, the age of the
 * status list and the policy version (`pv`, else the one in the result). The event carries no claim values.
 */
export function createDecisionEvent(
  r: VerificationResult,
  i: { iss: string; seq: number; chk: string; pv?: number },
): DecisionEventV1 {
  if (typeof i.iss !== 'string' || i.iss === '') throw new UmisError('INVALID_ARGUMENT', 'iss must name the verifier');
  if (typeof i.chk !== 'string' || i.chk === '')
    throw new UmisError('INVALID_ARGUMENT', 'chk must name the checkpoint');
  if (!Number.isSafeInteger(i.seq) || i.seq < 1) {
    throw new UmisError('INVALID_ARGUMENT', 'seq is a positive integer');
  }

  const latency = Number.isFinite(r.timings.totalMs) ? Math.max(0, r.timings.totalMs) : 0;
  const event: DecisionEventV1 = {
    iss: i.iss,
    seq: i.seq,
    iat: r.at,
    chk: i.chk,
    ch: r.channel,
    dec: r.decision,
    rsn: [...r.reasons],
    lat: Math.round(latency * 1000) / 1000,
  };
  if (r.vct !== undefined) event.vct = r.vct;
  if (r.issuer !== undefined) event.ciss = r.issuer;
  if (r.credentialRef !== undefined) event.cref = r.credentialRef;
  if (r.statusListAgeSeconds !== undefined) event.sla = r.statusListAgeSeconds;
  const policyVersion = i.pv ?? r.policyVersion;
  if (policyVersion !== undefined) event.pv = policyVersion;
  return event;
}
