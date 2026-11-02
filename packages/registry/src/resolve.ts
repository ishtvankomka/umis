import { UmisError, asEcPublicJwk, type EcPublicJwk, type TrustedIssuerEntryV1 } from '@umis/core';
import { describeIssues, trustedIssuerEntrySchema } from './schema.js';

/** The outcome of {@link resolveIssuer}: the trusted entry with the key to verify with, or the one reason for refusing. */
export type IssuerResolution =
  | { ok: true; entry: TrustedIssuerEntryV1; key: EcPublicJwk }
  | { ok: false; reason: 'ISSUER_UNTRUSTED' | 'ISSUER_SUSPENDED' | 'ISSUER_VCT_NOT_ALLOWED' | 'ISSUER_KEY_UNKNOWN' };

/**
 * The key that verifies a credential. A header `kid` selects the key with that `kid`; failing that, an entry with one
 * key that has no `kid` serves. Without a header `kid` the entry's only key is used. Otherwise there is no key.
 */
function selectKey(keys: readonly EcPublicJwk[], kid: string | undefined): EcPublicJwk | undefined {
  const only = keys.length === 1 ? keys[0] : undefined;
  if (kid === undefined) return only;
  return keys.find((key) => key.kid === kid) ?? (only?.kid === undefined ? only : undefined);
}

/**
 * Decides whether an issuer may be trusted for a credential type and which of its keys verifies the credential. The
 * only source of trust is `trusted`, the verifier's own registry (as returned by `parseRegistry`, one entry per
 * issuer); the issuer must match an entry exactly. The checks run in this order and the first failure is the answer:
 * no entry (`ISSUER_UNTRUSTED`), an entry that is not active or whose `validUntil` is before `now`
 * (`ISSUER_SUSPENDED`), a type the entry does not list (`ISSUER_VCT_NOT_ALLOWED`), no matching key
 * (`ISSUER_KEY_UNKNOWN`).
 */
export function resolveIssuer(
  trusted: readonly TrustedIssuerEntryV1[],
  i: { issuer: string; vct: string; kid?: string; now: number },
): IssuerResolution {
  const entry = trusted.find((candidate) => candidate.issuer === i.issuer);
  if (entry === undefined) return { ok: false, reason: 'ISSUER_UNTRUSTED' };
  // `!(validUntil >= now)` rather than `validUntil < now`: a now that is not a number then fails closed.
  if (entry.status !== 'active' || (entry.validUntil !== undefined && !(entry.validUntil >= i.now))) {
    return { ok: false, reason: 'ISSUER_SUSPENDED' };
  }
  if (!entry.vcts.includes(i.vct)) return { ok: false, reason: 'ISSUER_VCT_NOT_ALLOWED' };
  const key = selectKey(entry.jwks.keys, i.kid);
  if (key === undefined) return { ok: false, reason: 'ISSUER_KEY_UNKNOWN' };
  return { ok: true, entry, key };
}

/**
 * The entry of `issuer` itself when it lists the status list `uri`. A list published under the same address by
 * another issuer's entry does not count: a status list is only trusted through the entry of the issuer that signs it.
 */
export function entryForStatusList(
  trusted: readonly TrustedIssuerEntryV1[],
  issuer: string,
  uri: string,
): TrustedIssuerEntryV1 | undefined {
  return trusted.find((entry) => entry.issuer === issuer && entry.statusLists.includes(uri));
}

/**
 * The active entry of an organisation's own issuer, built from its keys (the public part is taken; a private member is
 * dropped). A verifier whose policy accepts `'self'` adds it to its trusted list.
 */
export function selfEntry(i: {
  issuer: string;
  name: string;
  keys: EcPublicJwk[];
  vcts: string[];
  statusLists: string[];
}): TrustedIssuerEntryV1 {
  const keys: unknown = Array.isArray(i.keys) ? i.keys.map((key) => asEcPublicJwk(key)) : i.keys;
  const parsed = trustedIssuerEntrySchema.safeParse({
    issuer: i.issuer,
    name: i.name,
    jwks: { keys },
    vcts: i.vcts,
    statusLists: i.statusLists,
    status: 'active',
  });
  if (!parsed.success) {
    throw new UmisError(
      'INVALID_ARGUMENT',
      `the registry entry is not valid: ${describeIssues(parsed.error).join('; ')}`,
    );
  }
  return parsed.data;
}
