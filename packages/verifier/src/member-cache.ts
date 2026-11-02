import { UmisError, parseSdJwt } from '@umis/core';
import type { CryptoProvider, MemberCacheEntry } from '@umis/core';

/**
 * Builds the member-cache entry of a credential, the record a verifier keeps to accept one-way tokens of it offline.
 * `sdJwtVc` is the credential as issued, with all its disclosures. Its structure is checked, its issuer signature is
 * not: the party that fills the cache has verified the credential before it goes in. The credential must disclose
 * `org`; `org_unit`, `role` and `display` are kept when present, `authority` and `delegation` never are.
 */
export async function memberCacheEntryFromCredential(
  sdJwtVc: string,
  crypto?: CryptoProvider,
): Promise<MemberCacheEntry> {
  const parsed = await parseSdJwt(sdJwtVc, crypto);
  const payload = parsed.issuerJwt.payload;
  const { org, org_unit: orgUnit, role, display } = parsed.claims;
  if (org === undefined) throw new UmisError('MALFORMED', 'the credential discloses no org claim');

  const claims: MemberCacheEntry['claims'] = { org };
  if (orgUnit !== undefined) claims.org_unit = orgUnit;
  if (role !== undefined) claims.role = role;
  if (display !== undefined) claims.display = display;
  return {
    credRef: payload.jti,
    issuer: payload.iss,
    vct: payload.vct,
    cnfJwk: payload.cnf.jwk,
    exp: payload.exp,
    status: payload.status.status_list,
    claims,
  };
}
