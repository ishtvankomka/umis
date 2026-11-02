import { VCT } from '@umis/core';
import type { AuthorityItem, DecodedCredential, DelegationClaim, UmisClaimSet } from '@umis/core';
import { assertDelegationAllowed, issueSdJwtVc } from './issue.js';
import type { IssueSdJwtVcInput } from './issue.js';
import { authorityProblems, invalid, isNatural, isRecord, isText, own } from './profile.js';

/** What is unusable about the issuer's copy of a parent credential; empty when it can be delegated from. */
function parentProblems(parent: unknown, issuer: unknown): string[] {
  if (!isRecord(parent)) return ['parent must be a decoded credential'];
  const problems: string[] = [];
  if (parent.vct !== VCT.roleAuthority) problems.push('parent must be a role-authority credential');
  if (!isText(parent.jti)) problems.push('parent.jti must be a non-empty string');
  if (parent.issuer !== issuer) problems.push('a credential can only be delegated by the issuer of its parent');
  if (typeof parent.exp !== 'number' || !Number.isFinite(parent.exp)) {
    problems.push('parent.exp must be a finite number');
  }
  const status = parent.status;
  if (!isRecord(status) || !isText(own(status, 'uri')) || !isNatural(own(status, 'idx'))) {
    problems.push('parent.status must hold a uri and an index');
  }
  const claims = parent.claims;
  if (!isRecord(claims)) return [...problems, 'parent.claims must hold the disclosed claims'];
  if (!isRecord(own(claims, 'org'))) problems.push('the parent copy must disclose org');
  const authority = own(claims, 'authority');
  if (authority === undefined) problems.push('the parent copy must disclose authority');
  else problems.push(...authorityProblems(authority, 'parent authority'));
  const delegation = own(claims, 'delegation');
  if (!isRecord(delegation) || !isNatural(own(delegation, 'depth')) || !isNatural(own(delegation, 'max_depth'))) {
    problems.push('the parent copy must disclose delegation with its depth and max_depth');
  }
  return problems;
}

/**
 * Issues a credential that hands part of the authority of `parent` on, signed by the same issuer. `parent` is the
 * issuer's own full copy of the parent credential, with `org`, `authority` and `delegation` disclosed (what
 * `decodeCredential` returns for it).
 *
 * The new credential takes its organisation from the parent, and its role from the parent unless `claims.role` is given.
 * Its `delegation` claim carries a summary of the parent `{id, status, authority, exp}`, `depth: parent.depth + 1` and
 * the `max_depth` of the parent, so that a verifier can hold it to the parent without reaching the issuer.
 *
 * It is never wider than the parent, which is checked before anything is signed, in this order: depth
 * (DELEGATION_DEPTH_EXCEEDED), lifetime (DELEGATION_OUTLIVES_PARENT) and authority (DELEGATION_WIDER_THAN_PARENT: every
 * item needs a parent item with the same action, resource, unit and period, an amount that is not larger, the object
 * restriction kept and a `valid_until` that does not come after the parent's). Other mistakes are INVALID_ARGUMENT.
 */
export async function issueDelegated(
  i: Omit<IssueSdJwtVcInput, 'vct' | 'claims'> & {
    parent: DecodedCredential; //  the issuer's full copy (authority and delegation disclosed)
    claims: Pick<UmisClaimSet, 'org_unit' | 'role' | 'display'> & { authority: AuthorityItem[] }; // org copied from the parent; role defaults to the parent's
  },
): Promise<string> {
  const request: unknown = i;
  if (!isRecord(request)) throw invalid('the issuance request must be an object');
  const { parent, claims, ...rest } = i;

  const problems = parentProblems(parent, i.issuer);
  const given: unknown = claims;
  if (isRecord(given)) problems.push(...authorityProblems(own(given, 'authority'), 'claims.authority'));
  else problems.push('claims must be an object');
  if (typeof i.exp !== 'number' || !Number.isFinite(i.exp)) problems.push('exp must be a finite number of seconds');
  if (problems.length === 0) {
    if (i.jti === parent.jti) problems.push('jti must differ from the jti of the parent');
    const status: unknown = i.status;
    if (isRecord(status) && status.uri === parent.status.uri && status.idx === parent.status.idx) {
      problems.push('status must differ from the status of the parent');
    }
  }
  if (problems.length > 0) throw invalid(`the credential cannot be delegated: ${problems.join('; ')}`);

  // the copy was checked above: the three claims it must disclose are there and well-formed
  const held = parent.claims as Required<Pick<UmisClaimSet, 'org' | 'authority' | 'delegation'>> &
    Partial<UmisClaimSet>;
  const { depth, max_depth: maxDepth } = held.delegation;
  assertDelegationAllowed({
    parent: { authority: held.authority, exp: parent.exp, depth, maxDepth },
    child: { authority: claims.authority, exp: i.exp },
  });

  const delegation: DelegationClaim = {
    parent: {
      id: parent.jti,
      status: { uri: parent.status.uri, idx: parent.status.idx },
      authority: held.authority,
      exp: parent.exp,
    },
    depth: depth + 1,
    max_depth: maxDepth,
  };
  const delegated: UmisClaimSet = { org: held.org, authority: claims.authority, delegation };
  if (claims.org_unit !== undefined) delegated.org_unit = claims.org_unit;
  const role = claims.role ?? held.role;
  if (role !== undefined) delegated.role = role;
  if (claims.display !== undefined) delegated.display = claims.display;
  return issueSdJwtVc({ ...rest, vct: VCT.roleAuthority, claims: delegated });
}
