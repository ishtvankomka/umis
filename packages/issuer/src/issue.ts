import { DISCLOSABLE_CLAIMS, UmisError, VCT, asEcPublicJwk, checkDelegation, issueCredential } from '@umis/core';
import type {
  AuthorityItem,
  CredentialPayload,
  CryptoProvider,
  DisclosableClaim,
  EcPublicJwk,
  Signer,
  StatusRef,
  UmisClaimSet,
} from '@umis/core';
import { credentialKind, invalid, isRecord, isText, own, profileErrors } from './profile.js';

export interface IssueSdJwtVcInput {
  signer: Signer;
  issuer: string;
  vct: string;
  jti: string;
  sub: string;
  iat: number;
  exp: number;
  nbf?: number;
  cnfJwk: EcPublicJwk;
  status: StatusRef;
  claims: UmisClaimSet;
  /** The claims that become selective disclosures; every other claim stays visible. Default: every claim present. */
  sdClaims?: readonly DisclosableClaim[];
  crypto?: CryptoProvider;
}

const isFiniteNumber = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);

const LINEAGE_MESSAGES = {
  DELEGATION_DEPTH_EXCEEDED: 'the parent credential cannot be delegated any further: max_depth is reached',
  DELEGATION_OUTLIVES_PARENT: 'the delegated credential would expire after its parent',
  DELEGATION_WIDER_THAN_PARENT: 'the delegated authority is wider than the authority of the parent',
} as const;

/**
 * The delegation rules of the core, as an error: throws DELEGATION_DEPTH_EXCEEDED, DELEGATION_OUTLIVES_PARENT or
 * DELEGATION_WIDER_THAN_PARENT (checked in that order) when the child is not allowed under the parent.
 */
export function assertDelegationAllowed(i: Parameters<typeof checkDelegation>[0]): void {
  const result = checkDelegation(i);
  if (!result.ok) throw new UmisError(result.reason, LINEAGE_MESSAGES[result.reason]);
}

/** Problems with the parts of an issuance request that are not claims. */
function inputProblems(i: IssueSdJwtVcInput): string[] {
  const problems: string[] = [];
  const { signer } = i;
  if (!isRecord(signer) || signer.alg !== 'ES256' || typeof signer.sign !== 'function' || !isText(signer.kid)) {
    problems.push('signer must be an ES256 signer with a kid');
  }
  for (const name of ['issuer', 'sub', 'jti'] as const) {
    if (!isText(i[name])) problems.push(`${name} must be a non-empty string`);
  }
  if (!isFiniteNumber(i.iat)) problems.push('iat must be a finite number of seconds');
  if (!isFiniteNumber(i.exp)) problems.push('exp must be a finite number of seconds');
  if (isFiniteNumber(i.iat) && isFiniteNumber(i.exp) && !(i.exp > i.iat)) problems.push('exp must be after iat');
  if (i.nbf !== undefined) {
    if (!isFiniteNumber(i.nbf)) problems.push('nbf must be a finite number of seconds');
    else if (isFiniteNumber(i.exp) && !(i.nbf < i.exp)) problems.push('nbf must be before exp');
  }
  if (isRecord(i.cnfJwk) && Object.hasOwn(i.cnfJwk, 'd')) {
    problems.push('cnfJwk must be a public key: it has a private member');
  } else {
    try {
      asEcPublicJwk(i.cnfJwk);
    } catch (error) {
      problems.push(`cnfJwk is not a P-256 public key (${error instanceof Error ? error.message : 'unreadable'})`);
    }
  }
  const status: unknown = i.status;
  if (!isRecord(status) || !isText(own(status, 'uri'))) problems.push('status.uri must be a non-empty string');
  const idx = isRecord(status) ? own(status, 'idx') : undefined;
  if (typeof idx !== 'number' || !Number.isSafeInteger(idx) || idx < 0) {
    problems.push('status.idx must be a non-negative integer');
  }
  if (i.sdClaims !== undefined) {
    const names: unknown = i.sdClaims;
    if (!Array.isArray(names)) problems.push('sdClaims must be a list of claim names');
    else {
      for (const name of names) {
        if (!(DISCLOSABLE_CLAIMS as readonly unknown[]).includes(name)) {
          problems.push(`sdClaims names "${String(name)}", which is not a claim of the profile`);
        }
      }
    }
  }
  return problems;
}

/**
 * Issues a credential of the UMIS profile as an SD-JWT VC: `<issuer-jwt>~<disclosure>~...~`.
 *
 * The request is checked first and every problem is reported in one INVALID_ARGUMENT error: the scalar inputs, then the
 * claim set against the credential type ({@link profileErrors}). A role-authority credential without a `delegation`
 * claim gets the root claim `{depth: 0, max_depth: 0}`, so that a verifier that asks for authority can always ask for the
 * delegation as well. When `authority` is a selective disclosure, `delegation` is one too: the parent summary repeats
 * authority details and must not stay visible while the authority itself is hidden.
 *
 * A delegated credential (`delegation.parent`) must be no wider than its parent, as `checkDelegation` of the core decides
 * it; a violation is DELEGATION_WIDER_THAN_PARENT, DELEGATION_DEPTH_EXCEEDED or DELEGATION_OUTLIVES_PARENT. The holder
 * key goes into `cnf.jwk` as bare coordinates; a key with a private member is refused.
 */
export async function issueSdJwtVc(i: IssueSdJwtVcInput): Promise<string> {
  const request: unknown = i;
  if (!isRecord(request)) throw invalid('the issuance request must be an object');
  const problems = inputProblems(i);

  const claimSet: unknown = i.claims;
  const claims: Partial<UmisClaimSet> | undefined = isRecord(claimSet)
    ? { ...(claimSet as Partial<UmisClaimSet>) }
    : undefined;
  if (claims !== undefined && credentialKind(i.vct) === 'role-authority' && claims.delegation === undefined) {
    claims.delegation = { depth: 0, max_depth: 0 };
  }
  problems.push(...profileErrors(i.vct, (claims ?? claimSet) as Partial<UmisClaimSet>));
  if (problems.length > 0 || claims === undefined) {
    throw invalid(`the credential does not fit the profile: ${problems.join('; ')}`);
  }

  const delegation = claims.delegation;
  if (delegation?.parent !== undefined) {
    assertDelegationAllowed({
      parent: {
        authority: delegation.parent.authority,
        exp: delegation.parent.exp,
        depth: delegation.depth - 1,
        maxDepth: delegation.max_depth,
      },
      child: { authority: claims.authority ?? [], exp: i.exp },
    });
  }

  const selective = new Set<DisclosableClaim>(i.sdClaims ?? DISCLOSABLE_CLAIMS);
  if (selective.has('authority') && claims.delegation !== undefined) selective.add('delegation');

  const payload: CredentialPayload = {
    iss: i.issuer,
    sub: i.sub,
    jti: i.jti,
    iat: i.iat,
    exp: i.exp,
    vct: i.vct,
    cnf: { jwk: asEcPublicJwk(i.cnfJwk) },
    status: { status_list: { uri: i.status.uri, idx: i.status.idx } },
  };
  if (i.nbf !== undefined) payload.nbf = i.nbf;
  return issueCredential({ signer: i.signer, payload, claims, sd: [...selective], crypto: i.crypto });
}

/** Issues an organisation-member credential: `org`, and optionally `org_unit`, `role` and `display`. */
export async function issueOrgMember(
  i: Omit<IssueSdJwtVcInput, 'vct' | 'claims'> & {
    claims: Pick<UmisClaimSet, 'org' | 'org_unit' | 'role' | 'display'>;
  },
): Promise<string> {
  return issueSdJwtVc({ ...i, vct: VCT.orgMember });
}

/**
 * Issues a root role-authority credential: a role with at least one authority item, and the delegation claim
 * `{depth: 0, max_depth: maxDepth}` that bounds how far the holder's powers can be handed on.
 */
export async function issueRoleAuthority(
  i: Omit<IssueSdJwtVcInput, 'vct' | 'claims'> & {
    claims: Omit<UmisClaimSet, 'delegation' | 'role' | 'authority'> & {
      role: { code: string; name: string };
      authority: AuthorityItem[];
    };
    maxDepth: number; //  delegation {depth: 0, max_depth: maxDepth}
  },
): Promise<string> {
  const { maxDepth, claims, ...rest } = i;
  if (typeof maxDepth !== 'number' || !Number.isSafeInteger(maxDepth) || maxDepth < 0) {
    throw invalid('maxDepth must be a non-negative integer');
  }
  return issueSdJwtVc({
    ...rest,
    vct: VCT.roleAuthority,
    claims: { ...claims, delegation: { depth: 0, max_depth: maxDepth } },
  });
}
