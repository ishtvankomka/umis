import { DISCLOSABLE_CLAIMS, PERIODS, UmisError, splitUri, VCT } from '@umis/core';
import type { UmisClaimSet } from '@umis/core';

/** The two credential types of the profile. */
export type CredentialKind = 'org-member' | 'role-authority';

type Json = Record<string, unknown>;

/** The credential type that a `vct` names, if it names one. */
export function credentialKind(vct: unknown): CredentialKind | undefined {
  if (vct === VCT.orgMember) return 'org-member';
  if (vct === VCT.roleAuthority) return 'role-authority';
  return undefined;
}

export const invalid = (message: string, cause?: unknown): UmisError =>
  new UmisError('INVALID_ARGUMENT', message, { cause });

export function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** An own member of an object; inherited properties never count. */
export function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

export function isText(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

export const isNatural = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

// ---------------------------------------------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------------------------------------------

/**
 * Why `value` cannot be used as an address that other parties fetch, or undefined when it can: an `https` URL, or an
 * `http` URL for a loopback host, made of visible ASCII characters only, with a host, without user information or a
 * fragment.
 */
export function urlProblem(value: unknown, what: string): string | undefined {
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value)) {
    return `${what} must be a URL of visible ASCII characters`;
  }
  const { scheme, authority, fragment } = splitUri(value);
  const host = authority.toLowerCase().replace(/:[0-9]{1,5}$/, '');
  const loopback = host === 'localhost' || host === '127.0.0.1';
  if (!(scheme === 'https' || (scheme === 'http' && loopback))) return `${what} must be an https URL`;
  if (authority === '' || authority.includes('@')) return `${what} must have a host and no user information`;
  if (fragment !== '' || value.includes('#')) return `${what} must not have a fragment`;
  return undefined;
}

export function assertUrl(value: unknown, what: string): void {
  const problem = urlProblem(value, what);
  if (problem !== undefined) throw invalid(problem);
}

// ---------------------------------------------------------------------------------------------------------------
// authority and delegation
// ---------------------------------------------------------------------------------------------------------------

const ITEM_MEMBERS: ReadonlySet<string> = new Set(['action', 'resource', 'limit', 'object', 'valid_until']);
const LIMIT_MEMBERS: ReadonlySet<string> = new Set(['amount', 'unit', 'per']);
const DELEGATION_MEMBERS: ReadonlySet<string> = new Set(['parent', 'depth', 'max_depth']);
const PARENT_MEMBERS: ReadonlySet<string> = new Set(['id', 'status', 'authority', 'exp']);

/**
 * A member that a credential would silently lose is an error. The credential codec copies only the members it knows, so a
 * misspelled `valid_until` or `object` would otherwise drop an expiry or a restriction without a word.
 */
function strangers(object: Json, allowed: ReadonlySet<string>, what: string): string[] {
  return Object.keys(object)
    .filter((name) => !allowed.has(name))
    .map((name) => `${what} has the unknown member "${name}"`);
}

function itemProblems(item: unknown, what: string): string[] {
  if (!isRecord(item)) return [`${what} must be an object`];
  const problems = strangers(item, ITEM_MEMBERS, what);
  if (!isText(own(item, 'action'))) problems.push(`${what}.action must be a non-empty string`);
  if (!isText(own(item, 'resource'))) problems.push(`${what}.resource must be a non-empty string`);
  const limit = own(item, 'limit');
  if (!isRecord(limit)) {
    problems.push(`${what}.limit must be an object`);
  } else {
    problems.push(...strangers(limit, LIMIT_MEMBERS, `${what}.limit`));
    const amount = own(limit, 'amount');
    if (typeof amount !== 'number' || !Number.isFinite(amount) || !(amount > 0)) {
      problems.push(`${what}.limit.amount must be a finite number above zero`);
    }
    if (!isText(own(limit, 'unit'))) problems.push(`${what}.limit.unit must be a non-empty string`);
    const per = own(limit, 'per');
    if (per !== undefined && !(PERIODS as readonly unknown[]).includes(per)) {
      problems.push(`${what}.limit.per must be one of ${PERIODS.join(', ')}`);
    }
  }
  const object = own(item, 'object');
  if (object !== undefined && !isText(object)) problems.push(`${what}.object must be a non-empty string`);
  const validUntil = own(item, 'valid_until');
  if (validUntil !== undefined && !Number.isSafeInteger(validUntil)) {
    problems.push(`${what}.valid_until must be an integer`);
  }
  return problems;
}

/** What is wrong with a list of authority items; empty when it is a non-empty list of well-formed items. */
export function authorityProblems(list: unknown, what: string): string[] {
  if (!Array.isArray(list) || list.length === 0) return [`${what} must be a non-empty list of authority items`];
  return list.flatMap((item, index) => itemProblems(item, `${what}[${index}]`));
}

function statusProblems(status: unknown, what: string): string[] {
  if (!isRecord(status)) return [`${what} must be an object`];
  const problems: string[] = [];
  if (!isText(own(status, 'uri'))) problems.push(`${what}.uri must be a non-empty string`);
  if (!isNatural(own(status, 'idx'))) problems.push(`${what}.idx must be a non-negative integer`);
  return problems;
}

function parentProblems(parent: unknown, what: string): string[] {
  if (!isRecord(parent)) return [`${what} must be an object`];
  const problems = strangers(parent, PARENT_MEMBERS, what);
  if (!isText(own(parent, 'id'))) problems.push(`${what}.id must be a non-empty string`);
  problems.push(...statusProblems(own(parent, 'status'), `${what}.status`));
  problems.push(...authorityProblems(own(parent, 'authority'), `${what}.authority`));
  const exp = own(parent, 'exp');
  if (typeof exp !== 'number' || !Number.isFinite(exp)) problems.push(`${what}.exp must be a finite number`);
  return problems;
}

function delegationProblems(delegation: unknown): string[] {
  if (!isRecord(delegation)) return ['delegation must be an object'];
  const problems = strangers(delegation, DELEGATION_MEMBERS, 'delegation');
  const depth = own(delegation, 'depth');
  const maxDepth = own(delegation, 'max_depth');
  const parent = own(delegation, 'parent');
  if (!isNatural(depth)) problems.push('delegation.depth must be a non-negative integer');
  if (!isNatural(maxDepth)) problems.push('delegation.max_depth must be a non-negative integer');
  if (isNatural(depth) && isNatural(maxDepth)) {
    if ((depth as number) > (maxDepth as number))
      problems.push('delegation.depth must not exceed delegation.max_depth');
  }
  if (isNatural(depth)) {
    if ((depth as number) > 0 && parent === undefined) {
      problems.push('a delegated credential (depth above 0) needs delegation.parent');
    }
    if (depth === 0 && parent !== undefined)
      problems.push('a root credential (depth 0) must not carry delegation.parent');
  }
  if (parent !== undefined) problems.push(...parentProblems(parent, 'delegation.parent'));
  return problems;
}

// ---------------------------------------------------------------------------------------------------------------
// the profile
// ---------------------------------------------------------------------------------------------------------------

/**
 * Everything that keeps `claims` from being a valid claim set of the credential type `vct`; the empty list means that it
 * is valid.
 *
 * - `vct` is one of the two UMIS credential types and the claim names belong to the profile;
 * - `org` is present with a non-empty `id` and `name`; `org_unit`, `role` and `display` are well-formed when present;
 * - an organisation-member credential carries neither `authority` nor `delegation`;
 * - a role-authority credential carries a `role` and at least one authority item with a non-empty action, resource and
 *   unit, a finite amount above zero, a period from the profile when it names one, and an integer `valid_until` when it
 *   has one; its `delegation`, when present, has integers `0 <= depth <= max_depth`, and `parent` is present exactly when
 *   `depth` is above 0.
 */
export function profileErrors(vct: string, claims: Partial<UmisClaimSet>): string[] {
  const errors: string[] = [];
  const kind = credentialKind(vct);
  if (kind === undefined) errors.push(`vct "${String(vct)}" is not a UMIS credential type`);
  if (!isRecord(claims)) return [...errors, 'the claims must be an object'];

  for (const name of Object.keys(claims)) {
    if (!(DISCLOSABLE_CLAIMS as readonly string[]).includes(name)) {
      errors.push(`"${name}" is not a claim of the profile`);
    }
  }

  const org = own(claims, 'org');
  if (!isRecord(org)) {
    errors.push('org is required and must be an object');
  } else {
    if (!isText(own(org, 'id'))) errors.push('org.id must be a non-empty string');
    if (!isText(own(org, 'name'))) errors.push('org.name must be a non-empty string');
    const lei = own(org, 'lei');
    if (lei !== undefined && !isText(lei)) errors.push('org.lei must be a non-empty string');
  }

  const orgUnit = own(claims, 'org_unit');
  if (orgUnit !== undefined) {
    if (!isRecord(orgUnit)) {
      errors.push('org_unit must be an object');
    } else {
      if (!isText(own(orgUnit, 'id'))) errors.push('org_unit.id must be a non-empty string');
      if (!isText(own(orgUnit, 'name'))) errors.push('org_unit.name must be a non-empty string');
    }
  }

  const role = own(claims, 'role');
  if (role === undefined) {
    if (kind === 'role-authority') errors.push('a role-authority credential needs a role');
  } else if (!isRecord(role)) {
    errors.push('role must be an object');
  } else {
    if (!isText(own(role, 'code'))) errors.push('role.code must be a non-empty string');
    if (!isText(own(role, 'name'))) errors.push('role.name must be a non-empty string');
  }

  const display = own(claims, 'display');
  if (display !== undefined) {
    if (!isRecord(display)) {
      errors.push('display must be an object');
    } else {
      if (!isText(own(display, 'name'))) errors.push('display.name must be a non-empty string');
      const photoHash = own(display, 'photo_hash');
      if (photoHash !== undefined && !isText(photoHash)) errors.push('display.photo_hash must be a non-empty string');
    }
  }

  const authority = own(claims, 'authority');
  const delegation = own(claims, 'delegation');
  if (kind === 'org-member') {
    if (authority !== undefined) errors.push('an org-member credential must not carry authority');
    if (delegation !== undefined) errors.push('an org-member credential must not carry delegation');
  } else {
    if (kind === 'role-authority' || authority !== undefined) errors.push(...authorityProblems(authority, 'authority'));
    if (delegation !== undefined) errors.push(...delegationProblems(delegation));
  }
  return errors;
}
