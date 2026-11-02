import { UmisError, asEcPublicJwk } from '@umis/core';
import type {
  CheckpointPolicyV1,
  MemberCacheEntry,
  ReplayStore,
  TrustedIssuerEntryV1,
  VerifierContext,
} from '@umis/core';
import { validatePolicy } from '@umis/policy';
import { trustedIssuerEntrySchema } from '@umis/registry';

/** A verifier context as plain JSON: what a station keeps in a replay file and loads again. */
export interface SerializedVerifierContextV1 {
  v: 1;
  now: number;
  audiences: string[];
  policy: CheckpointPolicyV1;
  trusted: TrustedIssuerEntryV1[];
  statusLists: Array<{ uri: string; token: string; fetchedAt: number }>;
  memberCache?: MemberCacheEntry[];
  selfIssuer?: string;
  pointId?: string;
  policyVersion?: number;
}

type Json = Record<string, unknown>;

/** A detached copy of a JSON-compatible value; members that are `undefined` are dropped. */
export function jsonCopy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

const byKey =
  <T>(key: (item: T) => string) =>
  (a: T, b: T): number => {
    const left = key(a);
    const right = key(b);
    return left < right ? -1 : left > right ? 1 : 0;
  };

/**
 * The data of a verifier context as plain JSON: the time, audiences, policy, trusted issuers, held status lists and
 * member cache, in a stable order. The replay store, ledger, caches, fetch function and crypto provider are runtime
 * objects and are not part of it.
 */
export function serializeVerifierContext(ctx: VerifierContext): SerializedVerifierContextV1 {
  const serialized: SerializedVerifierContextV1 = {
    v: 1,
    now: ctx.now,
    audiences: [...ctx.audiences],
    policy: jsonCopy(ctx.policy),
    trusted: jsonCopy([...ctx.trusted]),
    statusLists: [...ctx.statusLists]
      .map(([uri, held]) => ({ uri, token: held.token, fetchedAt: held.fetchedAt }))
      .sort(byKey((item) => item.uri)),
  };
  if (ctx.memberCache !== undefined) {
    serialized.memberCache = jsonCopy([...ctx.memberCache.values()]).sort(byKey((entry) => entry.credRef));
  }
  if (ctx.selfIssuer !== undefined) serialized.selfIssuer = ctx.selfIssuer;
  if (ctx.pointId !== undefined) serialized.pointId = ctx.pointId;
  if (ctx.policyVersion !== undefined) serialized.policyVersion = ctx.policyVersion;
  return serialized;
}

const malformed = (message: string): UmisError =>
  new UmisError('MALFORMED', `the verifier context is not valid: ${message}`);

function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

function record(value: unknown, what: string): Json {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw malformed(`${what} must be an object`);
  return value as Json;
}

function list(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw malformed(`${what} must be an array`);
  return value;
}

function text(value: unknown, what: string): string {
  if (typeof value !== 'string' || value === '') throw malformed(`${what} must be a non-empty string`);
  return value;
}

function finite(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw malformed(`${what} must be a finite number`);
  return value;
}

function nameOf(value: unknown, what: string): { id: string; name: string } {
  const o = record(value, what);
  return { id: text(own(o, 'id'), `${what}.id`), name: text(own(o, 'name'), `${what}.name`) };
}

function readMember(value: unknown, what: string): MemberCacheEntry {
  const o = record(value, what);
  let cnfJwk: MemberCacheEntry['cnfJwk'];
  try {
    cnfJwk = asEcPublicJwk(own(o, 'cnfJwk'));
  } catch {
    throw malformed(`${what}.cnfJwk must be a P-256 public key`);
  }
  const status = record(own(o, 'status'), `${what}.status`);
  const idx = finite(own(status, 'idx'), `${what}.status.idx`);
  if (!Number.isSafeInteger(idx) || idx < 0) throw malformed(`${what}.status.idx must be a non-negative integer`);

  const claims = record(own(o, 'claims'), `${what}.claims`);
  const org = record(own(claims, 'org'), `${what}.claims.org`);
  const entryClaims: MemberCacheEntry['claims'] = {
    org: { id: text(own(org, 'id'), `${what}.claims.org.id`), name: text(own(org, 'name'), `${what}.claims.org.name`) },
  };
  if (own(org, 'lei') !== undefined) entryClaims.org.lei = text(own(org, 'lei'), `${what}.claims.org.lei`);
  if (own(claims, 'org_unit') !== undefined) {
    entryClaims.org_unit = nameOf(own(claims, 'org_unit'), `${what}.claims.org_unit`);
  }
  if (own(claims, 'role') !== undefined) {
    const role = record(own(claims, 'role'), `${what}.claims.role`);
    entryClaims.role = {
      code: text(own(role, 'code'), `${what}.claims.role.code`),
      name: text(own(role, 'name'), `${what}.claims.role.name`),
    };
  }
  if (own(claims, 'display') !== undefined) {
    const display = record(own(claims, 'display'), `${what}.claims.display`);
    entryClaims.display = { name: text(own(display, 'name'), `${what}.claims.display.name`) };
    const photoHash = own(display, 'photo_hash');
    if (photoHash !== undefined) entryClaims.display.photo_hash = text(photoHash, `${what}.claims.display.photo_hash`);
  }
  return {
    credRef: text(own(o, 'credRef'), `${what}.credRef`),
    issuer: text(own(o, 'issuer'), `${what}.issuer`),
    vct: text(own(o, 'vct'), `${what}.vct`),
    cnfJwk,
    exp: finite(own(o, 'exp'), `${what}.exp`),
    status: { uri: text(own(status, 'uri'), `${what}.status.uri`), idx },
    claims: entryClaims,
  };
}

/**
 * Rebuilds a verifier context from its serialized form. The policy and every trusted-issuer entry are validated
 * again, as is the rest of the document (MALFORMED otherwise); `i.replay` is the replay store the context decides
 * with, and `i.now` replaces the recorded time, so that a recorded situation can be decided at another instant. A
 * duplicate status list uri, member or issuer is MALFORMED.
 */
export function deserializeVerifierContext(
  s: SerializedVerifierContextV1,
  i: { replay: ReplayStore; now?: number },
): VerifierContext {
  const doc = record(s, 'the document');
  if (own(doc, 'v') !== 1) throw malformed('v must be 1');

  const checked = validatePolicy(own(doc, 'policy'));
  if (!checked.ok) throw malformed(`the policy is invalid (${checked.errors.join('; ')})`);

  const trusted: TrustedIssuerEntryV1[] = [];
  const issuers = new Set<string>();
  list(own(doc, 'trusted'), 'trusted').forEach((item, index) => {
    const parsed = trustedIssuerEntrySchema.safeParse(item);
    if (!parsed.success) throw malformed(`trusted[${index}] is not a registry entry`);
    if (issuers.has(parsed.data.issuer)) throw malformed(`the issuer "${parsed.data.issuer}" has more than one entry`);
    issuers.add(parsed.data.issuer);
    trusted.push(parsed.data);
  });

  const statusLists = new Map<string, { token: string; fetchedAt: number }>();
  list(own(doc, 'statusLists'), 'statusLists').forEach((item, index) => {
    const o = record(item, `statusLists[${index}]`);
    const uri = text(own(o, 'uri'), `statusLists[${index}].uri`);
    if (statusLists.has(uri)) throw malformed(`the status list "${uri}" appears twice`);
    statusLists.set(uri, {
      token: text(own(o, 'token'), `statusLists[${index}].token`),
      fetchedAt: finite(own(o, 'fetchedAt'), `statusLists[${index}].fetchedAt`),
    });
  });

  const ctx: VerifierContext = {
    now: i.now === undefined ? finite(own(doc, 'now'), 'now') : finite(i.now, 'now'),
    audiences: list(own(doc, 'audiences'), 'audiences').map((audience, index) => text(audience, `audiences[${index}]`)),
    policy: checked.policy,
    trusted,
    statusLists,
    replay: i.replay,
  };

  if (own(doc, 'memberCache') !== undefined) {
    const members = new Map<string, MemberCacheEntry>();
    list(own(doc, 'memberCache'), 'memberCache').forEach((item, index) => {
      const entry = readMember(item, `memberCache[${index}]`);
      if (members.has(entry.credRef)) throw malformed(`the credential "${entry.credRef}" appears twice`);
      members.set(entry.credRef, entry);
    });
    ctx.memberCache = members;
  }
  if (own(doc, 'selfIssuer') !== undefined) ctx.selfIssuer = text(own(doc, 'selfIssuer'), 'selfIssuer');
  if (own(doc, 'pointId') !== undefined) ctx.pointId = text(own(doc, 'pointId'), 'pointId');
  if (own(doc, 'policyVersion') !== undefined) {
    const version = finite(own(doc, 'policyVersion'), 'policyVersion');
    if (!Number.isSafeInteger(version) || version < 0) throw malformed('policyVersion must be a non-negative integer');
    ctx.policyVersion = version;
  }
  return ctx;
}
