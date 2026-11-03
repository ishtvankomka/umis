import { DEFAULT_REFRESH_S, URN_PREFIX, UmisError, VCT, decodeCredential, randomId, utf8Encode } from '@umis/core';
import type {
  AuthorityLedger,
  CryptoProvider,
  MemberCacheEntry,
  ReplayStore,
  Signer,
  StatusRef,
  TrustedIssuerEntryV1,
  VerifierContext,
} from '@umis/core';
import { keyFromSeed } from '@umis/core/noble';
import { cascadeRevocation, issueDelegated, issueOrgMember, issueRoleAuthority, randomStatusIndex } from '@umis/issuer';
import { DEFAULT_POLICIES } from '@umis/policy';
import { signRegistry } from '@umis/registry';
import type { RegistrySnapshotV1 } from '@umis/registry';
import { buildStatusListToken } from '@umis/status-list';
import { createMemoryReplayStore, memberCacheEntryFromCredential } from '@umis/verifier';
import { createSimClock } from './clock.js';
import type { SimClock } from './clock.js';
import { BRIDGE_CREW, PERSON_NAMES, ROLES, crewLeadAuthority, crewMemberAuthority } from './people.js';
import { deterministicCrypto } from './random.js';

export type OrgSlug = 'pidriadnyk-a' | 'postachalnyk-b' | 'kovorking-v';
export type PersonKey = 'oleg' | 'ivan' | 'maria';

export interface DemoOrg {
  slug: OrgSlug;
  name: string;
  /** The identifier of the organisation's issuer: `<issuerBase>/issuer/t/<slug>`. */
  issuer: string;
  issuerSigner: Signer;
  verifierSigner: Signer;
  statusListUri: string;
  /** What this organisation trusts, as it signed it with its verifier key. */
  registry: RegistrySnapshotV1;
  registryJws: string;
}

export interface DemoPerson {
  key: PersonKey;
  name: string;
  holder: Signer;
  credentials: Partial<Record<'coworkingMember' | 'roleAuthority' | 'delegated' | 'supplierMember', string>>;
}

/**
 * Three invented organisations, the people who work for them, their credentials, signed registries and status lists,
 * and a simulated clock. Everything is built from public seeds, so the keys protect nothing and the world is the same
 * on every run unless another `crypto` provider is given.
 */
export interface DemoWorld {
  readonly clock: SimClock;
  /** The provider that made the world; frames built for it use the same one. */
  readonly crypto: CryptoProvider;
  readonly orgs: Readonly<Record<OrgSlug, DemoOrg>>;
  readonly people: Readonly<Record<PersonKey, DemoPerson>>;
  /** The status lists as last published, keyed by address; a copy, so a verifier that holds it keeps the old lists. */
  statusLists(): Map<string, { token: string; fetchedAt: number }>;
  /**
   * What the verifier of `org` decides with at checkpoint policy `policy`, at the current time of the clock: its own
   * registry, the status lists of the issuers in it, and (for a policy that takes one-way tokens) its member cache.
   */
  context(i: {
    org: OrgSlug;
    policy: keyof typeof DEFAULT_POLICIES;
    replay?: ReplayStore;
    ledger?: AuthorityLedger;
  }): VerifierContext;
  /**
   * Marks a credential revoked (`status` 1) or suspended (2) in its issuer's list. Revoking also revokes every credential
   * delegated from it. Nothing changes for a verifier until {@link DemoWorld.publish}.
   */
  revoke(jti: string, status?: 1 | 2): void;
  /** Signs every status list again at the current time of the clock. */
  publish(): Promise<void>;
}

const DEFAULT_START = 1_793_606_400; // 2026-11-02T08:00:00Z
const DEFAULT_ISSUER_BASE = 'https://api.umis.systems';
const DEFAULT_SEED = 'umis-demo';
const STATUS_LIST_SIZE = 131_072;
const CREDENTIAL_LIFETIME_S = 90 * 86_400;

const ORG_SLUGS: readonly OrgSlug[] = ['pidriadnyk-a', 'postachalnyk-b', 'kovorking-v'];
const PERSON_KEYS: readonly PersonKey[] = ['oleg', 'ivan', 'maria'];

const ORG_NAMES: Readonly<Record<OrgSlug, string>> = {
  'pidriadnyk-a': 'Підрядник А',
  'postachalnyk-b': 'Постачальник Б',
  'kovorking-v': 'Коворкінг В',
};

/** Whom each organisation trusts, and for which credential types. */
const TRUST: Readonly<Record<OrgSlug, ReadonlyArray<{ issuer: OrgSlug; vcts: readonly string[] }>>> = {
  'pidriadnyk-a': [
    { issuer: 'pidriadnyk-a', vcts: [VCT.orgMember, VCT.roleAuthority] },
    { issuer: 'postachalnyk-b', vcts: [VCT.orgMember] },
  ],
  'postachalnyk-b': [
    { issuer: 'postachalnyk-b', vcts: [VCT.orgMember] },
    { issuer: 'pidriadnyk-a', vcts: [VCT.roleAuthority] },
  ],
  'kovorking-v': [{ issuer: 'kovorking-v', vcts: [VCT.orgMember] }],
};

/** The checkpoint of each policy preset: `<org slug>-<point>`. */
const POINTS: Readonly<Record<keyof typeof DEFAULT_POLICIES, string>> = {
  door_low: 'door-1',
  warehouse_medium: 'warehouse-1',
  mutual_medium: 'mutual-1',
  login_oid4vp: 'login-1',
};

interface ListState {
  readonly uri: string;
  /** One byte per entry: 0 valid, 1 revoked, 2 suspended. */
  readonly values: Uint8Array;
  readonly used: Set<number>;
}

function invalid(message: string): UmisError {
  return new UmisError('INVALID_ARGUMENT', message);
}

/** A key from a public seed. The label tells the demo keys apart and says in every `kid` that they are demo keys. */
async function demoSigner(crypto: CryptoProvider, label: string): Promise<Signer> {
  return crypto.importSigner(keyFromSeed(utf8Encode(`umis-demo:${label}`)), { kid: `demo-${label.replace('/', '-')}` });
}

function baseOf(value: string | undefined): string {
  const base = value ?? DEFAULT_ISSUER_BASE;
  if (typeof base !== 'string' || base === '') throw invalid('issuerBase must be a non-empty address');
  return base.replace(/\/+$/, '');
}

/** The demo world: see {@link DemoWorld}. Without options it starts at 2026-11-02T08:00:00Z on a fixed seed. */
export async function createDemoWorld(
  o: { start?: number; issuerBase?: string; crypto?: CryptoProvider } = {},
): Promise<DemoWorld> {
  const crypto = o.crypto ?? deterministicCrypto(DEFAULT_SEED);
  const start = o.start ?? DEFAULT_START;
  const issuerBase = baseOf(o.issuerBase);
  const clock = createSimClock(start);
  const expires = start + CREDENTIAL_LIFETIME_S;

  // keys, in a fixed order
  const orgs = {} as Record<OrgSlug, DemoOrg>;
  const lists = {} as Record<OrgSlug, ListState>;
  for (const slug of ORG_SLUGS) {
    const statusListUri = `${issuerBase}/status/t/${slug}/1`;
    orgs[slug] = {
      slug,
      name: ORG_NAMES[slug],
      issuer: `${issuerBase}/issuer/t/${slug}`,
      issuerSigner: await demoSigner(crypto, `issuer/${slug}`),
      verifierSigner: await demoSigner(crypto, `verifier/${slug}`),
      statusListUri,
      registry: { iss: '', ver: 1, iat: start, entries: [] },
      registryJws: '',
    };
    lists[slug] = { uri: statusListUri, values: new Uint8Array(STATUS_LIST_SIZE), used: new Set() };
  }
  const people = {} as Record<PersonKey, DemoPerson>;
  for (const key of PERSON_KEYS) {
    people[key] = { key, name: PERSON_NAMES[key], holder: await demoSigner(crypto, `holder/${key}`), credentials: {} };
  }

  // credentials
  const issued = new Map<string, { slug: OrgSlug; idx: number }>();
  const children = new Map<string, Array<{ jti: string; status: StatusRef }>>();
  const identity = (slug: OrgSlug): { jti: string; sub: string; status: StatusRef } => {
    const list = lists[slug];
    const idx = randomStatusIndex(STATUS_LIST_SIZE, (candidate) => list.used.has(candidate), crypto);
    list.used.add(idx);
    const jti = randomId(16, crypto);
    issued.set(jti, { slug, idx });
    return { jti, sub: `p_${randomId(12, crypto)}`, status: { uri: list.uri, idx } };
  };
  const common = (slug: OrgSlug, holder: Signer) => ({
    signer: orgs[slug].issuerSigner,
    issuer: orgs[slug].issuer,
    iat: start,
    exp: expires,
    cnfJwk: holder.publicJwk,
    crypto,
    ...identity(slug),
  });
  const orgClaim = (slug: OrgSlug) => ({ id: slug, name: ORG_NAMES[slug] });

  const { oleg, ivan, maria } = people;
  const coworkingMember = await issueOrgMember({
    ...common('kovorking-v', oleg.holder),
    claims: { org: orgClaim('kovorking-v'), role: ROLES.resident, display: { name: oleg.name } },
  });
  const roleAuthority = await issueRoleAuthority({
    ...common('pidriadnyk-a', oleg.holder),
    maxDepth: 1,
    claims: {
      org: orgClaim('pidriadnyk-a'),
      org_unit: BRIDGE_CREW,
      role: ROLES.crewLead,
      authority: crewLeadAuthority(),
      display: { name: oleg.name },
    },
  });
  const parent = decodeCredential(roleAuthority);
  const delegatedCredential = await issueDelegated({
    ...common('pidriadnyk-a', ivan.holder),
    parent,
    claims: {
      org_unit: BRIDGE_CREW,
      role: ROLES.crewMember,
      authority: crewMemberAuthority(),
      display: { name: ivan.name },
    },
  });
  const child = decodeCredential(delegatedCredential);
  children.set(parent.jti, [{ jti: child.jti, status: child.status }]);
  const supplierMember = await issueOrgMember({
    ...common('postachalnyk-b', maria.holder),
    claims: { org: orgClaim('postachalnyk-b'), role: ROLES.storekeeper, display: { name: maria.name } },
  });
  oleg.credentials.coworkingMember = coworkingMember;
  oleg.credentials.roleAuthority = roleAuthority;
  ivan.credentials.delegated = delegatedCredential;
  maria.credentials.supplierMember = supplierMember;

  // registries: each organisation signs the list of issuers it trusts
  for (const slug of ORG_SLUGS) {
    const entries: TrustedIssuerEntryV1[] = TRUST[slug].map((trusted) => ({
      issuer: orgs[trusted.issuer].issuer,
      name: orgs[trusted.issuer].name,
      jwks: { keys: [orgs[trusted.issuer].issuerSigner.publicJwk] },
      vcts: [...trusted.vcts],
      statusLists: [orgs[trusted.issuer].statusListUri],
      status: 'active',
    }));
    const registry: RegistrySnapshotV1 = { iss: orgs[slug].issuer, ver: 1, iat: start, entries };
    orgs[slug].registry = registry;
    orgs[slug].registryJws = await signRegistry(registry, orgs[slug].verifierSigner);
  }

  // the credentials a door keeps to accept one-way tokens
  const members: Record<OrgSlug, Map<string, MemberCacheEntry>> = {
    'pidriadnyk-a': new Map(),
    'postachalnyk-b': new Map(),
    'kovorking-v': new Map(),
  };
  const coworking = await memberCacheEntryFromCredential(coworkingMember, crypto);
  members['kovorking-v'].set(coworking.credRef, coworking);
  const supplier = await memberCacheEntryFromCredential(supplierMember, crypto);
  members['postachalnyk-b'].set(supplier.credRef, supplier);

  // status lists
  const published = new Map<string, { token: string; fetchedAt: number }>();
  async function publish(): Promise<void> {
    const at = Math.floor(clock.now());
    const next = new Map<string, { token: string; fetchedAt: number }>();
    for (const slug of ORG_SLUGS) {
      const list = lists[slug];
      const token = await buildStatusListToken({
        signer: orgs[slug].issuerSigner,
        uri: list.uri,
        bits: 2,
        values: list.values,
        iat: at,
        ttlSeconds: DEFAULT_REFRESH_S.economy,
      });
      next.set(list.uri, { token, fetchedAt: at });
    }
    for (const [uri, held] of next) published.set(uri, held);
  }
  await publish();

  return {
    clock,
    crypto,
    orgs,
    people,

    statusLists() {
      return new Map([...published].map(([uri, held]) => [uri, { ...held }]));
    },

    context(i) {
      if (!Object.hasOwn(orgs, i.org)) {
        throw invalid(`unknown organisation "${String(i.org).slice(0, 64)}" (one of ${ORG_SLUGS.join(', ')})`);
      }
      if (!Object.hasOwn(DEFAULT_POLICIES, i.policy)) {
        throw invalid(
          `unknown policy "${String(i.policy).slice(0, 64)}" (one of ${Object.keys(DEFAULT_POLICIES).join(', ')})`,
        );
      }
      const org = orgs[i.org];
      const policy = DEFAULT_POLICIES[i.policy];
      const point = `${i.org}-${POINTS[i.policy]}`;
      const trusted = org.registry.entries;
      const held = new Map<string, { token: string; fetchedAt: number }>();
      for (const entry of trusted) {
        for (const uri of entry.statusLists) {
          const list = published.get(uri);
          if (list !== undefined) held.set(uri, { ...list });
        }
      }
      const ctx: VerifierContext = {
        now: clock.now(),
        audiences: [`${URN_PREFIX.checkpoint}${point}`, org.issuer],
        policy,
        trusted: [...trusted],
        statusLists: held,
        replay: i.replay ?? createMemoryReplayStore(),
        selfIssuer: org.issuer,
        crypto,
        pointId: point,
        policyVersion: 1,
      };
      if (policy.channels.includes('qr_oneway') && members[i.org].size > 0) ctx.memberCache = new Map(members[i.org]);
      if (i.ledger !== undefined) ctx.ledger = i.ledger;
      return ctx;
    },

    revoke(jti, status = 1) {
      if (status !== 1 && status !== 2) throw invalid('status is 1 (revoked) or 2 (suspended)');
      const record = issued.get(jti);
      if (record === undefined) throw invalid('this world issued no credential with that jti');
      const targets = [jti];
      if (status === 1) {
        targets.push(...cascadeRevocation({ root: jti, childrenOf: (id) => children.get(id) ?? [] }).map((c) => c.jti));
      }
      for (const target of targets) {
        const { slug, idx } = issued.get(target)!;
        lists[slug].values[idx] = status;
      }
    },

    publish,
  };
}
