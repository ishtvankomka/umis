import { describe, expect, it } from 'vitest';
import {
  VCT,
  checkDelegation,
  decodeCredential,
  matchAuthority,
  parseSdJwt,
  presentCredential,
  verifyIssuerSignature,
} from '@umis/core';
import type { AuthorityItem, AuthorityRequest, DecodedCredential, StatusRef } from '@umis/core';
import { cascadeRevocation, issueDelegated, issueOrgMember, issueRoleAuthority, issueSdJwtVc } from '../src/index.js';
import {
  DAY,
  IVAN_AUTHORITY,
  ISSUER,
  NOW,
  OLEH_AUTHORITY,
  OLEH_ROLE,
  ORG,
  ORG_UNIT,
  STATUS_URI,
  codeOf,
  makeKeys,
} from './fixtures.js';
import type { Keys } from './fixtures.js';

const OLEH_EXP = NOW + 90 * DAY;
const TEN_TONNES: AuthorityRequest = { action: 'receive_materials', resource: 'rebar', amount: 10, unit: 't' };

/** Oleh's credential, the root: ten tonnes per shift, delegable one level down. */
async function issueOleh(keys: Keys, over: { authority?: AuthorityItem[]; maxDepth?: number; nbf?: number } = {}) {
  const sdJwt = await issueRoleAuthority({
    signer: keys.issuer,
    issuer: ISSUER,
    jti: 'cred-oleh-0001',
    sub: 'p_oleh',
    iat: NOW,
    exp: OLEH_EXP,
    ...(over.nbf === undefined ? {} : { nbf: over.nbf }),
    cnfJwk: keys.oleh.publicJwk,
    status: { uri: STATUS_URI, idx: 40_213 },
    claims: {
      org: ORG,
      org_unit: ORG_UNIT,
      role: OLEH_ROLE,
      authority: over.authority ?? OLEH_AUTHORITY,
      display: { name: 'Олег' },
    },
    maxDepth: over.maxDepth ?? 1,
  });
  return { sdJwt, copy: decodeCredential(sdJwt) };
}

/** The request to delegate to Ivan; `over` replaces members of it, and `claims` those of the claims. */
function ivanRequest(
  keys: Keys,
  parent: DecodedCredential,
  over: {
    iat?: number;
    nbf?: number;
    exp?: number;
    jti?: string;
    status?: StatusRef;
    claims?: {
      authority?: AuthorityItem[];
      role?: { code: string; name: string };
      org_unit?: { id: string; name: string };
    };
  } = {},
) {
  const { claims, ...rest } = over;
  return {
    signer: keys.issuer,
    issuer: ISSUER,
    parent,
    jti: 'cred-ivan-0001',
    sub: 'p_ivan',
    iat: NOW + 60,
    exp: NOW + 30 * DAY,
    cnfJwk: keys.ivan.publicJwk,
    status: { uri: STATUS_URI, idx: 40_214 },
    claims: { authority: IVAN_AUTHORITY, display: { name: 'Іван' }, ...claims },
    ...rest,
  };
}

const first = (items: AuthorityItem[]): AuthorityItem => items[0]!;
const wider = (over: Partial<AuthorityItem>, limit: Partial<AuthorityItem['limit']> = {}): AuthorityItem[] => [
  { ...first(IVAN_AUTHORITY), ...over, limit: { ...first(IVAN_AUTHORITY).limit, ...limit } },
];

describe('delegation (S-1)', () => {
  it('hands 8 t of the 10 t of Oleh to Ivan, with a summary of the parent inside the credential', async () => {
    const keys = await makeKeys();
    const oleh = await issueOleh(keys);
    const ivanSdJwt = await issueDelegated(ivanRequest(keys, oleh.copy));
    const ivan = await parseSdJwt(ivanSdJwt);

    expect(ivan.claims.delegation).toEqual({
      parent: {
        id: 'cred-oleh-0001',
        status: { uri: STATUS_URI, idx: 40_213 },
        authority: OLEH_AUTHORITY,
        exp: OLEH_EXP,
      },
      depth: 1,
      max_depth: 1,
    });
    expect(ivan.claims.org).toEqual(ORG); //                               copied from the parent
    expect(ivan.claims.role).toEqual(OLEH_ROLE); //                        the role of the parent, as none was given
    expect(ivan.claims.org_unit).toBeUndefined(); //                       only what the delegate is given
    expect(ivan.claims.display).toEqual({ name: 'Іван' });
    expect(ivan.claims.authority).toEqual(IVAN_AUTHORITY);
    expect(ivan.issuerJwt.payload.vct).toBe(VCT.roleAuthority);
    expect(ivan.issuerJwt.payload.sub).toBe('p_ivan');
    expect(ivan.disclosures.map((disclosure) => disclosure.name)).toEqual([
      'org',
      'role',
      'authority',
      'delegation',
      'display',
    ]);
    expect(await verifyIssuerSignature(ivan, keys.issuer.publicJwk)).toBe(true);

    // what a verifier does with the pair: 10 t is within the 10 t of Oleh, and over the 8 t of Ivan
    const olehCredential = await parseSdJwt(oleh.sdJwt);
    expect(matchAuthority(olehCredential.claims.authority, TEN_TONNES, NOW + 120)).toEqual({
      ok: true,
      item: first(OLEH_AUTHORITY),
    });
    const refused = matchAuthority(ivan.claims.authority, TEN_TONNES, NOW + 120);
    expect(refused).toEqual({ ok: false, reason: 'AUTHORITY_LIMIT_EXCEEDED', item: first(IVAN_AUTHORITY) });
    expect(refused.ok === false && refused.item?.limit.amount).toBe(8);
    expect(matchAuthority(ivan.claims.authority, { ...TEN_TONNES, amount: 8 }, NOW + 120).ok).toBe(true);
    // and the check of the core, which the verifier repeats on every presentation, passes for the credential as issued
    const delegation = ivan.claims.delegation!;
    expect(
      checkDelegation({
        parent: {
          authority: delegation.parent!.authority,
          exp: delegation.parent!.exp,
          depth: delegation.depth - 1,
          maxDepth: delegation.max_depth,
        },
        child: { authority: ivan.claims.authority!, exp: ivan.issuerJwt.payload.exp },
      }),
    ).toEqual({ ok: true });
  });

  it('does not let the delegate become valid before its parent', async () => {
    const keys = await makeKeys();
    const parentStart = NOW + 10 * DAY;
    const oleh = await issueOleh(keys, { nbf: parentStart });
    expect(oleh.copy.nbf).toBe(parentStart);
    // the request starts at NOW + 60 by iat alone, or by an nbf one second before the parent's
    expect(await codeOf(() => issueDelegated(ivanRequest(keys, oleh.copy)))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => issueDelegated(ivanRequest(keys, oleh.copy, { nbf: parentStart - 1 })))).toBe(
      'INVALID_ARGUMENT',
    );
    const ivan = decodeCredential(await issueDelegated(ivanRequest(keys, oleh.copy, { nbf: parentStart })));
    expect(ivan.nbf).toBe(parentStart);
    expect(await codeOf(() => issueDelegated(ivanRequest(keys, oleh.copy, { iat: parentStart })))).toBeUndefined();
  });

  it('takes the unit, the role and the display from the request when they are given', async () => {
    const keys = await makeKeys();
    const oleh = await issueOleh(keys);
    const role = { code: 'crew_member', name: 'Бригадир зміни' };
    const ivan = await parseSdJwt(
      await issueDelegated(ivanRequest(keys, oleh.copy, { claims: { role, org_unit: ORG_UNIT } })),
    );
    expect(ivan.claims.role).toEqual(role);
    expect(ivan.claims.org_unit).toEqual(ORG_UNIT);
  });

  it('refuses a delegation that is wider than its parent', async () => {
    const keys = await makeKeys();
    const oleh = await issueOleh(keys);
    const cases: Array<[string, AuthorityItem[]]> = [
      ['12 t of 10 t', wider({}, { amount: 12 })],
      ['another period', wider({}, { per: 'day' })],
      ['no period', wider({}, { per: undefined })],
      ['the object dropped', wider({ object: undefined })],
      ['another object', wider({ object: 'bridge-02' })],
      ['another unit', wider({}, { unit: 'kg' })],
      ['another resource', wider({ resource: 'cement' })],
      ['another action', wider({ action: 'issue_materials' })],
      ['one good item and one wide', [...IVAN_AUTHORITY, ...wider({}, { amount: 12 })]],
    ];
    for (const [label, authority] of cases) {
      expect(await codeOf(() => issueDelegated(ivanRequest(keys, oleh.copy, { claims: { authority } }))), label).toBe(
        'DELEGATION_WIDER_THAN_PARENT',
      );
    }
    // 10 t of 10 t is not wider
    const same = await parseSdJwt(
      await issueDelegated(ivanRequest(keys, oleh.copy, { claims: { authority: wider({}, { amount: 10 }) } })),
    );
    expect(same.claims.authority).toEqual(wider({}, { amount: 10 }));

    // an end of validity on the parent binds the delegate: it may end sooner, never after it and never not at all
    const limited = await issueOleh(keys, { authority: [{ ...first(OLEH_AUTHORITY), valid_until: NOW + 10 * DAY }] });
    for (const [label, validUntil, expected] of [
      ['after', NOW + 20 * DAY, 'DELEGATION_WIDER_THAN_PARENT'],
      ['none', undefined, 'DELEGATION_WIDER_THAN_PARENT'],
      ['before', NOW + 5 * DAY, undefined],
      ['the same', NOW + 10 * DAY, undefined],
    ] as const) {
      const authority = wider({ valid_until: validUntil });
      expect(
        await codeOf(() => issueDelegated(ivanRequest(keys, limited.copy, { claims: { authority } }))),
        label,
      ).toBe(expected);
    }
  });

  it('refuses a delegation that outlives its parent', async () => {
    const keys = await makeKeys();
    const oleh = await issueOleh(keys);
    expect(await codeOf(() => issueDelegated(ivanRequest(keys, oleh.copy, { exp: OLEH_EXP + 1 })))).toBe(
      'DELEGATION_OUTLIVES_PARENT',
    );
    expect(await codeOf(() => issueDelegated(ivanRequest(keys, oleh.copy, { exp: OLEH_EXP })))).toBeUndefined();
    // the lifetime is checked before the width
    const both = ivanRequest(keys, oleh.copy, { exp: OLEH_EXP + 1, claims: { authority: wider({}, { amount: 12 }) } });
    expect(await codeOf(() => issueDelegated(both))).toBe('DELEGATION_OUTLIVES_PARENT');
  });

  it('refuses to delegate from a delegate, and from a root that does not allow it', async () => {
    const keys = await makeKeys();
    const oleh = await issueOleh(keys);
    const ivan = decodeCredential(await issueDelegated(ivanRequest(keys, oleh.copy)));
    const petro = ivanRequest(keys, ivan, { jti: 'cred-petro-0001', status: { uri: STATUS_URI, idx: 40_215 } });
    expect(await codeOf(() => issueDelegated(petro))).toBe('DELEGATION_DEPTH_EXCEEDED');
    // the depth is checked first, however wide or long-lived the request is
    const worse = { ...petro, exp: ivan.exp + 1, claims: { authority: wider({}, { amount: 12 }) } };
    expect(await codeOf(() => issueDelegated(worse))).toBe('DELEGATION_DEPTH_EXCEEDED');

    // a root issued without a delegation claim has max_depth 0: nobody can hand its powers on
    const sealed = decodeCredential(await issueSdJwtVc({ ...(await rootInput(keys)) }));
    expect(sealed.claims.delegation).toEqual({ depth: 0, max_depth: 0 });
    expect(await codeOf(() => issueDelegated(ivanRequest(keys, sealed)))).toBe('DELEGATION_DEPTH_EXCEEDED');
  });

  it('applies the same rule to a delegation claim built by hand', async () => {
    const keys = await makeKeys();
    const input = await rootInput(keys);
    const parent = {
      id: 'cred-oleh-0001',
      status: { uri: STATUS_URI, idx: 40_213 },
      authority: OLEH_AUTHORITY,
      exp: OLEH_EXP,
    };
    const delegated = (authority: AuthorityItem[], exp: number, depth = 1, maxDepth = 1) => ({
      ...input,
      jti: 'cred-ivan-0001',
      exp,
      claims: {
        org: ORG,
        role: OLEH_ROLE,
        authority,
        delegation: { parent, depth, max_depth: maxDepth },
      },
    });
    expect(await codeOf(() => issueSdJwtVc(delegated(IVAN_AUTHORITY, OLEH_EXP)))).toBeUndefined();
    expect(await codeOf(() => issueSdJwtVc(delegated(wider({}, { amount: 12 }), OLEH_EXP)))).toBe(
      'DELEGATION_WIDER_THAN_PARENT',
    );
    expect(await codeOf(() => issueSdJwtVc(delegated(IVAN_AUTHORITY, OLEH_EXP + 1)))).toBe(
      'DELEGATION_OUTLIVES_PARENT',
    );
    // a claim whose depth is beyond its max_depth is not a valid claim at all
    expect(await codeOf(() => issueSdJwtVc(delegated(IVAN_AUTHORITY, OLEH_EXP, 2, 1)))).toBe('INVALID_ARGUMENT');
    // the summary does not carry the parent's max_depth, so a claim built by hand keeps the max_depth it is given;
    // issueDelegated reads it from the parent: under a root with max_depth 2 both give {depth 1, max_depth 2}
    const deep = await issueOleh(keys, { maxDepth: 2 });
    const ivan = decodeCredential(await issueDelegated(ivanRequest(keys, deep.copy)));
    expect(ivan.claims.delegation).toMatchObject({ depth: 1, max_depth: 2 });
    const byHand = decodeCredential(await issueSdJwtVc(delegated(IVAN_AUTHORITY, OLEH_EXP, 1, 2)));
    expect(byHand.claims.delegation).toEqual(ivan.claims.delegation);
  });

  it('refuses a parent that cannot be delegated from with INVALID_ARGUMENT', async () => {
    const keys = await makeKeys();
    const oleh = await issueOleh(keys);
    const request = (parent: DecodedCredential, over = {}) => ivanRequest(keys, parent, over);

    expect(await codeOf(() => issueDelegated(request({ ...oleh.copy, issuer: 'https://issuer.example/other' })))).toBe(
      'INVALID_ARGUMENT',
    );
    const member = decodeCredential(
      await issueOrgMember({
        signer: keys.issuer,
        issuer: ISSUER,
        jti: 'cred-member-1',
        sub: 'p_member',
        iat: NOW,
        exp: OLEH_EXP,
        cnfJwk: keys.oleh.publicJwk,
        status: { uri: STATUS_URI, idx: 1 },
        claims: { org: ORG },
      }),
    );
    expect(await codeOf(() => issueDelegated(request(member)))).toBe('INVALID_ARGUMENT');

    // a copy in which authority and delegation stayed hidden (a presentation of org and role only)
    const presentation = await presentCredential({
      credential: oleh.sdJwt,
      disclose: ['org', 'role'],
      kb: { signer: keys.oleh, aud: 'urn:umis:verifier:warehouse-b', nonce: 'AAAAAAAAAAAAAAAAAAAAAA', iat: NOW },
    });
    expect(await codeOf(() => issueDelegated(request(decodeCredential(presentation))))).toBe('INVALID_ARGUMENT');

    // the delegate is a credential of its own: its own jti and its own place in the status list
    expect(await codeOf(() => issueDelegated(request(oleh.copy, { jti: 'cred-oleh-0001' })))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => issueDelegated(request(oleh.copy, { status: { uri: STATUS_URI, idx: 40_213 } })))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await codeOf(() => issueDelegated(request(oleh.copy, { claims: { authority: [] } })))).toBe(
      'INVALID_ARGUMENT',
    );
  });
});

/** A request for a root role-authority credential without a delegation claim. */
async function rootInput(keys: Keys) {
  return {
    signer: keys.issuer,
    issuer: ISSUER,
    vct: VCT.roleAuthority,
    jti: 'cred-oleh-0001',
    sub: 'p_oleh',
    iat: NOW,
    exp: OLEH_EXP,
    cnfJwk: keys.oleh.publicJwk,
    status: { uri: STATUS_URI, idx: 40_213 },
    claims: { org: ORG, role: OLEH_ROLE, authority: OLEH_AUTHORITY },
  };
}

describe('cascadeRevocation', () => {
  const status = (idx: number): StatusRef => ({ uri: STATUS_URI, idx });
  const entry = (jti: string, idx: number) => ({ jti, status: status(idx) });

  it('lists every descendant once, nearest first, whatever loops the delegation graph has', () => {
    // root -> a, b;  a -> c, d;  b -> d, e;  c -> c;  e -> root, f
    const children: Record<string, Array<{ jti: string; status: StatusRef }>> = {
      root: [entry('a', 1), entry('b', 2)],
      a: [entry('c', 3), entry('d', 4)],
      b: [entry('d', 4), entry('e', 5)],
      c: [entry('c', 3)],
      e: [entry('root', 0), entry('f', 6)],
    };
    const asked: string[] = [];
    const revoked = cascadeRevocation({
      root: 'root',
      childrenOf: (jti) => {
        asked.push(jti);
        return children[jti] ?? [];
      },
    });
    expect(revoked).toEqual([entry('a', 1), entry('b', 2), entry('c', 3), entry('d', 4), entry('e', 5), entry('f', 6)]);
    expect([...asked].sort()).toEqual(['a', 'b', 'c', 'd', 'e', 'f', 'root']); //  each credential is expanded once
    // the entries are copies
    revoked[0]!.status.idx = 99;
    expect(children.root![0]!.status.idx).toBe(1);
  });

  it('has nothing to revoke for a credential without delegates and refuses a malformed graph', async () => {
    expect(cascadeRevocation({ root: 'root', childrenOf: () => [] })).toEqual([]);
    expect(await codeOf(() => cascadeRevocation({ root: '', childrenOf: () => [] }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => cascadeRevocation({ root: 'root', childrenOf: () => [{ jti: 'a' } as never] }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await codeOf(() => cascadeRevocation({ root: 'root', childrenOf: (() => null) as never }))).toBe(
      'INVALID_ARGUMENT',
    );
  });
});
