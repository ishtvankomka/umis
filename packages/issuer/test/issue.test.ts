import { describe, expect, it } from 'vitest';
import { DISCLOSABLE_CLAIMS, VCT, parseSdJwt, verifyIssuerSignature } from '@umis/core';
import type { AuthorityItem } from '@umis/core';
import { issueOrgMember, issueRoleAuthority, issueSdJwtVc, profileErrors, randomStatusIndex } from '../src/index.js';
import type { IssueSdJwtVcInput } from '../src/index.js';
import {
  DAY,
  IVAN_AUTHORITY,
  NOW,
  OLEH_AUTHORITY,
  OLEH_ROLE,
  ORG,
  ORG_UNIT,
  STATUS_URI,
  bareJwk,
  codeOf,
  countingCrypto,
  makeKeys,
  messageOf,
  roleAuthorityInput,
  scriptedRandom,
} from './fixtures.js';

describe('issueSdJwtVc', () => {
  it('issues a credential that the core parses: plain registered claims, six disclosures, a root delegation', async () => {
    const keys = await makeKeys();
    const counting = countingCrypto();
    const sdJwt = await issueSdJwtVc(roleAuthorityInput(keys, { crypto: counting }));
    const parsed = await parseSdJwt(sdJwt);

    expect(parsed.issuerJwt.header).toEqual({ alg: 'ES256', typ: 'dc+sd-jwt', kid: keys.issuer.kid });
    const payload = parsed.issuerJwt.payload;
    expect(Object.keys(payload).sort()).toEqual([
      '_sd',
      '_sd_alg',
      'cnf',
      'exp',
      'iat',
      'iss',
      'jti',
      'status',
      'sub',
      'vct',
    ]);
    expect(payload.iss).toBe('https://issuer.example/contractor-a');
    expect(payload.sub).toBe('p_oleh');
    expect(payload.jti).toBe('cred-oleh-0001');
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + 90 * DAY);
    expect(payload.vct).toBe(VCT.roleAuthority);
    expect(payload._sd_alg).toBe('sha-256');
    expect(payload._sd).toHaveLength(6);
    // the holder key is bare coordinates: no kid, alg, use and never a private part
    expect(payload.cnf).toEqual({ jwk: bareJwk(keys.oleh.publicJwk) });
    expect(payload.status).toEqual({ status_list: { uri: STATUS_URI, idx: 40_213 } });

    expect(parsed.disclosures.map((disclosure) => disclosure.name)).toEqual([...DISCLOSABLE_CLAIMS]);
    expect(parsed.claims.org).toEqual(ORG);
    expect(parsed.claims.authority).toEqual(OLEH_AUTHORITY);
    // a role-authority credential without a delegation claim is a root credential that cannot be delegated further
    expect(parsed.claims.delegation).toEqual({ depth: 0, max_depth: 0 });
    expect(await verifyIssuerSignature(parsed, keys.issuer.publicJwk)).toBe(true);
    expect(sdJwt.endsWith('~')).toBe(true);
    expect(sdJwt.split('~')).toHaveLength(8);

    // hashing and salts came from the provider that was handed in
    expect(counting.calls.sha256).toBeGreaterThan(0);
    expect(counting.calls.random).toBeGreaterThan(0);
  });

  it('writes nbf when given and keeps the claims that are not selected for disclosure in the open', async () => {
    const keys = await makeKeys();
    const withNbf = await parseSdJwt(await issueSdJwtVc(roleAuthorityInput(keys, { nbf: NOW + DAY })));
    expect(withNbf.issuerJwt.payload.nbf).toBe(NOW + DAY);

    // authority hidden by default takes the delegation with it: the parent summary repeats authority details
    const hidden = await parseSdJwt(await issueSdJwtVc(roleAuthorityInput(keys, { sdClaims: ['authority'] })));
    expect(hidden.disclosures.map((disclosure) => disclosure.name)).toEqual(['authority', 'delegation']);
    const open = hidden.issuerJwt.payload as unknown as Record<string, unknown>;
    expect(open.org).toEqual(ORG);
    expect(open.role).toEqual(OLEH_ROLE);
    expect(open.authority).toBeUndefined();
    expect(open.delegation).toBeUndefined();

    const noDisclosures = await parseSdJwt(await issueSdJwtVc(roleAuthorityInput(keys, { sdClaims: [] })));
    expect(noDisclosures.disclosures).toEqual([]);
    expect(noDisclosures.claims.authority).toEqual(OLEH_AUTHORITY);
  });

  it('issues organisation-member and root role-authority credentials through the typed entry points', async () => {
    const keys = await makeKeys();
    const { signer, issuer, jti, sub, iat, exp, cnfJwk, status } = roleAuthorityInput(keys);
    const common = { signer, issuer, jti, sub, iat, exp, cnfJwk, status };

    const member = await parseSdJwt(
      await issueOrgMember({
        ...common,
        claims: { org: ORG, org_unit: ORG_UNIT, role: OLEH_ROLE, display: { name: 'Олег' } },
      }),
    );
    expect(member.issuerJwt.payload.vct).toBe(VCT.orgMember);
    expect(member.disclosures.map((disclosure) => disclosure.name)).toEqual(['org', 'org_unit', 'role', 'display']);
    expect(member.claims.authority).toBeUndefined();
    expect(member.claims.delegation).toBeUndefined();

    const root = await parseSdJwt(
      await issueRoleAuthority({
        ...common,
        claims: { org: ORG, role: OLEH_ROLE, authority: OLEH_AUTHORITY },
        maxDepth: 2,
      }),
    );
    expect(root.issuerJwt.payload.vct).toBe(VCT.roleAuthority);
    expect(root.claims.delegation).toEqual({ depth: 0, max_depth: 2 });
    expect(await verifyIssuerSignature(root, keys.issuer.publicJwk)).toBe(true);

    for (const maxDepth of [-1, 1.5, Number.NaN]) {
      const request = { ...common, claims: { org: ORG, role: OLEH_ROLE, authority: OLEH_AUTHORITY }, maxDepth };
      expect(await codeOf(() => issueRoleAuthority(request))).toBe('INVALID_ARGUMENT');
    }
  });

  it('refuses a request that breaks the profile with INVALID_ARGUMENT and says why', async () => {
    const keys = await makeKeys();
    const base = roleAuthorityInput(keys);

    // an organisation-member credential with authority
    const member = () => issueSdJwtVc({ ...base, vct: VCT.orgMember, claims: { org: ORG, authority: OLEH_AUTHORITY } });
    expect(await codeOf(member)).toBe('INVALID_ARGUMENT');
    expect(await messageOf(member)).toContain('org-member credential must not carry authority');

    // a role-authority credential without a role
    const noRole = () => issueSdJwtVc({ ...base, claims: { org: ORG, authority: OLEH_AUTHORITY } });
    expect(await codeOf(noRole)).toBe('INVALID_ARGUMENT');
    expect(await messageOf(noRole)).toContain('needs a role');

    // all the problems are listed, not just the first
    const several = await messageOf(() =>
      issueSdJwtVc({ ...base, vct: 'https://example.org/vct/other', jti: '', claims: { org: { id: '', name: 'A' } } }),
    );
    for (const part of ['vct "https://example.org/vct/other"', 'jti must be', 'org.id must be']) {
      expect(several).toContain(part);
    }

    // a private key is not something to bind a credential to
    const privateKey = { ...keys.oleh.publicJwk, d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
    expect(await messageOf(() => issueSdJwtVc({ ...base, cnfJwk: privateKey }))).toContain('private member');

    const requests: Array<[string, Partial<IssueSdJwtVcInput>, string]> = [
      ['exp before iat', { exp: NOW - 1 }, 'exp must be after iat'],
      ['nbf after exp', { nbf: NOW + 91 * DAY }, 'nbf must be before exp'],
      ['a non-finite time', { iat: Number.NaN }, 'iat must be a finite number'],
      ['an empty subject', { sub: '' }, 'sub must be a non-empty string'],
      ['a negative status index', { status: { uri: STATUS_URI, idx: -1 } }, 'status.idx'],
      ['a status index with a fraction', { status: { uri: STATUS_URI, idx: 1.5 } }, 'status.idx'],
      ['an unknown claim to disclose', { sdClaims: ['colour' as never] }, 'sdClaims names "colour"'],
      ['a holder key that is not P-256', { cnfJwk: { kty: 'EC', crv: 'P-384', x: 'a', y: 'b' } as never }, 'cnfJwk'],
      ['a signer without a kid', { signer: { ...keys.issuer, kid: '' } }, 'signer must be an ES256 signer'],
    ];
    for (const [label, over, fragment] of requests) {
      const run = () => issueSdJwtVc({ ...base, ...over });
      expect(await codeOf(run), label).toBe('INVALID_ARGUMENT');
      expect(await messageOf(run), label).toContain(fragment);
    }
  });
});

describe('profileErrors', () => {
  const member = { org: ORG, role: OLEH_ROLE };
  const roleAuthority = { org: ORG, role: OLEH_ROLE, authority: OLEH_AUTHORITY };
  const item = (over: Record<string, unknown> = {}, limit: Record<string, unknown> = {}): AuthorityItem => ({
    ...OLEH_AUTHORITY[0]!,
    ...over,
    limit: { ...OLEH_AUTHORITY[0]!.limit, ...limit },
  });
  const parentSummary = {
    id: 'cred-oleh-0001',
    status: { uri: STATUS_URI, idx: 40_213 },
    authority: OLEH_AUTHORITY,
    exp: NOW,
  };

  it('finds nothing wrong with valid claim sets', () => {
    expect(profileErrors(VCT.orgMember, member)).toEqual([]);
    expect(profileErrors(VCT.orgMember, { org: ORG })).toEqual([]);
    expect(profileErrors(VCT.roleAuthority, roleAuthority)).toEqual([]);
    expect(profileErrors(VCT.roleAuthority, { ...roleAuthority, delegation: { depth: 0, max_depth: 3 } })).toEqual([]);
    expect(
      profileErrors(VCT.roleAuthority, {
        ...roleAuthority,
        authority: IVAN_AUTHORITY,
        delegation: { parent: parentSummary, depth: 1, max_depth: 1 },
      }),
    ).toEqual([]);
    // the period and the end of validity are optional
    const bare = { action: 'open', resource: 'door', limit: { amount: 1, unit: 'time' } };
    expect(profileErrors(VCT.roleAuthority, { ...roleAuthority, authority: [bare] })).toEqual([]);
  });

  it('reports each rule of the profile', () => {
    const cases: Array<[string, string, unknown, string]> = [
      ['an unknown type', 'https://example.org/vct', member, 'is not a UMIS credential type'],
      ['no organisation', VCT.orgMember, { role: OLEH_ROLE }, 'org is required'],
      ['an empty organisation name', VCT.orgMember, { org: { id: 'a', name: '' } }, 'org.name'],
      ['an empty unit id', VCT.orgMember, { ...member, org_unit: { id: '', name: 'B' } }, 'org_unit.id'],
      ['a claim outside the profile', VCT.orgMember, { ...member, nickname: 'x' }, '"nickname" is not a claim'],
      ['authority on a member', VCT.orgMember, { ...member, authority: OLEH_AUTHORITY }, 'must not carry authority'],
      [
        'delegation on a member',
        VCT.orgMember,
        { ...member, delegation: { depth: 0, max_depth: 0 } },
        'must not carry delegation',
      ],
      ['no role', VCT.roleAuthority, { org: ORG, authority: OLEH_AUTHORITY }, 'needs a role'],
      ['no authority', VCT.roleAuthority, { org: ORG, role: OLEH_ROLE }, 'authority must be a non-empty list'],
      [
        'an empty authority list',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [] },
        'authority must be a non-empty list',
      ],
      [
        'an empty action',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({ action: '' })] },
        'authority[0].action',
      ],
      [
        'an empty unit',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({}, { unit: '' })] },
        'authority[0].limit.unit',
      ],
      [
        'an amount of zero',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({}, { amount: 0 })] },
        'above zero',
      ],
      [
        'a negative amount',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({}, { amount: -2 })] },
        'above zero',
      ],
      [
        'an amount that is not finite',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({}, { amount: Infinity })] },
        'finite',
      ],
      [
        'an amount that is not a number',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({}, { amount: '10' })] },
        'finite',
      ],
      [
        'a period outside the profile',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({}, { per: 'hour' })] },
        'limit.per must be one of',
      ],
      [
        'a valid_until with a fraction',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({ valid_until: 1.5 })] },
        'valid_until must be an integer',
      ],
      // a misspelled restriction would otherwise vanish when the credential is written
      [
        'a misspelled valid_until',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({ validUntil: NOW })] },
        'unknown member "validUntil"',
      ],
      [
        'an unknown limit member',
        VCT.roleAuthority,
        { ...roleAuthority, authority: [item({}, { max: 5 })] },
        'unknown member "max"',
      ],
      [
        'a depth below zero',
        VCT.roleAuthority,
        { ...roleAuthority, delegation: { depth: -1, max_depth: 1 } },
        'delegation.depth must be a non-negative integer',
      ],
      [
        'a depth with a fraction',
        VCT.roleAuthority,
        { ...roleAuthority, delegation: { depth: 0.5, max_depth: 1 } },
        'delegation.depth must be a non-negative integer',
      ],
      [
        'a depth above max_depth',
        VCT.roleAuthority,
        { ...roleAuthority, delegation: { depth: 2, max_depth: 1, parent: parentSummary } },
        'must not exceed',
      ],
      [
        'depth 1 without a parent',
        VCT.roleAuthority,
        { ...roleAuthority, delegation: { depth: 1, max_depth: 1 } },
        'needs delegation.parent',
      ],
      [
        'depth 0 with a parent',
        VCT.roleAuthority,
        { ...roleAuthority, delegation: { depth: 0, max_depth: 1, parent: parentSummary } },
        'must not carry delegation.parent',
      ],
      [
        'a parent without authority',
        VCT.roleAuthority,
        { ...roleAuthority, delegation: { depth: 1, max_depth: 1, parent: { ...parentSummary, authority: [] } } },
        'delegation.parent.authority',
      ],
      [
        'a parent without a status',
        VCT.roleAuthority,
        { ...roleAuthority, delegation: { depth: 1, max_depth: 1, parent: { ...parentSummary, status: {} } } },
        'delegation.parent.status.uri',
      ],
    ];
    for (const [label, vct, claims, fragment] of cases) {
      const errors = profileErrors(vct, claims as never);
      expect(
        errors.some((error) => error.includes(fragment)),
        `${label}: ${JSON.stringify(errors)}`,
      ).toBe(true);
    }
    expect(profileErrors(VCT.orgMember, null as never)).toEqual(['the claims must be an object']);
  });
});

describe('randomStatusIndex', () => {
  it('finds the one free index of a list, whether by random draws or by the scan', () => {
    for (const size of [1, 2, 3, 64, 1_000, 1_048_576]) {
      const free = size - 1;
      expect(randomStatusIndex(size, (idx) => idx !== free)).toBe(free);
    }
    const seen = new Set<number>();
    for (let round = 0; round < 200; round++) seen.add(randomStatusIndex(50, () => false));
    expect([...seen].every((idx) => Number.isInteger(idx) && idx >= 0 && idx < 50)).toBe(true);
    expect(seen.size).toBeGreaterThan(20);
  });

  it('refuses a full list and unusable sizes with INVALID_ARGUMENT', async () => {
    expect(await codeOf(() => randomStatusIndex(10, () => true))).toBe('INVALID_ARGUMENT');
    for (const size of [0, -3, 2.5, Number.NaN, 2 ** 33]) {
      expect(await codeOf(() => randomStatusIndex(size, () => false)), String(size)).toBe('INVALID_ARGUMENT');
    }
  });

  it('draws without bias and scans from a random start after 64 taken draws', () => {
    // three entries from one random byte: 255 would favour index 0, so it is thrown away and the next byte decides
    const biased = scriptedRandom([255, 4]);
    const asked: number[] = [];
    expect(randomStatusIndex(3, (idx) => (asked.push(idx), false), biased)).toBe(1);
    expect(asked).toEqual([1]);
    expect(biased.consumed()).toBe(2);

    // five entries, only 3 is free: 64 draws all land on 0, then the scan starts at 4 and wraps around
    const crypto = scriptedRandom([...Array.from({ length: 64 }, () => 0), 4]);
    const visited: number[] = [];
    const found = randomStatusIndex(5, (idx) => (visited.push(idx), idx !== 3), crypto);
    expect(found).toBe(3);
    expect(visited).toEqual([...Array.from({ length: 64 }, () => 0), 4, 0, 1, 2, 3]);
  });
});
