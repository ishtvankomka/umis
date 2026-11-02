import {
  TYP,
  UmisError,
  VCT,
  decodeJwsUnverified,
  generateSigner,
  signJws,
  type EcPublicJwk,
  type TrustedIssuerEntryV1,
} from '@umis/core';
import { describe, expect, it } from 'vitest';
import {
  entryForStatusList,
  parseRegistry,
  resolveIssuer,
  selfEntry,
  signRegistry,
  trustedIssuerEntrySchema,
  type RegistrySnapshotV1,
} from '../src/index.js';

const NOW = 1_793_664_000;

async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

const withoutKid = ({ kid: _kid, ...rest }: EcPublicJwk): EcPublicJwk => rest;

const owner = await generateSigner();
const keyA = await generateSigner({ kid: 'a-1' });
const keyB = await generateSigner({ kid: 'b-1' });
const keyM1 = await generateSigner({ kid: 'm-1' });
const keyM2 = await generateSigner({ kid: 'm-2' });
const keyN = await generateSigner();

const A = 'https://contractor-a.example/issuer';
const B = 'https://supplier-b.example/issuer';
const LIST_A = 'https://contractor-a.example/status/1';
const LIST_B = 'https://supplier-b.example/status/1';

const entryA = selfEntry({
  issuer: A,
  name: 'Contractor A',
  keys: [keyA.publicJwk],
  vcts: [VCT.roleAuthority],
  statusLists: [LIST_A],
});
const entryB = selfEntry({
  issuer: B,
  name: 'Supplier B',
  keys: [keyB.publicJwk],
  vcts: [VCT.orgMember, VCT.roleAuthority],
  statusLists: [LIST_B],
});
const entryM: TrustedIssuerEntryV1 = {
  ...entryA,
  issuer: 'https://multi.example/issuer',
  name: 'Two keys',
  jwks: { keys: [keyM1.publicJwk, keyM2.publicJwk] },
};
const entryN: TrustedIssuerEntryV1 = {
  ...entryA,
  issuer: 'https://plain.example/issuer',
  name: 'One key without kid',
  jwks: { keys: [withoutKid(keyN.publicJwk)] },
};

describe('registry snapshot', () => {
  const snapshot: RegistrySnapshotV1 = { iss: 'org-b', ver: 7, iat: NOW, entries: [entryA, entryB] };

  it('signs, parses and rejects a wrong type, a wrong key and entries that are not acceptable', async () => {
    const jws = await signRegistry(snapshot, owner);
    expect(decodeJwsUnverified(jws).header).toMatchObject({ alg: 'ES256', typ: 'umis-registry+jwt', kid: owner.kid });

    const parsed = await parseRegistry(jws, owner.publicJwk);
    expect(parsed).toEqual({ iss: 'org-b', version: 7, iat: NOW, entries: [entryA, entryB] });
    await expect(parseRegistry(jws, [keyA.publicJwk, owner.publicJwk])).resolves.toEqual(parsed);
    expect(resolveIssuer(parsed.entries, { issuer: B, vct: VCT.orgMember, kid: 'b-1', now: NOW }).ok).toBe(true);

    expect(await codeOf(() => parseRegistry(jws, keyA.publicJwk))).toBe('SIGNATURE_INVALID');
    const policyToken = await signJws({ header: { typ: TYP.policy }, payload: snapshot, signer: owner });
    expect(await codeOf(() => parseRegistry(policyToken, owner.publicJwk))).toBe('UNSUPPORTED_FORMAT');

    // One entry per issuer: the signer refuses a duplicate and the parser does not accept one that was signed anyway.
    const duplicated = { ...snapshot, entries: [entryA, entryB, { ...entryA, name: 'Contractor A again' }] };
    expect(await codeOf(() => signRegistry(duplicated, owner))).toBe('INVALID_ARGUMENT');
    const forced = await signJws({ header: { typ: TYP.registry }, payload: duplicated, signer: owner });
    expect(await codeOf(() => parseRegistry(forced, owner.publicJwk))).toBe('MALFORMED');

    // A registry holds public keys only, and nothing it does not define.
    const privateKey = { ...keyA.publicJwk, d: 'A'.repeat(43) };
    const leaking = { ...snapshot, entries: [{ ...entryA, jwks: { keys: [privateKey] } }] };
    expect(await codeOf(() => signRegistry(leaking as unknown as RegistrySnapshotV1, owner))).toBe('INVALID_ARGUMENT');
    const leaked = await signJws({ header: { typ: TYP.registry }, payload: leaking, signer: owner });
    expect(await codeOf(() => parseRegistry(leaked, owner.publicJwk))).toBe('MALFORMED');
    const unknownMember = await signJws({
      header: { typ: TYP.registry },
      payload: { ...snapshot, global: true },
      signer: owner,
    });
    expect(await codeOf(() => parseRegistry(unknownMember, owner.publicJwk))).toBe('MALFORMED');
    const badStatus = { ...snapshot, entries: [{ ...entryA, status: 'deleted' }] };
    expect(await codeOf(() => signRegistry(badStatus as unknown as RegistrySnapshotV1, owner))).toBe(
      'INVALID_ARGUMENT',
    );
    const shortKey = { ...entryA, jwks: { keys: [{ ...keyA.publicJwk, x: 'AAAA' }] } };
    expect(trustedIssuerEntrySchema.safeParse(shortKey).success).toBe(false);
    expect(trustedIssuerEntrySchema.safeParse(entryA).success).toBe(true);
  });
});

describe('issuer resolution', () => {
  const suspended: TrustedIssuerEntryV1 = {
    ...entryA,
    issuer: 'https://suspended.example/issuer',
    status: 'suspended',
  };
  const revoked: TrustedIssuerEntryV1 = { ...entryA, issuer: 'https://revoked.example/issuer', status: 'revoked' };
  const expired: TrustedIssuerEntryV1 = { ...entryA, issuer: 'https://expired.example/issuer', validUntil: NOW - 1 };
  const lastDay: TrustedIssuerEntryV1 = { ...entryA, issuer: 'https://last-day.example/issuer', validUntil: NOW };
  const trusted = [entryA, entryB, entryM, entryN, suspended, revoked, expired, lastDay];
  const resolve = (issuer: string, extra: { vct?: string; kid?: string } = {}) =>
    resolveIssuer(trusted, { issuer, vct: extra.vct ?? VCT.roleAuthority, kid: extra.kid, now: NOW });

  it('answers each outcome from the verifier own entries only', () => {
    // accepted: the entry and the key come back
    expect(resolve(A, { kid: 'a-1' })).toEqual({ ok: true, entry: entryA, key: keyA.publicJwk });
    expect(resolve(B, { vct: VCT.orgMember, kid: 'b-1' })).toEqual({ ok: true, entry: entryB, key: keyB.publicJwk });

    // ISSUER_UNTRUSTED: no entry with exactly this issuer
    expect(resolve('https://stranger.example/issuer')).toEqual({ ok: false, reason: 'ISSUER_UNTRUSTED' });
    expect(resolve(`${A}/`)).toEqual({ ok: false, reason: 'ISSUER_UNTRUSTED' });
    expect(resolve(A.toUpperCase())).toEqual({ ok: false, reason: 'ISSUER_UNTRUSTED' });
    expect(resolveIssuer([], { issuer: A, vct: VCT.roleAuthority, now: NOW })).toEqual({
      ok: false,
      reason: 'ISSUER_UNTRUSTED',
    });

    // ISSUER_SUSPENDED: suspended, revoked, or past validUntil (the last day still counts)
    expect(resolve(suspended.issuer)).toEqual({ ok: false, reason: 'ISSUER_SUSPENDED' });
    expect(resolve(revoked.issuer)).toEqual({ ok: false, reason: 'ISSUER_SUSPENDED' });
    expect(resolve(expired.issuer)).toEqual({ ok: false, reason: 'ISSUER_SUSPENDED' });
    expect(resolve(lastDay.issuer).ok).toBe(true);
    expect(resolveIssuer(trusted, { issuer: lastDay.issuer, vct: VCT.roleAuthority, now: Number.NaN })).toEqual({
      ok: false,
      reason: 'ISSUER_SUSPENDED',
    });

    // ISSUER_VCT_NOT_ALLOWED: the entry does not list the credential type
    expect(resolve(A, { vct: VCT.orgMember, kid: 'a-1' })).toEqual({ ok: false, reason: 'ISSUER_VCT_NOT_ALLOWED' });

    // ISSUER_KEY_UNKNOWN: no key for the header kid, or no way to tell which of several keys
    expect(resolve(A, { kid: 'a-2' })).toEqual({ ok: false, reason: 'ISSUER_KEY_UNKNOWN' });
    expect(resolve(entryM.issuer)).toEqual({ ok: false, reason: 'ISSUER_KEY_UNKNOWN' });
    expect(resolve(entryM.issuer, { kid: 'm-3' })).toEqual({ ok: false, reason: 'ISSUER_KEY_UNKNOWN' });
    expect(resolve(entryM.issuer, { kid: 'm-2' })).toMatchObject({ ok: true, key: keyM2.publicJwk });

    // A single key serves without a header kid; it also serves any kid when it has none of its own.
    expect(resolve(A)).toMatchObject({ ok: true, key: keyA.publicJwk });
    expect(resolve(entryN.issuer)).toMatchObject({ ok: true, key: withoutKid(keyN.publicJwk) });
    expect(resolve(entryN.issuer, { kid: 'anything' })).toMatchObject({ ok: true, key: withoutKid(keyN.publicJwk) });

    // The first failing check decides.
    expect(resolve(suspended.issuer, { vct: VCT.orgMember, kid: 'nope' })).toEqual({
      ok: false,
      reason: 'ISSUER_SUSPENDED',
    });
    expect(resolve(A, { vct: VCT.orgMember, kid: 'nope' })).toEqual({ ok: false, reason: 'ISSUER_VCT_NOT_ALLOWED' });
  });

  it('takes a status list only from the entry of the issuer that signs it', () => {
    const copycat: TrustedIssuerEntryV1 = { ...entryB, statusLists: [LIST_A, LIST_B] };
    const both = [entryA, copycat];

    expect(entryForStatusList(both, A, LIST_A)).toBe(entryA);
    expect(entryForStatusList(both, B, LIST_B)).toBe(copycat);
    // B lists A's address too, but the list is not accepted for A through B's entry, nor for B through A's.
    expect(entryForStatusList([copycat], A, LIST_A)).toBeUndefined();
    expect(entryForStatusList([entryA], B, LIST_A)).toBeUndefined();
    expect(entryForStatusList(both, A, LIST_B)).toBeUndefined();
    expect(entryForStatusList(both, 'https://stranger.example/issuer', LIST_A)).toBeUndefined();
  });

  it('builds the entry of an own issuer from public keys', () => {
    const input = {
      issuer: A,
      name: 'Contractor A',
      keys: [keyA.publicJwk],
      vcts: [VCT.orgMember],
      statusLists: [] as string[],
    };
    const own = selfEntry(input);
    expect(own).toEqual({
      issuer: A,
      name: 'Contractor A',
      jwks: { keys: [keyA.publicJwk] },
      vcts: [VCT.orgMember],
      statusLists: [],
      status: 'active',
    });
    expect(resolveIssuer([own], { issuer: A, vct: VCT.orgMember, kid: 'a-1', now: NOW }).ok).toBe(true);

    const withPrivatePart = { ...keyA.publicJwk, d: 'A'.repeat(43) };
    expect(selfEntry({ ...input, keys: [withPrivatePart] }).jwks.keys[0]).toEqual(keyA.publicJwk);
    expect(() => selfEntry({ ...input, issuer: '' })).toThrow(UmisError);
    expect(() => selfEntry({ ...input, keys: [{ ...keyA.publicJwk, x: 'AAAA' }] })).toThrow(UmisError);
    expect(() => selfEntry({ ...input, keys: undefined as never })).toThrow(UmisError);
  });
});
