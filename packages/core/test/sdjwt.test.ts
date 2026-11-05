import { readFileSync } from 'node:fs';
import { compactVerify, importJWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  DISCLOSABLE_CLAIMS,
  base64urlDecode,
  base64urlEncode,
  checkCredentialTimes,
  decodeCredential,
  disclosureDigest,
  issueCredential,
  parseSdJwt,
  presentCredential,
  randomId,
  utf8Decode,
  utf8Encode,
  verifyIssuerSignature,
  verifyKeyBinding,
  type CryptoProvider,
  type ParsedSdJwt,
} from '../src/index.js';
import {
  DAY,
  NOW,
  VERIFIER,
  buildWorld,
  codeOf,
  disclosureText,
  forgeJws,
  presentWith,
  providers,
  segment,
  type World,
} from './fixtures.js';

interface DigestVectors {
  digest: Array<{ disclosure: string; digest: string; decoded: unknown[] }>;
}

const vectors = JSON.parse(
  readFileSync(new URL('../../../test-vectors/rfc9901-disclosures.json', import.meta.url), 'utf8'),
) as DigestVectors;

const KB_CHECK = { aud: VERIFIER, now: NOW + 125, maxAgeSeconds: 30, skewSeconds: 10 };

const jsonOf = (segment: string): Record<string, unknown> =>
  JSON.parse(utf8Decode(base64urlDecode(segment))) as Record<string, unknown>;

describe('disclosure digests (RFC 9901 sections 4.2.1 to 4.2.3)', () => {
  it.each(providers)('hashes the published disclosures to the published digests (%s)', async (_name, crypto) => {
    for (const vector of vectors.digest) {
      expect(await disclosureDigest(vector.disclosure, crypto)).toBe(vector.digest);
      expect(JSON.parse(utf8Decode(base64urlDecode(vector.disclosure)))).toEqual(vector.decoded);
    }
  });

  it('refuses text that is not ASCII', async () => {
    expect(await codeOf(() => disclosureDigest('Möbius'))).toBe('INVALID_ARGUMENT');
  });
});

describe.each(providers)('SD-JWT VC issue, present, parse and verify (%s)', (_name, crypto: CryptoProvider) => {
  let world: World;
  beforeAll(async () => {
    world = await buildWorld(crypto);
  });

  it('round-trips the root authority credential: plain claims stay plain, the rest is disclosed on request', async () => {
    const [jwt, ...rest] = world.olehCredential.split('~');
    const header = jsonOf(jwt!.split('.')[0]!);
    const payload = jsonOf(jwt!.split('.')[1]!);
    expect(header).toEqual({ typ: 'dc+sd-jwt', kid: world.issuer.kid, alg: 'ES256' });
    expect(rest.at(-1)).toBe('');
    expect(rest.slice(0, -1)).toHaveLength(6);
    expect(payload).toMatchObject({ iss: world.olehPayload.iss, vct: world.olehPayload.vct, _sd_alg: 'sha-256' });
    for (const name of DISCLOSABLE_CLAIMS) expect(payload).not.toHaveProperty(name);
    expect(payload.cnf).toEqual({
      jwk: { kty: 'EC', crv: 'P-256', x: world.oleh.publicJwk.x, y: world.oleh.publicJwk.y },
    });
    expect(payload._sd).toHaveLength(6);

    const nonce = randomId(16, crypto);
    const presentation = await presentWith(world, world.olehCredential, world.oleh, { nonce });
    const parsed = await parseSdJwt(presentation, crypto);
    const { org, role, authority, delegation } = world.olehClaims;
    expect(parsed.claims).toEqual({ org, role, authority, delegation });
    expect(parsed.claims).not.toHaveProperty('display');
    expect(parsed.disclosures.map((d) => d.name)).toEqual(['org', 'role', 'authority', 'delegation']);
    for (const disclosure of parsed.disclosures) {
      expect(base64urlDecode(disclosure.salt)).toHaveLength(16);
      expect(DISCLOSABLE_CLAIMS).toContain(disclosure.name);
    }
    expect(await verifyIssuerSignature(parsed, world.issuer.publicJwk, crypto)).toBe(true);
    expect(await verifyKeyBinding(parsed, { ...KB_CHECK, nonce, crypto })).toEqual({ ok: true, iat: NOW + 120, nonce });
    expect(parsed.sdHashInput).toBe(presentation.slice(0, presentation.lastIndexOf('~') + 1));
  });

  it('writes the claims that are not selected as plain claims', async () => {
    const credential = await issueCredential({
      signer: world.issuer,
      payload: world.olehPayload,
      claims: world.olehClaims,
      sd: ['authority', 'delegation'],
      crypto,
    });
    const parsed = await parseSdJwt(credential, crypto);
    expect(parsed.disclosures.map((d) => d.name).sort()).toEqual(['authority', 'delegation']);
    expect(parsed.claims).toEqual(world.olehClaims);
    expect(jsonOf(credential.split('.')[1]!)).toMatchObject({ org: world.olehClaims.org, role: world.olehClaims.role });
  });

  it('decodes a credential for display without checking it', async () => {
    const decoded = decodeCredential(world.ivanCredential);
    expect(decoded).toMatchObject({
      issuer: world.ivanPayload.iss,
      vct: world.ivanPayload.vct,
      jti: world.ivanPayload.jti,
      kid: world.issuer.kid,
      status: world.ivanPayload.status.status_list,
      hasKeyBinding: false,
    });
    expect(decoded.disclosable).toEqual(['org', 'org_unit', 'role', 'authority', 'delegation', 'display']);
    expect(decoded.claims).toEqual(world.ivanClaims);
    expect(decoded.cnfJwk).toMatchObject({ x: world.ivan.publicJwk.x, y: world.ivan.publicJwk.y });
    expect(await codeOf(() => decodeCredential('not a credential'))).toBe('MALFORMED');
    expect(await codeOf(() => decodeCredential(`${world.ivanCredential.split('.')[0]}.e30.AA~`))).toBeDefined();
  });

  it('refuses to present a claim the credential holds no disclosure for', async () => {
    const credential = await issueCredential({
      signer: world.issuer,
      payload: world.olehPayload,
      claims: world.olehClaims,
      sd: ['role'],
      crypto,
    });
    const kb = { signer: world.oleh, aud: VERIFIER, nonce: randomId(16, crypto), iat: NOW };
    expect(await codeOf(() => presentCredential({ credential, disclose: ['org'], kb, crypto }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await codeOf(() => presentCredential({ credential, disclose: ['role'], kb, crypto }))).toBeUndefined();
    const presented = await presentCredential({ credential, disclose: [], kb, crypto });
    expect(await codeOf(() => presentCredential({ credential: presented, disclose: [], kb, crypto }))).toBe(
      'INVALID_ARGUMENT',
    );
  });

  it('interoperates with jose for the issuer JWT and the key-binding JWT', async () => {
    const presentation = await presentWith(world, world.olehCredential, world.oleh, { nonce: randomId(16, crypto) });
    const parts = presentation.split('~');
    const issuerKey = await importJWK(world.issuer.publicJwk, 'ES256');
    const holderKey = await importJWK(world.oleh.publicJwk, 'ES256');
    const issuerResult = await compactVerify(parts[0]!, issuerKey);
    const kbResult = await compactVerify(parts.at(-1)!, holderKey);
    expect(issuerResult.protectedHeader).toMatchObject({ typ: 'dc+sd-jwt', alg: 'ES256' });
    expect(kbResult.protectedHeader).toEqual({ typ: 'kb+jwt', alg: 'ES256' });
  });
});

describe('RFC 9901 sections 7.1 and 7.3 negative cases', () => {
  let world: World;
  let parts: string[]; //          the root credential split at "~": issuer JWT, six disclosures, ""
  let presentation: string;
  const nonce = 'AAAAAAAAAAAAAAAAAAAAAA';

  beforeAll(async () => {
    world = await buildWorld(providers[0]![1]);
    parts = world.olehCredential.split('~');
    presentation = await presentWith(world, world.olehCredential, world.oleh, { nonce });
  });

  /**
   * A credential with this issuer header and payload (merged over the usual plain claims) and these disclosures. Without
   * disclosures it is `<jwt>~`, a valid credential that discloses nothing.
   */
  async function forge(i: {
    header?: Record<string, unknown>;
    payload?: Record<string, unknown>;
    disclosures: string[];
    listed?: string[];
  }): Promise<string> {
    const digests = i.listed ?? (await Promise.all(i.disclosures.map((d) => disclosureDigest(d))));
    const header = { typ: 'dc+sd-jwt', kid: world.issuer.kid, alg: 'ES256', ...i.header };
    const { iss, sub, jti, iat, exp, vct } = world.olehPayload;
    const payload = {
      iss,
      sub,
      jti,
      iat,
      exp,
      vct,
      cnf: { jwk: { kty: 'EC', crv: 'P-256', x: world.oleh.publicJwk.x, y: world.oleh.publicJwk.y } },
      status: { status_list: world.olehPayload.status.status_list },
      _sd_alg: 'sha-256',
      _sd: digests,
      ...i.payload,
    };
    return [await forgeJws(world.issuer, header, payload), ...i.disclosures, ''].join('~');
  }

  /** A forged credential of exactly `length` characters: the salt of its one disclosure and a hidden digest fill it. */
  async function forgeOfLength(length: number): Promise<string> {
    for (let hidden = 43; hidden < 46; hidden++) {
      const build = async (saltLength: number): Promise<string> => {
        const disclosure = disclosureText('s'.repeat(saltLength), 'org', { id: 'a', name: 'A' });
        return forge({ disclosures: [disclosure], listed: [await disclosureDigest(disclosure), 'h'.repeat(hidden)] });
      };
      const shortest = (await build(16)).length;
      // three more salt characters add exactly four base64url characters
      let saltLength = 16 + 3 * Math.floor((length - shortest) / 4);
      for (let step = 0; step < 4; step++, saltLength++) {
        const text = await build(saltLength);
        if (text.length === length) return text;
      }
    }
    throw new Error(`no forged credential has exactly ${length} characters`);
  }

  const orgDisclosure = disclosureText('salt-org-0000000000', 'org', { id: 'a', name: 'A' });
  const roleDisclosure = disclosureText('salt-role-000000000', 'role', { code: 'x', name: 'X' });

  it('accepts the forged baseline, so that each rejection below is caused by its one change', async () => {
    const parsed = await parseSdJwt(await forge({ disclosures: [orgDisclosure, roleDisclosure] }));
    expect(Object.keys(parsed.claims)).toEqual(['org', 'role']);
    const bare = await parseSdJwt(await forge({ disclosures: [] }));
    expect(bare.disclosures).toEqual([]);
    expect(bare.claims).toEqual({});
  });

  it('caps the input at 16 384 characters: a valid credential of that length parses, one more is MALFORMED', async () => {
    const atLimit = await forgeOfLength(16_384);
    expect(atLimit).toHaveLength(16_384);
    expect(Object.keys((await parseSdJwt(atLimit)).claims)).toEqual(['org']);
    const aboveLimit = await forgeOfLength(16_385);
    expect(aboveLimit).toHaveLength(16_385);
    expect(await codeOf(() => parseSdJwt(aboveLimit))).toBe('MALFORMED');
  });

  it.each([
    [
      'an altered disclosure',
      () =>
        [parts[0], disclosureText('salt-org-0000000000', 'org', { id: 'evil', name: 'E' }), ...parts.slice(2)].join(
          '~',
        ),
    ],
    ['a repeated disclosure', () => [parts[0], parts[1], parts[1], ...parts.slice(2)].join('~')],
    ['an empty disclosure', () => [parts[0], '', ...parts.slice(1)].join('~')],
    ['an input without a tilde', () => parts[0]!],
    ['a key-binding JWT that is not a JWS', () => `${parts.slice(0, -1).join('~')}~not-a-jws`],
  ])('rejects %s as MALFORMED', async (_label, build) => {
    expect(await codeOf(() => parseSdJwt(build()))).toBe('MALFORMED');
  });

  it.each([
    ['a disclosure that _sd does not list', { disclosures: [orgDisclosure], listed: ['x'.repeat(43)] }],
    ['a digest listed twice in _sd', { disclosures: [orgDisclosure], listed: ['d'.repeat(43), 'd'.repeat(43)] }],
    [
      'a disclosure named like a plain claim',
      { disclosures: [orgDisclosure], payload: { org: { id: 'a', name: 'A' } } },
    ],
    [
      'two disclosures of one claim',
      { disclosures: [orgDisclosure, disclosureText('other-salt-000000000', 'org', { id: 'b', name: 'B' })] },
    ],
    ['an array-element disclosure', { disclosures: [segment(['salt-0000000000000', 'FR'])] }],
    [
      'a claim name the profile does not define',
      { disclosures: [disclosureText('salt-0000000000000', 'email', 'a@b.c')] },
    ],
    [
      'a disclosed value with _sd inside',
      { disclosures: [disclosureText('salt-0000000000000', 'org', { id: 'a', name: 'A', x: { _sd: [] } })] },
    ],
    [
      'a disclosed value with "..." inside',
      { disclosures: [disclosureText('salt-0000000000000', 'authority', [{ '...': 'x' }])] },
    ],
    [
      'a nested _sd among the plain claims',
      { disclosures: [], payload: { status: { status_list: { idx: 1, uri: 'u' }, _sd: [] } } },
    ],
    ['a plain claim of the wrong type', { disclosures: [], payload: { exp: 'tomorrow' } }],
    ['a holder key that is not a P-256 key', { disclosures: [], payload: { cnf: { jwk: { kty: 'oct', k: 'AAAA' } } } }],
    ['a disclosed org without a name', { disclosures: [disclosureText('salt-0000000000000', 'org', { id: 'a' })] }],
  ])('rejects %s as MALFORMED', async (_label, input) => {
    expect(await codeOf(async () => parseSdJwt(await forge(input as Parameters<typeof forge>[0])))).toBe('MALFORMED');
  });

  it('rejects a digest algorithm other than sha-256 and a typ other than dc+sd-jwt as UNSUPPORTED_FORMAT', async () => {
    const sha512 = await forge({ disclosures: [orgDisclosure], payload: { _sd_alg: 'sha-512' } });
    expect(await codeOf(() => parseSdJwt(sha512))).toBe('UNSUPPORTED_FORMAT');
    const vcTyp = await forge({ disclosures: [orgDisclosure], header: { typ: 'vc+sd-jwt' } });
    expect(await codeOf(() => parseSdJwt(vcTyp))).toBe('UNSUPPORTED_FORMAT');
    const none = await forge({ disclosures: [orgDisclosure], header: { alg: 'none' } });
    expect(await codeOf(() => parseSdJwt(none))).toBe('UNSUPPORTED_FORMAT');
  });

  it('refuses header members beyond alg, typ and kid, an embedded key included', async () => {
    const withJwk = await forge({ disclosures: [], header: { jwk: world.issuer.publicJwk } });
    expect(await codeOf(() => parseSdJwt(withJwk))).toBe('MALFORMED');
    const withCrit = await forge({ disclosures: [], header: { crit: ['x'], x: 1 } });
    expect(await codeOf(() => parseSdJwt(withCrit))).toBe('MALFORMED');
  });

  it('accepts digests in _sd that have no disclosure: claims that stay hidden', async () => {
    const parsed = await parseSdJwt(
      await forge({ disclosures: [orgDisclosure], listed: [await disclosureDigest(orgDisclosure), 'h'.repeat(43)] }),
    );
    expect(Object.keys(parsed.claims)).toEqual(['org']);
  });

  it('rejects an issuer signature of another key and a presentation without a key-binding JWT', async () => {
    const parsed = await parseSdJwt(presentation);
    expect(await verifyIssuerSignature(parsed, world.issuer.publicJwk)).toBe(true);
    expect(await verifyIssuerSignature(parsed, world.oleh.publicJwk)).toBe(false);
    const bare = await parseSdJwt(world.olehCredential);
    expect(await verifyKeyBinding(bare, { ...KB_CHECK, nonce })).toEqual({
      ok: false,
      reason: 'HOLDER_BINDING_INVALID',
    });
  });

  describe('key binding', () => {
    const check = async (presentationText: string, over: Partial<Parameters<typeof verifyKeyBinding>[1]> = {}) =>
      verifyKeyBinding(await parseSdJwt(presentationText), { ...KB_CHECK, nonce, ...over });
    const reasonOf = async (text: string, over?: Partial<Parameters<typeof verifyKeyBinding>[1]>) => {
      const result = await check(text, over);
      return result.ok ? 'ok' : result.reason;
    };

    /** A key-binding JWT with the usual payload over this presentation, changed as asked. */
    async function withKb(i: { signer?: typeof world.oleh; header?: object; payload?: object; hashOf?: string }) {
      const base = presentation.slice(0, presentation.lastIndexOf('~') + 1);
      const sdHash = base64urlEncode(await world.crypto.sha256(utf8Encode(i.hashOf ?? base)));
      const header = { typ: 'kb+jwt', alg: 'ES256', ...i.header };
      const payload = { iat: NOW + 120, aud: VERIFIER, nonce, sd_hash: sdHash, ...i.payload };
      return `${base}${await forgeJws(i.signer ?? world.oleh, header, payload)}`;
    }

    it('accepts the presentation, with or without an expected nonce', async () => {
      expect(await reasonOf(presentation)).toBe('ok');
      expect(await check(presentation, { nonce: undefined })).toEqual({ ok: true, iat: NOW + 120, nonce });
      expect(await reasonOf(presentation, { aud: ['urn:other', VERIFIER] })).toBe('ok');
    });

    it('rejects a key-binding JWT over another set of disclosures (sd_hash)', async () => {
      const [issuerJwt, ...rest] = presentation.split('~');
      const kb = rest.at(-1)!;
      const dropped = [issuerJwt, ...rest.slice(1, -1), kb].join('~'); //  the first disclosure is gone
      expect(await reasonOf(dropped)).toBe('HOLDER_BINDING_INVALID');
      const added = [issuerJwt, ...rest.slice(0, -1), parts[2], kb].join('~'); //  one more is shown
      expect(await reasonOf(added)).toBe('HOLDER_BINDING_INVALID');
      expect(await reasonOf(await withKb({ hashOf: 'unrelated text~' }))).toBe('HOLDER_BINDING_INVALID');
    });

    it('rejects a key-binding JWT signed by a key other than cnf, and one with the wrong typ or header', async () => {
      expect(await reasonOf(await withKb({ signer: world.ivan }))).toBe('HOLDER_BINDING_INVALID');
      expect(await reasonOf(await withKb({ header: { typ: 'JWT' } }))).toBe('HOLDER_BINDING_INVALID');
      expect(await reasonOf(await withKb({ header: { kid: 'k' } }))).toBe('HOLDER_BINDING_INVALID');
      expect(await reasonOf(await withKb({ payload: { nonce: 5 } }))).toBe('HOLDER_BINDING_INVALID');
      expect(await reasonOf(await withKb({ payload: { sd_hash: undefined } }))).toBe('HOLDER_BINDING_INVALID');
    });

    it('rejects a wrong nonce, a wrong audience and a short nonce when none is expected', async () => {
      expect(await reasonOf(presentation, { nonce: 'BBBBBBBBBBBBBBBBBBBBBB' })).toBe('NONCE_MISMATCH');
      expect(await reasonOf(presentation, { aud: 'urn:umis:verifier:elsewhere' })).toBe('AUDIENCE_MISMATCH');
      expect(await reasonOf(await withKb({ payload: { nonce: 'short' } }), { nonce: undefined })).toBe(
        'NONCE_MISMATCH',
      );
    });

    it('bounds the age of the key binding: the maximum age is accepted, one second more is expired', async () => {
      expect(await reasonOf(presentation, { now: NOW + 120 + 30 })).toBe('ok');
      expect(await reasonOf(presentation, { now: NOW + 120 + 31 })).toBe('PRESENTATION_EXPIRED');
    });

    it('bounds the clock skew: ten seconds ahead are accepted, eleven are not', async () => {
      expect(await reasonOf(presentation, { now: NOW + 110 })).toBe('ok');
      expect(await reasonOf(presentation, { now: NOW + 109 })).toBe('CLOCK_SKEW');
    });

    it('can require the key binding to be newer than a request (notBefore)', async () => {
      expect(await reasonOf(presentation, { notBefore: NOW + 130 })).toBe('ok'); // 10 s of skew
      expect(await reasonOf(presentation, { notBefore: NOW + 131 })).toBe('CLOCK_SKEW');
    });

    it('refuses time inputs that are not numbers instead of accepting everything', async () => {
      expect(await codeOf(() => check(presentation, { now: Number.NaN }))).toBe('INVALID_ARGUMENT');
      expect(await codeOf(() => check(presentation, { maxAgeSeconds: Number.NaN }))).toBe('INVALID_ARGUMENT');
      expect(await codeOf(() => check(presentation, { skewSeconds: Number.POSITIVE_INFINITY }))).toBe(
        'INVALID_ARGUMENT',
      );
    });

    it('refuses an expected nonce that is empty, so that an empty one in the key binding cannot match it', async () => {
      const empty = await withKb({ payload: { nonce: '' } });
      expect(await codeOf(() => check(empty, { nonce: '' }))).toBe('INVALID_ARGUMENT');
      expect(await codeOf(() => check(presentation, { nonce: 7 as unknown as string }))).toBe('INVALID_ARGUMENT');
      expect(await reasonOf(empty, { nonce })).toBe('NONCE_MISMATCH');
      expect(await reasonOf(empty, { nonce: undefined })).toBe('NONCE_MISMATCH');
    });
  });
});

describe('credential times', () => {
  const credential = { iat: NOW, exp: NOW + 100, nbf: NOW + 10 };

  it('expires at exp plus the skew, and not before nbf minus the skew', () => {
    expect(checkCredentialTimes(credential, NOW + 109, 10)).toBeUndefined();
    expect(checkCredentialTimes(credential, NOW + 110, 10)).toBe('CREDENTIAL_EXPIRED');
    expect(checkCredentialTimes(credential, NOW, 10)).toBeUndefined();
    expect(checkCredentialTimes(credential, NOW - 1, 10)).toBe('CREDENTIAL_NOT_YET_VALID');
  });

  it('reports an iat in the future beyond the skew as CLOCK_SKEW', () => {
    expect(checkCredentialTimes({ iat: NOW + 10, exp: NOW + DAY }, NOW, 10)).toBeUndefined();
    expect(checkCredentialTimes({ iat: NOW + 11, exp: NOW + DAY }, NOW, 10)).toBe('CLOCK_SKEW');
  });

  it('fails closed on values that are not numbers', () => {
    expect(checkCredentialTimes({ iat: NOW, exp: Number.NaN }, NOW, 10)).toBe('CREDENTIAL_EXPIRED');
    expect(checkCredentialTimes({ iat: Number.NaN, exp: NOW + DAY }, NOW, 10)).toBe('CLOCK_SKEW');
  });
});

describe('parsed result shape', () => {
  it('keeps the issuer payload in the form the verification steps read', async () => {
    const world = await buildWorld(providers[0]![1]);
    const parsed: ParsedSdJwt = await parseSdJwt(world.ivanCredential);
    expect(parsed.issuerJwt.payload).toMatchObject({ iss: world.ivanPayload.iss, jti: world.ivanPayload.jti });
    expect(parsed.issuerJwt.payload.status.status_list).toEqual(world.ivanPayload.status.status_list);
    expect(parsed.issuerJwt.header.kid).toBe(world.issuer.kid);
    expect(parsed.kbJwt).toBeUndefined();
  });
});
