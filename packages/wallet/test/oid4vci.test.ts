import { TYP, VCT, decodeCredential, decodeJwsUnverified, formEncode, generateSigner, parseQuery } from '@umis/core';
import type { Signer } from '@umis/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { redeemOffer, resolveOffer } from '../src/index.js';
import type { FakeIssuer, FakeIssuerOptions } from './fake-issuer.js';
import { CONFIGURATION_IDS, ISSUER_ID, OFFER_URL, T0, URLS, createFakeIssuer, failureOf } from './fake-issuer.js';

const NOW = T0 + 3_600;
const PRE_AUTHORIZED_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

let holder: Signer;
let stranger: Signer;

beforeAll(async () => {
  [holder, stranger] = await Promise.all([generateSigner(), generateSigner()]);
});

describe('receiving a credential with the pre-authorized-code flow', () => {
  it('resolves an offer held by the issuer, and redeems it with the transaction code', async () => {
    const issuer = await createFakeIssuer();
    const view = await resolveOffer(issuer.byReference, { fetch: issuer.fetch });

    expect(issuer.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      `GET ${OFFER_URL}`,
      `GET ${URLS.issuerMetadata}`,
      `GET ${URLS.serverMetadata}`,
    ]);
    expect(view).toMatchObject({
      credentialIssuer: ISSUER_ID,
      configurationId: CONFIGURATION_IDS.roleAuthority,
      vct: VCT.roleAuthority,
      preAuthorizedCode: issuer.preAuthorizedCode,
      txCode: { length: 6, inputMode: 'numeric', description: 'The code was sent by e-mail' },
      tokenEndpoint: URLS.token,
      credentialEndpoint: URLS.credential,
      nonceEndpoint: URLS.nonce,
    });
    expect(view.offer).toEqual(issuer.offer);
    expect(view.display).toEqual([
      { name: 'Роль і повноваження', locale: 'uk-UA' },
      { name: 'Role and authority', locale: 'en-US' },
    ]);

    const received = await redeemOffer(view, issuer.txCode, holder, { now: NOW, fetch: issuer.fetch });
    const [token, nonce, credential] = issuer.requests.slice(3);

    // the token request is a form (section 6.1)
    expect(token).toMatchObject({ method: 'POST', url: URLS.token });
    expect(token!.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(token!.body.startsWith('{')).toBe(false);
    expect(parseQuery(token!.body)).toEqual({
      grant_type: PRE_AUTHORIZED_GRANT,
      'pre-authorized_code': issuer.preAuthorizedCode,
      tx_code: '493021',
    });

    // a nonce, then the credential request with the proof in proofs.jwt (section 8.2)
    expect(nonce).toMatchObject({ method: 'POST', url: URLS.nonce });
    expect(credential).toMatchObject({ method: 'POST', url: URLS.credential });
    expect(credential!.headers.authorization).toMatch(/^Bearer \S+$/);
    expect(credential!.headers['content-type']).toBe('application/json');
    const body = JSON.parse(credential!.body) as { proofs: { jwt: string[] } };
    expect(body).toEqual({
      credential_configuration_id: CONFIGURATION_IDS.roleAuthority,
      proofs: { jwt: [expect.any(String)] },
    });
    const proof = decodeJwsUnverified(body.proofs.jwt[0]!);
    expect(proof.header).toEqual({
      alg: 'ES256',
      typ: TYP.vciProof,
      jwk: { kty: 'EC', crv: 'P-256', x: holder.publicJwk.x, y: holder.publicJwk.y },
    });
    expect(proof.payload).toEqual({ aud: ISSUER_ID, iat: NOW, nonce: expect.any(String) });

    // the credential is the holder's, of the offered type and from the offering issuer
    expect(received.decoded).toEqual(decodeCredential(received.sdJwtVc));
    expect(received.decoded).toMatchObject({ issuer: ISSUER_ID, vct: VCT.roleAuthority });
    expect(received.decoded.cnfJwk).toMatchObject({ x: holder.publicJwk.x, y: holder.publicJwk.y });
    expect(received.decoded.disclosable).toContain('authority');
  });

  it('reads an offer carried in the address, and takes a nonce from the token response when there is no nonce endpoint', async () => {
    const issuer = await createFakeIssuer({
      txCode: false,
      nonceFrom: 'token',
      configurations: [CONFIGURATION_IDS.orgMember],
    });
    const view = await resolveOffer(issuer.byValue, { fetch: issuer.fetch });
    expect(issuer.requests).toHaveLength(2); // no offer to fetch: metadata of the issuer and of its server
    expect(view).toMatchObject({ configurationId: CONFIGURATION_IDS.orgMember, vct: VCT.orgMember });
    expect(view.txCode).toBeUndefined();
    expect(view.nonceEndpoint).toBeUndefined();

    const received = await redeemOffer(view, undefined, holder, { now: NOW, fetch: issuer.fetch });
    expect(issuer.requests.slice(2).map((r) => r.url)).toEqual([URLS.token, URLS.credential]);
    expect(parseQuery(issuer.requests[2]!.body)).not.toHaveProperty('tx_code');
    expect(received.decoded.vct).toBe(VCT.orgMember);
  });

  it('takes the first offered configuration in dc+sd-jwt format that the issuer supports', async () => {
    const issuer = await createFakeIssuer({
      configurations: ['not-listed-by-the-issuer', CONFIGURATION_IDS.orgMember, CONFIGURATION_IDS.roleAuthority],
    });
    const view = await resolveOffer(issuer.byValue, { fetch: issuer.fetch });
    expect(view.configurationId).toBe(CONFIGURATION_IDS.orgMember);

    const none = await createFakeIssuer({ configurations: ['not-listed-by-the-issuer'] });
    expect((await failureOf(resolveOffer(none.byValue, { fetch: none.fetch }))).code).toBe('PROTOCOL');
  });
});

describe('when the exchange goes wrong', () => {
  async function viewOf(issuer: FakeIssuer) {
    return resolveOffer(issuer.byReference, { fetch: issuer.fetch });
  }

  it('reports a wrong transaction code as an OAuth error', async () => {
    const issuer = await createFakeIssuer();
    const view = await viewOf(issuer);
    const error = await failureOf(redeemOffer(view, '000000', holder, { now: NOW, fetch: issuer.fetch }));
    expect(error.code).toBe('PROTOCOL');
    expect(error.message).toContain('invalid_grant');
    expect(issuer.requests.at(-1)!.url).toBe(URLS.token); // nothing was sent after the refusal
  });

  it('wants the transaction code before it sends anything', async () => {
    const issuer = await createFakeIssuer();
    const view = await viewOf(issuer);
    const sent = issuer.requests.length;
    const error = await failureOf(redeemOffer(view, undefined, holder, { now: NOW, fetch: issuer.fetch }));
    expect(error.code).toBe('INVALID_ARGUMENT');
    expect(issuer.requests).toHaveLength(sent);
  });

  const MISMATCHES: Array<[string, () => FakeIssuerOptions, string]> = [
    ['bound to another key', () => ({ bindTo: stranger.publicJwk }), 'another key'],
    ['of another type than offered', () => ({ issuedVct: VCT.orgMember }), 'type'],
    [
      'from another issuer than the one that offered it',
      () => ({ issuedIss: 'https://issuer.example/issuer/t/other' }),
      'issuer',
    ],
  ];

  it.each(MISMATCHES)('refuses a credential %s', async (_name, options, part) => {
    const issuer = await createFakeIssuer(options());
    const view = await viewOf(issuer);
    const error = await failureOf(redeemOffer(view, issuer.txCode, holder, { now: NOW, fetch: issuer.fetch }));
    expect(error.code).toBe('PROTOCOL');
    expect(error.message).toContain(part);
  });

  it('refuses metadata that names another issuer than the offer', async () => {
    const issuer = await createFakeIssuer({ metadataIssuer: 'https://issuer.example/issuer/t/other' });
    expect((await failureOf(viewOf(issuer))).code).toBe('PROTOCOL');
  });

  it('does not follow an offer address that is not https, except on the local machine', async () => {
    const issuer = await createFakeIssuer();
    const insecure = `openid-credential-offer://?${formEncode({ credential_offer_uri: 'http://issuer.example/offers/1' })}`;
    expect((await failureOf(resolveOffer(insecure, { fetch: issuer.fetch }))).code).toBe('MALFORMED');
    const credentials = `openid-credential-offer://?${formEncode({ credential_offer_uri: 'https://user@issuer.example/offers/1' })}`;
    expect((await failureOf(resolveOffer(credentials, { fetch: issuer.fetch }))).code).toBe('MALFORMED');
    expect(issuer.requests).toHaveLength(0);

    const local = `openid-credential-offer://?${formEncode({ credential_offer_uri: 'http://localhost:8080/offers/1' })}`;
    const reply = await failureOf(resolveOffer(local, { fetch: issuer.fetch }));
    expect(reply.code).toBe('NETWORK'); // the fake issuer has no such address: the request was made, and answered 404
    expect(issuer.requests.map((r) => r.url)).toEqual(['http://localhost:8080/offers/1']);
  });

  it('takes http addresses from an issuer on the local machine, and from no other', async () => {
    const local = await createFakeIssuer({ origin: 'http://localhost:8080', txCode: false });
    const view = await resolveOffer(local.byReference, { fetch: local.fetch });
    expect(view.credentialIssuer).toBe('http://localhost:8080/issuer/t/contractor-a');
    expect(view.tokenEndpoint).toBe(local.where.token);
    const received = await redeemOffer(view, undefined, holder, { now: NOW, fetch: local.fetch });
    expect(received.decoded.issuer).toBe(local.id);

    // a remote issuer cannot send the wallet to a plain-http address, on the local machine or elsewhere
    for (const credentialEndpoint of ['http://localhost:8080/credential', 'http://issuer.example/credential']) {
      const remote = await createFakeIssuer({ credentialEndpoint });
      const refused = await failureOf(resolveOffer(remote.byValue, { fetch: remote.fetch }));
      expect(refused.code).toBe('PROTOCOL');
      expect(remote.requests.map((r) => r.url)).toEqual([remote.where.issuerMetadata]); // refused as soon as it is read
    }
  });

  it('sends nothing to an address that is not https, whoever made the offer view', async () => {
    const issuer = await createFakeIssuer();
    const view = await viewOf(issuer);
    const sent = issuer.requests.length;
    const tampered = [
      { ...view, tokenEndpoint: 'http://issuer.example/token' },
      { ...view, credentialEndpoint: 'http://localhost:8080/credential' },
      { ...view, nonceEndpoint: 'ftp://issuer.example/nonce' },
      { ...view, credentialIssuer: 'http://issuer.example/issuer/t/contractor-a' },
    ];
    for (const offerView of tampered) {
      const error = await failureOf(redeemOffer(offerView, issuer.txCode, holder, { now: NOW, fetch: issuer.fetch }));
      expect(error.code).toBe('INVALID_ARGUMENT');
    }
    expect(issuer.requests).toHaveLength(sent);
  });

  it('tells what is not an offer, and what cannot be reached', async () => {
    const issuer = await createFakeIssuer();
    expect((await failureOf(resolveOffer('https://issuer.example/', { fetch: issuer.fetch }))).code).toBe(
      'UNSUPPORTED_FORMAT',
    );
    expect(
      (await failureOf(resolveOffer('openid-credential-offer://?credential_offer=%7B', { fetch: issuer.fetch }))).code,
    ).toBe('MALFORMED');
    expect((await failureOf(resolveOffer('openid-credential-offer://', { fetch: issuer.fetch }))).code).toBe(
      'MALFORMED',
    );

    const unreachable = await failureOf(
      resolveOffer(issuer.byReference, {
        fetch: () => Promise.reject(new TypeError('network down')),
      }),
    );
    expect(unreachable.code).toBe('NETWORK');
  });
});
