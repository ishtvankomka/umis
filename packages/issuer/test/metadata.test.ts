import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { TypeMetadataFormatSchema } from '@sd-jwt/sd-jwt-vc';
import { DISCLOSABLE_CLAIMS, UMIS_METADATA_KEYS, VCT, generateSigner, parseQuery, splitUri } from '@umis/core';
import {
  CREDENTIAL_CONFIGURATION_IDS,
  TYPE_METADATA,
  createCredentialOffer,
  credentialIssuerMetadata,
  credentialOfferUri,
  credentialOfferUriByReference,
  jwtVcIssuerMetadata,
} from '../src/index.js';
import { codeOf } from './fixtures.js';

const ISSUER = 'https://issuer.example/contractor-a';
const DISPLAY = [
  { name: 'Contractor A', locale: 'en-US' },
  { name: 'Підрядник А', locale: 'uk-UA' },
];

const readJson = (relative: string): unknown => JSON.parse(readFileSync(new URL(relative, import.meta.url), 'utf8'));

describe('jwtVcIssuerMetadata', () => {
  it('publishes the public keys inline together with the status lists, and nothing private', async () => {
    const [signing, rotated, verifier] = await Promise.all([generateSigner(), generateSigner(), generateSigner()]);
    const metadata = jwtVcIssuerMetadata({
      issuer: ISSUER,
      keys: [signing.publicJwk, rotated.publicJwk],
      statusLists: ['https://issuer.example/status/contractor-a/1', 'https://issuer.example/status/contractor-a/2'],
      verifierKeys: [verifier.publicJwk],
      registryUri: 'https://issuer.example/registry/contractor-a',
      display: DISPLAY,
    });

    expect(metadata.issuer).toBe(ISSUER);
    expect(metadata.jwks).toEqual({ keys: [signing.publicJwk, rotated.publicJwk] });
    expect(metadata.umis_status_lists).toEqual([
      'https://issuer.example/status/contractor-a/1',
      'https://issuer.example/status/contractor-a/2',
    ]);
    expect(metadata.umis_verifier_jwks).toEqual({ keys: [verifier.publicJwk] });
    expect(metadata.umis_registry_uri).toBe('https://issuer.example/registry/contractor-a');
    expect(metadata.display).toEqual(DISPLAY);
    expect(Object.keys(metadata).sort()).toEqual(
      [
        'display',
        'issuer',
        'jwks',
        UMIS_METADATA_KEYS.registryUri,
        UMIS_METADATA_KEYS.statusLists,
        UMIS_METADATA_KEYS.verifierJwks,
      ].sort(),
    );
    // exactly one way of publishing the keys, and no private member anywhere in the document
    expect(Object.hasOwn(metadata, 'jwks_uri')).toBe(false);
    const json = JSON.stringify(metadata);
    expect(json).not.toMatch(/"d":/);
    expect(JSON.parse(json)).toEqual(metadata);

    // optional members are left out when absent or empty
    const minimal = jwtVcIssuerMetadata({
      issuer: ISSUER,
      keys: [signing.publicJwk],
      statusLists: [],
      verifierKeys: [],
      display: [],
    });
    expect(Object.keys(minimal).sort()).toEqual(['issuer', 'jwks', UMIS_METADATA_KEYS.statusLists].sort());
  });

  it('refuses private keys wherever a key is published (INVALID_ARGUMENT)', async () => {
    const key = (await generateSigner()).publicJwk;
    const withPrivatePart = { ...key, d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
    const base = { issuer: ISSUER, keys: [key], statusLists: [] as string[] };
    expect(await codeOf(() => jwtVcIssuerMetadata({ ...base, keys: [key, withPrivatePart] }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => jwtVcIssuerMetadata({ ...base, verifierKeys: [withPrivatePart] }))).toBe(
      'INVALID_ARGUMENT',
    );
    // not P-256 keys, or no key at all
    expect(await codeOf(() => jwtVcIssuerMetadata({ ...base, keys: [{ ...key, crv: 'P-384' } as never] }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await codeOf(() => jwtVcIssuerMetadata({ ...base, keys: [] }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => jwtVcIssuerMetadata({ ...base, keys: undefined as never }))).toBe('INVALID_ARGUMENT');
  });

  it('writes the issuer as given and refuses an identifier that has no well-known location', async () => {
    const key = (await generateSigner()).publicJwk;
    const make = (issuer: string, over: Record<string, unknown> = {}) =>
      jwtVcIssuerMetadata({ issuer, keys: [key], statusLists: [], ...over });
    // byte for byte, a terminating slash included
    for (const issuer of [ISSUER, `${ISSUER}/`, 'https://Issuer.Example:8443/t/a', 'http://localhost:3000/issuer']) {
      expect(make(issuer).issuer, issuer).toBe(issuer);
    }
    for (const issuer of [
      '',
      'http://issuer.example/a',
      'https://issuer.example/a?x=1',
      'https://issuer.example/a#top',
      'https://user@issuer.example/a',
      'issuer.example/a',
    ]) {
      expect(await codeOf(() => make(issuer)), issuer).toBe('INVALID_ARGUMENT');
    }
    for (const statusLists of [['ftp://issuer.example/list'], ['https://issuer.example/list#1'], [42 as never]]) {
      expect(await codeOf(() => make(ISSUER, { statusLists }))).toBe('INVALID_ARGUMENT');
    }
    expect(await codeOf(() => make(ISSUER, { registryUri: 'http://issuer.example/registry' }))).toBe(
      'INVALID_ARGUMENT',
    );
    // one entry per language
    expect(await codeOf(() => make(ISSUER, { display: [DISPLAY[0], DISPLAY[0]] }))).toBe('INVALID_ARGUMENT');
  });
});

describe('credentialIssuerMetadata', () => {
  const input = {
    issuer: ISSUER,
    credentialEndpoint: 'https://issuer.example/contractor-a/credential',
    nonceEndpoint: 'https://issuer.example/contractor-a/nonce',
  };

  it('lists both credential configurations as dc+sd-jwt with their vct, ES256 and jwk keys', () => {
    const metadata = credentialIssuerMetadata(input);
    expect(metadata.credential_issuer).toBe(ISSUER);
    expect(metadata.credential_endpoint).toBe(input.credentialEndpoint);
    expect(metadata.nonce_endpoint).toBe(input.nonceEndpoint);
    expect(Object.keys(metadata.credential_configurations_supported).sort()).toEqual(
      [CREDENTIAL_CONFIGURATION_IDS.orgMember, CREDENTIAL_CONFIGURATION_IDS.roleAuthority].sort(),
    );

    const supported = metadata.credential_configurations_supported;
    for (const [id, vct, type] of [
      [CREDENTIAL_CONFIGURATION_IDS.orgMember, VCT.orgMember, TYPE_METADATA.orgMember],
      [CREDENTIAL_CONFIGURATION_IDS.roleAuthority, VCT.roleAuthority, TYPE_METADATA.roleAuthority],
    ] as const) {
      const configuration = supported[id]!;
      expect(configuration.format, id).toBe('dc+sd-jwt');
      expect(configuration.vct, id).toBe(vct);
      expect(configuration.cryptographic_binding_methods_supported, id).toEqual(['jwk']);
      expect(configuration.credential_signing_alg_values_supported, id).toEqual(['ES256']);
      expect(configuration.proof_types_supported, id).toEqual({
        jwt: { proof_signing_alg_values_supported: ['ES256'] },
      });
      // what the wallet shows: the names of the type and the labels of its claims, in both languages
      expect(configuration.credential_metadata?.display, id).toEqual(
        type.display.map(({ locale, name }) => ({ name, locale })),
      );
      expect(
        configuration.credential_metadata?.claims?.map((c) => c.path[0]),
        id,
      ).toEqual(type.claims.map((c) => c.path[0]));
      expect(configuration.credential_metadata?.claims?.[0]?.display, id).toEqual([
        { name: 'Organisation', locale: 'en-US' },
        { name: 'Організація', locale: 'uk-UA' },
      ]);
    }
    expect(Object.hasOwn(metadata, 'authorization_servers')).toBe(false);
    expect(JSON.parse(JSON.stringify(metadata))).toEqual(metadata);
  });

  it('adds the authorization servers and the display names when given, and checks every address', () => {
    const metadata = credentialIssuerMetadata({
      ...input,
      authorizationServers: ['https://auth.example/realms/contractor-a'],
      display: DISPLAY,
    });
    expect(metadata.authorization_servers).toEqual(['https://auth.example/realms/contractor-a']);
    expect(metadata.display).toEqual(DISPLAY);
    expect(
      Object.hasOwn(credentialIssuerMetadata({ ...input, authorizationServers: [], display: [] }), 'display'),
    ).toBe(false);

    for (const over of [
      { issuer: 'http://issuer.example/a' },
      { credentialEndpoint: 'http://issuer.example/credential' },
      { nonceEndpoint: 'ftp://issuer.example/nonce' },
      { nonceEndpoint: 'https://issuer.example/nonce#top' },
      { authorizationServers: ['http://auth.example'] },
      { authorizationServers: 'https://auth.example' as never },
    ]) {
      expect(() => credentialIssuerMetadata({ ...input, ...over }), JSON.stringify(over)).toThrowError(
        expect.objectContaining({ code: 'INVALID_ARGUMENT' }),
      );
    }
  });

  it('hands out copies, so that editing one document cannot change the next', () => {
    const first = credentialIssuerMetadata(input);
    first.credential_configurations_supported[CREDENTIAL_CONFIGURATION_IDS.orgMember]!.vct = 'https://example.org/x';
    first.credential_configurations_supported[CREDENTIAL_CONFIGURATION_IDS.roleAuthority]!.credential_metadata!.claims =
      [];
    const second = credentialIssuerMetadata(input);
    expect(second.credential_configurations_supported[CREDENTIAL_CONFIGURATION_IDS.orgMember]!.vct).toBe(VCT.orgMember);
    expect(
      second.credential_configurations_supported[CREDENTIAL_CONFIGURATION_IDS.roleAuthority]!.credential_metadata!
        .claims,
    ).toHaveLength(6);
  });
});

describe('credential offers', () => {
  const offerInput = {
    credentialIssuer: ISSUER,
    configurationIds: [CREDENTIAL_CONFIGURATION_IDS.roleAuthority],
    preAuthorizedCode: 'oaKazRN8I0IbtZ0C7JuMn5',
    txCode: { length: 6, inputMode: 'numeric' as const, description: 'The code that the office sent to you by e-mail' },
  };

  it('builds the offer of the pre-authorized code flow with a transaction code', () => {
    expect(createCredentialOffer(offerInput)).toEqual({
      credential_issuer: ISSUER,
      credential_configuration_ids: ['umis-role-authority-v1'],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': 'oaKazRN8I0IbtZ0C7JuMn5',
          tx_code: { length: 6, input_mode: 'numeric', description: 'The code that the office sent to you by e-mail' },
        },
      },
    });
    const bare = createCredentialOffer({ ...offerInput, txCode: undefined });
    expect(bare.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).toEqual({
      'pre-authorized_code': 'oaKazRN8I0IbtZ0C7JuMn5',
    });
    const minimal = createCredentialOffer({ ...offerInput, txCode: { length: 4 } });
    expect(minimal.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].tx_code).toEqual({ length: 4 });
  });

  it('puts the offer into a link by value that reads back to the same JSON', () => {
    const offer = createCredentialOffer({
      ...offerInput,
      configurationIds: [CREDENTIAL_CONFIGURATION_IDS.orgMember, CREDENTIAL_CONFIGURATION_IDS.roleAuthority],
    });
    const uri = credentialOfferUri(offer);
    expect(uri.startsWith('openid-credential-offer://?credential_offer=')).toBe(true);

    const { scheme, query } = splitUri(uri);
    expect(scheme).toBe('openid-credential-offer');
    const fields = parseQuery(query);
    expect(Object.keys(fields)).toEqual(['credential_offer']);
    expect(JSON.parse(fields.credential_offer!)).toEqual(offer);

    // percent-encoding that every URL decoder reads the same way: no "+" for a space
    expect(uri).toBe(`openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`);
    expect(JSON.parse(decodeURIComponent(query.slice('credential_offer='.length)))).toEqual(offer);
  });

  it('writes only the members of the specification, whatever else the offer object holds', () => {
    const offer = createCredentialOffer(offerInput);
    const extended = { ...offer, secret: 'x', grants: { ...offer.grants, authorization_code: {} } };
    const fields = parseQuery(splitUri(credentialOfferUri(extended as never)).query);
    expect(JSON.parse(fields.credential_offer!)).toEqual(offer);
  });

  it('puts the address of the offer into a link by reference', () => {
    const offerUrl = 'https://issuer.example/contractor-a/offers/9f2c1d?lang=uk';
    const uri = credentialOfferUriByReference(offerUrl);
    expect(uri.startsWith('openid-credential-offer://?credential_offer_uri=')).toBe(true);
    const fields = parseQuery(splitUri(uri).query);
    expect(Object.keys(fields)).toEqual(['credential_offer_uri']);
    expect(fields.credential_offer_uri).toBe(offerUrl);
    expect(uri).toBe(`openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUrl)}`);
  });

  it('refuses offers and links that a wallet could not use (INVALID_ARGUMENT)', async () => {
    const make = (over: Record<string, unknown>) => createCredentialOffer({ ...offerInput, ...over } as never);
    const bad: Array<[string, Record<string, unknown>]> = [
      ['an issuer on http', { credentialIssuer: 'http://issuer.example/a' }],
      ['an issuer with a query', { credentialIssuer: 'https://issuer.example/a?x=1' }],
      ['no configurations', { configurationIds: [] }],
      ['a configuration listed twice', { configurationIds: ['a', 'a'] }],
      ['an empty configuration id', { configurationIds: [''] }],
      ['no code', { preAuthorizedCode: '' }],
      ['a code with a space', { preAuthorizedCode: 'abc def' }],
      ['a code with a line break', { preAuthorizedCode: 'abc\ndef' }],
      ['a transaction code of length 0', { txCode: { length: 0 } }],
      ['a transaction code of length 2.5', { txCode: { length: 2.5 } }],
      ['an unknown input mode', { txCode: { length: 4, inputMode: 'alphanumeric' } }],
      ['a description of 301 characters', { txCode: { length: 4, description: 'x'.repeat(301) } }],
      ['an empty description', { txCode: { length: 4, description: '' } }],
    ];
    for (const [label, over] of bad) expect(await codeOf(() => make(over)), label).toBe('INVALID_ARGUMENT');
    expect(make({ txCode: { length: 4, description: 'x'.repeat(300) } })).toBeTruthy();

    for (const offerUrl of [
      'http://issuer.example/offer',
      'ftp://issuer.example/offer',
      '',
      'https://issuer.example/a b',
    ]) {
      expect(await codeOf(() => credentialOfferUriByReference(offerUrl)), offerUrl).toBe('INVALID_ARGUMENT');
    }
    expect(await codeOf(() => credentialOfferUri({ credential_issuer: ISSUER } as never))).toBe('INVALID_ARGUMENT');
  });
});

describe('type metadata', () => {
  const documents = [
    ['org-member-v1.json', TYPE_METADATA.orgMember, VCT.orgMember],
    ['role-authority-v1.json', TYPE_METADATA.roleAuthority, VCT.roleAuthority],
  ] as const;

  it('passes the type metadata schema of the SD-JWT VC library and describes the claims of each type', () => {
    for (const [file, metadata, vct] of documents) {
      const parsed = TypeMetadataFormatSchema.safeParse(metadata);
      expect(parsed.success, file).toBe(true);
      expect(parsed.data, file).toEqual(metadata);

      expect(metadata.vct, file).toBe(vct);
      expect(
        metadata.display.map((d) => d.locale),
        file,
      ).toEqual(['en-US', 'uk-UA']);
      for (const display of metadata.display) expect(display.name && display.description, file).toBeTruthy();
      for (const claim of metadata.claims) {
        expect((DISCLOSABLE_CLAIMS as readonly string[]).includes(claim.path[0]), file).toBe(true);
        expect(claim.sd, file).toBe('always');
        expect(
          claim.display.map((d) => d.locale),
          file,
        ).toEqual(['en-US', 'uk-UA']);
        expect(
          claim.display.every((d) => d.label !== ''),
          file,
        ).toBe(true);
      }
    }
    expect(TYPE_METADATA.orgMember.claims.map((c) => c.path[0])).toEqual(['org', 'org_unit', 'role', 'display']);
    expect(TYPE_METADATA.roleAuthority.claims.map((c) => c.path[0])).toEqual([...DISCLOSABLE_CLAIMS]);
  });

  it('equals the JSON files that the package publishes through ./type-metadata/*.json', () => {
    for (const [file, metadata] of documents) {
      expect(readJson(`../type-metadata/${file}`), file).toEqual(metadata);
    }
    const manifest = readJson('../package.json') as { exports: Record<string, unknown>; files: string[] };
    expect(manifest.exports['./type-metadata/*.json']).toBe('./type-metadata/*.json');
    expect(manifest.files).toContain('type-metadata');
  });

  it('cannot be edited by the code that imports it', () => {
    expect(Object.isFrozen(TYPE_METADATA)).toBe(true);
    expect(Object.isFrozen(TYPE_METADATA.orgMember)).toBe(true);
    expect(Object.isFrozen(TYPE_METADATA.orgMember.claims[0])).toBe(true);
    expect(Object.isFrozen(TYPE_METADATA.roleAuthority.display[1])).toBe(true);
  });
});
