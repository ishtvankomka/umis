import { ALG, TYP, UMIS_METADATA_KEYS, VCT, asEcPublicJwk, wellKnownUrl } from '@umis/core';
import type { DisclosableClaim, EcPublicJwk } from '@umis/core';
import { CREDENTIAL_CONFIGURATION_IDS } from './offer.js';
import { assertUrl, invalid, isRecord, isText, own } from './profile.js';

// ---------------------------------------------------------------------------------------------------------------
// type metadata
// ---------------------------------------------------------------------------------------------------------------

/** SD-JWT VC type metadata document (draft-22 section 5) of one UMIS credential type. */
export interface TypeMetadataV1 {
  vct: string;
  name: string;
  description: string;
  display: Array<{ locale: string; name: string; description?: string }>;
  claims: Array<{ path: [DisclosableClaim]; display: Array<{ locale: string; label: string }>; sd: 'always' }>;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function claim(path: DisclosableClaim, english: string, ukrainian: string): TypeMetadataV1['claims'][number] {
  return {
    path: [path],
    display: [
      { locale: 'en-US', label: english },
      { locale: 'uk-UA', label: ukrainian },
    ],
    sd: 'always',
  };
}

/**
 * The type metadata of the two credential types, in `en-US` and `uk-UA`. The same documents are published as
 * `type-metadata/org-member-v1.json` and `type-metadata/role-authority-v1.json`, for the issuer to serve at the `vct`
 * address.
 */
export const TYPE_METADATA: Readonly<{ orgMember: TypeMetadataV1; roleAuthority: TypeMetadataV1 }> = deepFreeze({
  orgMember: {
    vct: VCT.orgMember,
    name: 'Organisation member',
    description: 'Membership of a person in an organisation, with an optional unit, role and display name.',
    display: [
      {
        locale: 'en-US',
        name: 'Organisation member',
        description: 'Confirms that the holder is a member of an organisation.',
      },
      {
        locale: 'uk-UA',
        name: 'Член організації',
        description: 'Підтверджує, що власник є членом організації.',
      },
    ],
    claims: [
      claim('org', 'Organisation', 'Організація'),
      claim('org_unit', 'Unit', 'Підрозділ'),
      claim('role', 'Role', 'Роль'),
      claim('display', 'Name', 'Ім’я'),
    ],
  },
  roleAuthority: {
    vct: VCT.roleAuthority,
    name: 'Role and authority',
    description:
      'A role in an organisation with powers that carry numeric limits, and the delegation chain that they come from.',
    display: [
      {
        locale: 'en-US',
        name: 'Role and authority',
        description:
          'Confirms the role of the holder in an organisation and the powers, with limits, that come with it.',
      },
      {
        locale: 'uk-UA',
        name: 'Роль і повноваження',
        description: 'Підтверджує роль власника в організації та повноваження з обмеженнями, які до неї належать.',
      },
    ],
    claims: [
      claim('org', 'Organisation', 'Організація'),
      claim('org_unit', 'Unit', 'Підрозділ'),
      claim('role', 'Role', 'Роль'),
      claim('authority', 'Authority', 'Повноваження'),
      claim('delegation', 'Delegation', 'Делегування'),
      claim('display', 'Name', 'Ім’я'),
    ],
  },
});

// ---------------------------------------------------------------------------------------------------------------
// OpenID4VCI credential issuer metadata
// ---------------------------------------------------------------------------------------------------------------

export interface CredentialConfiguration {
  format: 'dc+sd-jwt';
  vct: string;
  cryptographic_binding_methods_supported: ['jwk'];
  credential_signing_alg_values_supported: ['ES256'];
  proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } };
  credential_metadata?: {
    display?: Array<{ name: string; locale?: string }>;
    claims?: Array<{ path: [DisclosableClaim]; display?: Array<{ name: string; locale?: string }> }>;
  };
}

export interface CredentialIssuerMetadata {
  credential_issuer: string;
  authorization_servers?: string[];
  credential_endpoint: string;
  nonce_endpoint: string;
  display?: Array<{ name: string; locale?: string }>;
  credential_configurations_supported: Record<string, CredentialConfiguration>;
}

type NamedLocale = { name: string; locale?: string };

/** A list of display names, one per language (OpenID4VCI 1.0 section 12.2.4); undefined when it is absent or empty. */
function displayNames(display: unknown, what: string): NamedLocale[] | undefined {
  if (display === undefined) return undefined;
  if (!Array.isArray(display)) throw invalid(`${what} must be a list`);
  const locales = new Set<string | undefined>();
  const names = (display as unknown[]).map((entry, index): NamedLocale => {
    if (!isRecord(entry) || !isText(own(entry, 'name')))
      throw invalid(`${what}[${index}].name must be a non-empty string`);
    const locale = own(entry, 'locale');
    if (locale !== undefined && !isText(locale)) throw invalid(`${what}[${index}].locale must be a non-empty string`);
    if (locales.has(locale)) throw invalid(`${what} has more than one entry for the language ${String(locale)}`);
    locales.add(locale);
    const name = own(entry, 'name') as string;
    return locale === undefined ? { name } : { name, locale };
  });
  return names.length === 0 ? undefined : names;
}

/** A published list of keys: public P-256 keys only, a private member anywhere is an error. */
function publishedKeys(keys: unknown, what: string): EcPublicJwk[] {
  if (!Array.isArray(keys)) throw invalid(`${what} must be a list of public keys`);
  return (keys as unknown[]).map((key, index) => {
    if (isRecord(key) && Object.hasOwn(key, 'd')) throw invalid(`${what}[${index}] has a private member`);
    return asEcPublicJwk(key);
  });
}

function configuration(vct: string, type: TypeMetadataV1): CredentialConfiguration {
  return {
    format: TYP.sdJwtVc,
    vct,
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: [ALG],
    proof_types_supported: { jwt: { proof_signing_alg_values_supported: [ALG] } },
    credential_metadata: {
      display: type.display.map(({ locale, name }) => ({ name, locale })),
      claims: type.claims.map(({ path, display }) => ({
        path: [path[0]],
        display: display.map(({ locale, label }) => ({ name: label, locale })),
      })),
    },
  };
}

/**
 * The credential issuer metadata (OpenID4VCI 1.0 section 12.2.4 and appendix A.3) that is served at
 * `/.well-known/openid-credential-issuer`: the endpoints, and both credential configurations, `dc+sd-jwt` with the `vct`
 * of the type, ES256, holder keys as `jwk` and `jwt` key proofs signed with ES256. The configurations carry the display
 * names and claim labels of the type metadata. `issuer` is written as given, after it is checked like any issuer
 * identifier; the endpoints must be `https` URLs (`http` for loopback hosts), and each authorization server an issuer
 * identifier. Empty optional lists are left out.
 */
export function credentialIssuerMetadata(i: {
  issuer: string;
  credentialEndpoint: string;
  nonceEndpoint: string;
  authorizationServers?: string[];
  display?: Array<{ name: string; locale?: string }>;
}): CredentialIssuerMetadata {
  const request: unknown = i;
  if (!isRecord(request)) throw invalid('the metadata input must be an object');
  wellKnownUrl(i.issuer, 'openid-credential-issuer');
  assertUrl(i.credentialEndpoint, 'credentialEndpoint');
  assertUrl(i.nonceEndpoint, 'nonceEndpoint');
  const given: unknown = i.authorizationServers;
  if (given !== undefined && !Array.isArray(given)) throw invalid('authorizationServers must be a list');
  const servers = (given as string[] | undefined) ?? [];
  for (const server of servers) wellKnownUrl(server, 'oauth-authorization-server');
  const display = displayNames(i.display, 'display');

  return {
    credential_issuer: i.issuer,
    ...(servers.length > 0 && { authorization_servers: [...servers] }),
    credential_endpoint: i.credentialEndpoint,
    nonce_endpoint: i.nonceEndpoint,
    ...(display !== undefined && { display }),
    credential_configurations_supported: {
      [CREDENTIAL_CONFIGURATION_IDS.orgMember]: configuration(VCT.orgMember, TYPE_METADATA.orgMember),
      [CREDENTIAL_CONFIGURATION_IDS.roleAuthority]: configuration(VCT.roleAuthority, TYPE_METADATA.roleAuthority),
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// SD-JWT VC issuer metadata
// ---------------------------------------------------------------------------------------------------------------

export interface JwtVcIssuerMetadata {
  issuer: string;
  jwks: { keys: EcPublicJwk[] };
  umis_status_lists: string[];
  umis_verifier_jwks?: { keys: EcPublicJwk[] };
  umis_registry_uri?: string;
  display?: Array<{ name: string; locale?: string }>;
}

/**
 * The issuer metadata of SD-JWT VC (draft-22 section 4) that is served at `/.well-known/jwt-vc-issuer`, with the UMIS
 * members for the status lists, the verifier keys and the registry. The keys are always inline (`jwks`, never
 * `jwks_uri`) and always public: a key with a private member is INVALID_ARGUMENT, so is a list without a key. `issuer`
 * is written as given, after it is checked like any issuer identifier; every address must be an `https` URL (`http` for
 * loopback hosts). Empty optional lists are left out.
 */
export function jwtVcIssuerMetadata(i: {
  issuer: string;
  keys: EcPublicJwk[];
  statusLists: string[];
  verifierKeys?: EcPublicJwk[];
  registryUri?: string;
  display?: Array<{ name: string; locale?: string }>;
}): JwtVcIssuerMetadata {
  const request: unknown = i;
  if (!isRecord(request)) throw invalid('the metadata input must be an object');
  wellKnownUrl(i.issuer, 'jwt-vc-issuer');
  const keys = publishedKeys(i.keys, 'keys');
  if (keys.length === 0) throw invalid('keys must hold at least one public key');
  const lists: unknown = i.statusLists;
  if (!Array.isArray(lists)) throw invalid('statusLists must be a list of URLs');
  (lists as unknown[]).forEach((uri, index) => assertUrl(uri, `statusLists[${index}]`));
  const verifierKeys = i.verifierKeys === undefined ? [] : publishedKeys(i.verifierKeys, 'verifierKeys');
  if (i.registryUri !== undefined) assertUrl(i.registryUri, 'registryUri');
  const display = displayNames(i.display, 'display');

  const metadata: JwtVcIssuerMetadata = {
    issuer: i.issuer,
    jwks: { keys },
    [UMIS_METADATA_KEYS.statusLists]: [...(lists as string[])],
  };
  if (verifierKeys.length > 0) metadata[UMIS_METADATA_KEYS.verifierJwks] = { keys: verifierKeys };
  if (i.registryUri !== undefined) metadata[UMIS_METADATA_KEYS.registryUri] = i.registryUri;
  if (display !== undefined) metadata.display = display;
  return metadata;
}
