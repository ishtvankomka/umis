import {
  TYP,
  UmisError,
  VCT,
  formEncode,
  generateSigner,
  issueCredential,
  parseQuery,
  randomId,
  verifyJws,
} from '@umis/core';
import type { AuthorityItem, CredentialOffer, EcPublicJwk, FetchLike, Signer, UmisClaimSet } from '@umis/core';

/** 2026-11-04T00:00:00Z: the moment the credentials of the tests were issued. */
export const T0 = 1_793_750_400;
export const DAY = 86_400;

const ORIGIN = 'https://issuer.example';
const PATH = '/issuer/t/contractor-a';
const PRE_AUTHORIZED_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

/** The addresses of an issuer that is served from `origin`. */
export function addressesOf(origin: string) {
  return {
    id: `${origin}${PATH}`,
    offer: `${origin}${PATH}/offers/ref-0001`,
    issuerMetadata: `${origin}/.well-known/openid-credential-issuer${PATH}`,
    serverMetadata: `${origin}/.well-known/oauth-authorization-server${PATH}`,
    token: `${origin}${PATH}/token`,
    nonce: `${origin}${PATH}/nonce`,
    credential: `${origin}${PATH}/credential`,
    statusList: `${origin}/status/contractor-a/1`,
  } as const;
}

const { id: ISSUER_ID_DEFAULT, offer: OFFER_URL_DEFAULT, ...URLS_DEFAULT } = addressesOf(ORIGIN);
export const ISSUER_ID: string = ISSUER_ID_DEFAULT;
export const OFFER_URL: string = OFFER_URL_DEFAULT;
export const URLS: Readonly<Record<keyof typeof URLS_DEFAULT, string>> = URLS_DEFAULT;

export const CONFIGURATION_IDS = { orgMember: 'umis-org-member-v1', roleAuthority: 'umis-role-authority-v1' } as const;
const CONFIGURATION_VCT: Readonly<Record<string, string>> = {
  [CONFIGURATION_IDS.orgMember]: VCT.orgMember,
  [CONFIGURATION_IDS.roleAuthority]: VCT.roleAuthority,
};

export const OLEH_AUTHORITY: AuthorityItem[] = [
  {
    action: 'receive_materials',
    resource: 'rebar',
    limit: { amount: 10, unit: 't', per: 'shift' },
    object: 'bridge-01',
  },
];

/** Claims of Oleh, crew lead of contractor A: a role with a power of authority and the root of a delegation. */
export const OLEH_CLAIMS: Partial<UmisClaimSet> = {
  org: { id: 'contractor-a', name: 'Підрядник А' },
  org_unit: { id: 'bridge-crew', name: 'Бригада будівництва мосту' },
  role: { code: 'crew_lead', name: 'Керівник бригади' },
  authority: OLEH_AUTHORITY,
  delegation: { depth: 0, max_depth: 1 },
  display: { name: 'Олег' },
};

/** Claims of a plain member of an organisation. */
export const MEMBER_CLAIMS: Partial<UmisClaimSet> = {
  org: { id: 'contractor-a', name: 'Підрядник А' },
  role: { code: 'engineer', name: 'Інженер' },
  display: { name: 'Марія' },
};

/** The error a call fails with; the test fails if the call succeeds or fails with anything but a UmisError. */
export async function failureOf(call: Promise<unknown>): Promise<UmisError> {
  try {
    await call;
  } catch (error) {
    if (error instanceof UmisError) return error;
    throw error;
  }
  throw new Error('expected the call to fail');
}

export interface IssueSpec {
  /** The holder key the credential is bound to. */
  holder: EcPublicJwk;
  vct?: string;
  jti?: string;
  iss?: string;
  claims?: Partial<UmisClaimSet>;
}

/** One request as the fake issuer saw it. Header names are in lower case. */
export interface Seen {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
}

export interface FakeIssuerOptions {
  /** Where the issuer is served from. Default: `https://issuer.example`. */
  origin?: string;
  /** The `credential_endpoint` of the issuer metadata when it is not an address of the issuer. */
  credentialEndpoint?: string;
  /** Whether the offer asks for a transaction code. Default: yes. */
  txCode?: boolean;
  /** The configurations the offer lists, in order. */
  configurations?: string[];
  /** Where a nonce comes from. Default: the nonce endpoint; `token` leaves it in the token response. */
  nonceFrom?: 'endpoint' | 'token';
  /** The `credential_issuer` of the issuer metadata when it is not the issuer's own identifier. */
  metadataIssuer?: string;
  /** Issue the credential for this key instead of the key of the proof. */
  bindTo?: EcPublicJwk;
  /** The `iss` and the `vct` of the credential when they are not the offered ones. */
  issuedIss?: string;
  issuedVct?: string;
}

export interface FakeIssuer {
  id: string;
  /** The addresses the issuer answers at. */
  where: ReturnType<typeof addressesOf>;
  /** The issuer's own signing key. */
  signer: Signer;
  preAuthorizedCode: string;
  txCode: string | undefined;
  offer: CredentialOffer;
  /** `openid-credential-offer://?credential_offer=…` */
  byValue: string;
  /** `openid-credential-offer://?credential_offer_uri=…`, which names `where.offer`. */
  byReference: string;
  fetch: FetchLike;
  requests: Seen[];
  /** A credential as this issuer signs it. */
  issue(spec: IssueSpec): Promise<string>;
}

interface Reply {
  status: number;
  body: unknown;
}

const answer = (status: number, body: unknown): Reply => ({ status, body });
const failure = (error: string, status = 400): Reply => answer(status, { error });

/** An OpenID4VCI 1.0 issuer with a pre-authorized-code grant, built from the core package alone. */
export async function createFakeIssuer(o: FakeIssuerOptions = {}): Promise<FakeIssuer> {
  const where = addressesOf(o.origin ?? ORIGIN);
  const id = where.id;
  const signer = await generateSigner();
  const preAuthorizedCode = randomId(16);
  const txCode = o.txCode === false ? undefined : '493021';
  const nonceFrom = o.nonceFrom ?? 'endpoint';
  const configurations = o.configurations ?? [CONFIGURATION_IDS.roleAuthority];
  const accessTokens = new Set<string>();
  const nonces = new Set<string>();
  const requests: Seen[] = [];

  const offer: CredentialOffer = {
    credential_issuer: id,
    credential_configuration_ids: configurations,
    grants: {
      [PRE_AUTHORIZED_GRANT]: {
        'pre-authorized_code': preAuthorizedCode,
        ...(txCode === undefined
          ? {}
          : { tx_code: { length: 6, input_mode: 'numeric' as const, description: 'The code was sent by e-mail' } }),
      },
    },
  };

  function issue(spec: IssueSpec): Promise<string> {
    const vct = spec.vct ?? VCT.roleAuthority;
    const jti = spec.jti ?? `cred-${randomId(8)}`;
    return issueCredential({
      signer,
      payload: {
        iss: spec.iss ?? id,
        sub: `p_${jti}`,
        jti,
        iat: T0,
        exp: T0 + 90 * DAY,
        vct,
        cnf: { jwk: spec.holder },
        status: { status_list: { idx: 1, uri: where.statusList } },
      },
      claims: spec.claims ?? (vct === VCT.roleAuthority ? OLEH_CLAIMS : MEMBER_CLAIMS),
    });
  }

  const display = (names: Array<[string, string]>) => names.map(([name, locale]) => ({ name, locale }));
  const configuration = (vct: string, names: Array<[string, string]>) => ({
    format: 'dc+sd-jwt',
    vct,
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: ['ES256'],
    proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
    credential_metadata: { display: display(names) },
  });

  const issuerMetadata = {
    credential_issuer: o.metadataIssuer ?? id,
    credential_endpoint: o.credentialEndpoint ?? where.credential,
    ...(nonceFrom === 'endpoint' ? { nonce_endpoint: where.nonce } : {}),
    display: display([['Підрядник А', 'uk-UA']]),
    credential_configurations_supported: {
      [CONFIGURATION_IDS.orgMember]: configuration(VCT.orgMember, [
        ['Член організації', 'uk-UA'],
        ['Organisation member', 'en-US'],
      ]),
      [CONFIGURATION_IDS.roleAuthority]: configuration(VCT.roleAuthority, [
        ['Роль і повноваження', 'uk-UA'],
        ['Role and authority', 'en-US'],
      ]),
    },
  };

  const serverMetadata = {
    issuer: id,
    token_endpoint: where.token,
    grant_types_supported: [PRE_AUTHORIZED_GRANT],
    'pre-authorized_grant_anonymous_access_supported': true,
  };

  function token(request: Seen): Reply {
    if (!(request.headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded')) {
      return failure('invalid_request');
    }
    const form = parseQuery(request.body);
    if (form.grant_type !== PRE_AUTHORIZED_GRANT) return failure('unsupported_grant_type');
    if (form['pre-authorized_code'] !== preAuthorizedCode) return failure('invalid_grant');
    if (txCode !== undefined && form.tx_code !== txCode) return failure('invalid_grant');
    const accessToken = randomId(24);
    accessTokens.add(accessToken);
    const issued: Record<string, unknown> = { access_token: accessToken, token_type: 'Bearer', expires_in: 300 };
    if (nonceFrom === 'token') {
      const nonce = randomId(16);
      nonces.add(nonce);
      issued.c_nonce = nonce;
    }
    return answer(200, issued);
  }

  function nonce(): Reply {
    const issued = randomId(16);
    nonces.add(issued);
    return answer(200, { c_nonce: issued });
  }

  async function credential(request: Seen): Promise<Reply> {
    const bearer = /^Bearer (\S+)$/.exec(request.headers.authorization ?? '');
    if (bearer === null || !accessTokens.has(bearer[1]!)) return failure('invalid_token', 401);

    let body: { credential_configuration_id?: unknown; proofs?: { jwt?: unknown } };
    try {
      body = JSON.parse(request.body);
    } catch {
      return failure('invalid_credential_request');
    }
    const vct =
      typeof body.credential_configuration_id === 'string'
        ? CONFIGURATION_VCT[body.credential_configuration_id]
        : undefined;
    if (vct === undefined) return failure('unknown_credential_configuration');
    const proofs = body.proofs?.jwt;
    if (!Array.isArray(proofs) || proofs.length !== 1 || typeof proofs[0] !== 'string') {
      return failure('invalid_credential_request');
    }

    let proof;
    try {
      proof = await verifyJws<{ aud?: unknown; iat?: unknown; nonce?: unknown }>(proofs[0], {
        typ: TYP.vciProof,
        key: (header) => header.jwk,
      });
    } catch {
      return failure('invalid_proof');
    }
    const { header, payload } = proof;
    if (header.kid !== undefined || header.jwk === undefined || payload.aud !== id) {
      return failure('invalid_proof');
    }
    if (typeof payload.iat !== 'number' || typeof payload.nonce !== 'string' || !nonces.delete(payload.nonce)) {
      return failure('invalid_nonce');
    }
    return answer(200, {
      credentials: [
        { credential: await issue({ holder: o.bindTo ?? header.jwk, vct: o.issuedVct ?? vct, iss: o.issuedIss }) },
      ],
    });
  }

  const routes: Record<string, (request: Seen) => Reply | Promise<Reply>> = {
    [`GET ${where.offer}`]: () => answer(200, offer),
    [`GET ${where.issuerMetadata}`]: () => answer(200, issuerMetadata),
    [`GET ${where.serverMetadata}`]: () => answer(200, serverMetadata),
    [`POST ${where.token}`]: token,
    [`POST ${where.nonce}`]: nonce,
    [`POST ${o.credentialEndpoint ?? where.credential}`]: credential,
  };

  const fetch: FetchLike = async (url, init) => {
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(init?.headers ?? {})) headers[name.toLowerCase()] = value;
    const seen: Seen = { method: init?.method ?? 'GET', url, headers, body: init?.body ?? '' };
    requests.push(seen);
    const route = Object.hasOwn(routes, `${seen.method} ${url}`) ? routes[`${seen.method} ${url}`] : undefined;
    const reply = route === undefined ? answer(404, { message: 'no such address' }) : await route(seen);
    const text = JSON.stringify(reply.body);
    return {
      status: reply.status,
      headers: { get: (name) => (name.toLowerCase() === 'content-type' ? 'application/json' : null) },
      text: async () => text,
    };
  };

  return {
    id,
    where,
    signer,
    preAuthorizedCode,
    txCode,
    offer,
    byValue: `openid-credential-offer://?${formEncode({ credential_offer: JSON.stringify(offer) })}`,
    byReference: `openid-credential-offer://?${formEncode({ credential_offer_uri: where.offer })}`,
    fetch,
    requests,
    issue,
  };
}
