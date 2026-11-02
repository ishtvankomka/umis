import {
  TYP,
  VCT,
  UmisError,
  base64urlEncode,
  generateSigner,
  issueCredential,
  presentCredential,
  signJws,
  utf8Encode,
  webCryptoProvider,
  type AuthorityItem,
  type CredentialPayload,
  type CryptoProvider,
  type DisclosableClaim,
  type Signer,
  type UmisClaimSet,
} from '../src/index.js';
import { nobleCryptoProvider } from '../src/noble.js';

export const providers: Array<[string, CryptoProvider]> = [
  ['webcrypto', webCryptoProvider],
  ['noble', nobleCryptoProvider()],
];

/** 2026-11-04T00:00:00Z. */
export const NOW = 1_793_750_400;
export const DAY = 86_400;
export const ISSUER = 'https://issuer.example/contractor-a';
export const STATUS_URI = 'https://issuer.example/status/contractor-a/1';
export const VERIFIER = 'urn:umis:verifier:warehouse-b';

/** What the code of a failure is, or undefined when nothing failed. */
export async function codeOf(run: () => Promise<unknown> | unknown): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

export const OLEH_AUTHORITY: AuthorityItem[] = [
  {
    action: 'receive_materials',
    resource: 'rebar',
    limit: { amount: 10, unit: 't', per: 'shift' },
    object: 'bridge-01',
  },
];

export const IVAN_AUTHORITY: AuthorityItem[] = [
  {
    action: 'receive_materials',
    resource: 'rebar',
    limit: { amount: 8, unit: 't', per: 'shift' },
    object: 'bridge-01',
  },
];

const ORG = { id: 'contractor-a', name: 'Підрядник А' };
const ORG_UNIT = { id: 'bridge-crew', name: 'Бригада будівництва мосту' };

export interface World {
  crypto: CryptoProvider;
  issuer: Signer;
  /** The holder keys. */
  oleh: Signer;
  ivan: Signer;
  olehPayload: CredentialPayload;
  olehClaims: Partial<UmisClaimSet>;
  ivanPayload: CredentialPayload;
  ivanClaims: Partial<UmisClaimSet>;
  /** A root credential with the authority of ten tonnes per shift. */
  olehCredential: string;
  /** A credential delegated by the first one, limited to eight tonnes. */
  ivanCredential: string;
}

/** Two role-authority credentials (a root and its delegate), their holders and their issuer. */
export async function buildWorld(crypto: CryptoProvider): Promise<World> {
  const issuer = await generateSigner({ crypto });
  const oleh = await generateSigner({ crypto });
  const ivan = await generateSigner({ crypto });

  const olehPayload: CredentialPayload = {
    iss: ISSUER,
    sub: 'p_oleh',
    jti: 'cred-oleh-0001',
    iat: NOW,
    exp: NOW + 90 * DAY,
    vct: VCT.roleAuthority,
    cnf: { jwk: oleh.publicJwk },
    status: { status_list: { idx: 40_213, uri: STATUS_URI } },
  };
  const olehClaims: Partial<UmisClaimSet> = {
    org: ORG,
    org_unit: ORG_UNIT,
    role: { code: 'crew_lead', name: 'Керівник бригади' },
    authority: OLEH_AUTHORITY,
    delegation: { depth: 0, max_depth: 1 },
    display: { name: 'Олег' },
  };
  const ivanPayload: CredentialPayload = {
    iss: ISSUER,
    sub: 'p_ivan',
    jti: 'cred-ivan-0001',
    iat: NOW + 60,
    exp: NOW + 30 * DAY,
    vct: VCT.roleAuthority,
    cnf: { jwk: ivan.publicJwk },
    status: { status_list: { idx: 40_214, uri: STATUS_URI } },
  };
  const ivanClaims: Partial<UmisClaimSet> = {
    org: ORG,
    org_unit: ORG_UNIT,
    role: { code: 'crew_member', name: 'Бригадир зміни' },
    authority: IVAN_AUTHORITY,
    delegation: {
      parent: {
        id: olehPayload.jti,
        status: olehPayload.status.status_list,
        authority: OLEH_AUTHORITY,
        exp: olehPayload.exp,
      },
      depth: 1,
      max_depth: 1,
    },
    display: { name: 'Іван' },
  };

  const [olehCredential, ivanCredential] = await Promise.all([
    issueCredential({ signer: issuer, payload: olehPayload, claims: olehClaims, crypto }),
    issueCredential({ signer: issuer, payload: ivanPayload, claims: ivanClaims, crypto }),
  ]);
  return {
    crypto,
    issuer,
    oleh,
    ivan,
    olehPayload,
    olehClaims,
    ivanPayload,
    ivanClaims,
    olehCredential,
    ivanCredential,
  };
}

/** The claims a verifier of authority asks for. */
export const AUTHORITY_CLAIMS: DisclosableClaim[] = ['org', 'role', 'authority', 'delegation'];

export function presentWith(
  world: World,
  credential: string,
  holder: Signer,
  kb: { aud?: string; nonce: string; iat?: number },
  disclose: readonly DisclosableClaim[] = AUTHORITY_CLAIMS,
): Promise<string> {
  return presentCredential({
    credential,
    disclose,
    kb: { signer: holder, aud: kb.aud ?? VERIFIER, nonce: kb.nonce, iat: kb.iat ?? NOW + 120 },
    crypto: world.crypto,
  });
}

// ---------------------------------------------------------------------------------------------------------------
// forging tokens that are signed correctly and wrong in one respect
// ---------------------------------------------------------------------------------------------------------------

/** The base64url text of a JSON value (or of a string as it is). */
export const segment = (value: unknown): string =>
  base64urlEncode(utf8Encode(typeof value === 'string' ? value : JSON.stringify(value)));

/** A JWS with this exact header and payload (an object, or JSON text as it is), signed by `signer`. */
export async function forgeJws(signer: Signer, header: object | string, payload: object | string): Promise<string> {
  const signingText = `${segment(header)}.${segment(payload)}`;
  return `${signingText}.${base64urlEncode(await signer.sign(utf8Encode(signingText)))}`;
}

export const disclosureText = (salt: string, name: string, value: unknown): string => segment([salt, name, value]);

export { signJws, TYP };
