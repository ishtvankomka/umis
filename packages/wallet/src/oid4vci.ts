import {
  TYP,
  URI_SCHEMES,
  UmisError,
  asEcPublicJwk,
  decodeCredential,
  formEncode,
  isReasonCode,
  parseQuery,
  parseSdJwt,
  publicJwkEquals,
  signJws,
  splitUri,
  utf8Encode,
  wellKnownUrl,
} from '@umis/core';
import type { CredentialOffer, CryptoProvider, DecodedCredential, FetchLike, Signer } from '@umis/core';
import type { OfferView } from './types.js';

type Json = Record<string, unknown>;
type RequestInit = NonNullable<Parameters<FetchLike>[1]>;
type OfferCode = 'MALFORMED' | 'PROTOCOL';

const PRE_AUTHORIZED_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const SD_JWT_VC_FORMAT = 'dc+sd-jwt';
const OFFER_SCHEME = URI_SCHEMES.credentialOffer.slice(0, -'://'.length);
/** Offers, metadata and responses are small documents; a longer one is refused unread. */
const MAX_BODY_BYTES = 65_536;
/** The longest guidance text for a transaction code that a wallet shows (OpenID4VCI 1.0, section 4.1.1). */
const MAX_TX_DESCRIPTION_CHARS = 300;
/** Characters of an OAuth `error` value (RFC 6749, section 5.2) without the space, at most 64 of them. */
const OAUTH_ERROR_CODE = /^[\x21\x23-\x5b\x5d-\x7e]{1,64}$/;
const LOCAL_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1']);

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);
const protocol = (message: string, cause?: unknown): UmisError => new UmisError('PROTOCOL', message, { cause });

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

function isText(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

// ---------------------------------------------------------------------------------------------------------------
// addresses and HTTP
// ---------------------------------------------------------------------------------------------------------------

/**
 * An absolute address that a wallet may send secrets to or take documents from: `https`, or, when `local` is true, also
 * `http` for a development host on the same machine. No user information, no fragment, and nothing but visible ASCII.
 */
function address(value: unknown, what: string, code: UmisError['code'], local = false): string {
  const fail = (reason: string): UmisError => new UmisError(code, `${what} ${reason}`);
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value)) throw fail('is not an address');
  const { scheme, authority, fragment } = splitUri(value);
  const hostAndPort = /^([A-Za-z0-9.-]+)(?::[0-9]{1,5})?$/.exec(authority);
  if (hostAndPort === null || fragment !== '') throw fail('is not a plain address');
  const onThisMachine = LOCAL_HOSTS.has((hostAndPort[1] ?? '').toLowerCase());
  if (!(scheme === 'https' || (scheme === 'http' && local && onThisMachine))) throw fail('must be an https address');
  return value;
}

/**
 * Whether an issuer or server identifier that `wellKnownUrl` accepted is a development host on the same machine: that
 * function allows `http` for those and for nothing else. Only such an issuer may name `http` endpoints.
 */
const isLocalIdentifier = (identifier: string): boolean => splitUri(identifier).scheme === 'http';

function fetcher(custom: FetchLike | undefined): FetchLike {
  if (custom !== undefined) {
    if (typeof custom !== 'function') throw invalid('fetch must be a function');
    return custom;
  }
  if (typeof globalThis.fetch !== 'function') throw new UmisError('NETWORK', 'no fetch function is available');
  return (url, init) => globalThis.fetch(url, init);
}

function jsonObject(text: string): Json | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/** The `error` of an OAuth error response with its description, cleaned for a message; undefined if there is none. */
function oauthError(body: Json | undefined): string | undefined {
  const code = body === undefined ? undefined : own(body, 'error');
  if (body === undefined || typeof code !== 'string' || !OAUTH_ERROR_CODE.test(code)) return undefined;
  const description = own(body, 'error_description');
  const text =
    typeof description === 'string'
      ? description
          .replace(/[^\x20-\x7e]/g, '')
          .trim()
          .slice(0, 200)
      : '';
  return text === '' ? code : `${code}: ${text}`;
}

/**
 * One HTTP exchange that must end in a JSON object. The request asks not to follow redirects (`redirect: 'error'`), so
 * that the answer comes from the address that was checked. A request that fails, or an HTTP error without an OAuth
 * `error`, is NETWORK; an OAuth `error` (with its code in the message), a body that is too large or no JSON object is
 * PROTOCOL.
 */
async function exchange(send: FetchLike, url: string, init: RequestInit, what: string): Promise<Json> {
  let response: Awaited<ReturnType<FetchLike>>;
  try {
    response = await send(url, { ...init, redirect: 'error' });
  } catch (cause) {
    throw new UmisError('NETWORK', `${what}: the request failed`, { cause });
  }
  const announced = Number(response.headers.get('content-length') ?? 0);
  if (announced > MAX_BODY_BYTES) throw protocol(`${what}: the response is too large`);
  let text: string;
  try {
    text = await response.text();
  } catch (cause) {
    throw new UmisError('NETWORK', `${what}: the response could not be read`, { cause });
  }
  if (text.length > MAX_BODY_BYTES || utf8Encode(text).length > MAX_BODY_BYTES) {
    throw protocol(`${what}: the response is too large`);
  }

  const body = jsonObject(text);
  if (!(response.status >= 200 && response.status < 300)) {
    const reason = oauthError(body);
    if (reason !== undefined) throw protocol(`${what}: ${reason}`);
    throw new UmisError('NETWORK', `${what}: HTTP ${response.status}`);
  }
  if (body === undefined) throw protocol(`${what}: the response is not a JSON object`);
  return body;
}

function get(send: FetchLike, url: string, what: string): Promise<Json> {
  return exchange(send, url, { method: 'GET', headers: { Accept: 'application/json' } }, what);
}

// ---------------------------------------------------------------------------------------------------------------
// the offer
// ---------------------------------------------------------------------------------------------------------------

/** Reads a credential offer object (OpenID4VCI 1.0, section 4.1) and keeps what a pre-authorized-code wallet needs. */
function readOffer(raw: unknown, code: OfferCode): CredentialOffer {
  const fail = (reason: string, cause?: unknown): UmisError =>
    new UmisError(code, `the credential offer ${reason}`, { cause });
  if (!isRecord(raw)) throw fail('is not a JSON object');

  const issuer = own(raw, 'credential_issuer');
  if (!isText(issuer)) throw fail('names no issuer');
  try {
    wellKnownUrl(issuer, 'openid-credential-issuer');
  } catch (cause) {
    throw fail('names an issuer without a usable address', cause);
  }
  const ids = own(raw, 'credential_configuration_ids');
  if (!Array.isArray(ids) || ids.length === 0 || !ids.every(isText)) throw fail('lists no credential configuration');

  const grants = own(raw, 'grants');
  const grant = isRecord(grants) ? own(grants, PRE_AUTHORIZED_GRANT) : undefined;
  if (!isRecord(grant)) throw fail('has no pre-authorized-code grant');
  const preAuthorizedCode = own(grant, 'pre-authorized_code');
  if (!isText(preAuthorizedCode)) throw fail('carries no pre-authorized code');

  const preAuthorized: CredentialOffer['grants'][typeof PRE_AUTHORIZED_GRANT] = {
    'pre-authorized_code': preAuthorizedCode,
  };
  const txRaw = own(grant, 'tx_code');
  if (txRaw !== undefined) {
    if (!isRecord(txRaw)) throw fail('has a transaction code that is not an object');
    const txCode: NonNullable<typeof preAuthorized.tx_code> = {};
    const length = own(txRaw, 'length');
    if (length !== undefined) {
      if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 1) {
        throw fail('has a transaction code of an unusable length');
      }
      txCode.length = length;
    }
    const inputMode = own(txRaw, 'input_mode');
    if (inputMode !== undefined) {
      if (inputMode !== 'numeric' && inputMode !== 'text')
        throw fail('has a transaction code of an unknown input mode');
      txCode.input_mode = inputMode;
    }
    const description = own(txRaw, 'description');
    if (description !== undefined) {
      if (typeof description !== 'string') throw fail('has a transaction code description that is not text');
      txCode.description = description.slice(0, MAX_TX_DESCRIPTION_CHARS);
    }
    preAuthorized.tx_code = txCode;
  }
  return {
    credential_issuer: issuer,
    credential_configuration_ids: [...ids],
    grants: { [PRE_AUTHORIZED_GRANT]: preAuthorized },
  };
}

/**
 * The offer behind a `openid-credential-offer://` address: carried in the address (`credential_offer`) or fetched from
 * the https address it names (`credential_offer_uri`). Exactly one of the two must be there.
 */
async function loadOffer(uri: string, send: FetchLike): Promise<CredentialOffer> {
  if (typeof uri !== 'string') throw invalid('the offer address must be a string');
  const trimmed = uri.trim();
  if (trimmed.length > MAX_BODY_BYTES) throw new UmisError('MALFORMED', 'the credential offer is too long');
  const parts = splitUri(trimmed);
  if (parts.scheme !== OFFER_SCHEME) throw new UmisError('UNSUPPORTED_FORMAT', 'not a credential offer');

  const query = parseQuery(parts.query);
  const byValue = Object.hasOwn(query, 'credential_offer') ? query.credential_offer : undefined;
  const byReference = Object.hasOwn(query, 'credential_offer_uri') ? query.credential_offer_uri : undefined;
  if ((byValue === undefined) === (byReference === undefined)) {
    throw new UmisError(
      'MALFORMED',
      'a credential offer carries credential_offer or credential_offer_uri, not both or neither',
    );
  }
  if (byValue !== undefined) {
    const offer = jsonObject(byValue);
    if (offer === undefined) throw new UmisError('MALFORMED', 'the credential offer is not a JSON object');
    return readOffer(offer, 'MALFORMED');
  }
  const location = address(byReference, 'the credential offer address', 'MALFORMED', true);
  return readOffer(await get(send, location, 'the credential offer'), 'PROTOCOL');
}

// ---------------------------------------------------------------------------------------------------------------
// metadata
// ---------------------------------------------------------------------------------------------------------------

function readDisplay(configuration: Json): Array<{ name: string; locale?: string }> | undefined {
  const metadata = own(configuration, 'credential_metadata');
  const inMetadata = isRecord(metadata) ? own(metadata, 'display') : undefined;
  const list = Array.isArray(inMetadata) ? inMetadata : own(configuration, 'display');
  if (!Array.isArray(list)) return undefined;
  const display: Array<{ name: string; locale?: string }> = [];
  for (const entry of list) {
    const name = isRecord(entry) ? own(entry, 'name') : undefined;
    if (!isRecord(entry) || !isText(name)) continue;
    const item: { name: string; locale?: string } = { name };
    const locale = own(entry, 'locale');
    if (isText(locale)) item.locale = locale;
    display.push(item);
  }
  return display.length > 0 ? display : undefined;
}

interface IssuerMetadata {
  configurationId: string;
  vct: string;
  display?: Array<{ name: string; locale?: string }>;
  credentialEndpoint: string;
  nonceEndpoint?: string;
  authorizationServer: string;
}

/**
 * Reads the credential issuer metadata (OpenID4VCI 1.0, section 12.2): it must name the issuer of the offer, and the
 * first offered configuration in `dc+sd-jwt` format is the one taken.
 */
function readIssuerMetadata(metadata: Json, offer: CredentialOffer): IssuerMetadata {
  const what = 'the issuer metadata';
  if (own(metadata, 'credential_issuer') !== offer.credential_issuer) {
    throw protocol(`${what} names another issuer than the offer`);
  }
  const local = isLocalIdentifier(offer.credential_issuer);
  const credentialEndpoint = address(
    own(metadata, 'credential_endpoint'),
    `${what} credential_endpoint`,
    'PROTOCOL',
    local,
  );
  const nonceEndpoint = own(metadata, 'nonce_endpoint');
  if (nonceEndpoint !== undefined) address(nonceEndpoint, `${what} nonce_endpoint`, 'PROTOCOL', local);

  let authorizationServer = offer.credential_issuer;
  const servers = own(metadata, 'authorization_servers');
  if (servers !== undefined) {
    if (!Array.isArray(servers) || (servers.length > 0 && !isText(servers[0]))) {
      throw protocol(`${what} lists authorization servers that are not addresses`);
    }
    if (servers.length > 0) authorizationServer = servers[0] as string;
    if (!local && isLocalIdentifier(authorizationServer)) {
      throw protocol(`${what} names an authorization server on the local machine`);
    }
  }

  const configurations = own(metadata, 'credential_configurations_supported');
  if (!isRecord(configurations)) throw protocol(`${what} lists no credential configurations`);
  for (const id of offer.credential_configuration_ids) {
    const configuration = own(configurations, id);
    if (!isRecord(configuration) || own(configuration, 'format') !== SD_JWT_VC_FORMAT) continue;
    const vct = own(configuration, 'vct');
    if (!isText(vct)) continue;
    const found: IssuerMetadata = { configurationId: id, vct, credentialEndpoint, authorizationServer };
    if (typeof nonceEndpoint === 'string') found.nonceEndpoint = nonceEndpoint;
    const display = readDisplay(configuration);
    if (display !== undefined) found.display = display;
    return found;
  }
  throw protocol('the issuer supports none of the offered credentials in dc+sd-jwt format');
}

function wellKnown(identifier: string, name: 'openid-credential-issuer' | 'oauth-authorization-server'): string {
  try {
    return wellKnownUrl(identifier, name);
  } catch (cause) {
    throw protocol(`${name} metadata has no usable address`, cause);
  }
}

/**
 * Reads what the holder is shown about an offer and what is needed to redeem it, from the text of a QR code or a link
 * (`openid-credential-offer://?credential_offer=...`, or `?credential_offer_uri=...` for an offer held by the issuer).
 *
 * The offer must carry a pre-authorized-code grant. The metadata of the issuer is read from its well-known address and
 * must name the issuer of the offer; the token endpoint comes from the metadata of its authorization server (the first
 * of `authorization_servers`, else the issuer itself). An offer address to fetch must be `https`, or `http` on the local
 * machine, and so must every endpoint. A text that is not an offer is UNSUPPORTED_FORMAT, a damaged offer in the address
 * MALFORMED; the metadata and offers fetched from a server are PROTOCOL when they do not fit, and NETWORK when the
 * server cannot be reached. `opts.fetch` is the global `fetch` by default. Every request asks not to follow redirects
 * (`redirect: 'error'`): the global `fetch` then fails on a redirect (NETWORK); a `fetch` passed in decides for itself.
 */
export async function resolveOffer(uri: string, opts: { fetch?: FetchLike } = {}): Promise<OfferView> {
  if (typeof opts !== 'object' || opts === null) throw invalid('the options must be an object');
  const send = fetcher(opts.fetch);
  const offer = await loadOffer(uri, send);

  const issuer = readIssuerMetadata(
    await get(send, wellKnown(offer.credential_issuer, 'openid-credential-issuer'), 'the issuer metadata'),
    offer,
  );
  const serverMetadata = await get(
    send,
    wellKnown(issuer.authorizationServer, 'oauth-authorization-server'),
    'the authorization server metadata',
  );
  const serverId = own(serverMetadata, 'issuer');
  if (serverId !== undefined && serverId !== issuer.authorizationServer) {
    throw protocol('the authorization server metadata names another server than the one asked');
  }

  const grant = offer.grants[PRE_AUTHORIZED_GRANT];
  const view: OfferView = {
    offer,
    credentialIssuer: offer.credential_issuer,
    configurationId: issuer.configurationId,
    vct: issuer.vct,
    preAuthorizedCode: grant['pre-authorized_code'],
    tokenEndpoint: address(
      own(serverMetadata, 'token_endpoint'),
      'the authorization server token_endpoint',
      'PROTOCOL',
      isLocalIdentifier(offer.credential_issuer),
    ),
    credentialEndpoint: issuer.credentialEndpoint,
  };
  if (grant.tx_code !== undefined) {
    view.txCode = {};
    if (grant.tx_code.length !== undefined) view.txCode.length = grant.tx_code.length;
    if (grant.tx_code.input_mode !== undefined) view.txCode.inputMode = grant.tx_code.input_mode;
    if (grant.tx_code.description !== undefined) view.txCode.description = grant.tx_code.description;
  }
  if (issuer.display !== undefined) view.display = issuer.display;
  if (issuer.nonceEndpoint !== undefined) view.nonceEndpoint = issuer.nonceEndpoint;
  return view;
}

// ---------------------------------------------------------------------------------------------------------------
// redeeming
// ---------------------------------------------------------------------------------------------------------------

function checkedView(view: OfferView): OfferView {
  const ok =
    typeof view === 'object' &&
    view !== null &&
    isText(view.credentialIssuer) &&
    isText(view.configurationId) &&
    isText(view.vct) &&
    isText(view.preAuthorizedCode);
  if (!ok) throw invalid('expected an offer from resolveOffer');
  address(view.credentialIssuer, 'the issuer', 'INVALID_ARGUMENT', true);
  const local = isLocalIdentifier(view.credentialIssuer);
  address(view.tokenEndpoint, 'the token endpoint', 'INVALID_ARGUMENT', local);
  address(view.credentialEndpoint, 'the credential endpoint', 'INVALID_ARGUMENT', local);
  if (view.nonceEndpoint !== undefined) address(view.nonceEndpoint, 'the nonce endpoint', 'INVALID_ARGUMENT', local);
  return view;
}

function required(body: Json, name: string, what: string): string {
  const value = own(body, name);
  if (!isText(value)) throw protocol(`${what}: ${name} is missing`);
  return value;
}

/** The credential from a credential response (OpenID4VCI 1.0, section 8.3): the first of `credentials`. */
function credentialOf(body: Json): string {
  const credentials = own(body, 'credentials');
  const first: unknown = Array.isArray(credentials) ? credentials[0] : undefined;
  const credential = isRecord(first) ? own(first, 'credential') : undefined;
  if (!isText(credential)) throw protocol('the credential response holds no credential');
  return credential;
}

/** Whether the credential the issuer sent is the one that was offered, for this holder key. */
async function checkedCredential(
  credential: string,
  view: OfferView,
  signer: Signer,
  crypto: CryptoProvider | undefined,
): Promise<DecodedCredential> {
  let decoded: DecodedCredential;
  try {
    await parseSdJwt(credential, crypto);
    decoded = decodeCredential(credential);
  } catch (cause) {
    if (cause instanceof UmisError && isReasonCode(cause.code)) {
      throw protocol(`the issuer sent a credential that cannot be read: ${cause.message}`, cause);
    }
    throw cause;
  }
  if (decoded.hasKeyBinding) throw protocol('the issuer sent a presentation, not a credential');
  if (!publicJwkEquals(decoded.cnfJwk, signer.publicJwk)) throw protocol('the credential is bound to another key');
  if (decoded.vct !== view.vct) throw protocol('the credential is not of the type that was offered');
  if (decoded.issuer !== view.credentialIssuer) throw protocol('the credential comes from another issuer');
  return decoded;
}

/**
 * Redeems an offer from `resolveOffer` for a credential bound to `signer`, with the pre-authorized-code flow of
 * OpenID4VCI 1.0. Three requests, in this order:
 *
 * 1. the token request (section 6.1), a form with the grant type, the pre-authorized code and the transaction code;
 * 2. a nonce from the nonce endpoint (section 7) when the issuer has one, else the `c_nonce` of the token response;
 * 3. the credential request (section 8.2), JSON with the configuration and a proof JWT (appendix F.1) in `proofs.jwt`,
 *    signed by `signer`, with the issuer as audience, `opts.now` as `iat` and the nonce, under `Authorization: Bearer`.
 *
 * `txCode` is the code the holder typed; an offer that asks for one and gets none is INVALID_ARGUMENT. The credential in
 * the answer must read as an SD-JWT VC, be bound to the key of `signer`, be of the offered type and come from the
 * issuer of the offer. An OAuth error (`invalid_grant` for a wrong transaction code, say) or anything else that breaks
 * the protocol is PROTOCOL with the error code in the message; a server that cannot be reached is NETWORK. Redirects
 * are refused as in {@link resolveOffer}.
 */
export async function redeemOffer(
  view: OfferView,
  txCode: string | undefined,
  signer: Signer,
  opts: { now: number; fetch?: FetchLike; crypto?: CryptoProvider },
): Promise<{ sdJwtVc: string; decoded: DecodedCredential }> {
  if (typeof opts !== 'object' || opts === null) throw invalid('the options must be an object');
  checkedView(view);
  if (typeof opts.now !== 'number' || !Number.isFinite(opts.now))
    throw invalid('now must be a finite number of seconds');
  if (typeof signer !== 'object' || signer === null || signer.alg !== 'ES256' || typeof signer.sign !== 'function') {
    throw invalid('expected an ES256 signer');
  }
  const holderKey = asEcPublicJwk(signer.publicJwk);
  if (txCode !== undefined && !isText(txCode)) throw invalid('the transaction code must be a non-empty string');
  if (view.txCode !== undefined && txCode === undefined) throw invalid('this offer needs the transaction code');
  const send = fetcher(opts.fetch);

  const token = await exchange(
    send,
    view.tokenEndpoint,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: formEncode({
        grant_type: PRE_AUTHORIZED_GRANT,
        'pre-authorized_code': view.preAuthorizedCode,
        ...(txCode === undefined ? {} : { tx_code: txCode }),
      }),
    },
    'the token request',
  );
  const accessToken = required(token, 'access_token', 'the token response');
  const tokenType = own(token, 'token_type');
  if (tokenType !== undefined && (typeof tokenType !== 'string' || tokenType.toLowerCase() !== 'bearer')) {
    throw protocol('the token response is not for a bearer token');
  }

  let nonce: string | undefined;
  if (view.nonceEndpoint !== undefined) {
    const answer = await exchange(
      send,
      view.nonceEndpoint,
      { method: 'POST', headers: { Accept: 'application/json' } },
      'the nonce request',
    );
    nonce = required(answer, 'c_nonce', 'the nonce response');
  } else if (own(token, 'c_nonce') !== undefined) {
    nonce = required(token, 'c_nonce', 'the token response');
  }

  // the key travels as bare coordinates: a key name of the wallet is nobody else's business
  const jwk = { kty: holderKey.kty, crv: holderKey.crv, x: holderKey.x, y: holderKey.y };
  const proof = await signJws({
    header: { typ: TYP.vciProof, jwk },
    payload: { aud: view.credentialIssuer, iat: opts.now, ...(nonce === undefined ? {} : { nonce }) },
    signer,
  });
  const answer = await exchange(
    send,
    view.credentialEndpoint,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ credential_configuration_id: view.configurationId, proofs: { jwt: [proof] } }),
    },
    'the credential request',
  );

  const sdJwtVc = credentialOf(answer);
  const decoded = await checkedCredential(sdJwtVc, view, signer, opts.crypto);
  return { sdJwtVc, decoded };
}
