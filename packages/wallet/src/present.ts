import {
  ALG,
  DISCLOSABLE_CLAIMS,
  LIMITS,
  TYP,
  UmisError,
  asEcPublicJwk,
  decodeCredential,
  encodeFrame,
  presentCredential,
  publicJwkEquals,
  randomBytes,
  randomId,
  signJws,
} from '@umis/core';
import type {
  CryptoProvider,
  DecodedCredential,
  DisclosableClaim,
  Frame,
  OneWayTokenPayload,
  ParsedRequest,
  Signer,
} from '@umis/core';

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

function inputOf<T extends object>(i: T): T {
  if (typeof i !== 'object' || i === null) throw invalid('the input is missing');
  return i;
}

function secondsOf(now: unknown): number {
  if (typeof now !== 'number' || !Number.isFinite(now)) throw invalid('now must be a finite number of seconds');
  return now;
}

function isText(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

/**
 * Reads a stored credential for display and checks that `signer` holds the key it is bound to. Every frame the wallet
 * makes is signed by that key, and a verifier refuses any other.
 */
function boundCredential(sdJwtVc: string, signer: Signer): DecodedCredential {
  if (typeof signer !== 'object' || signer === null || signer.alg !== ALG || typeof signer.sign !== 'function') {
    throw invalid('expected an ES256 signer');
  }
  const decoded = decodeCredential(sdJwtVc);
  if (!publicJwkEquals(asEcPublicJwk(signer.publicJwk), decoded.cnfJwk)) {
    throw invalid('the signer is not the holder key of this credential');
  }
  return decoded;
}

/** The audience of a frame the holder starts: the one given, else the issuer of the credential. */
function audienceOf(audience: string | undefined, decoded: DecodedCredential): string {
  if (audience === undefined) return decoded.issuer;
  if (!isText(audience)) throw invalid('audience must be a non-empty string');
  return audience;
}

// ---------------------------------------------------------------------------------------------------------------
// one-way token
// ---------------------------------------------------------------------------------------------------------------

/** Starts at four random bytes the first time a token is made and goes up by one for each token after that. */
let oneWayCounter: number | undefined;

function nextCounter(): number {
  if (oneWayCounter === undefined) {
    const seed = randomBytes(4);
    oneWayCounter = ((seed[0]! << 24) | (seed[1]! << 16) | (seed[2]! << 8) | seed[3]!) >>> 0;
  }
  const value = oneWayCounter;
  oneWayCounter += 1;
  return value;
}

/**
 * `signJws` names the signer's key in the header unless the signer has none. A one-way token carries no key name: the
 * verifier finds the key through the credential reference, and every character counts in a QR code.
 */
function withoutKeyId(signer: Signer): Signer {
  return { alg: signer.alg, kid: undefined as never, publicJwk: signer.publicJwk, sign: (data) => signer.sign(data) };
}

/**
 * The text of a QR code with a one-way token: a short proof, signed by the holder key, that this credential is held
 * right now. The header is `{"alg":"ES256","typ":"umis-ow+jwt"}` and the payload `{cred_ref, aud, iat, exp, ctr}`:
 * `cred_ref` is the `jti` of the credential, `aud` the issuer of the credential unless `audience` says otherwise, `exp`
 * is `ttlSeconds` (30, the most there is) after `now`, and `ctr` counts up from a random start so that two tokens made
 * in the same second differ. A verifier accepts the token only for a credential it already holds in its member cache.
 * The signer must hold the key the credential is bound to, and `ttlSeconds` must be more than 0 and at most 30; either
 * mistake is INVALID_ARGUMENT.
 */
export async function createOneWayQr(i: {
  sdJwtVc: string;
  signer: Signer;
  audience?: string;
  now: number;
  ttlSeconds?: number;
  ctr?: number;
}): Promise<string> {
  inputOf(i);
  const now = secondsOf(i.now);
  const decoded = boundCredential(i.sdJwtVc, i.signer);
  const audience = audienceOf(i.audience, decoded);
  const ttl = i.ttlSeconds ?? LIMITS.oneWayMaxTtlS;
  if (typeof ttl !== 'number' || !(ttl > 0 && ttl <= LIMITS.oneWayMaxTtlS)) {
    throw invalid(`ttlSeconds is more than 0 and at most ${LIMITS.oneWayMaxTtlS}`);
  }
  const ctr = i.ctr ?? nextCounter();
  if (typeof ctr !== 'number' || !Number.isSafeInteger(ctr) || ctr < 0)
    throw invalid('ctr must be a non-negative integer');

  const payload: OneWayTokenPayload = { cred_ref: decoded.jti, aud: audience, iat: now, exp: now + ttl, ctr };
  const token = await signJws({ header: { typ: TYP.oneWay }, payload, signer: withoutKeyId(i.signer) });
  return encodeFrame({ kind: 'oneway', tokens: [token] });
}

// ---------------------------------------------------------------------------------------------------------------
// full presentation
// ---------------------------------------------------------------------------------------------------------------

/**
 * A presentation the holder offers without being asked, as a `full` frame: the credential with the disclosures named in
 * `disclose` and a key-binding JWT signed at `now` for `audience` (the issuer of the credential by default) with a fresh
 * 16-byte nonce. A claim the credential holds no disclosure for, or a signer that is not the holder key, is
 * INVALID_ARGUMENT.
 */
export async function createFullFrame(i: Parameters<typeof createFullQr>[0]): Promise<Frame> {
  inputOf(i);
  const now = secondsOf(i.now);
  const decoded = boundCredential(i.sdJwtVc, i.signer);
  const presentation = await presentCredential({
    credential: i.sdJwtVc,
    disclose: i.disclose,
    kb: {
      signer: i.signer,
      aud: audienceOf(i.audience, decoded),
      nonce: randomId(LIMITS.nonceBytes, i.crypto),
      iat: now,
    },
    crypto: i.crypto,
  });
  return { kind: 'full', tokens: [presentation] };
}

/** The same presentation as the text of a QR code. */
export async function createFullQr(i: {
  sdJwtVc: string;
  disclose: readonly DisclosableClaim[];
  signer: Signer;
  audience?: string;
  now: number;
  crypto?: CryptoProvider;
}): Promise<string> {
  return encodeFrame(await createFullFrame(i));
}

// ---------------------------------------------------------------------------------------------------------------
// response to a request
// ---------------------------------------------------------------------------------------------------------------

function answerable(request: ParsedRequest): ParsedRequest {
  const ok =
    typeof request === 'object' &&
    request !== null &&
    (request.kind === 'request' || request.kind === 'mutual_init') &&
    isText(request.nonce) &&
    isText(request.aud) &&
    Array.isArray(request.vct) &&
    request.vct.every(isText) &&
    Array.isArray(request.claims) &&
    request.claims.every(isText);
  if (!ok) throw invalid('expected a parsed presentation request');
  return request;
}

/**
 * The claims to disclose in answer to `request`. The credential must be of a type the request accepts, and every claim
 * must be one the request asks for. A holder who discloses `authority` also discloses `delegation` when the credential
 * has it and the request asks for it, because a verifier cannot judge an authority without the chain behind it.
 */
function chosenClaims(
  request: ParsedRequest,
  decoded: DecodedCredential,
  disclose: readonly DisclosableClaim[],
): DisclosableClaim[] {
  if (!request.vct.includes(decoded.vct)) throw invalid('the request does not accept this type of credential');
  if (!Array.isArray(disclose)) throw invalid('disclose must be an array of claim names');
  const chosen: DisclosableClaim[] = [];
  for (const name of disclose) {
    if (!(DISCLOSABLE_CLAIMS as readonly string[]).includes(name))
      throw invalid(`"${String(name)}" is not a UMIS claim`);
    if (!request.claims.includes(name)) throw invalid(`the request does not ask for "${name}"`);
    if (!chosen.includes(name)) chosen.push(name);
  }
  if (
    chosen.includes('authority') &&
    !chosen.includes('delegation') &&
    request.claims.includes('delegation') &&
    decoded.disclosable.includes('delegation')
  ) {
    chosen.push('delegation');
  }
  return chosen;
}

/**
 * The answer to a request parsed by `parseRequestQr`, as a frame: `response` for a request and `mutual_reply` for the
 * opening of a mutual exchange. It holds the credential with the disclosures named in `disclose` and a key-binding JWT
 * `{iat: now, aud: request.aud, nonce: request.nonce}`, so the answer is good for that request only.
 *
 * Nothing beyond the request is ever disclosed: a claim the request does not ask for, or a credential of a type it does
 * not accept, is INVALID_ARGUMENT, and so is a signer that is not the holder key.
 */
export async function createResponseFrame(i: Parameters<typeof createResponseQr>[0]): Promise<Frame> {
  inputOf(i);
  const request = answerable(i.request);
  const now = secondsOf(i.now);
  const decoded = boundCredential(i.sdJwtVc, i.signer);
  const disclose = chosenClaims(request, decoded, i.disclose);
  const presentation = await presentCredential({
    credential: i.sdJwtVc,
    disclose,
    kb: { signer: i.signer, aud: request.aud, nonce: request.nonce, iat: now },
    crypto: i.crypto,
  });
  return { kind: request.kind === 'mutual_init' ? 'mutual_reply' : 'response', tokens: [presentation] };
}

/** The same answer as the text of a QR code. */
export async function createResponseQr(i: {
  request: ParsedRequest;
  sdJwtVc: string;
  disclose: readonly DisclosableClaim[];
  signer: Signer;
  now: number;
  crypto?: CryptoProvider;
}): Promise<string> {
  return encodeFrame(await createResponseFrame(i));
}

// ---------------------------------------------------------------------------------------------------------------
// what will be shown
// ---------------------------------------------------------------------------------------------------------------

/**
 * What answering `request` with `credential` would show, for the screen that asks the holder: `disclose` lists the
 * requested claims the credential can disclose, in the order of the request, `missing` those it cannot, and `usable` is
 * true when the request accepts the type of the credential and nothing is missing, that is, when a verifier would find
 * everything it asked for. For a credential of an unaccepted type nothing is disclosed.
 */
export function disclosurePlan(
  request: Pick<ParsedRequest, 'claims' | 'vct'>,
  credential: DecodedCredential,
): { usable: boolean; disclose: DisclosableClaim[]; missing: DisclosableClaim[] } {
  const accepted = request.vct.includes(credential.vct);
  const asked = [...new Set(request.claims)];
  const missing = asked.filter((name) => !credential.disclosable.includes(name));
  const disclose = accepted ? asked.filter((name) => credential.disclosable.includes(name)) : [];
  return { usable: accepted && missing.length === 0, disclose, missing };
}
