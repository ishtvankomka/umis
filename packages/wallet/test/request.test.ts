import {
  LIMITS,
  MUTUAL_AUD,
  VCT,
  encodeFrame,
  generateSigner,
  presentCredential,
  randomId,
  signPresentationRequest,
} from '@umis/core';
import type { PresentationRequestPayloadV1, Signer } from '@umis/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { createOneWayQr, createResponseQr, parseRequestQr } from '../src/index.js';
import { T0, createFakeIssuer, failureOf } from './fake-issuer.js';

const NOW = T0 + 3_600;
const VERIFIER = 'urn:umis:verifier:warehouse-b';
const OPENER = 'urn:umis:wallet:oleh';

let verifier: Signer;
let oleh: Signer;
let stranger: Signer;
let credential: string;

beforeAll(async () => {
  const issuer = await createFakeIssuer();
  [verifier, oleh, stranger] = await Promise.all([generateSigner(), generateSigner(), generateSigner()]);
  credential = await issuer.issue({ holder: oleh.publicJwk, jti: 'cred-oleh-0001' });
});

function payloadOf(over: Partial<PresentationRequestPayloadV1> = {}): PresentationRequestPayloadV1 {
  return {
    v: 1,
    nonce: randomId(16),
    aud: VERIFIER,
    iat: NOW,
    exp: NOW + 60,
    vct: [VCT.roleAuthority],
    claims: ['org', 'role'],
    verifier: { name: 'Постачальник Б' },
    ...over,
  };
}

async function requestQr(signer: Signer, over: Partial<PresentationRequestPayloadV1> = {}): Promise<string> {
  return encodeFrame({ kind: 'request', tokens: [await signPresentationRequest(payloadOf(over), signer)] });
}

/** A mutual opening: the request signed by `requestSigner`, the presentation attached by Oleh. */
async function openingQr(requestSigner: Signer): Promise<string> {
  const payload = payloadOf({ aud: OPENER, mutual: true });
  const jws = await signPresentationRequest(payload, requestSigner);
  const presentation = await presentCredential({
    credential,
    disclose: ['org', 'role'],
    kb: { signer: oleh, aud: MUTUAL_AUD, nonce: payload.nonce, iat: NOW },
  });
  return encodeFrame({ kind: 'mutual_init', tokens: [jws, presentation] });
}

describe('reading a request', () => {
  it('returns the request, and says whether a known verifier key signed it', async () => {
    const qr = await requestQr(verifier);

    const known = await parseRequestQr(qr, { verifierKeys: [verifier.publicJwk], now: NOW });
    expect(known).toMatchObject({
      kind: 'request',
      aud: VERIFIER,
      claims: ['org', 'role'],
      vct: [VCT.roleAuthority],
      verifier: { name: 'Постачальник Б' },
      kid: verifier.kid,
      signatureVerified: true,
    });
    expect(known.counterPresentation).toBeUndefined();
    expect(known.jws.split('.')).toHaveLength(3);

    expect(
      (await parseRequestQr(qr, { verifierKeys: [stranger.publicJwk, verifier.publicJwk] })).signatureVerified,
    ).toBe(true);
    expect((await parseRequestQr(qr, { verifierKeys: [stranger.publicJwk] })).signatureVerified).toBe(false);
    expect((await parseRequestQr(qr, { verifierKeys: [] })).signatureVerified).toBe(false);
    expect((await parseRequestQr(qr)).signatureVerified).toBe(false);
  });

  it('reads a Frame object from a transport like the text of a QR code', async () => {
    const qr = await requestQr(verifier);
    const fromText = await parseRequestQr(qr, { verifierKeys: [verifier.publicJwk] });
    const fromFrame = await parseRequestQr(
      { kind: 'request', tokens: [fromText.jws] },
      { verifierKeys: [verifier.publicJwk] },
    );
    expect(fromFrame).toEqual(fromText);
  });

  it('refuses a request that has run out, counting 10 seconds of skew unless told otherwise', async () => {
    const qr = await requestQr(verifier); // exp = NOW + 60
    const exp = NOW + 60;
    await expect(parseRequestQr(qr, { now: exp + LIMITS.defaultSkewS - 1 })).resolves.toMatchObject({ aud: VERIFIER });
    expect((await failureOf(parseRequestQr(qr, { now: exp + LIMITS.defaultSkewS }))).code).toBe('PRESENTATION_EXPIRED');
    expect((await failureOf(parseRequestQr(qr, { now: exp, skewSeconds: 0 }))).code).toBe('PRESENTATION_EXPIRED');
    await expect(parseRequestQr(qr, { now: exp - 1, skewSeconds: 0 })).resolves.toMatchObject({ aud: VERIFIER });
    await expect(parseRequestQr(qr)).resolves.toMatchObject({ aud: VERIFIER }); // no clock, no check
  });
});

describe('reading the opening of a mutual exchange', () => {
  it('is signed when the request is made by the key the attached presentation is bound to', async () => {
    const own = await parseRequestQr(await openingQr(oleh), { now: NOW });
    expect(own).toMatchObject({ kind: 'mutual_init', aud: OPENER, mutual: true, signatureVerified: true });
    expect(own.counterPresentation!.split('~').length).toBeGreaterThan(2);

    const other = await parseRequestQr(await openingQr(stranger), { now: NOW });
    expect(other.kind).toBe('mutual_init');
    expect(other.signatureVerified).toBe(false);
  });

  it('is not signed because a verifier key is known: only the attached presentation vouches for it', async () => {
    const parsed = await parseRequestQr(await openingQr(stranger), { verifierKeys: [stranger.publicJwk], now: NOW });
    expect(parsed.signatureVerified).toBe(false);
  });
});

describe('what is not a request', () => {
  it('is UNSUPPORTED_FORMAT for another kind of frame and for text that is no frame', async () => {
    const oneWay = await createOneWayQr({ sdJwtVc: credential, signer: oleh, now: NOW });
    expect((await failureOf(parseRequestQr(oneWay))).code).toBe('UNSUPPORTED_FORMAT');

    const request = await parseRequestQr(await requestQr(verifier));
    const answer = await createResponseQr({ request, sdJwtVc: credential, disclose: ['org'], signer: oleh, now: NOW });
    expect((await failureOf(parseRequestQr(answer))).code).toBe('UNSUPPORTED_FORMAT');
    expect((await failureOf(parseRequestQr({ kind: 'response', tokens: [] }))).code).toBe('UNSUPPORTED_FORMAT');
    expect((await failureOf(parseRequestQr('https://example.org/'))).code).toBe('UNSUPPORTED_FORMAT');
  });

  it('is MALFORMED when a request is damaged', async () => {
    expect((await failureOf(parseRequestQr('UMIS1R:NOT BASE45!.'))).code).toBe('MALFORMED');
    expect((await failureOf(parseRequestQr({ kind: 'request', tokens: ['a.b.c'] }))).code).toBe('MALFORMED');
    expect((await failureOf(parseRequestQr({ kind: 'mutual_init', tokens: ['only-one'] }))).code).toBe('MALFORMED');
    // a well-formed request in a Frame object that carries one token too many
    const jws = await signPresentationRequest(payloadOf(), verifier);
    expect((await failureOf(parseRequestQr({ kind: 'request', tokens: [jws, jws] }))).code).toBe('MALFORMED');
    expect((await failureOf(parseRequestQr(undefined as unknown as string))).code).toBe('MALFORMED');
  });
});
