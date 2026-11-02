import { describe, expect, it } from 'vitest';
import { TYP, base64urlDecode, generateSigner, publicJwkEquals, signJws, utf8Decode } from '@umis/core';
import type { Signer } from '@umis/core';
import { verifyKeyProof } from '../src/index.js';
import { NOW, bareJwk, codeOf, countingCrypto, forgeJws, segment } from './fixtures.js';

const AUDIENCE = 'https://issuer.example/contractor-a';
const NONCE = 'c_nonce_8Zq2pV1xKdTn4W';

interface ProofParts {
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  signer?: Signer;
}

/** A proof signed correctly by `holder`, with the members of the header and the payload replaced as given. */
function proofOf(holder: Signer, over: ProofParts = {}): Promise<string> {
  const header = { alg: 'ES256', typ: TYP.vciProof, jwk: bareJwk(holder.publicJwk), ...over.header };
  const payload = { aud: AUDIENCE, iat: NOW, nonce: NONCE, ...over.payload };
  return forgeJws(over.signer ?? holder, header, payload);
}

const verify = (proofJwt: unknown, over: Partial<Parameters<typeof verifyKeyProof>[0]> = {}) =>
  verifyKeyProof({ proofJwt: proofJwt as string, audience: AUDIENCE, nonce: NONCE, now: NOW, ...over });

const invalidProof = { ok: false, error: 'invalid_proof' };
const invalidNonce = { ok: false, error: 'invalid_nonce' };

describe('verifyKeyProof', () => {
  it('accepts the proof that the SDK builds and returns the key to bind the credential to', async () => {
    const holder = await generateSigner();
    const jwt = await signJws({
      header: { typ: TYP.vciProof, jwk: holder.publicJwk },
      payload: { aud: AUDIENCE, iat: NOW, nonce: NONCE },
      signer: holder,
    });
    const header = JSON.parse(utf8Decode(base64urlDecode(jwt.split('.')[0]!)));
    expect(Object.keys(header).sort()).toEqual(['alg', 'jwk', 'typ']);

    const result = await verify(jwt);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(publicJwkEquals(result.jwk, holder.publicJwk)).toBe(true);
    expect(Object.hasOwn(result.jwk, 'd')).toBe(false);

    // the audience may be a list that contains the issuer, and the clock may run a minute apart
    const listed = await proofOf(holder, { payload: { aud: ['https://other.example', AUDIENCE] } });
    expect((await verify(listed)).ok).toBe(true);
  });

  it('is invalid_proof for a wrong audience and invalid_nonce for a wrong nonce', async () => {
    const holder = await generateSigner();
    const wrongAudiences = ['https://issuer.example/other', '', ['https://other.example'], [AUDIENCE, 7], 7, undefined];
    for (const aud of wrongAudiences) {
      expect(await verify(await proofOf(holder, { payload: { aud } })), JSON.stringify(aud)).toEqual(invalidProof);
    }
    // a wrong nonce, an empty one and a missing one ask the wallet for a fresh nonce; a nonce of the wrong type is a broken proof
    for (const nonce of ['c_nonce_other', '', undefined]) {
      expect(await verify(await proofOf(holder, { payload: { nonce } })), String(nonce)).toEqual(invalidNonce);
    }
    expect(await verify(await proofOf(holder, { payload: { nonce: 42 } }))).toEqual(invalidProof);
    // the nonce is compared exactly
    expect(await verify(await proofOf(holder, { payload: { nonce: NONCE.toUpperCase() } }))).toEqual(invalidNonce);
    // a bad signature is invalid_proof even when the nonce is wrong too
    const forged = await proofOf(holder, { payload: { nonce: 'c_nonce_other' }, signer: await generateSigner() });
    expect(await verify(forged)).toEqual(invalidProof);
  });

  it('refuses a proof whose header is not exactly typ, alg and the key of the wallet', async () => {
    const holder = await generateSigner();
    const other = await generateSigner();
    const jwk = bareJwk(holder.publicJwk);
    const badHeaders: Array<[string, Record<string, unknown>]> = [
      ['typ JWT', { typ: 'JWT' }],
      ['no typ', { typ: undefined }],
      ['typ with a suffix', { typ: `${TYP.vciProof} ` }],
      ['the typ of a credential', { typ: TYP.sdJwtVc }],
      ['a kid instead of a jwk', { jwk: undefined, kid: 'did:example:123#key-1' }],
      ['a kid beside the jwk', { kid: 'key-1' }],
      ['a certificate chain beside the jwk', { x5c: ['MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'] }],
      ['a certificate chain and no jwk', { jwk: undefined, x5c: ['MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'] }],
      ['no key at all', { jwk: undefined }],
      ['a jwk with a private part', { jwk: { ...jwk, d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } }],
      ['a jwk that is not a key', { jwk: 'MFkwEwYHKoZIzj0C' }],
      ['an RSA key', { jwk: { kty: 'RSA', n: 'AQAB', e: 'AQAB' } }],
      ['a point that is not on the curve', { jwk: { ...jwk, x: jwk.y, y: jwk.y } }],
      ['another algorithm', { alg: 'ES384' }],
      ['no algorithm', { alg: 'none' }],
      ['a symmetric algorithm', { alg: 'HS256' }],
      ['a critical extension', { crit: ['exp'] }],
      ['a header member that nobody asked for', { trust_chain: ['x'] }],
    ];
    for (const [label, header] of badHeaders) {
      expect(await verify(await proofOf(holder, { header })), label).toEqual(invalidProof);
    }
    // the signature must be by the embedded key
    expect(await verify(await proofOf(holder, { signer: other })), 'signed by another key').toEqual(invalidProof);
    // and over this payload
    const good = await proofOf(holder);
    const [head, , signature] = good.split('.');
    expect(
      await verify(`${head}.${segment({ aud: AUDIENCE, iat: NOW, nonce: 'c_nonce_other' })}.${signature}`),
    ).toEqual(invalidProof);
    expect(await verify(good.slice(0, -4))).toEqual(invalidProof);
  });

  it('accepts a proof from five minutes ago and a minute ahead, and nothing older or further ahead', async () => {
    const holder = await generateSigner();
    const at = (iat: unknown) => proofOf(holder, { payload: { iat } });
    expect((await verify(await at(NOW - 300))).ok).toBe(true);
    expect(await verify(await at(NOW - 301))).toEqual(invalidProof);
    expect(await verify(await at(NOW - 600))).toEqual(invalidProof); //  ten minutes old
    expect((await verify(await at(NOW + 60))).ok).toBe(true);
    expect(await verify(await at(NOW + 61))).toEqual(invalidProof);
    for (const iat of [undefined, '1793750400', null, Number.NaN]) {
      expect(await verify(await at(iat)), String(iat)).toEqual(invalidProof);
    }
    // the window can be widened or narrowed by the issuer
    expect((await verify(await at(NOW - 600), { maxAgeSeconds: 600 })).ok).toBe(true);
    expect(await verify(await at(NOW - 31), { maxAgeSeconds: 30 })).toEqual(invalidProof);
    expect((await verify(await at(NOW), { maxAgeSeconds: 0 })).ok).toBe(true);
  });

  it('reports hostile input instead of throwing, and throws only for the mistakes of its caller', async () => {
    const holder = await generateSigner();
    const good = await proofOf(holder);
    const hostile = [
      '',
      'a.b.c',
      'not a jwt',
      `${segment({ alg: 'ES256' })}.${segment('[]')}.AAAA`,
      `${good}.extra`,
      `${good}x`.repeat(1_000),
      good.replace(/^[^.]+/, '!!!'),
      123,
      null,
      undefined,
      {},
    ];
    for (const proof of hostile) expect(await verify(proof), String(proof).slice(0, 20)).toEqual(invalidProof);

    expect(await codeOf(() => verify(good, { audience: '' }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => verify(good, { nonce: '' }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => verify(good, { now: Number.NaN }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => verify(good, { maxAgeSeconds: -1 }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => verify(good, { maxAgeSeconds: Number.NaN }))).toBe('INVALID_ARGUMENT');
  });

  it('verifies with the crypto provider that it is given', async () => {
    const holder = await generateSigner();
    const counting = countingCrypto();
    expect((await verify(await proofOf(holder), { crypto: counting })).ok).toBe(true);
    expect(counting.calls.verify).toBe(1);
  });
});
