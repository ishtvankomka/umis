import { TYP, decodeCredential, decodeFrame, generateSigner, verifyJws } from '@umis/core';
import type { OneWayTokenPayload, Signer } from '@umis/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { createOneWayQr } from '../src/index.js';
import { ISSUER_ID, T0, createFakeIssuer, failureOf } from './fake-issuer.js';

const NOW = T0 + 3_600;
const QR_ALPHANUMERIC = /^[0-9A-Z $%*+\-./:]+$/;

let oleh: Signer;
let stranger: Signer;
let credential: string;

beforeAll(async () => {
  const issuer = await createFakeIssuer();
  [oleh, stranger] = await Promise.all([generateSigner(), generateSigner()]);
  credential = await issuer.issue({ holder: oleh.publicJwk, jti: 'cred-oleh-0001' });
});

async function tokenOf(qr: string) {
  const frame = decodeFrame(qr);
  expect(frame.kind).toBe('oneway');
  return verifyJws<OneWayTokenPayload>(frame.tokens[0]!, {
    typ: TYP.oneWay,
    key: decodeCredential(credential).cnfJwk,
  });
}

describe('the one-way QR code', () => {
  it('carries a token of the credential that verifies with the key the credential is bound to', async () => {
    const qr = await createOneWayQr({ sdJwtVc: credential, signer: oleh, now: NOW });
    expect(qr.startsWith('UMIS1O:') && qr.endsWith('.')).toBe(true);
    expect(qr).toMatch(QR_ALPHANUMERIC);

    const token = await tokenOf(qr);
    expect(token.header).toEqual({ alg: 'ES256', typ: 'umis-ow+jwt' }); // no key name: it only costs room in the code
    expect(token.payload).toMatchObject({ cred_ref: 'cred-oleh-0001', iat: NOW, exp: NOW + 30 });
  });

  it('is meant for the issuer of the credential unless an audience is given', async () => {
    expect((await tokenOf(await createOneWayQr({ sdJwtVc: credential, signer: oleh, now: NOW }))).payload.aud).toBe(
      ISSUER_ID,
    );
    const elsewhere = await createOneWayQr({
      sdJwtVc: credential,
      signer: oleh,
      now: NOW,
      audience: 'https://issuer.example/issuer/t/coworking-v',
    });
    expect((await tokenOf(elsewhere)).payload.aud).toBe('https://issuer.example/issuer/t/coworking-v');
  });

  it('lives 30 seconds by default, and every token has a counter that goes up', async () => {
    const first = (await tokenOf(await createOneWayQr({ sdJwtVc: credential, signer: oleh, now: NOW }))).payload;
    const second = (await tokenOf(await createOneWayQr({ sdJwtVc: credential, signer: oleh, now: NOW }))).payload;
    expect(first.exp - first.iat).toBe(30);
    expect(second.ctr).toBe(first.ctr + 1);

    const short = (await tokenOf(await createOneWayQr({ sdJwtVc: credential, signer: oleh, now: NOW, ttlSeconds: 10 })))
      .payload;
    expect(short.exp - short.iat).toBe(10);
    const counted = await createOneWayQr({ sdJwtVc: credential, signer: oleh, now: NOW, ctr: 7 });
    expect((await tokenOf(counted)).payload.ctr).toBe(7);
  });

  it('refuses a lifetime over 30 seconds and a signer that does not hold the credential', async () => {
    for (const ttlSeconds of [31, 0, -1, Number.NaN]) {
      const error = await failureOf(createOneWayQr({ sdJwtVc: credential, signer: oleh, now: NOW, ttlSeconds }));
      expect(error.code).toBe('INVALID_ARGUMENT');
    }
    const foreign = await failureOf(createOneWayQr({ sdJwtVc: credential, signer: stranger, now: NOW }));
    expect(foreign.code).toBe('INVALID_ARGUMENT');
    const noClock = await failureOf(createOneWayQr({ sdJwtVc: credential, signer: oleh, now: Number.NaN }));
    expect(noClock.code).toBe('INVALID_ARGUMENT');
  });
});
