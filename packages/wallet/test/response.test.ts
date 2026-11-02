import {
  MUTUAL_AUD,
  VCT,
  decodeCredential,
  decodeFrame,
  encodeFrame,
  generateSigner,
  parseSdJwt,
  presentCredential,
  randomId,
  signPresentationRequest,
  verifyKeyBinding,
} from '@umis/core';
import type { DisclosableClaim, ParsedRequest, PresentationRequestPayloadV1, Signer } from '@umis/core';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  createFullFrame,
  createFullQr,
  createResponseFrame,
  createResponseQr,
  disclosurePlan,
  parseRequestQr,
} from '../src/index.js';
import { ISSUER_ID, MEMBER_CLAIMS, T0, createFakeIssuer, failureOf } from './fake-issuer.js';

const NOW = T0 + 3_600;
const VERIFIER = 'urn:umis:verifier:warehouse-b';
const OPENER = 'urn:umis:wallet:oleh';
const TEN_TONNES = { action: 'receive_materials', resource: 'rebar', amount: 10, unit: 't' };

let verifier: Signer;
let oleh: Signer;
let maria: Signer;
let olehCredential: string;
let mariaCredential: string;

beforeAll(async () => {
  const issuer = await createFakeIssuer();
  [verifier, oleh, maria] = await Promise.all([generateSigner(), generateSigner(), generateSigner()]);
  olehCredential = await issuer.issue({ holder: oleh.publicJwk, jti: 'cred-oleh-0001' });
  mariaCredential = await issuer.issue({
    holder: maria.publicJwk,
    jti: 'cred-maria-0001',
    vct: VCT.orgMember,
    claims: MEMBER_CLAIMS,
  });
});

/** The request of a verifier as the text of a QR code, read by the wallet. */
async function asked(over: Partial<PresentationRequestPayloadV1> = {}): Promise<ParsedRequest> {
  const payload: PresentationRequestPayloadV1 = {
    v: 1,
    nonce: randomId(16),
    aud: VERIFIER,
    iat: NOW,
    exp: NOW + 60,
    vct: [VCT.orgMember, VCT.roleAuthority],
    claims: ['org', 'role', 'authority', 'delegation'],
    authority: TEN_TONNES,
    ...over,
  };
  const qr = encodeFrame({ kind: 'request', tokens: [await signPresentationRequest(payload, verifier)] });
  return parseRequestQr(qr, { verifierKeys: [verifier.publicJwk], now: NOW });
}

/** The opening of a mutual exchange by Oleh: his request and his own presentation in one frame. */
async function opened(): Promise<ParsedRequest> {
  const nonce = randomId(16);
  const request = await signPresentationRequest(
    {
      v: 1,
      nonce,
      aud: OPENER,
      iat: NOW,
      exp: NOW + 60,
      vct: [VCT.orgMember, VCT.roleAuthority],
      claims: ['org', 'role', 'display'],
      mutual: true,
    },
    oleh,
  );
  const presentation = await presentCredential({
    credential: olehCredential,
    disclose: ['org', 'role'],
    kb: { signer: oleh, aud: MUTUAL_AUD, nonce, iat: NOW },
  });
  return parseRequestQr(encodeFrame({ kind: 'mutual_init', tokens: [request, presentation] }), { now: NOW });
}

/** The claims a presentation discloses, by name. */
const namesOf = (presentation: string): string[] => decodeCredential(presentation).disclosable.slice().sort();

describe('the response to a request', () => {
  it('is bound to the audience and the nonce of the request and discloses what is asked', async () => {
    const request = await asked();
    const qr = await createResponseQr({
      request,
      sdJwtVc: olehCredential,
      disclose: ['org', 'role', 'authority'],
      signer: oleh,
      now: NOW + 1,
    });
    expect(qr.startsWith('UMIS1P:')).toBe(true);

    const frame = decodeFrame(qr);
    expect(frame.kind).toBe('response');
    const presentation = await parseSdJwt(frame.tokens[0]!);
    const binding = await verifyKeyBinding(presentation, {
      aud: VERIFIER,
      nonce: request.nonce,
      now: NOW + 1,
      maxAgeSeconds: 60,
      skewSeconds: 10,
    });
    expect(binding).toEqual({ ok: true, iat: NOW + 1, nonce: request.nonce });
    expect(presentation.kbJwt!.payload).toMatchObject({ aud: VERIFIER, nonce: request.nonce, iat: NOW + 1 });

    // the authority comes with its delegation; the unit of the crew and the name stay with the holder
    expect(namesOf(frame.tokens[0]!)).toEqual(['authority', 'delegation', 'org', 'role']);
    expect(Object.keys(presentation.claims).sort()).toEqual(['authority', 'delegation', 'org', 'role']);
  });

  it('is the same frame for a transport as for a QR code', async () => {
    const request = await asked();
    const frame = await createResponseFrame({
      request,
      sdJwtVc: olehCredential,
      disclose: ['org'],
      signer: oleh,
      now: NOW + 1,
    });
    expect(frame.kind).toBe('response');
    expect(frame.tokens).toHaveLength(1);
    expect(decodeFrame(encodeFrame(frame))).toEqual(frame);
  });

  it('never discloses beyond the request', async () => {
    const request = await asked({ claims: ['org', 'role'], authority: undefined });
    const beyond = await failureOf(
      createResponseQr({ request, sdJwtVc: olehCredential, disclose: ['org', 'display'], signer: oleh, now: NOW }),
    );
    expect(beyond.code).toBe('INVALID_ARGUMENT');
    expect(beyond.message).toContain('display');

    const unknown = await failureOf(
      createResponseQr({
        request,
        sdJwtVc: olehCredential,
        disclose: ['org', 'photo' as DisclosableClaim],
        signer: oleh,
        now: NOW,
      }),
    );
    expect(unknown.code).toBe('INVALID_ARGUMENT');

    const wrongType = await asked({ vct: [VCT.orgMember], claims: ['org'], authority: undefined });
    const refused = await failureOf(
      createResponseQr({ request: wrongType, sdJwtVc: olehCredential, disclose: ['org'], signer: oleh, now: NOW }),
    );
    expect(refused.code).toBe('INVALID_ARGUMENT');

    // authority alone does not bring the delegation along when the request does not ask for it
    const bare = await asked({ claims: ['org', 'authority'], authority: undefined });
    const frame = await createResponseFrame({
      request: bare,
      sdJwtVc: olehCredential,
      disclose: ['authority'],
      signer: oleh,
      now: NOW,
    });
    expect(namesOf(frame.tokens[0]!)).toEqual(['authority']);
  });

  it('is signed by the holder key and by nobody else', async () => {
    const request = await asked();
    const error = await failureOf(
      createResponseQr({ request, sdJwtVc: olehCredential, disclose: ['org'], signer: maria, now: NOW }),
    );
    expect(error.code).toBe('INVALID_ARGUMENT');
  });

  it('answers the opening of a mutual exchange with a mutual reply', async () => {
    const opening = await opened();
    expect(opening.kind).toBe('mutual_init');
    const frame = await createResponseFrame({
      request: opening,
      sdJwtVc: mariaCredential,
      disclose: ['org', 'role', 'display'],
      signer: maria,
      now: NOW + 1,
    });
    expect(frame.kind).toBe('mutual_reply');

    const presentation = await parseSdJwt(frame.tokens[0]!);
    expect(presentation.kbJwt!.payload).toMatchObject({ aud: OPENER, nonce: opening.nonce, iat: NOW + 1 });
    expect(Object.keys(presentation.claims).sort()).toEqual(['display', 'org', 'role']);
  });
});

describe('the full presentation', () => {
  it('is bound to the issuer by default, with a fresh nonce each time', async () => {
    const first = await createFullFrame({
      sdJwtVc: mariaCredential,
      disclose: ['org', 'display'],
      signer: maria,
      now: NOW,
    });
    const second = await createFullFrame({ sdJwtVc: mariaCredential, disclose: ['org'], signer: maria, now: NOW });
    expect(first.kind).toBe('full');

    const one = (await parseSdJwt(first.tokens[0]!)).kbJwt!.payload;
    const two = (await parseSdJwt(second.tokens[0]!)).kbJwt!.payload;
    expect(one).toMatchObject({ aud: ISSUER_ID, iat: NOW });
    expect(one.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/); // 16 random bytes
    expect(two.nonce).not.toBe(one.nonce);

    const qr = await createFullQr({
      sdJwtVc: mariaCredential,
      disclose: ['org'],
      signer: maria,
      audience: 'urn:umis:verifier:door',
      now: NOW,
    });
    expect(qr.startsWith('UMIS1F:')).toBe(true);
    const presentation = await parseSdJwt(decodeFrame(qr).tokens[0]!);
    expect(presentation.kbJwt!.payload.aud).toBe('urn:umis:verifier:door');
  });

  it('refuses a claim the credential cannot disclose and a signer that does not hold it', async () => {
    const missing = await failureOf(
      createFullQr({ sdJwtVc: mariaCredential, disclose: ['authority'], signer: maria, now: NOW }),
    );
    expect(missing.code).toBe('INVALID_ARGUMENT');
    const foreign = await failureOf(
      createFullQr({ sdJwtVc: mariaCredential, disclose: ['org'], signer: oleh, now: NOW }),
    );
    expect(foreign.code).toBe('INVALID_ARGUMENT');
  });
});

describe('what answering a request would show', () => {
  it('lists what would be shown and what the credential lacks', async () => {
    const full = disclosurePlan(
      { claims: ['org', 'authority', 'delegation'], vct: [VCT.roleAuthority] },
      decodeCredential(olehCredential),
    );
    expect(full).toEqual({ usable: true, disclose: ['org', 'authority', 'delegation'], missing: [] });

    const member = decodeCredential(mariaCredential);
    const lacking = disclosurePlan({ claims: ['org', 'authority'], vct: [VCT.orgMember, VCT.roleAuthority] }, member);
    expect(lacking).toEqual({ usable: false, disclose: ['org'], missing: ['authority'] });

    const unaccepted = disclosurePlan({ claims: ['org'], vct: [VCT.roleAuthority] }, member);
    expect(unaccepted).toEqual({ usable: false, disclose: [], missing: [] });
  });
});
