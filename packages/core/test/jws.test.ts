import { createHmac } from 'node:crypto';
import { CompactSign, compactVerify, exportJWK, generateKeyPair, importJWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  UmisError,
  base64urlDecode,
  base64urlEncode,
  concatBytes,
  decodeJwsUnverified,
  hexDecode,
  hexEncode,
  signJws,
  utf8Decode,
  utf8Encode,
  verifyJws,
  webCryptoProvider,
  type CryptoProvider,
  type EcPublicJwk,
  type JwsHeader,
  type Signer,
} from '../src/index.js';
import { nobleCryptoProvider } from '../src/noble.js';

const providers: Array<[string, CryptoProvider]> = [
  ['webcrypto', webCryptoProvider],
  ['noble', nobleCryptoProvider()],
];

/** The ES256 example of RFC 7515 appendix A.3, public key only, kept in pieces. */
const RFC7515_A3 = {
  header: 'eyJhbGciOiJFUzI1NiJ9',
  payload: 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
  signature: 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  },
} satisfies { header: string; payload: string; signature: string; key: EcPublicJwk };

/** Order of the P-256 group (FIPS 186-4 D.1.2.3). */
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const TYP = 'umis-test+jwt';
const PAYLOAD = { sub: 'holder-1', n: 7, nested: { ok: true } };

async function codeOf(run: () => Promise<unknown> | unknown): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

const segment = (value: unknown): string =>
  base64urlEncode(utf8Encode(typeof value === 'string' ? value : JSON.stringify(value)));

/** A token whose signature is valid for exactly this header and payload, so that only the rules can reject it. */
async function forge(signer: Signer, header: object, payload: object | string = PAYLOAD): Promise<string> {
  const signingText = `${segment(header)}.${segment(payload)}`;
  return `${signingText}.${base64urlEncode(await signer.sign(utf8Encode(signingText)))}`;
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * The same 64 signature bytes spelled another way: the last of the 86 characters carries four unused bits, and a
 * canonical encoder leaves them zero.
 */
function withTrailingBits(signatureText: string): string {
  const last = BASE64URL_ALPHABET.indexOf(signatureText.slice(-1));
  return signatureText.slice(0, -1) + BASE64URL_ALPHABET.charAt(last | 1);
}

const sOf = (signature: Uint8Array): bigint => BigInt(`0x${hexEncode(signature.subarray(32))}`);

/** Same signature with s replaced by n - s, which ECDSA verifies just as well (the malleable twin). */
function mirrored(signature: Uint8Array): Uint8Array {
  return concatBytes(
    signature.subarray(0, 32),
    hexDecode((P256_ORDER - sOf(signature)).toString(16).padStart(64, '0')),
  );
}

describe.each(providers)('RFC 7515 appendix A.3 with the %s provider', (_name, provider) => {
  const signingInput = utf8Encode(`${RFC7515_A3.header}.${RFC7515_A3.payload}`);
  const signature = base64urlDecode(RFC7515_A3.signature);

  it('verifies the published signature', async () => {
    expect(await provider.verifyEs256(RFC7515_A3.key, signingInput, signature)).toBe(true);
  });

  it('fails when one bit of the signature, the data or the key changes', async () => {
    const badSignature = signature.slice();
    badSignature[17] = badSignature[17]! ^ 0x04;
    expect(await provider.verifyEs256(RFC7515_A3.key, signingInput, badSignature)).toBe(false);

    const badData = signingInput.slice();
    badData[9] = badData[9]! ^ 0x01;
    expect(await provider.verifyEs256(RFC7515_A3.key, badData, signature)).toBe(false);

    const badX = base64urlDecode(RFC7515_A3.key.x);
    badX[5] = badX[5]! ^ 0x10;
    expect(await provider.verifyEs256({ ...RFC7515_A3.key, x: base64urlEncode(badX) }, signingInput, signature)).toBe(
      false,
    );
  });

  it('answers false, never throws, for signatures of another length and for keys that are not curve points', async () => {
    for (const length of [0, 63, 65, 72]) {
      expect(await provider.verifyEs256(RFC7515_A3.key, signingInput, new Uint8Array(length))).toBe(false);
    }
    const offCurve = { ...RFC7515_A3.key, y: RFC7515_A3.key.x };
    expect(await provider.verifyEs256(offCurve, signingInput, signature)).toBe(false);
    expect(await provider.verifyEs256({ ...RFC7515_A3.key, crv: 'P-384' } as never, signingInput, signature)).toBe(
      false,
    );
  });
});

describe.each(providers)('interoperability with jose, signing with the %s provider', (_name, provider) => {
  it('signJws output passes jose.compactVerify', async () => {
    const signer = await provider.generateSigner();
    const token = await signJws({ header: { typ: TYP }, payload: PAYLOAD, signer });
    const verified = await compactVerify(token, await importJWK(signer.publicJwk, 'ES256'));
    expect(verified.protectedHeader).toEqual({ alg: 'ES256', typ: TYP, kid: signer.kid });
    expect(JSON.parse(new TextDecoder().decode(verified.payload))).toEqual(PAYLOAD);
  });

  it('jose.CompactSign output passes verifyJws', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const jwk = await exportJWK(publicKey);
    const token = await new CompactSign(utf8Encode(JSON.stringify(PAYLOAD)))
      .setProtectedHeader({ alg: 'ES256', typ: TYP, kid: 'jose-key' })
      .sign(privateKey);
    const key: EcPublicJwk = { kty: 'EC', crv: 'P-256', x: jwk.x!, y: jwk.y!, kid: 'jose-key' };
    const decoded = await verifyJws(token, { typ: TYP, key, crypto: provider });
    expect(decoded.payload).toEqual(PAYLOAD);
    expect(decoded.header).toEqual({ alg: 'ES256', typ: TYP, kid: 'jose-key' });
  });
});

describe.each(providers)('high-S signatures, verified by the %s provider', (_name, verifier) => {
  it.each(providers)('are accepted when produced by the %s provider', async (_signerName, signerProvider) => {
    const signer = await signerProvider.generateSigner();
    const token = await signJws({ header: { typ: TYP }, payload: PAYLOAD, signer });
    const [header, payload, encoded] = token.split('.') as [string, string, string];
    const signature = base64urlDecode(encoded);
    const twin = mirrored(signature);
    const [low, high] = sOf(signature) < sOf(twin) ? [signature, twin] : [twin, signature];
    expect(sOf(low)).toBeLessThanOrEqual(P256_ORDER / 2n);
    expect(sOf(high)).toBeGreaterThan(P256_ORDER / 2n);
    for (const variant of [low, high]) {
      const rebuilt = `${header}.${payload}.${base64urlEncode(variant)}`;
      const decoded = await verifyJws(rebuilt, { typ: TYP, key: signer.publicJwk, crypto: verifier });
      expect(decoded.payload).toEqual(PAYLOAD);
      expect(await verifier.verifyEs256(signer.publicJwk, decoded.signingInput, variant)).toBe(true);
    }
  });
});

describe.each(providers)('JWS hardening with the %s provider', (_name, provider) => {
  let signer: Signer;
  let other: Signer;

  beforeAll(async () => {
    signer = await provider.generateSigner({ kid: 'k1' });
    other = await provider.generateSigner({ kid: 'k2' });
  });

  const verify = (
    token: string,
    extra: { allowHeader?: string[]; key?: Parameters<typeof verifyJws>[1]['key'] } = {},
  ) => verifyJws(token, { typ: TYP, key: signer.publicJwk, crypto: provider, ...extra });

  it('accepts a well-formed token', async () => {
    const token = await signJws({ header: { typ: TYP }, payload: PAYLOAD, signer });
    expect(await verify(token)).toMatchObject({ payload: PAYLOAD, header: { alg: 'ES256', typ: TYP, kid: 'k1' } });
  });

  it('rejects every algorithm but ES256 before looking at the signature: UNSUPPORTED_FORMAT', async () => {
    const empty = `${segment({ alg: 'none', typ: TYP })}.${segment(PAYLOAD)}.`;
    const secret = utf8Encode(JSON.stringify(signer.publicJwk));
    const signingText = `${segment({ alg: 'HS256', typ: TYP, kid: 'k1' })}.${segment(PAYLOAD)}`;
    const hmac = `${signingText}.${base64urlEncode(createHmac('sha256', secret).update(signingText).digest())}`;
    const lowercase = await forge(signer, { alg: 'es256', typ: TYP, kid: 'k1' });
    const es384 = await forge(signer, { alg: 'ES384', typ: TYP, kid: 'k1' });
    const missing = await forge(signer, { typ: TYP, kid: 'k1' });
    for (const [why, token] of Object.entries({
      none: empty,
      'HS256 keyed with the public key': hmac,
      lowercase,
      es384,
      missing,
    })) {
      expect(await codeOf(() => verify(token)), why).toBe('UNSUPPORTED_FORMAT');
    }
  });

  it('rejects crit, even when the caller allows it: MALFORMED', async () => {
    const token = await forge(signer, { alg: 'ES256', typ: TYP, kid: 'k1', crit: ['exp'], exp: 1 });
    expect(await codeOf(() => verify(token))).toBe('MALFORMED');
    expect(await codeOf(() => verify(token, { allowHeader: ['crit', 'exp'] }))).toBe('MALFORMED');
  });

  it('rejects header members it was not told about, and accepts them once allowed: MALFORMED', async () => {
    const token = await forge(signer, { alg: 'ES256', typ: TYP, kid: 'k1', foo: 'bar' });
    expect(await codeOf(() => verify(token))).toBe('MALFORMED');
    expect((await verify(token, { allowHeader: ['foo'] })).header.foo).toBe('bar');
    const x5c = await forge(signer, { alg: 'ES256', typ: TYP, kid: 'k1', x5c: ['MIIB'] });
    expect(await codeOf(() => verify(x5c))).toBe('MALFORMED');
    const polluted = await forge(
      signer,
      JSON.parse('{"alg":"ES256","typ":"umis-test+jwt","kid":"k1","__proto__":{"admin":true}}'),
    );
    expect(await codeOf(() => verify(polluted))).toBe('MALFORMED');
  });

  it('demands the exact typ: UNSUPPORTED_FORMAT', async () => {
    for (const typ of ['umis-other+jwt', 'UMIS-TEST+JWT', `application/${TYP}`, '', undefined]) {
      const token = await forge(signer, { alg: 'ES256', kid: 'k1', ...(typ === undefined ? {} : { typ }) });
      expect(await codeOf(() => verify(token)), String(typ)).toBe('UNSUPPORTED_FORMAT');
    }
    const token = await signJws({ header: { typ: 'umis-other+jwt' }, payload: PAYLOAD, signer });
    expect(await codeOf(() => verifyJws(token, { typ: TYP, key: signer.publicJwk, crypto: provider }))).toBe(
      'UNSUPPORTED_FORMAT',
    );
    expect(
      (await verifyJws(token, { typ: [TYP, 'umis-other+jwt'], key: signer.publicJwk, crypto: provider })).header.typ,
    ).toBe('umis-other+jwt');
  });

  it('demands three segments, JSON objects and a 64-byte signature: MALFORMED', async () => {
    const good = await signJws({ header: { typ: TYP }, payload: PAYLOAD, signer });
    const [h, p, s] = good.split('.') as [string, string, string];
    const signature = base64urlDecode(s);
    // The respelled signature is the same 64 bytes to a lenient decoder such as atob, which is why ours must not allow it.
    const standard = (text: string): string => text.replace(/-/g, '+').replace(/_/g, '/');
    expect(withTrailingBits(s)).not.toBe(s);
    expect(atob(standard(withTrailingBits(s)))).toBe(atob(standard(s)));
    const cases: Record<string, string> = {
      'four segments': `${good}.AAAA`,
      'two segments': `${h}.${p}`,
      'one segment': h,
      'empty string': '',
      'JWE-shaped five segments': `${good}.AAAA.AAAA`,
      '65-byte signature': `${h}.${p}.${base64urlEncode(concatBytes(signature, Uint8Array.of(0)))}`,
      '63-byte signature': `${h}.${p}.${base64urlEncode(signature.subarray(0, 63))}`,
      'empty signature': `${h}.${p}.`,
      'DER-length signature': `${h}.${p}.${base64urlEncode(new Uint8Array(70).fill(1))}`,
      'padded signature': `${h}.${p}.${s}==`,
      'standard-alphabet character': `${h}.${p}.${s.slice(0, 10)}+${s.slice(11)}`,
      'signature with non-zero trailing bits (the same bytes in another spelling)': `${h}.${p}.${withTrailingBits(s)}`,
      'header that is an array': `${segment('[]')}.${p}.${s}`,
      'header that is not JSON': `${segment('not json')}.${p}.${s}`,
      'header with invalid UTF-8': `${base64urlEncode(Uint8Array.of(0x7b, 0xff, 0x7d))}.${p}.${s}`,
      'payload that is an array': `${h}.${segment('[1]')}.${s}`,
      'payload that is a string': `${h}.${segment('"text"')}.${s}`,
      'payload that is null': `${h}.${segment('null')}.${s}`,
      'payload that is not JSON': `${h}.${segment('{')}.${s}`,
      'header typ that is not a string': await forge(signer, { alg: 'ES256', typ: 7, kid: 'k1' }),
      'header kid that is not a string': await forge(signer, { alg: 'ES256', typ: TYP, kid: { a: 1 } }),
      'header jwk that is not a P-256 key': await forge(signer, {
        alg: 'ES256',
        typ: TYP,
        jwk: { kty: 'oct', k: 'AAAA' },
      }),
    };
    for (const [why, token] of Object.entries(cases)) {
      expect(await codeOf(() => verify(token)), why).toBe('MALFORMED');
      expect(await codeOf(() => decodeJwsUnverified(token)), `decode: ${why}`).toBe('MALFORMED');
    }
    expect(await codeOf(() => verify(undefined as never))).toBe('MALFORMED');
  });

  it('rejects altered tokens and foreign keys: SIGNATURE_INVALID', async () => {
    const good = await signJws({ header: { typ: TYP }, payload: PAYLOAD, signer });
    const [h, p, s] = good.split('.') as [string, string, string];
    const flipped = base64urlDecode(s);
    flipped[3] = flipped[3]! ^ 0x01;
    const cases: Record<string, string> = {
      'one signature bit flipped': `${h}.${p}.${base64urlEncode(flipped)}`,
      'payload replaced': `${h}.${segment({ ...PAYLOAD, sub: 'attacker' })}.${s}`,
      'header re-serialised with the same members in another order': `${segment({ typ: TYP, alg: 'ES256', kid: 'k1' })}.${p}.${s}`,
      'signed by another key': await forge(other, { alg: 'ES256', typ: TYP, kid: 'k1' }),
    };
    for (const [why, token] of Object.entries(cases)) {
      expect(await codeOf(() => verify(token)), why).toBe('SIGNATURE_INVALID');
    }
    const garbage = { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' } as unknown as EcPublicJwk;
    expect(await codeOf(() => verify(good, { key: garbage }))).toBe('SIGNATURE_INVALID');
    expect(await codeOf(() => verify(good, { key: { ...signer.publicJwk, y: signer.publicJwk.x } }))).toBe(
      'SIGNATURE_INVALID',
    );
  });

  it('finds the key by kid, tries a bounded number without one, and reports a missing key: ISSUER_KEY_UNKNOWN', async () => {
    const withKid = await signJws({ header: { typ: TYP }, payload: PAYLOAD, signer });
    const withoutKid = await signJws({ header: { typ: TYP, jwk: signer.publicJwk }, payload: PAYLOAD, signer });
    expect(await verify(withKid, { key: [other.publicJwk, signer.publicJwk] })).toMatchObject({ payload: PAYLOAD });
    expect(await codeOf(() => verify(withKid, { key: [other.publicJwk] }))).toBe('ISSUER_KEY_UNKNOWN');
    expect(await codeOf(() => verify(withKid, { key: [] }))).toBe('ISSUER_KEY_UNKNOWN');
    expect(await codeOf(() => verify(withKid, { key: () => undefined }))).toBe('ISSUER_KEY_UNKNOWN');
    expect(await codeOf(() => verify(withKid, { key: [{ ...signer.publicJwk, kid: 'k2' }] }))).toBe(
      'ISSUER_KEY_UNKNOWN',
    );

    expect(await verify(withoutKid, { key: [other.publicJwk, signer.publicJwk] })).toMatchObject({ payload: PAYLOAD });
    const decoys = await Promise.all(Array.from({ length: 8 }, () => provider.generateSigner()));
    const crowded = [...decoys.map((d) => d.publicJwk), signer.publicJwk];
    expect(await codeOf(() => verify(withoutKid, { key: crowded }))).toBe('SIGNATURE_INVALID');
    expect(await verify(withoutKid, { key: crowded.slice(1) })).toMatchObject({ payload: PAYLOAD });

    const seen: JwsHeader[] = [];
    await verify(withoutKid, {
      key: (header) => {
        seen.push(header);
        return header.jwk;
      },
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.jwk).toEqual(signer.publicJwk);
  });
});

describe('signJws', () => {
  it('forces ES256, defaults kid to the signer, and puts the members in a fixed order', async () => {
    const signer = await webCryptoProvider.generateSigner({ kid: 'kid-1' });
    const token = await signJws({ header: { typ: TYP, alg: 'none', custom: 1 }, payload: PAYLOAD, signer });
    const { header, payload } = decodeJwsUnverified(token);
    expect(Object.keys(header)).toEqual(['alg', 'typ', 'kid', 'custom']);
    expect(header).toEqual({ alg: 'ES256', typ: TYP, kid: 'kid-1', custom: 1 });
    expect(payload).toEqual(PAYLOAD);
    const named = decodeJwsUnverified(
      await signJws({ header: { typ: TYP, kid: 'explicit' }, payload: PAYLOAD, signer }),
    );
    expect(named.header.kid).toBe('explicit');
  });

  it('embeds a jwk instead of a kid, and only its public members', async () => {
    const signer = await webCryptoProvider.generateSigner();
    const leaky = { ...signer.publicJwk, d: 'c2VjcmV0LXByaXZhdGUta2V5LWJ5dGVz', key_ops: ['sign'] };
    const token = await signJws({ header: { typ: TYP, jwk: leaky }, payload: PAYLOAD, signer });
    const headerJson = utf8Decode(base64urlDecode(token.split('.')[0]!));
    expect(JSON.parse(headerJson).jwk).toEqual(signer.publicJwk);
    expect(headerJson).not.toContain('"d"');
    expect(decodeJwsUnverified(token).header.kid).toBeUndefined();
  });

  it('refuses what verification would refuse, and signers that break the contract: INVALID_ARGUMENT', async () => {
    const signer = await webCryptoProvider.generateSigner();
    const ok = { header: { typ: TYP }, payload: PAYLOAD, signer };
    expect(await codeOf(() => signJws({ ...ok, header: { typ: '' } }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => signJws({ ...ok, header: {} as never }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => signJws({ ...ok, header: { typ: TYP, crit: ['exp'] } }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => signJws({ ...ok, header: { typ: TYP, jwk: { kty: 'oct' } as never } }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await codeOf(() => signJws({ ...ok, payload: [1] }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => signJws({ ...ok, payload: null as never }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => signJws({ ...ok, payload: { n: 1n } }))).toBe('INVALID_ARGUMENT');
    const der: Signer = { ...signer, sign: async () => new Uint8Array(70) };
    expect(await codeOf(() => signJws({ ...ok, signer: der }))).toBe('INVALID_ARGUMENT');
  });
});
