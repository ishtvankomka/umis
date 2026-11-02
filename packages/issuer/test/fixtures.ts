import { UmisError, base64urlEncode, generateSigner, utf8Encode, webCryptoProvider, VCT } from '@umis/core';
import type { AuthorityItem, CryptoProvider, EcPublicJwk, Signer, UmisClaimSet } from '@umis/core';
import type { IssueSdJwtVcInput } from '../src/index.js';

export const DAY = 86_400;
/** 2026-11-04T00:00:00Z. */
export const NOW = 1_793_750_400;
export const ISSUER = 'https://issuer.example/contractor-a';
export const STATUS_URI = 'https://issuer.example/status/contractor-a/1';

export const ORG = { id: 'contractor-a', name: 'Підрядник А' };
export const ORG_UNIT = { id: 'bridge-crew', name: 'Бригада будівництва мосту' };
export const OLEH_ROLE = { code: 'crew_lead', name: 'Керівник бригади' };

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

/** The code of the error that `run` throws or rejects with, or undefined when it finishes. */
export async function codeOf(run: () => unknown): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

/** The message of the error that `run` throws or rejects with. */
export async function messageOf(run: () => unknown): Promise<string> {
  try {
    await run();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error('expected a failure, but nothing failed');
}

export interface Keys {
  issuer: Signer;
  oleh: Signer;
  ivan: Signer;
}

export async function makeKeys(): Promise<Keys> {
  const [issuer, oleh, ivan] = await Promise.all([generateSigner(), generateSigner(), generateSigner()]);
  return { issuer, oleh, ivan };
}

/** A request for a root role-authority credential of Oleh, as the platform would make it. */
export function roleAuthorityInput(keys: Keys, over: Partial<IssueSdJwtVcInput> = {}): IssueSdJwtVcInput {
  const claims: UmisClaimSet = {
    org: ORG,
    org_unit: ORG_UNIT,
    role: OLEH_ROLE,
    authority: OLEH_AUTHORITY,
    display: { name: 'Олег' },
  };
  return {
    signer: keys.issuer,
    issuer: ISSUER,
    vct: VCT.roleAuthority,
    jti: 'cred-oleh-0001',
    sub: 'p_oleh',
    iat: NOW,
    exp: NOW + 90 * DAY,
    cnfJwk: keys.oleh.publicJwk,
    status: { uri: STATUS_URI, idx: 40_213 },
    claims,
    ...over,
  };
}

/** A crypto provider that counts how it is used, so that a test can tell that a given provider was the one used. */
export function countingCrypto(): CryptoProvider & { calls: { random: number; sha256: number; verify: number } } {
  const calls = { random: 0, sha256: 0, verify: 0 };
  return {
    ...webCryptoProvider,
    name: 'counting',
    calls,
    getRandomValues(array) {
      calls.random += 1;
      return webCryptoProvider.getRandomValues(array);
    },
    sha256(data) {
      calls.sha256 += 1;
      return webCryptoProvider.sha256(data);
    },
    verifyEs256(key, data, signature) {
      calls.verify += 1;
      return webCryptoProvider.verifyEs256(key, data, signature);
    },
  };
}

/** A crypto provider whose random bytes are the ones given, in order; asking for more is a failure of the test. */
export function scriptedRandom(bytes: readonly number[]): CryptoProvider & { consumed: () => number } {
  let next = 0;
  return {
    ...webCryptoProvider,
    name: 'scripted',
    consumed: () => next,
    getRandomValues(array) {
      for (let index = 0; index < array.length; index++) {
        const byte = bytes[next];
        if (byte === undefined) throw new Error('the scripted random bytes ran out');
        array[index] = byte;
        next += 1;
      }
      return array;
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// forging tokens that are signed correctly and wrong in one respect
// ---------------------------------------------------------------------------------------------------------------

/** The base64url text of a JSON value (or of a string as it is). */
export const segment = (value: unknown): string =>
  base64urlEncode(utf8Encode(typeof value === 'string' ? value : JSON.stringify(value)));

/** A JWS with exactly this header and payload, signed by `signer`. */
export async function forgeJws(signer: Signer, header: object, payload: object): Promise<string> {
  const signingText = `${segment(header)}.${segment(payload)}`;
  return `${signingText}.${base64urlEncode(await signer.sign(utf8Encode(signingText)))}`;
}

/** The bare coordinates of a public key, as a wallet would embed it. */
export const bareJwk = ({ kty, crv, x, y }: EcPublicJwk): EcPublicJwk => ({ kty, crv, x, y });
