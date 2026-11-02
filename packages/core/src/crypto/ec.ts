// Shared by the crypto providers and by `jwk.ts`. This module sits below both, so that the providers need nothing from
// the modules that resolve the default provider and the import graph stays free of cycles.
import { base64urlDecode, base64urlEncode, utf8Encode } from '../bytes.js';
import { UmisError } from '../reasons.js';

/** Byte length of a P-256 coordinate, scalar or ES256 signature half. */
export const EC_COORDINATE_BYTES = 32;

/** The bytes behind a JWK coordinate, or undefined unless `value` is the canonical base64url of exactly 32 bytes. */
export function decodeCoordinate(value: unknown): Uint8Array | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const bytes = base64urlDecode(value);
    return bytes.length === EC_COORDINATE_BYTES ? bytes : undefined;
  } catch {
    return undefined;
  }
}

/** Members that enter an RFC 7638 §3.2 thumbprint, already in lexicographic order. */
const THUMBPRINT_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ['crv', 'kty', 'x', 'y'],
  OKP: ['crv', 'kty', 'x'],
  RSA: ['e', 'kty', 'n'],
};

/** The JSON text that RFC 7638 §3.3 hashes: required members only, sorted, no whitespace. Built by hand, never from `JSON.stringify` of the key. */
export function thumbprintInput(jwk: { kty: string }): string {
  const members = jwk as Record<string, unknown>;
  const kty = typeof jwk === 'object' && jwk !== null ? members.kty : undefined;
  if (typeof kty !== 'string' || !Object.hasOwn(THUMBPRINT_MEMBERS, kty)) {
    throw new UmisError('INVALID_ARGUMENT', 'JWK thumbprints are defined for kty EC, RSA and OKP');
  }
  const required = THUMBPRINT_MEMBERS[kty]!;
  const parts = required.map((name) => {
    const value = Object.hasOwn(members, name) ? members[name] : undefined;
    if (typeof value !== 'string' || value === '') {
      throw new UmisError('INVALID_ARGUMENT', `JWK member "${name}" is missing or not a string`);
    }
    return `${JSON.stringify(name)}:${JSON.stringify(value)}`;
  });
  return `{${parts.join(',')}}`;
}

/** base64url(SHA-256(thumbprint input)), hashing with the given function. */
export async function thumbprintOf(
  sha256: (data: Uint8Array) => Promise<Uint8Array>,
  jwk: { kty: string },
): Promise<string> {
  return base64urlEncode(await sha256(utf8Encode(thumbprintInput(jwk))));
}
