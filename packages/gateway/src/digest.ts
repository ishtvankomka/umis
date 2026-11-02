import { UmisError, getDefaultCrypto, hexEncode, utf8Encode } from '@umis/core';
import type { CryptoProvider } from '@umis/core';

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

function text(value: unknown, what: string): string {
  if (typeof value !== 'string' || value === '') throw invalid(`${what} must be a non-empty text`);
  return value;
}

/**
 * The `response` value of an HTTP Digest `Authorization` header with SHA-256 and `qop=auth` (RFC 7616, section 3.4.1):
 * `H(H(username:realm:password) : nonce : nc : cnonce : qop : H(method:uri))` in lowercase hexadecimal. This is how
 * Shelly Gen2 and newer devices ask a client to prove a password. The password is only ever an argument here: nothing
 * in this module stores, logs or returns it.
 */
export async function computeDigestResponse(i: {
  username: string;
  realm: string;
  password: string;
  method: string;
  uri: string;
  nonce: string;
  cnonce: string;
  nc: string;
  qop: 'auth';
  crypto?: CryptoProvider;
}): Promise<string> {
  if (typeof i !== 'object' || i === null) throw invalid('computeDigestResponse needs its input object');
  const username = text(i.username, 'username');
  const realm = text(i.realm, 'realm');
  const method = text(i.method, 'method');
  const uri = text(i.uri, 'uri');
  const nonce = text(i.nonce, 'nonce');
  const cnonce = text(i.cnonce, 'cnonce');
  if (typeof i.password !== 'string') throw invalid('password must be a text');
  if (typeof i.nc !== 'string' || !/^[0-9a-fA-F]{8}$/.test(i.nc)) throw invalid('nc must be eight hexadecimal digits');
  if (i.qop !== 'auth') throw invalid('only qop auth is supported');

  const provider = i.crypto ?? getDefaultCrypto();
  const hash = async (value: string): Promise<string> => hexEncode(await provider.sha256(utf8Encode(value)));
  const secret = await hash(`${username}:${realm}:${i.password}`);
  const request = await hash(`${method}:${uri}`);
  return hash(`${secret}:${nonce}:${i.nc}:${cnonce}:auth:${request}`);
}
