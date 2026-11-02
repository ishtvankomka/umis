import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import * as root from '../dist/index.js';
import * as noble from '../dist/noble.js';

const distribution = new URL('../dist/', import.meta.url);

const ROOT_VALUES = [
  // profile, reason codes, errors
  'PROFILE_ID',
  'ALG',
  'TYP',
  'VCT',
  'LIMITS',
  'CHANNELS',
  'REASON_CODES',
  'UmisError',
  'isReasonCode',
  // bytes
  'utf8Encode',
  'utf8Decode',
  'base64urlEncode',
  'base64urlDecode',
  'base45Encode',
  'base45Decode',
  'base32Encode',
  'hexEncode',
  'hexDecode',
  'concatBytes',
  'bytesEqual',
  'varintEncode',
  'varintDecode',
  // crypto
  'webCryptoProvider',
  'getDefaultCrypto',
  'setDefaultCrypto',
  'randomBytes',
  'randomId',
  'webCryptoSigner',
  'generateSigner',
  'importSigner',
  // JWK and JWS
  'jwkThumbprint',
  'keyFingerprint',
  'asEcPublicJwk',
  'publicJwkEquals',
  'signJws',
  'decodeJwsUnverified',
  'verifyJws',
];

describe('built entries', () => {
  it('the root entry exports the contracts, the byte helpers, the providers, the JWK and the JWS functions', () => {
    for (const name of ROOT_VALUES) expect(root, name).toHaveProperty(name);
  });

  it('keeps the noble provider out of the root entry and in its own', () => {
    expect(root).not.toHaveProperty('nobleCryptoProvider');
    expect(root).not.toHaveProperty('keyFromSeed');
    expect(Object.keys(noble).sort()).toEqual(['keyFromSeed', 'nobleCryptoProvider']);
  });

  it('imports the @noble packages from one module only', () => {
    const importing = (readdirSync(distribution, { recursive: true, encoding: 'utf8' }) as string[])
      .filter((file) => file.endsWith('.js'))
      .filter((file) => /['"]@noble\//.test(readFileSync(new URL(file, distribution), 'utf8')))
      .map((file) => file.replaceAll('\\', '/'));
    expect(importing).toEqual(['crypto/noble.js']);
  });
});
