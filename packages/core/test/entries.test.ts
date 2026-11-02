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
  // SD-JWT VC
  'issueCredential',
  'presentCredential',
  'disclosureDigest',
  'parseSdJwt',
  'verifyIssuerSignature',
  'verifyKeyBinding',
  'checkCredentialTimes',
  'decodeCredential',
  // authority
  'matchAuthority',
  'isNarrowerItem',
  'checkDelegation',
  'periodWindow',
  'ledgerKey',
  // frames, requests, QR codes
  'encodeFrame',
  'decodeFrame',
  'encodeFrameBytes',
  'decodeFrameBytes',
  'frameKindOf',
  'signPresentationRequest',
  'decodePresentationRequest',
  'classifyQr',
  // events
  'GENESIS_HASH',
  'canonicalJson',
  'chainHash',
  'signEvent',
  'verifyEvent',
  'createMemoryJournal',
  'verifyJournal',
  // URIs
  'formEncode',
  'parseQuery',
  'splitUri',
  'wellKnownUrl',
];

describe('built entries', () => {
  it('the root entry exports the contracts, the byte helpers, the providers, the JWK and the JWS functions', () => {
    for (const name of ROOT_VALUES) expect(root, name).toHaveProperty(name);
  });

  it('keeps the helpers that exist for the tests out of the root entry', () => {
    expect(root).not.toHaveProperty('inflateCapped');
  });

  it('keeps the noble provider out of the root entry and in its own', () => {
    expect(root).not.toHaveProperty('nobleCryptoProvider');
    expect(root).not.toHaveProperty('keyFromSeed');
    expect(Object.keys(noble).sort()).toEqual(['keyFromSeed', 'nobleCryptoProvider']);
  });

  it('imports each dependency from the module that needs it and from no other', () => {
    const sources = (readdirSync(distribution, { recursive: true, encoding: 'utf8' }) as string[])
      .filter((file) => file.endsWith('.js'))
      .map((file) => [file.replaceAll('\\', '/'), readFileSync(new URL(file, distribution), 'utf8')] as const);
    const importing = (specifier: RegExp): string[] =>
      sources
        .filter(([, code]) => specifier.test(code))
        .map(([file]) => file)
        .sort();

    expect(importing(/from\s*['"]@noble\/curves/)).toEqual(['crypto/noble.js']);
    expect(importing(/from\s*['"]@noble\/hashes/)).toEqual(['crypto/noble.js', 'event.js']);
    expect(importing(/from\s*['"]@sd-jwt\//)).toEqual(['sdjwt.js']);
    expect(importing(/from\s*['"]fflate['"]/)).toEqual(['frame.js']);
    expect(importing(/from\s*['"]canonicalize['"]/)).toEqual(['event.js']);
    expect(importing(/from\s*['"]jose['"]/)).toEqual([]);
    expect(importing(/from\s*['"](?:node:|zlib|crypto|buffer|url)/)).toEqual([]);
  });

  it('takes from the SD-JWT library its issuing and its presenting, and nothing else', () => {
    const code = readFileSync(new URL('sdjwt.js', distribution), 'utf8');
    expect(code).toMatch(/^import \{ SDJwtInstance \} from /m); //  the one name that is taken from the library
    expect(code.match(/new SDJwtInstance\(/g)).toHaveLength(2);
    expect(code.match(/\blibrary\.issue\(/g)).toHaveLength(1);
    expect(code.match(/\blibrary\.present\(/g)).toHaveLength(1);
    expect(code).not.toMatch(/\blibrary\.(?!issue\b|present\b)\w+/);
    expect(code).not.toContain('SDJwtVcInstance');
  });
});
