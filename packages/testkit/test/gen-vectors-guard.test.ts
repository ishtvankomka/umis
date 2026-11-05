import { describe, expect, it } from 'vitest';
import { buildVectors, serializeVectors } from '../scripts/gen-vectors.js';

const PUBLIC_KEY = { kty: 'EC', crv: 'P-256', kid: 'k1', x: 'a', y: 'b' };

describe('serializeVectors', () => {
  it('refuses a private key member d and names where it is', () => {
    expect(() => serializeVectors({ keys: [{ kty: 'EC', x: 'a', y: 'b', d: 'c' }] })).toThrow(
      'the vector file would hold a private key member "d" at keys[0].d',
    );
    expect(() => serializeVectors({ d: 'c' })).toThrow('at d');
  });

  it('finds a d nested deeper, in objects and in arrays', () => {
    expect(() => serializeVectors({ a: { b: { d: 'c' } } })).toThrow('at a.b.d');
    expect(() => serializeVectors({ issuers: [{ jwks: { keys: [PUBLIC_KEY, { ...PUBLIC_KEY, d: 'c' }] } }] })).toThrow(
      'at issuers[0].jwks.keys[1].d',
    );
  });

  it('returns the text JSON.stringify gives for a document of public keys, and looks at names only', () => {
    const document = { issuers: [{ jwks: { keys: [PUBLIC_KEY] } }], data: 'd', id: ['d'], description: { D: 'd' } };
    expect(serializeVectors(document)).toBe(`${JSON.stringify(document, null, 2)}\n`);
  });

  it('is what the generator ends with: the vectors of the demo world are written', async () => {
    const text = await buildVectors();
    expect(text.endsWith('\n')).toBe(true);
    expect(JSON.parse(text)).toMatchObject({ format: 'umis-test-vectors/v1' });
  });
});
