import { describe, expect, it } from 'vitest';
import { computeDigestResponse } from '../src/index.js';

// RFC 7616, section 3.9.1: the SHA-256 example (user Mufasa, GET /dir/index.html).
const RFC_7616 = {
  username: 'Mufasa',
  realm: 'http-auth@example.org',
  password: 'Circle of Life',
  method: 'GET',
  uri: '/dir/index.html',
  nonce: '7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v',
  cnonce: 'f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ',
  nc: '00000001',
  qop: 'auth',
} as const;

describe('HTTP Digest response (RFC 7616, SHA-256)', () => {
  it('reproduces the response of the RFC 7616 section 3.9.1 example', async () => {
    expect(await computeDigestResponse(RFC_7616)).toBe(
      '753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1',
    );
  });

  it('depends on every input and refuses input it cannot hash', async () => {
    const reference = await computeDigestResponse(RFC_7616);
    for (const change of [
      { password: 'circle of life' },
      { method: 'POST' },
      { uri: '/dir/index.htm' },
      { nc: '00000002' },
      { realm: 'http-auth@example.com' },
    ]) {
      expect(await computeDigestResponse({ ...RFC_7616, ...change })).not.toBe(reference);
    }
    await expect(computeDigestResponse({ ...RFC_7616, nc: '1' })).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(computeDigestResponse({ ...RFC_7616, qop: 'auth-int' as 'auth' })).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(computeDigestResponse({ ...RFC_7616, username: '' })).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
  });
});
