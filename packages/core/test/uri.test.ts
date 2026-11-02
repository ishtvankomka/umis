import { describe, expect, it } from 'vitest';
import { formEncode, parseQuery, splitUri, wellKnownUrl } from '../src/index.js';
import { codeOf } from './fixtures.js';

/** What the built-in URLSearchParams makes of a query, keeping the first value of each name. */
function referenceQuery(query: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const [name, value] of new URLSearchParams(query)) {
    if (!Object.hasOwn(fields, name)) fields[name] = value;
  }
  return fields;
}

describe('form encoding', () => {
  it('writes a space as +, a plus as %2B, and every byte of UTF-8 text as %XX', () => {
    expect(formEncode({ a: 'b c', d: '1+2', e: '100%', f: 'x&y=z' })).toBe('a=b+c&d=1%2B2&e=100%25&f=x%26y%3Dz');
    expect(formEncode({ name: 'Склад Б' })).toBe('name=%D0%A1%D0%BA%D0%BB%D0%B0%D0%B4+%D0%91');
    expect(formEncode({ face: '😀', ключ: 'ё' })).toBe('face=%F0%9F%98%80&%D0%BA%D0%BB%D1%8E%D1%87=%D1%91');
    expect(formEncode({ safe: 'AZaz09*-._', tilde: '~', slash: '/', colon: ':' })).toBe(
      'safe=AZaz09*-._&tilde=%7E&slash=%2F&colon=%3A',
    );
    expect(formEncode({ 'pre-authorized_code': 'abc' })).toBe('pre-authorized_code=abc');
  });

  it('keeps the order of the fields and writes empty ones', () => {
    expect(formEncode({ z: '1', a: '2', m: '' })).toBe('z=1&a=2&m=');
    expect(formEncode({})).toBe('');
    expect(
      formEncode({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': 'oaKazRN8I0IbtZ0C7JuMn5',
        tx_code: '493536',
      }),
    ).toBe(
      'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=oaKazRN8I0IbtZ0C7JuMn5&tx_code=493536',
    );
  });

  it('agrees with URLSearchParams on what it writes', () => {
    const fields = {
      plain: 'value',
      spaces: ' a  b ',
      reserved: ":/?#[]@!$&'()*+,;=",
      percent: '%41%2b',
      cyrillic: 'Підрядник А — Склад Б',
      astral: '𝒜😀',
      controls: 'a\tb\nc\u0000d',
    };
    expect(formEncode(fields)).toBe(new URLSearchParams(fields).toString());
  });

  it('wants an object of strings', async () => {
    for (const fields of [null, undefined, 'a=b', ['a'], 5]) {
      expect(await codeOf(() => formEncode(fields as never))).toBe('INVALID_ARGUMENT');
    }
    for (const value of [1, null, undefined, true, ['x']]) {
      expect(await codeOf(() => formEncode({ a: value } as never))).toBe('INVALID_ARGUMENT');
    }
  });
});

describe('reading a query', () => {
  it('gives back what formEncode wrote: spaces, +, %2B, Cyrillic and the rest', () => {
    const tables: Array<Record<string, string>> = [
      { a: 'b c', d: '1+2', e: '100%', f: 'x&y=z' },
      { name: 'Склад Б', ключ: 'ё' },
      { plus: '+', encoded: '%2B', percent: '%', space: ' ', tilde: '~' },
      { empty: '', face: '😀', mixed: 'A b+c%d&e=f?g#h' },
      {},
    ];
    for (const fields of tables) {
      expect(parseQuery(formEncode(fields))).toEqual(fields);
      expect(parseQuery(`?${formEncode(fields)}`)).toEqual(fields);
    }
  });

  it('reads + as a space and %2B as a plus, as the form encoding says', () => {
    expect(parseQuery('a=b+c&d=%2B&e=%2b&f=1%2B2+3')).toEqual({ a: 'b c', d: '+', e: '+', f: '1+2 3' });
    expect(parseQuery('a+b=c+d')).toEqual({ 'a b': 'c d' });
    expect(parseQuery('%D1%96%D0%BC%27%D1%8F=%D0%86%D0%B2%D0%B0%D0%BD')).toEqual({ "ім'я": 'Іван' });
    expect(parseQuery('x=Склад')).toEqual({ x: 'Склад' }); //                            text that was not escaped
  });

  it('allows a leading ?, skips empty fields, splits at the first = and keeps the first of a repeated name', () => {
    expect(parseQuery('?a=1&b=2')).toEqual({ a: '1', b: '2' });
    expect(parseQuery('a=1&&b=2&')).toEqual({ a: '1', b: '2' });
    expect(parseQuery('a=1&a=2&a=3')).toEqual({ a: '1' });
    expect(parseQuery('a=b=c')).toEqual({ a: 'b=c' });
    expect(parseQuery('flag&a=1')).toEqual({ flag: '', a: '1' });
    expect(parseQuery('=x')).toEqual({ '': 'x' });
    expect(parseQuery('a=')).toEqual({ a: '' });
    expect(parseQuery('')).toEqual({});
    expect(parseQuery('?')).toEqual({});
    expect(parseQuery('&&')).toEqual({});
    expect(parseQuery('??a=1')).toEqual({ '?a': '1' });
  });

  it('agrees with URLSearchParams on well-formed queries', () => {
    const queries = [
      'client_id=urn%3Aumis%3Averifier%3Awarehouse-b&request_uri=https%3A%2F%2Fissuer.example%2Fr%2F1&state=a+b',
      'credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1',
      'a=1&a=2&b=%D0%A1%D0%BA%D0%BB%D0%B0%D0%B4&c=&d&=e',
      'x=%F0%9F%98%80&y=%E2%82%AC+%E2%82%AC',
      'q=%2B%2b%2F%2f%3d%3D',
    ];
    for (const query of queries) {
      expect(parseQuery(query), query).toEqual(referenceQuery(query));
      expect(parseQuery(`?${query}`), query).toEqual(referenceQuery(query));
    }
  });

  it('refuses an escape that is broken and bytes that are not UTF-8', async () => {
    for (const query of ['a=%', 'a=%2', 'a=%zz', 'a=%2g', '%=1', 'a%=1', 'a=100%&b=1', 'a=%%41']) {
      expect(await codeOf(() => parseQuery(query)), query).toBe('MALFORMED');
    }
    for (const query of ['a=%C3%28', 'a=%FF', 'a=%80', 'a=%C0%AF', 'a=%ED%A0%80', 'a=%E2%82', '%FF=1']) {
      expect(await codeOf(() => parseQuery(query)), query).toBe('MALFORMED');
    }
    expect(await codeOf(() => parseQuery(undefined as never))).toBe('MALFORMED');
    expect(await codeOf(() => parseQuery(5 as never))).toBe('MALFORMED');
  });

  it('keeps a field named like a property of objects an ordinary field', () => {
    const fields = parseQuery('__proto__=evil&constructor=c&toString=t&a=1');
    expect(Object.getPrototypeOf(fields)).toBe(Object.prototype);
    expect(Object.keys(fields).sort()).toEqual(['__proto__', 'a', 'constructor', 'toString']);
    expect(Object.getOwnPropertyDescriptor(fields, '__proto__')?.value).toBe('evil');
    expect(({} as Record<string, unknown>).evil).toBeUndefined();
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
    expect(fields.constructor).toBe('c');
    expect(parseQuery('a=1&__proto__=x&__proto__=y').constructor).toBe(Object);
  });
});

describe('splitting a URI', () => {
  it('splits the five components, empty when absent', () => {
    expect(splitUri('openid4vp://?a=b')).toEqual({
      scheme: 'openid4vp',
      authority: '',
      path: '',
      query: 'a=b',
      fragment: '',
    });
    expect(splitUri('http://www.ics.uci.edu/pub/ietf/uri/#Related')).toEqual({
      scheme: 'http',
      authority: 'www.ics.uci.edu',
      path: '/pub/ietf/uri/',
      query: '',
      fragment: 'Related',
    });
    expect(splitUri('https://issuer.example:8443/a/b?c=d&e=f#g')).toEqual({
      scheme: 'https',
      authority: 'issuer.example:8443',
      path: '/a/b',
      query: 'c=d&e=f',
      fragment: 'g',
    });
    expect(
      splitUri('openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1'),
    ).toEqual({
      scheme: 'openid-credential-offer',
      authority: '',
      path: '',
      query: 'credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1',
      fragment: '',
    });
  });

  it('handles schemes without an authority, relative references and the empty string', () => {
    expect(splitUri('urn:umis:verifier:warehouse-b')).toEqual({
      scheme: 'urn',
      authority: '',
      path: 'umis:verifier:warehouse-b',
      query: '',
      fragment: '',
    });
    expect(splitUri('mailto:john@example.com?subject=hi')).toEqual({
      scheme: 'mailto',
      authority: '',
      path: 'john@example.com',
      query: 'subject=hi',
      fragment: '',
    });
    expect(splitUri('/a/b?c#d')).toEqual({ scheme: '', authority: '', path: '/a/b', query: 'c', fragment: 'd' });
    expect(splitUri('//host/path')).toEqual({ scheme: '', authority: 'host', path: '/path', query: '', fragment: '' });
    expect(splitUri('a#b?c')).toEqual({ scheme: '', authority: '', path: 'a', query: '', fragment: 'b?c' });
    expect(splitUri('')).toEqual({ scheme: '', authority: '', path: '', query: '', fragment: '' });
    expect(splitUri('?')).toEqual({ scheme: '', authority: '', path: '', query: '', fragment: '' });
    expect(splitUri('#')).toEqual({ scheme: '', authority: '', path: '', query: '', fragment: '' });
  });

  it('writes the scheme in lower case and leaves everything else as it is', () => {
    expect(splitUri('OPENID4VP://Host/Path?A=B#C')).toEqual({
      scheme: 'openid4vp',
      authority: 'Host',
      path: '/Path',
      query: 'A=B',
      fragment: 'C',
    });
    expect(splitUri('https://x/%7Euser?q=%2F#f%20g')).toMatchObject({
      path: '/%7Euser',
      query: 'q=%2F',
      fragment: 'f%20g',
    });
  });

  it('loses nothing when there are line breaks, and agrees with URL on ordinary URLs', () => {
    expect(splitUri('https://x/a\nb?c\nd#e\nf')).toEqual({
      scheme: 'https',
      authority: 'x',
      path: '/a\nb',
      query: 'c\nd',
      fragment: 'e\nf',
    });
    for (const uri of [
      'https://issuer.example/issuer/t/contractor-a?x=1#top',
      'http://127.0.0.1:8080/status/1',
      'https://issuer.example',
    ]) {
      const url = new URL(uri);
      const parts = splitUri(uri);
      expect(parts.scheme).toBe(url.protocol.slice(0, -1));
      expect(parts.authority).toBe(url.host);
      expect(parts.path).toBe(url.pathname === '/' && !uri.endsWith('/') ? '' : url.pathname);
      expect(parts.query).toBe(url.search.slice(1));
      expect(parts.fragment).toBe(url.hash.slice(1));
    }
  });

  it('wants a string', async () => {
    for (const value of [undefined, null, 5, {}, ['https://x']]) {
      expect(await codeOf(() => splitUri(value as never))).toBe('INVALID_ARGUMENT');
    }
  });
});

describe('well-known locations', () => {
  it('puts /.well-known/<name> between the authority and the path, as the three specifications say', () => {
    expect(wellKnownUrl('https://issuer.example/issuer/t/contractor-a', 'jwt-vc-issuer')).toBe(
      'https://issuer.example/.well-known/jwt-vc-issuer/issuer/t/contractor-a',
    );
    expect(wellKnownUrl('https://issuer.example/issuer/t/contractor-a', 'openid-credential-issuer')).toBe(
      'https://issuer.example/.well-known/openid-credential-issuer/issuer/t/contractor-a',
    );
    expect(wellKnownUrl('https://issuer.example/issuer/t/contractor-a', 'oauth-authorization-server')).toBe(
      'https://issuer.example/.well-known/oauth-authorization-server/issuer/t/contractor-a',
    );
    expect(wellKnownUrl('https://issuer.example', 'jwt-vc-issuer')).toBe(
      'https://issuer.example/.well-known/jwt-vc-issuer',
    );
    expect(wellKnownUrl('https://issuer.example/', 'jwt-vc-issuer')).toBe(
      'https://issuer.example/.well-known/jwt-vc-issuer',
    );
    expect(wellKnownUrl('https://issuer.example/tenant/', 'jwt-vc-issuer')).toBe(
      'https://issuer.example/.well-known/jwt-vc-issuer/tenant',
    );
    expect(wellKnownUrl('https://issuer.example:8443/a%20b/c', 'jwt-vc-issuer')).toBe(
      'https://issuer.example:8443/.well-known/jwt-vc-issuer/a%20b/c',
    );
    expect(wellKnownUrl('HTTPS://issuer.example/t', 'jwt-vc-issuer')).toBe(
      'https://issuer.example/.well-known/jwt-vc-issuer/t',
    );
  });

  it('accepts http only for localhost and 127.0.0.1', () => {
    expect(wellKnownUrl('http://localhost:3000/t', 'jwt-vc-issuer')).toBe(
      'http://localhost:3000/.well-known/jwt-vc-issuer/t',
    );
    expect(wellKnownUrl('http://127.0.0.1:8080', 'openid-credential-issuer')).toBe(
      'http://127.0.0.1:8080/.well-known/openid-credential-issuer',
    );
    expect(wellKnownUrl('https://localhost/t', 'jwt-vc-issuer')).toBe('https://localhost/.well-known/jwt-vc-issuer/t');
    expect(wellKnownUrl('http://LOCALHOST/t', 'jwt-vc-issuer')).toBe('http://LOCALHOST/.well-known/jwt-vc-issuer/t');
  });

  it('refuses what is not an https identifier, or has dot segments, a query, a fragment or user information', async () => {
    const refused = [
      'https://x/a/../b',
      'https://x/a/./b',
      'https://x/a/%2e%2e/b',
      'https://x/a/%2E/b',
      'https://x/a/.%2e/b',
      'https://x/..',
      'https://x/a/..',
      'https://x/a//b',
      'https://x//a',
      'https://issuer.example/a?b=c',
      'https://issuer.example/a?',
      'https://issuer.example/a#frag',
      'https://issuer.example/a#',
      'https://user@issuer.example/a',
      'https://user:secret@issuer.example/a',
      'http://issuer.example/a',
      'http://localhost.evil.example/a',
      'http://127.0.0.1.evil.example/a',
      'http://127.0.0.2/a',
      'ftp://issuer.example/a',
      'file:///etc/passwd',
      'javascript:alert(1)',
      'urn:umis:issuer:a',
      'issuer.example/a',
      '//issuer.example/a',
      '/a/b',
      'https:///a',
      'https://',
      'https://issuer.example:70000/a',
      'https://issuer.example:/a',
      'https://issuer.example:80a/a',
      'https://issuer.example:123456/a',
      'https://[::1]/a',
      'https://issuer.example/a b',
      'https://issuer.example/a\tb',
      'https://issuer.example/a\nb',
      'https://issuer.example\\evil.example/a',
      'https://issuer.example/a\\b',
      ' https://issuer.example/a',
      'https://issuer.example/a ',
      'https://issuer.example/%zz',
      'https://issuer.example/a%',
      'https://issuer.example/%4',
      'https://issuer.example/склад',
      'https://склад.example/a',
      'https://iss\u0000uer.example/',
      'https://-issuer.example/a',
      'https://issuer-.example/a',
      'https://issuer..example/a',
      'https://.issuer.example/a',
      'https://issuer.example./a',
      'https://./a',
      'https://../a',
      `https://${'a'.repeat(64)}.example/a`,
      `https://${'a.'.repeat(130)}example/a`,
      '',
    ];
    for (const uri of refused) {
      expect(await codeOf(() => wellKnownUrl(uri, 'jwt-vc-issuer')), JSON.stringify(uri)).toBe('INVALID_ARGUMENT');
    }
    for (const value of [undefined, null, 5, {}]) {
      expect(await codeOf(() => wellKnownUrl(value as never, 'jwt-vc-issuer'))).toBe('INVALID_ARGUMENT');
    }
    for (const name of ['openid-configuration', 'jwks.json', '', 'JWT-VC-ISSUER', undefined]) {
      expect(await codeOf(() => wellKnownUrl('https://issuer.example/a', name as never)), String(name)).toBe(
        'INVALID_ARGUMENT',
      );
    }
  });

  it('keeps a percent escape that is sound, and a host label of 63 characters', () => {
    expect(wellKnownUrl('https://issuer.example/a%2Fb%252e', 'jwt-vc-issuer')).toBe(
      'https://issuer.example/.well-known/jwt-vc-issuer/a%2Fb%252e',
    );
    const label = 'a'.repeat(63);
    expect(wellKnownUrl(`https://${label}.example/t`, 'jwt-vc-issuer')).toBe(
      `https://${label}.example/.well-known/jwt-vc-issuer/t`,
    );
  });
});
