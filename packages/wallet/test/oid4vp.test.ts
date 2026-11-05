import {
  UmisError,
  VCT,
  formEncode,
  generateSigner,
  parseQuery,
  parseSdJwt,
  randomId,
  verifyKeyBinding,
} from '@umis/core';
import type { FetchLike, Signer } from '@umis/core';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import * as oid4vp from '../src/oid4vp.js';
import { parseVpRequest, respondToVpRequest } from '../src/oid4vp.js';
import { MEMBER_CLAIMS, T0, createFakeIssuer, failureOf } from './fake-issuer.js';

const NOW = T0 + 3_600;
const RESPONSE_URI = 'https://op.example/oid4vp/response';
const CLIENT_ID = `redirect_uri:${RESPONSE_URI}`;
const CONTINUE_URI = 'https://rp.example/callback?session=1';

const DCQL = {
  credentials: [
    {
      id: 'umis',
      format: 'dc+sd-jwt',
      meta: { vct_values: [VCT.orgMember, VCT.roleAuthority] },
      claims: [{ path: ['org'] }, { path: ['role'] }],
    },
  ],
};
const METADATA = {
  vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] } },
  client_name: 'Acme Intranet',
};

let oleh: Signer;
let maria: Signer;
let olehCredential: string;
let mariaCredential: string;

beforeAll(async () => {
  const issuer = await createFakeIssuer();
  [oleh, maria] = await Promise.all([generateSigner(), generateSigner()]);
  olehCredential = await issuer.issue({ holder: oleh.publicJwk, jti: 'cred-oleh-0001' });
  mariaCredential = await issuer.issue({
    holder: maria.publicJwk,
    jti: 'cred-maria-0001',
    vct: VCT.orgMember,
    claims: MEMBER_CLAIMS,
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
});

/** A request by value as a verifier writes it; a member set to `undefined` is left out. */
function link(over: Record<string, string | undefined> = {}, scheme = 'openid4vp://?'): string {
  const fields: Record<string, string | undefined> = {
    client_id: CLIENT_ID,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: randomId(16),
    state: randomId(16),
    dcql_query: JSON.stringify(DCQL),
    client_metadata: JSON.stringify(METADATA),
    ...over,
  };
  const present = Object.entries(fields).filter((entry): entry is [string, string] => entry[1] !== undefined);
  return scheme + formEncode(Object.fromEntries(present));
}

const withQuery = (query: unknown): string => link({ dcql_query: JSON.stringify(query) });
const withCredential = (over: Record<string, unknown>): string =>
  withQuery({ credentials: [{ ...DCQL.credentials[0], ...over }] });
/** A valid request with raw query text added at its end. */
const plus = (extra: string): string => `${link()}&${extra}`;

/** The error a request is refused with; the test fails when the request is taken. */
function refusal(uri: string): UmisError {
  try {
    parseVpRequest(uri);
  } catch (error) {
    if (error instanceof UmisError) return error;
    throw error;
  }
  throw new Error('expected the request to be refused');
}

interface Post {
  url: string;
  method: string | undefined;
  headers: Record<string, string>;
  body: string;
  redirect: string | undefined;
}

/** The verifier's response endpoint: it keeps what it was sent and answers with `status` and `body`. */
function endpoint(status = 200, body = JSON.stringify({ redirect_uri: CONTINUE_URI })) {
  const posts: Post[] = [];
  const fetch: FetchLike = async (url, init) => {
    posts.push({
      url,
      method: init?.method,
      headers: init?.headers ?? {},
      body: init?.body ?? '',
      redirect: init?.redirect,
    });
    return { status, headers: { get: () => null }, text: async () => body };
  };
  return { posts, fetch };
}

describe('reading a request', () => {
  it('takes a request by value: the client, the nonce, the state and what the query asks for', () => {
    const nonce = randomId(16);
    const state = randomId(16);
    const parsed = parseVpRequest(link({ nonce, state }));
    expect(parsed).toEqual({
      clientId: CLIENT_ID,
      responseUri: RESPONSE_URI,
      nonce,
      state,
      dcql: DCQL,
      clientName: 'Acme Intranet',
      requested: { vcts: [VCT.orgMember, VCT.roleAuthority], claims: ['org', 'role'] },
    });

    // the other spelling of the address, white space around it, and a request without state or metadata
    expect(parseVpRequest(`  ${link({ nonce }, 'openid4vp://authorize?')}\n`).nonce).toBe(nonce);
    const bare = parseVpRequest(link({ state: undefined, client_metadata: undefined }));
    expect(bare).not.toHaveProperty('state');
    expect(bare).not.toHaveProperty('clientName');
    // a name that contains control characters is not shown
    expect(parseVpRequest(link({ client_metadata: JSON.stringify({ client_name: 'Acme‮\nX' }) }))).not.toHaveProperty(
      'clientName',
    );
  });

  it('refuses what the profile does not take', () => {
    const byReference = `openid4vp://?${formEncode({ client_id: CLIENT_ID, request_uri: 'https://op.example/request/1' })}`;
    const refused: Array<[string, string, string]> = [
      ['a request by reference', byReference, 'PROTOCOL'],
      ['a signed request object', link({ request: 'eyJhbGciOiJFUzI1NiJ9.e30.AAAA' }), 'PROTOCOL'],
      ['an encrypted response', link({ response_mode: 'direct_post.jwt' }), 'PROTOCOL'],
      ['a response in the fragment', link({ response_mode: undefined }), 'PROTOCOL'],
      ['an authorization code', link({ response_type: 'code' }), 'PROTOCOL'],
      ['a client id without a prefix', link({ client_id: RESPONSE_URI }), 'PROTOCOL'],
      ['another kind of client id', link({ client_id: 'x509_san_dns:op.example' }), 'PROTOCOL'],
      ['a client id of another address', link({ client_id: 'redirect_uri:https://evil.example/cb' }), 'PROTOCOL'],
      [
        'a response address over http',
        link({ client_id: 'redirect_uri:http://op.example/cb', response_uri: 'http://op.example/cb' }),
        'PROTOCOL',
      ],
      ['credential sets', withQuery({ ...DCQL, credential_sets: [] }), 'PROTOCOL'],
      ['another format', withCredential({ format: 'mso_mdoc' }), 'PROTOCOL'],
      ['a trusted authority', withCredential({ trusted_authorities: [] }), 'PROTOCOL'],
      ['a nested claim path', withCredential({ claims: [{ path: ['org', 'name'] }] }), 'PROTOCOL'],
      ['a claim a UMIS credential does not have', withCredential({ claims: [{ path: ['given_name'] }] }), 'PROTOCOL'],
      ['no nonce', link({ nonce: undefined }), 'MALFORMED'],
      ['no query', link({ dcql_query: undefined }), 'MALFORMED'],
      ['a query that is not JSON', link({ dcql_query: '{' }), 'MALFORMED'],
      ['a query without credentials', withQuery({ credentials: [] }), 'MALFORMED'],
      ['a credential query without types', withCredential({ meta: { vct_values: [] } }), 'MALFORMED'],
      ['no response address', link({ response_uri: undefined }), 'MALFORMED'],
      ['metadata that is not JSON', link({ client_metadata: 'x' }), 'MALFORMED'],
      ['a text that is not an OpenID4VP link', RESPONSE_URI, 'UNSUPPORTED_FORMAT'],
      ['a link with a fragment', `${link()}#x`, 'MALFORMED'],
    ];
    for (const [name, uri, code] of refused) {
      let thrown: unknown;
      try {
        parseVpRequest(uri);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, name).toBeInstanceOf(UmisError);
      expect((thrown as UmisError).code, name).toBe(code);
    }
    expect(() => parseVpRequest(5 as never)).toThrow(UmisError);
    expect(() => parseVpRequest(`openid4vp://?x=${'a'.repeat(20_000)}`)).toThrow(UmisError);
  });

  it('refuses a request by reference, a signed request and transaction data added to a valid request', () => {
    // the control: the same request without the added parameter is taken
    expect(parseVpRequest(link()).clientId).toBe(CLIENT_ID);
    expect(refusal(plus(formEncode({ request_uri: 'https://op.example/request/1' }))).code).toBe('PROTOCOL');
    expect(refusal(plus(formEncode({ request: 'eyJhbGciOiJFUzI1NiJ9.e30.AAAA' }))).code).toBe('PROTOCOL');
    // OpenID4VP 1.0, 5.1: a wallet refuses a transaction data type it does not know, and UMIS knows none
    for (const value of ['eyJ0eXBlIjoicGF5bWVudCJ9', '']) {
      const refused = refusal(plus(formEncode({ transaction_data: value })));
      expect(refused.code).toBe('PROTOCOL');
      expect(refused.message).toContain('transaction_data');
    }
  });

  it('takes the redirect_uri prefix only, also for a client id that names the response address', () => {
    expect(parseVpRequest(link({ client_id: `redirect_uri:${RESPONSE_URI}` })).clientId).toBe(CLIENT_ID);
    // x509_san_dns: has as many characters as redirect_uri:, so only the check of the prefix refuses it
    expect(refusal(link({ client_id: `x509_san_dns:${RESPONSE_URI}` })).code).toBe('PROTOCOL');
  });

  it('refuses a request that names a parameter twice', () => {
    expect(parseVpRequest(link()).responseUri).toBe(RESPONSE_URI);
    const repeated = [
      'response_mode=direct_post.jwt', // the first value, direct_post, would win
      `nonce=${randomId(16)}`,
      'response%5Fmode=direct_post', // the same name written with an escape, and the same value
    ];
    for (const extra of repeated) expect(refusal(plus(extra)).code, extra).toBe('PROTOCOL');
  });

  it('takes the subset up to each of its limits and refuses one more', () => {
    const types = (count: number): string[] =>
      Array.from({ length: count }, (_, index) => `https://types.example/${index}`);
    expect(parseVpRequest(withCredential({ meta: { vct_values: types(8) } })).requested.vcts).toHaveLength(8);
    expect(refusal(withCredential({ meta: { vct_values: types(9) } })).code).toBe('MALFORMED');

    const queries = (count: number) => ({
      credentials: Array.from({ length: count }, (_, index) => ({ ...DCQL.credentials[0], id: `query-${index}` })),
    });
    expect(parseVpRequest(withQuery(queries(8))).dcql.credentials).toHaveLength(8);
    expect(refusal(withQuery(queries(9))).code).toBe('MALFORMED');

    // the whole link: white space in the query JSON makes it longer and leaves the request valid
    const fixed = { nonce: randomId(16), state: randomId(16) };
    const ofLength = (length: number): string =>
      link({ ...fixed, dcql_query: JSON.stringify(DCQL) + ' '.repeat(length - link(fixed).length) });
    const longest = ofLength(16_384);
    expect(longest).toHaveLength(16_384);
    expect(parseVpRequest(longest).dcql).toEqual(DCQL);
    const tooLong = ofLength(16_385);
    expect(tooLong).toHaveLength(16_385);
    expect(refusal(tooLong).code).toBe('MALFORMED');

    // the two spellings of the address, other schemes, and damage
    expect(parseVpRequest(link({}, 'openid4vp://?')).responseUri).toBe(RESPONSE_URI);
    expect(parseVpRequest(link({}, 'openid4vp://authorize?')).responseUri).toBe(RESPONSE_URI);
    for (const scheme of ['haip://?', 'openid-credential-offer://?', 'https://op.example/authorize?']) {
      expect(refusal(link({}, scheme)).code, scheme).toBe('UNSUPPORTED_FORMAT');
    }
    const damaged = [
      link({}, 'openid4vp://op.example?'),
      link({}, 'openid4vp://authorize/more?'),
      link({}, 'openid4vp:?'),
      plus('x=%zz'),
      `${link()}#x`,
    ];
    for (const uri of damaged) expect(refusal(uri).code, uri.slice(0, 32)).toBe('MALFORMED');
  });

  it('keeps a client name of at most 200 characters without control characters, and drops any other', () => {
    const named = (name: unknown) =>
      parseVpRequest(link({ client_metadata: JSON.stringify({ ...METADATA, client_name: name }) }));
    /** The request is still taken, only without the name. */
    const dropped = (name: unknown): void => {
      const parsed = named(name);
      expect(parsed.responseUri).toBe(RESPONSE_URI);
      expect(parsed, JSON.stringify(name)).not.toHaveProperty('clientName');
    };

    expect(named('n'.repeat(200)).clientName).toBe('n'.repeat(200));
    dropped('n'.repeat(201));
    for (const unit of [0x00, 0x07, 0x1f, 0x7f, 0x85, 0x9f]) dropped(`Acme${String.fromCharCode(unit)}Intranet`);
    for (const unit of [0x20, 0x7e, 0xa0]) {
      const kept = `Acme${String.fromCharCode(unit)}Intranet`;
      expect(named(kept).clientName).toBe(kept);
    }
    for (const notText of [5, { en: 'Acme' }, ['Acme'], null, '']) dropped(notText);
  });
});

describe('answering a request', () => {
  it('posts the presentation for the client id and the nonce, with only the claims asked for', async () => {
    const nonce = randomId(16);
    const state = randomId(16);
    const { posts, fetch } = endpoint();

    const answer = await respondToVpRequest({
      walletUri: link({ nonce, state }),
      sdJwtVc: olehCredential,
      disclose: ['org', 'role'],
      signer: oleh,
      now: NOW,
      fetch,
    });
    expect(answer).toEqual({ status: 200, redirectUri: CONTINUE_URI });

    expect(posts).toHaveLength(1);
    const post = posts[0]!;
    expect(post.url).toBe(RESPONSE_URI);
    expect(post.method).toBe('POST');
    expect(post.redirect).toBe('error'); // a redirect would carry the presentation to another address
    expect(post.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    const form = parseQuery(post.body);
    expect(Object.keys(form).sort()).toEqual(['state', 'vp_token']);
    expect(form.state).toBe(state);

    const token = JSON.parse(form.vp_token ?? '') as Record<string, string[]>;
    expect(Object.keys(token)).toEqual(['umis']);
    expect(token.umis).toHaveLength(1);
    const presentation = await parseSdJwt(token.umis![0]!);

    // I-5: the key-binding JWT is for the client id with its prefix, and for this nonce
    const bound = { nonce, now: NOW, maxAgeSeconds: 120, skewSeconds: 10 };
    expect(await verifyKeyBinding(presentation, { ...bound, aud: CLIENT_ID })).toMatchObject({ ok: true, iat: NOW });
    expect(await verifyKeyBinding(presentation, { ...bound, aud: RESPONSE_URI })).toEqual({
      ok: false,
      reason: 'AUDIENCE_MISMATCH',
    });
    expect(await verifyKeyBinding(presentation, { ...bound, aud: CLIENT_ID, nonce: randomId(16) })).toEqual({
      ok: false,
      reason: 'NONCE_MISMATCH',
    });
    // I-19: the credential has authority, delegation and display; only org and role leave the wallet
    expect(presentation.disclosures.map((disclosure) => disclosure.name).sort()).toEqual(['org', 'role']);
  });

  it('reports the status the verifier answered with, and follows only a usable address', async () => {
    const run = async (status: number, body: string) =>
      respondToVpRequest({
        walletUri: link(),
        sdJwtVc: mariaCredential,
        disclose: ['org'],
        signer: maria,
        now: NOW,
        fetch: endpoint(status, body).fetch,
      });

    expect(await run(400, JSON.stringify({ error: 'invalid_request', redirect_uri: CONTINUE_URI }))).toEqual({
      status: 400,
    });
    expect(await run(200, '')).toEqual({ status: 200 });
    expect(await run(200, 'not json')).toEqual({ status: 200 });
    expect(await run(200, JSON.stringify({ redirect_uri: 'javascript:alert(1)' }))).toEqual({ status: 200 });
    expect(await run(200, JSON.stringify({ redirect_uri: 'http://rp.example/callback' }))).toEqual({ status: 200 });
    expect(await run(200, JSON.stringify({ redirect_uri: 'http://localhost:3000/callback' }))).toEqual({
      status: 200,
      redirectUri: 'http://localhost:3000/callback',
    });

    // a post that cannot be made, and the global fetch when none is given
    const unreachable: FetchLike = async () => {
      throw new Error('offline');
    };
    const input = { walletUri: link(), sdJwtVc: mariaCredential, disclose: ['org' as const], signer: maria, now: NOW };
    expect((await failureOf(respondToVpRequest({ ...input, fetch: unreachable }))).code).toBe('NETWORK');
    const global = endpoint(200, '{}');
    vi.stubGlobal('fetch', global.fetch);
    expect(await respondToVpRequest(input)).toEqual({ status: 200 });
    expect(global.posts).toHaveLength(1);
    expect(global.posts[0]!.redirect).toBe('error');
  });

  it('discloses nothing beyond the request and sends nothing when it refuses', async () => {
    const { posts, fetch } = endpoint();
    const input = {
      walletUri: link(),
      sdJwtVc: olehCredential,
      disclose: ['org' as const, 'role' as const],
      signer: oleh,
      now: NOW,
      fetch,
    };
    // I-19: authority is in the credential but not in the query
    expect((await failureOf(respondToVpRequest({ ...input, disclose: ['org', 'role', 'authority'] }))).code).toBe(
      'INVALID_ARGUMENT',
    );
    expect((await failureOf(respondToVpRequest({ ...input, disclose: ['display'] }))).code).toBe('INVALID_ARGUMENT');
    // a type of credential the query does not name
    const roleOnly = withCredential({ meta: { vct_values: [VCT.roleAuthority] } });
    expect(
      (await failureOf(respondToVpRequest({ ...input, walletUri: roleOnly, sdJwtVc: mariaCredential, signer: maria })))
        .code,
    ).toBe('INVALID_ARGUMENT');
    // a key that is not the holder key of the credential
    expect((await failureOf(respondToVpRequest({ ...input, signer: maria }))).code).toBe('INVALID_ARGUMENT');
    expect((await failureOf(respondToVpRequest({ ...input, now: Number.NaN }))).code).toBe('INVALID_ARGUMENT');
    // a request the wallet does not take
    expect(
      (await failureOf(respondToVpRequest({ ...input, walletUri: link({ response_mode: 'fragment' }) }))).code,
    ).toBe('PROTOCOL');
    expect(posts).toHaveLength(0);
  });

  it('answers with the first credential query that takes the credential', async () => {
    const query = (id: string, claims: string[]) => ({
      id,
      format: 'dc+sd-jwt',
      meta: { vct_values: [VCT.roleAuthority] },
      claims: claims.map((name) => ({ path: [name] })),
    });
    const walletUri = withQuery({ credentials: [query('a', ['org']), query('b', ['org', 'role'])] });
    const input = { walletUri, sdJwtVc: olehCredential, signer: oleh, now: NOW };

    const first = endpoint();
    expect(await respondToVpRequest({ ...input, disclose: ['org'], fetch: first.fetch })).toMatchObject({
      status: 200,
    });
    expect(first.posts).toHaveLength(1);
    const token = JSON.parse(parseQuery(first.posts[0]!.body).vp_token ?? '') as Record<string, unknown>;
    expect(Object.keys(token)).toEqual(['a']);

    // role is in the claims of b only: the wallet answers a, so it refuses before it sends anything
    const second = endpoint();
    expect((await failureOf(respondToVpRequest({ ...input, disclose: ['role'], fetch: second.fetch }))).code).toBe(
      'INVALID_ARGUMENT',
    );
    expect(second.posts).toHaveLength(0);
  });

  it('exports exactly the names of the OpenID4VP helpers', () => {
    expect(Object.keys(oid4vp).sort()).toEqual(['parseVpRequest', 'respondToVpRequest']);
  });
});
