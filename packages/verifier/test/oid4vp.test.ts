import { UmisError, VCT, parseQuery, presentCredential, randomId, splitUri } from '@umis/core';
import type { DisclosableClaim, Signer } from '@umis/core';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createMemoryReplayStore } from '../src/index.js';
import * as oid4vp from '../src/oid4vp.js';
import { createVpRequest, umisDcqlQuery, verifyVpResponse } from '../src/oid4vp.js';
import type { VpRequestObject } from '../src/oid4vp.js';
import {
  AT,
  IDX,
  ISSUER_A,
  LIST_A,
  LIST_B,
  NOW,
  buildWorld,
  expectAccept,
  expectReject,
  statusList,
  type World,
} from './fixtures.js';

const RESPONSE_URI = 'https://op.example/oid4vp/response';
const CLIENT_ID = `redirect_uri:${RESPONSE_URI}`;
const QUERY_ID = 'umis';

type Input = Parameters<typeof verifyVpResponse>[0];

let w: World;
let listA: string;
let listB: string;

beforeAll(async () => {
  w = await buildWorld();
  [listA, listB] = await Promise.all([
    statusList(w.issuerA, LIST_A, { iat: AT - 100 }),
    statusList(w.issuerB, LIST_B, { iat: AT - 100 }),
  ]);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

/** The error code of a call that must fail with a UmisError. */
function codeOf(call: () => unknown): string {
  try {
    call();
  } catch (error) {
    if (error instanceof UmisError) return error.code;
    throw error;
  }
  throw new Error('expected the call to fail');
}

async function codeOfAsync(call: Promise<unknown>): Promise<string> {
  try {
    await call;
  } catch (error) {
    if (error instanceof UmisError) return error.code;
    throw error;
  }
  throw new Error('expected the call to fail');
}

/** The status lists an online verifier can reach, and the addresses it was asked for. */
function feed(tokens: Record<string, string>) {
  const calls: string[] = [];
  return {
    calls,
    fetch: async (uri: string): Promise<string> => {
      calls.push(uri);
      const token = tokens[uri];
      if (token === undefined) throw new Error(`no status list at ${uri}`);
      return token;
    },
  };
}

interface Asked {
  nonce: string;
  state: string;
  requestObject: VpRequestObject;
}

/** The login request of a relying party's OpenID provider. */
async function asked(): Promise<Asked> {
  const nonce = randomId(16, w.crypto);
  const state = randomId(16, w.crypto);
  const dcql = umisDcqlQuery({ vcts: [VCT.orgMember, VCT.roleAuthority], claims: ['org', 'role'], id: QUERY_ID });
  const { requestObject } = await createVpRequest({ responseUri: RESPONSE_URI, nonce, state, dcql });
  return { nonce, state, requestObject };
}

/** The form a wallet posts: the credential presented to `aud` with `nonce`, in the answer to the query `queryId`. */
async function posted(
  request: Asked,
  o: {
    credential?: string;
    holder?: Signer;
    disclose?: DisclosableClaim[];
    aud?: string;
    nonce?: string;
    iat?: number;
  } = {},
): Promise<Record<string, string>> {
  const presentation = await presentCredential({
    credential: o.credential ?? w.olehCredential,
    disclose: o.disclose ?? ['org', 'role'],
    kb: {
      signer: o.holder ?? w.oleh,
      aud: o.aud ?? request.requestObject.client_id,
      nonce: o.nonce ?? request.nonce,
      iat: o.iat ?? NOW + 1,
    },
    crypto: w.crypto,
  });
  return { vp_token: JSON.stringify({ [QUERY_ID]: [presentation] }), state: request.state };
}

/** The decision of the provider on a posted form. */
function decide(request: Asked, body: Record<string, string>, over: Partial<Input> = {}) {
  return verifyVpResponse({
    body,
    nonce: request.nonce,
    audience: request.requestObject.client_id,
    state: request.state,
    trusted: [w.entryA, w.entryB],
    fetchStatusList: feed({ [LIST_A]: listA, [LIST_B]: listB }).fetch,
    now: AT,
    crypto: w.crypto,
    ...over,
  });
}

describe('the login request', () => {
  it('is unsigned, by value, and names its response address as the client', async () => {
    const nonce = randomId(16);
    const state = randomId(16);
    const dcql = umisDcqlQuery({ vcts: [VCT.orgMember, VCT.roleAuthority], claims: ['org', 'role', 'org'] });
    expect(dcql).toEqual({
      credentials: [
        {
          id: 'umis',
          format: 'dc+sd-jwt',
          meta: { vct_values: [VCT.orgMember, VCT.roleAuthority] },
          claims: [{ path: ['org'] }, { path: ['role'] }],
        },
      ],
    });

    const { requestObject, walletUri } = await createVpRequest({
      responseUri: RESPONSE_URI,
      nonce,
      state,
      dcql,
      clientName: 'Acme Intranet',
    });
    expect(requestObject).toEqual({
      client_id: CLIENT_ID,
      response_type: 'vp_token',
      response_mode: 'direct_post',
      response_uri: RESPONSE_URI,
      nonce,
      state,
      dcql_query: dcql,
      client_metadata: {
        vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] } },
        client_name: 'Acme Intranet',
      },
    });

    // the link, read back without the wallet package: every parameter by value, the two objects as JSON
    expect(walletUri.startsWith('openid4vp://?')).toBe(true);
    expect(walletUri.length).toBeLessThan(2_000);
    const fields = parseQuery(splitUri(walletUri).query);
    expect(Object.keys(fields)).toEqual([
      'client_id',
      'response_type',
      'response_mode',
      'response_uri',
      'nonce',
      'state',
      'dcql_query',
      'client_metadata',
    ]);
    expect(fields.client_id).toBe(CLIENT_ID);
    expect(fields.response_uri).toBe(RESPONSE_URI);
    expect(JSON.parse(fields.dcql_query ?? '')).toEqual(dcql);
    expect(JSON.parse(fields.client_metadata ?? '')).toEqual(requestObject.client_metadata);
    expect(Object.keys(fields)).not.toContain('request_uri');
    expect(Object.keys(fields)).not.toContain('request');
  });

  it('refuses what it cannot carry', async () => {
    const dcql = umisDcqlQuery({ vcts: [VCT.orgMember], claims: ['org'] });
    const good = { responseUri: RESPONSE_URI, nonce: randomId(16), state: 'state-1', dcql };
    expect(await codeOfAsync(createVpRequest({ ...good, responseUri: 'http://op.example/cb' }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await codeOfAsync(createVpRequest({ ...good, responseUri: `${RESPONSE_URI}#top` }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await codeOfAsync(createVpRequest({ ...good, nonce: 'short' }))).toBe('INVALID_ARGUMENT');
    expect(await codeOfAsync(createVpRequest({ ...good, state: '' }))).toBe('INVALID_ARGUMENT');
    expect(await codeOfAsync(createVpRequest({ ...good, clientName: 'Acme\nIntranet' }))).toBe('INVALID_ARGUMENT');
    expect(await codeOfAsync(createVpRequest({ ...good, dcql: { credentials: [] } }))).toBe('INVALID_ARGUMENT');
    expect(await codeOfAsync(createVpRequest({ ...good, dcql: { credentials: [{ id: 'a b' }] } as never }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(await createVpRequest({ ...good, responseUri: 'http://localhost:3000/cb' })).toHaveProperty('walletUri');

    expect(codeOf(() => umisDcqlQuery({ vcts: [], claims: ['org'] }))).toBe('INVALID_ARGUMENT');
    expect(codeOf(() => umisDcqlQuery({ vcts: [VCT.orgMember], claims: ['given_name' as never] }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(codeOf(() => umisDcqlQuery({ vcts: [VCT.orgMember], claims: [], id: 'has space' }))).toBe(
      'INVALID_ARGUMENT',
    );
    expect(umisDcqlQuery({ vcts: [VCT.orgMember], claims: [] }).credentials[0]).not.toHaveProperty('claims');
  });
});

describe('the verdict on a login response', () => {
  it('accepts the claims the policy asks for, takes status lists only from fetchStatusList, once for each address', async () => {
    const network = vi.fn(() => {
      throw new Error('the network is off limits');
    });
    vi.stubGlobal('fetch', network);

    // a root credential: org and role, nothing else is shown
    const request = await asked();
    const root = feed({ [LIST_A]: listA });
    const accepted = await decide(request, await posted(request), { fetchStatusList: root.fetch });
    expectAccept(accepted);
    expect(accepted.channel).toBe('oid4vp');
    expect(accepted.issuer).toBe(ISSUER_A);
    expect(accepted.credentialRef).toBe('cred-oleh-0001');
    expect(accepted.claims).toMatchObject({
      org: { id: 'contractor-a' },
      role: { code: 'crew_lead' },
      sub: 'p_cred-oleh-0001',
    });
    expect(Object.keys(accepted.claims ?? {}).sort()).toEqual(['org', 'role', 'sub']);
    expect(accepted.statusListAgeSeconds).toBe(100);
    expect(root.calls).toEqual([LIST_A]);

    // a delegate that shows its chain: the status of the credential and that of its parent are on one list
    const second = await asked();
    const delegate = feed({ [LIST_A]: listA });
    const chained = await decide(
      second,
      await posted(second, {
        credential: w.ivanCredential,
        holder: w.ivan,
        disclose: ['org', 'role', 'authority', 'delegation'],
      }),
      { fetchStatusList: delegate.fetch },
    );
    expectAccept(chained);
    expect(chained.delegation).toEqual({ depth: 1, parentId: 'cred-oleh-0001' });
    expect(delegate.calls).toEqual([LIST_A]);

    // an org-member credential of the other issuer answers the same kind of request
    const third = await asked();
    const member = feed({ [LIST_B]: listB });
    expectAccept(
      await decide(third, await posted(third, { credential: w.mariiaCredential, holder: w.mariia }), {
        fetchStatusList: member.fetch,
      }),
    );
    expect(member.calls).toEqual([LIST_B]);
    expect(network).not.toHaveBeenCalled();
  });

  it('binds the response to the nonce and the prefixed client id, and accepts a nonce once', async () => {
    const request = await asked();
    const replay = createMemoryReplayStore();

    expectReject(await decide(request, await posted(request, { nonce: randomId(16) }), { replay }), 'NONCE_MISMATCH');
    // I-5: a key-binding JWT made for the bare response address is not made for this client
    expectReject(await decide(request, await posted(request, { aud: RESPONSE_URI }), { replay }), 'AUDIENCE_MISMATCH');
    expectReject(
      await decide(request, await posted(request, { aud: 'redirect_uri:https://evil.example/cb' }), { replay }),
      'AUDIENCE_MISMATCH',
    );
    // none of those used the request up
    const good = await posted(request);
    expectAccept(await decide(request, good, { replay }));

    // I-2: the nonce of a request answers once, the same body or another credential's body alike
    expectReject(await decide(request, good, { replay }), 'REPLAY');
    const other = await posted(request, { credential: w.mariiaCredential, holder: w.mariia });
    expectReject(await decide(request, other, { replay }), 'REPLAY');

    // the key-binding JWT must be recent
    const fresh = await asked();
    expectReject(await decide(fresh, await posted(fresh, { iat: AT - 121 })), 'PRESENTATION_EXPIRED');
    expectAccept(await decide(fresh, await posted(fresh, { iat: AT - 120 })));
  });

  it('refuses a response that is not exactly one presentation for the request, and never throws', async () => {
    const request = await asked();
    const one = await posted(request);
    const presentation = (JSON.parse(one.vp_token ?? '') as Record<string, string[]>)[QUERY_ID]![0]!;
    const { state } = request;

    const broken: Array<[string, Record<string, string>]> = [
      ['two presentations', { vp_token: JSON.stringify({ [QUERY_ID]: [presentation, presentation] }), state }],
      ['two query ids', { vp_token: JSON.stringify({ [QUERY_ID]: [presentation], other: [presentation] }), state }],
      ['no query id', { vp_token: '{}', state }],
      ['no presentation', { vp_token: JSON.stringify({ [QUERY_ID]: [] }), state }],
      ['a presentation that is not text', { vp_token: JSON.stringify({ [QUERY_ID]: [5] }), state }],
      ['a token that is not JSON', { vp_token: presentation, state }],
      ['a token that is a list', { vp_token: JSON.stringify([presentation]), state }],
      ['no vp_token', { state }],
      ['a token that is far too long', { vp_token: 'x'.repeat(70_000), state }],
      ['another state', { ...one, state: randomId(16) }],
      ['no state', { vp_token: one.vp_token ?? '' }],
    ];
    for (const [name, body] of broken) {
      const result = await decide(request, body);
      expect(result.decision, name).toBe('reject');
      expectReject(result, 'MALFORMED');
    }
    // without a state of its own the verifier asks for none
    expectAccept(await decide(request, { vp_token: one.vp_token ?? '' }, { state: undefined }));

    // a verifier that lost the nonce or the audience of its request would accept any: it rejects instead
    expectReject(await decide(request, one, { nonce: undefined as never }), 'MALFORMED');
    expectReject(await decide(request, one, { nonce: '' }), 'MALFORMED');
    expectReject(await decide(request, one, { audience: undefined as never }), 'MALFORMED');
    expectReject(await verifyVpResponse(null as never), 'MALFORMED');
    expectReject(await decide(request, null as never), 'MALFORMED');
    expectReject(await decide(request, one, { now: Number.NaN }), 'MALFORMED');
  });

  it('holds the status list to the maximum age of the policy and to revocation', async () => {
    const request = await asked();
    const body = await posted(request);
    const through = (tokens: Record<string, string>) => decide(request, body, { fetchStatusList: feed(tokens).fetch });

    // S is 600 seconds for the login policy, and the boundary is inclusive
    expectAccept(await through({ [LIST_A]: await statusList(w.issuerA, LIST_A, { iat: AT - 600 }) }));
    expectReject(
      await through({ [LIST_A]: await statusList(w.issuerA, LIST_A, { iat: AT - 601 }) }),
      'STATUS_LIST_STALE',
    );
    expectReject(
      await through({ [LIST_A]: await statusList(w.issuerA, LIST_A, { iat: AT - 10, revoked: [IDX.oleh] }) }),
      'STATUS_REVOKED',
    );
    // a list that the issuer did not sign, and a list that cannot be fetched
    expectReject(
      await through({ [LIST_A]: await statusList(w.issuerB, LIST_A, { iat: AT - 10 }) }),
      'STATUS_LIST_INVALID',
    );
    expectReject(await through({}), 'STATUS_LIST_MISSING');
  });

  it('exports exactly the names of the OpenID4VP helpers', () => {
    expect(Object.keys(oid4vp).sort()).toEqual(['createVpRequest', 'umisDcqlQuery', 'verifyVpResponse']);
  });
});
