import {
  UmisError,
  VCT,
  base64urlEncode,
  encodeFrameBytes,
  generateSigner,
  issueCredential,
  parseQuery,
  randomBytes,
  randomId,
} from '@umis/core';
import type {
  AuthorityItem,
  AuthorityRequest,
  CheckpointPolicyV1,
  FetchLike,
  Frame,
  Signer,
  TrustedIssuerEntryV1,
  VerificationResult,
  VerifierContext,
} from '@umis/core';
import { buildStatusListToken } from '@umis/status-list';
import { createMemoryReplayStore, createRequestFrame, verifyResponseQr } from '@umis/verifier';
import { createVpRequest, umisDcqlQuery, verifyVpResponse } from '@umis/verifier/oid4vp';
import { createResponseFrame, parseRequestQr } from '@umis/wallet';
import { parseVpRequest, respondToVpRequest } from '@umis/wallet/oid4vp';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import * as entry from '../src/index.js';
import {
  UMIS_BLE_V1,
  chunkFrame,
  createMemoryTransportPair,
  createReassembler,
  requestOverTransport,
  serveOverTransport,
} from '../src/index.js';

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

const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Pushes every chunk and returns what the last push gave. */
function pushAll(reassembler: ReturnType<typeof createReassembler>, chunks: readonly Uint8Array[]) {
  let last: Uint8Array | undefined;
  for (const chunk of chunks) last = reassembler.push(chunk);
  return last;
}

describe('chunks and their reassembly', () => {
  it.each([23, 185, 512])('carries a 3 KB frame through an MTU of %i, over the link as well', async (mtu) => {
    const frame = randomBytes(3_072);
    const chunks = chunkFrame(frame, mtu, 7);
    expect(chunks).toHaveLength(Math.ceil(3_072 / (mtu - 3)));
    chunks.forEach((chunk, index) => {
      expect(chunk.length).toBeLessThanOrEqual(mtu);
      expect([...chunk.subarray(0, 3)]).toEqual([7, index, chunks.length]);
    });

    const reassembler = createReassembler();
    const results = chunks.map((chunk) => reassembler.push(chunk));
    expect(results.slice(0, -1).every((result) => result === undefined)).toBe(true);
    expect(results.at(-1)).toEqual(frame);

    const [sender, receiver] = createMemoryTransportPair({ mtu });
    const arrived = new Promise<Uint8Array>((resolve) => receiver.onFrame(resolve));
    await sender.send(frame);
    expect(await arrived).toEqual(frame);
  });

  it('keeps a frame within the bytes the header and the link allow', () => {
    // 255 chunks of 20 bytes at an MTU of 23, and no more than the frame limit at a large MTU
    expect(chunkFrame(new Uint8Array(5_100), 23, 0)).toHaveLength(255);
    expect(codeOf(() => chunkFrame(new Uint8Array(5_101), 23, 0))).toBe('INVALID_ARGUMENT');
    expect(chunkFrame(new Uint8Array(16_384), 512, 0).length).toBeGreaterThan(1);
    expect(codeOf(() => chunkFrame(new Uint8Array(16_385), 512, 0))).toBe('INVALID_ARGUMENT');
    expect(chunkFrame(Uint8Array.of(1, 2, 3), 4, 0)).toHaveLength(3);

    expect(codeOf(() => chunkFrame(new Uint8Array(0), 23, 0))).toBe('INVALID_ARGUMENT');
    expect(codeOf(() => chunkFrame(new Uint8Array(10), 3, 0))).toBe('INVALID_ARGUMENT');
    expect(codeOf(() => chunkFrame(new Uint8Array(10), 23.5, 0))).toBe('INVALID_ARGUMENT');
    expect(codeOf(() => chunkFrame(new Uint8Array(10), 23, 256))).toBe('INVALID_ARGUMENT');
    expect(codeOf(() => chunkFrame([1, 2] as never, 23, 0))).toBe('INVALID_ARGUMENT');
    expect(codeOf(() => createMemoryTransportPair({ mtu: 2 }))).toBe('INVALID_ARGUMENT');
  });

  it('refuses a chunk that does not belong to the message and starts over (I-13)', () => {
    const frame = randomBytes(300);
    const chunks = chunkFrame(frame, 23, 1);
    expect(chunks).toHaveLength(15);
    const reassembler = createReassembler();

    // a dropped chunk
    reassembler.push(chunks[0]!);
    reassembler.push(chunks[1]!);
    expect(codeOf(() => reassembler.push(chunks[3]!))).toBe('MALFORMED');
    expect(pushAll(reassembler, chunks)).toEqual(frame);

    // a duplicated chunk
    reassembler.push(chunks[0]!);
    reassembler.push(chunks[1]!);
    expect(codeOf(() => reassembler.push(chunks[1]!))).toBe('MALFORMED');
    expect(pushAll(reassembler, chunks)).toEqual(frame);

    // a message that does not start at its first chunk, or whose total changes, or whose index is out of range
    expect(codeOf(() => reassembler.push(chunks[2]!))).toBe('MALFORMED');
    reassembler.push(chunks[0]!);
    expect(codeOf(() => reassembler.push(Uint8Array.of(1, 1, 16, 9, 9, 9)))).toBe('MALFORMED');
    expect(codeOf(() => reassembler.push(Uint8Array.of(1, 15, 15, 9)))).toBe('MALFORMED');
    expect(codeOf(() => reassembler.push(Uint8Array.of(1, 0, 0, 9)))).toBe('MALFORMED');
    reassembler.push(chunks[0]!);
    expect(codeOf(() => reassembler.push(Uint8Array.of(2, 1, 15, 9, 9)))).toBe('MALFORMED');

    // a chunk without data, or that is not bytes at all
    expect(codeOf(() => reassembler.push(Uint8Array.of(1, 0, 1)))).toBe('MALFORMED');
    expect(codeOf(() => reassembler.push('chunk' as never))).toBe('MALFORMED');

    // a sender that gave up starts again with a new id: the old message is dropped and the new one goes through
    reassembler.push(chunks[0]!);
    reassembler.push(chunks[1]!);
    const again = chunkFrame(frame, 23, 2);
    expect(pushAll(reassembler, again)).toEqual(frame);
    reassembler.push(chunks[0]!);
    reassembler.reset();
    expect(pushAll(reassembler, chunks)).toEqual(frame);
  });

  it('caps what it holds, whatever the sender announces (I-13)', () => {
    // 255 chunks of 509 bytes are announced; the default cap of 16 384 bytes ends the message in the 33rd
    const reassembler = createReassembler();
    const flood = Array.from({ length: 255 }, (_, index) => Uint8Array.of(9, index, 255, ...new Uint8Array(509)));
    let accepted = 0;
    let code = '';
    for (const chunk of flood) {
      try {
        reassembler.push(chunk);
        accepted += 1;
      } catch (error) {
        code = error instanceof UmisError ? error.code : String(error);
        break;
      }
    }
    expect(code).toBe('MALFORMED');
    expect(accepted).toBe(32);
    expect(pushAll(reassembler, chunkFrame(randomBytes(1_000), 185, 3))).toHaveLength(1_000);

    // a lower cap of the caller's own
    const small = createReassembler({ maxBytes: 100 });
    expect(codeOf(() => pushAll(small, chunkFrame(randomBytes(300), 23, 0)))).toBe('MALFORMED');
    expect(pushAll(small, chunkFrame(randomBytes(100), 23, 0))).toHaveLength(100);
    expect(codeOf(() => createReassembler({ maxBytes: 0 }))).toBe('INVALID_ARGUMENT');
    expect(codeOf(() => createReassembler({ maxBytes: 16_385 }))).toBe('INVALID_ARGUMENT');
  });
});

/** A base64url segment of `size` random bytes, which a frame cannot compress away. */
const segment = (size: number): string => base64urlEncode(randomBytes(size));
const jws = (): string => `${segment(36)}.${segment(90)}.${segment(64)}`;
const bigRequest = (): Frame => ({ kind: 'request', tokens: [jws()] });
const bigAnswer = (): Frame => ({ kind: 'response', tokens: [`${jws()}~${segment(40)}~${jws()}`] });

describe('a session over a link', () => {
  const request: Frame = { kind: 'request', tokens: ['AAAA.BBBB.CCCC'] };
  const answer: Frame = { kind: 'response', tokens: ['AAAA.BBBB.CCCC~AAAA~AAAA.BBBB.CCCC'] };

  it('gives up on a frame that lost a chunk, and ends with a timeout', async () => {
    const lost = bigRequest();
    expect(chunkFrame(encodeFrameBytes(lost), 23, 0).length).toBeGreaterThan(4);
    const [verifier, wallet] = createMemoryTransportPair({ mtu: 23, dropChunk: (n) => n === 2 });
    const handled = vi.fn();
    serveOverTransport(wallet, async (incoming) => {
      handled(incoming);
      return answer;
    });
    expect(await codeOfAsync(requestOverTransport(verifier, lost, { timeoutMs: 50 }))).toBe('NETWORK');
    expect(handled).not.toHaveBeenCalled();

    // the answer is lost the same way: the request is one chunk (number 0), so number 3 is a chunk of the answer
    const reply = bigAnswer();
    expect(chunkFrame(encodeFrameBytes(reply), 23, 0).length).toBeGreaterThan(4);
    const [asker, server] = createMemoryTransportPair({ mtu: 23, dropChunk: (n) => n === 3 });
    const asked = vi.fn();
    serveOverTransport(server, async (incoming) => {
      asked(incoming);
      return reply;
    });
    expect(await codeOfAsync(requestOverTransport(asker, request, { timeoutMs: 50 }))).toBe('NETWORK');
    expect(asked).toHaveBeenCalledTimes(1);

    // and with no chunk lost the same two frames get through
    const [verifierOk, walletOk] = createMemoryTransportPair({ mtu: 23 });
    const through = vi.fn();
    serveOverTransport(walletOk, async (incoming) => {
      through(incoming);
      return reply;
    });
    expect(await requestOverTransport(verifierOk, lost)).toEqual(reply);
    expect(through).toHaveBeenCalledWith(lost);
  });

  it('carries one request and one answer per session', async () => {
    const [verifier, wallet] = createMemoryTransportPair();
    const seen: Frame[] = [];
    serveOverTransport(wallet, async (incoming) => {
      seen.push(incoming);
      return answer;
    });
    expect(await requestOverTransport(verifier, request)).toEqual(answer);
    expect(seen).toEqual([request]);

    // a second request, by the helper and by hand, finds no one to answer it
    expect(await codeOfAsync(requestOverTransport(verifier, request))).toBe('PROTOCOL');
    await verifier.send(encodeFrameBytes(request));
    await pause(20);
    expect(seen).toHaveLength(1);
    expect(codeOf(() => serveOverTransport(wallet, async () => answer))).toBe('PROTOCOL');

    // a closed link neither sends nor delivers
    await verifier.close();
    expect(await codeOfAsync(verifier.send(Uint8Array.of(1)))).toBe('NETWORK');
    expect(await codeOfAsync(wallet.send(Uint8Array.of(1)))).toBe('NETWORK');
  });

  it('turns an answer that is not a UMIS frame into an error, and ignores a request that is not one', async () => {
    const [verifier, wallet] = createMemoryTransportPair();
    const pending = requestOverTransport(verifier, request, { timeoutMs: 500 });
    await wallet.send(Uint8Array.of(0, 1, 2, 3));
    expect(await codeOfAsync(pending)).toBe('UNSUPPORTED_FORMAT');

    const [asker, server] = createMemoryTransportPair();
    const handled = vi.fn(async () => answer);
    serveOverTransport(server, handled);
    await asker.send(Uint8Array.of(0, 1, 2, 3));
    await pause(20);
    expect(handled).not.toHaveBeenCalled();
    expect(await requestOverTransport(asker, request)).toEqual(answer);

    // what a session needs is checked
    expect(await codeOfAsync(requestOverTransport({} as never, request))).toBe('INVALID_ARGUMENT');
    const [other] = createMemoryTransportPair();
    expect(await codeOfAsync(requestOverTransport(other, request, { timeoutMs: 0 }))).toBe('INVALID_ARGUMENT');
    expect(await codeOfAsync(requestOverTransport(other, { kind: 'request', tokens: [] }))).toBe('INVALID_ARGUMENT');
  });

  it('exports the transport names and the UMIS-BLE identifiers', () => {
    expect(Object.keys(entry).sort()).toEqual([
      'UMIS_BLE_V1',
      'chunkFrame',
      'createMemoryTransportPair',
      'createReassembler',
      'requestOverTransport',
      'serveOverTransport',
    ]);
    expect(UMIS_BLE_V1.service).toBe('04855e79-ac59-4fd0-b286-dc08d76c0659');
  });
});

// ---------------------------------------------------------------------------------------------------------------
// the channels together: a verifier and a wallet from the other packages
// ---------------------------------------------------------------------------------------------------------------

const DAY = 86_400;
/** 2026-11-04T00:00:00Z: when the credentials were issued. */
const T0 = 1_793_750_400;
const NOW = T0 + 3_600;
const AT = NOW + 2;
const ISSUER_A = 'https://issuer.example/contractor-a';
const LIST_A = 'https://issuer.example/status/contractor-a/1';
const VERIFIER_B = 'urn:umis:verifier:warehouse-b';
const TEN_TONNES: AuthorityRequest = { action: 'receive_materials', resource: 'rebar', amount: 10, unit: 't' };
const OLEH_AUTHORITY: AuthorityItem[] = [
  {
    action: 'receive_materials',
    resource: 'rebar',
    limit: { amount: 10, unit: 't', per: 'shift' },
    object: 'bridge-01',
  },
];
const IVAN_AUTHORITY: AuthorityItem[] = [
  {
    action: 'receive_materials',
    resource: 'rebar',
    limit: { amount: 8, unit: 't', per: 'shift' },
    object: 'bridge-01',
  },
];
/** The medium-class checkpoint of a warehouse that trusts contractor A. */
const WAREHOUSE_POLICY: CheckpointPolicyV1 = {
  schema: 'umis.policy.v1',
  riskClass: 'medium',
  channels: ['qr_reverse', 'ble'],
  maxStatusAgeSeconds: 86_400,
  statusRefreshSeconds: 3_600,
  oneWayTokenMaxAgeSeconds: 30,
  requireBiometric: true,
  accepted: [{ vct: VCT.roleAuthority, issuers: 'registry' }],
  requestedClaims: ['org', 'role', 'authority'],
  authority: { action: 'receive_materials', resource: 'rebar', unit: 't', amountSource: 'request' },
};

let issuerA: Signer;
let deviceB: Signer;
let oleh: Signer;
let ivan: Signer;
let olehCredential: string;
let ivanCredential: string;
let trusted: TrustedIssuerEntryV1[];
let listToken: string;

beforeAll(async () => {
  [issuerA, deviceB, oleh, ivan] = await Promise.all([
    generateSigner(),
    generateSigner(),
    generateSigner(),
    generateSigner(),
  ]);
  const org = { id: 'contractor-a', name: 'Підрядник А' };
  const issue = (
    holder: Signer,
    jti: string,
    idx: number,
    exp: number,
    claims: Parameters<typeof issueCredential>[0]['claims'],
  ) =>
    issueCredential({
      signer: issuerA,
      payload: {
        iss: ISSUER_A,
        sub: `p_${jti}`,
        jti,
        iat: T0,
        exp,
        vct: VCT.roleAuthority,
        cnf: { jwk: holder.publicJwk },
        status: { status_list: { idx, uri: LIST_A } },
      },
      claims,
    });
  olehCredential = await issue(oleh, 'cred-oleh-0001', 1, T0 + 90 * DAY, {
    org,
    role: { code: 'crew_lead', name: 'Керівник бригади' },
    authority: OLEH_AUTHORITY,
    delegation: { depth: 0, max_depth: 1 },
    display: { name: 'Олег' },
  });
  ivanCredential = await issue(ivan, 'cred-ivan-0001', 2, T0 + 30 * DAY, {
    org,
    role: { code: 'crew_member', name: 'Бригадир зміни' },
    authority: IVAN_AUTHORITY,
    delegation: {
      parent: { id: 'cred-oleh-0001', status: { idx: 1, uri: LIST_A }, authority: OLEH_AUTHORITY, exp: T0 + 90 * DAY },
      depth: 1,
      max_depth: 1,
    },
    display: { name: 'Іван' },
  });
  trusted = [
    {
      issuer: ISSUER_A,
      name: org.name,
      jwks: { keys: [issuerA.publicJwk] },
      vcts: [VCT.roleAuthority, VCT.orgMember],
      statusLists: [LIST_A],
      status: 'active',
    },
  ];
  listToken = await buildStatusListToken({
    signer: issuerA,
    uri: LIST_A,
    bits: 2,
    values: new Uint8Array(1_024),
    iat: AT - 100,
  });
});

describe('the channel ble', () => {
  /** The warehouse asks for ten tonnes over a link with the smallest MTU; `credential` answers. */
  async function receiveOverLink(credential: string, holder: Signer): Promise<VerificationResult> {
    const [verifierSide, walletSide] = createMemoryTransportPair({ mtu: 23 });
    const { frame, pending } = await createRequestFrame({
      deviceSigner: deviceB,
      audience: VERIFIER_B,
      claims: ['org', 'role', 'authority'],
      authority: TEN_TONNES,
      now: NOW,
    });
    serveOverTransport(walletSide, async (incoming) => {
      const parsed = await parseRequestQr(incoming, { verifierKeys: [deviceB.publicJwk], now: NOW });
      return createResponseFrame({
        request: parsed,
        sdJwtVc: credential,
        disclose: parsed.claims,
        signer: holder,
        now: NOW + 1,
      });
    });
    const received = await requestOverTransport(verifierSide, frame);
    const ctx: VerifierContext = {
      now: AT,
      audiences: [VERIFIER_B],
      policy: WAREHOUSE_POLICY,
      trusted,
      statusLists: new Map([[LIST_A, { token: listToken, fetchedAt: NOW }]]),
      replay: createMemoryReplayStore(),
    };
    return verifyResponseQr(received, pending, ctx);
  }

  it('lets Oleh through with 10 t and stops Ivan at 8 t, the decision taken from frames that crossed the link (S-1)', async () => {
    const oleh10 = await receiveOverLink(olehCredential, oleh);
    expect(oleh10.decision).toBe('accept');
    expect(oleh10.reasons).toEqual(['OK']);
    expect(oleh10.channel).toBe('ble');
    expect(oleh10.authority?.matched?.limit.amount).toBe(10);

    const ivan8 = await receiveOverLink(ivanCredential, ivan);
    expect(ivan8.decision).toBe('reject');
    expect(ivan8.reasons).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    expect(ivan8.channel).toBe('ble');
    expect(ivan8.authority?.matched?.limit.amount).toBe(8);
  });
});

describe('the channel oid4vp', () => {
  it('carries a login from the link to the verdict: client id, nonce, one use, and only the status list it asks for', async () => {
    const responseUri = 'https://op.example/oid4vp/response';
    const nonce = randomId(16);
    const state = randomId(16);
    const dcql = umisDcqlQuery({ vcts: [VCT.orgMember, VCT.roleAuthority], claims: ['org', 'role'] });
    const { requestObject, walletUri } = await createVpRequest({
      responseUri,
      nonce,
      state,
      dcql,
      clientName: 'Acme Intranet',
    });
    expect(requestObject.client_id).toBe(`redirect_uri:${responseUri}`);
    expect(walletUri.length).toBeLessThan(2_000);

    // what the wallet reads from the link
    const parsed = parseVpRequest(walletUri);
    expect(parsed).toMatchObject({
      clientId: requestObject.client_id,
      responseUri,
      nonce,
      state,
      clientName: 'Acme Intranet',
      requested: { vcts: [VCT.orgMember, VCT.roleAuthority], claims: ['org', 'role'] },
    });
    expect(parsed.dcql).toEqual(dcql);
    expect(parsed.dcql.credentials[0]?.meta.vct_values).toEqual([VCT.orgMember, VCT.roleAuthority]);
    expect(parsed.dcql.credentials[0]?.claims).toEqual([{ path: ['org'] }, { path: ['role'] }]);

    // the response endpoint of the provider: it decides on the form that arrives
    const listsAsked: string[] = [];
    const fetchStatusList = async (uri: string): Promise<string> => {
      listsAsked.push(uri);
      return listToken;
    };
    const replay = createMemoryReplayStore();
    const decide = (body: Record<string, string>, over: Partial<Parameters<typeof verifyVpResponse>[0]> = {}) =>
      verifyVpResponse({
        body,
        nonce,
        state,
        audience: requestObject.client_id,
        trusted,
        fetchStatusList,
        now: AT,
        replay,
        ...over,
      });
    let posted: Record<string, string> = {};
    let verdict: VerificationResult | undefined;
    const endpoint: FetchLike = async (url, init) => {
      expect(url).toBe(responseUri);
      posted = parseQuery(init?.body ?? '');
      verdict = await decide(posted);
      const accepted = verdict.decision === 'accept';
      return {
        status: accepted ? 200 : 400,
        headers: { get: () => null },
        text: async () => JSON.stringify(accepted ? { redirect_uri: 'https://rp.example/callback' } : {}),
      };
    };

    const delivered = await respondToVpRequest({
      walletUri,
      sdJwtVc: olehCredential,
      disclose: ['org', 'role'],
      signer: oleh,
      now: NOW + 1,
      fetch: endpoint,
    });
    expect(delivered).toEqual({ status: 200, redirectUri: 'https://rp.example/callback' });
    expect(verdict).toMatchObject({ decision: 'accept', reasons: ['OK'], channel: 'oid4vp', issuer: ISSUER_A });
    expect(Object.keys(verdict?.claims ?? {}).sort()).toEqual(['org', 'role', 'sub']);
    expect(listsAsked).toEqual([LIST_A]);

    // I-2: the same form again is a replay; I-5: the nonce and the prefixed client id are what the answer is bound to
    expect((await decide(posted)).reasons).toEqual(['REPLAY']);
    const fresh = { replay: createMemoryReplayStore() };
    expect((await decide(posted, { ...fresh, nonce: randomId(16) })).reasons).toEqual(['NONCE_MISMATCH']);
    expect((await decide(posted, { ...fresh, audience: responseUri })).reasons).toEqual(['AUDIENCE_MISMATCH']);
    expect((await decide(posted, { ...fresh, state: 'another' })).reasons).toEqual(['MALFORMED']);
    expect((await decide(posted, fresh)).reasons).toEqual(['OK']);
  });
});
