import { createStatusListCache } from '@umis/status-list';
import { DEFAULT_POLICIES } from '@umis/policy';
import type { ReasonCode, VerifierContext } from '@umis/core';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { verifyAtCheckpoint, verifyResponseQr } from '../src/index.js';
import {
  AT,
  DAY,
  IDX,
  ISSUER_A,
  LIST_A,
  LIST_V,
  NOW,
  OLEH_AUTHORITY,
  T0,
  TEN_TONNES,
  answer,
  ask,
  buildWorld,
  credential,
  doorContext,
  expectAccept,
  expectReject,
  oneWayQr,
  statusList,
  warehouseContext,
  type World,
} from './fixtures.js';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const MEDIUM_S = DEFAULT_POLICIES.warehouse_medium.maxStatusAgeSeconds;
const LOW_S = DEFAULT_POLICIES.door_low.maxStatusAgeSeconds;

/** Oleh asks for ten tonnes, answers with this credential, and the warehouse decides with these lists. */
async function withLists(
  lists: Partial<VerifierContext>,
  cred: string = w.olehCredential,
  now: number = AT,
): ReturnType<typeof verifyResponseQr> {
  const { pending } = await ask(w);
  const reply = await answer(w, cred, w.oleh, pending);
  return verifyResponseQr(reply, pending, warehouseContext(w, { now, ...lists }));
}

const held = (token: string) => ({ token, fetchedAt: NOW - 300 });
const only = (token: string): Partial<VerifierContext> => ({ statusLists: new Map([[LIST_A, held(token)]]) });

describe('how old a status list may be', () => {
  it('is 24 hours for the medium class and 72 hours for the low class', () => {
    expect(MEDIUM_S).toBe(24 * 3_600);
    expect(LOW_S).toBe(72 * 3_600);
  });

  it('is exactly S for a medium checkpoint: an age of S is accepted and an age of S + 1 is stale', async () => {
    const edge = await statusList(w.issuerA, LIST_A, { iat: AT - MEDIUM_S });
    const accepted = await withLists(only(edge));
    expectAccept(accepted);
    expect(accepted.statusListAgeSeconds).toBe(MEDIUM_S);

    const over = await statusList(w.issuerA, LIST_A, { iat: AT - MEDIUM_S - 1 });
    const stale = await withLists(only(over));
    expectReject(stale, 'STATUS_LIST_STALE');
    expect(stale.trace[5]).toMatchObject({ name: 'status', ok: false, reason: 'STATUS_LIST_STALE' });
    expect(stale.statusListAgeSeconds).toBeUndefined();
  });

  it('is exactly S for a low checkpoint too', async () => {
    const qr = () => oneWayQr(w);
    const at = async (age: number) => {
      const token = await statusList(w.issuerV, LIST_V, { iat: AT - age });
      const ctx = await doorContext(w, { statusLists: new Map([[LIST_V, held(token)]]) });
      return verifyAtCheckpoint(await qr(), ctx);
    };
    expectAccept(await at(LOW_S));
    expectReject(await at(LOW_S + 1), 'STATUS_LIST_STALE');
    expectAccept(await at(0));
  });

  it('is the time since the list was issued, not the time since the device fetched it', async () => {
    const token = await statusList(w.issuerA, LIST_A, { iat: AT - MEDIUM_S - 1 });
    const justFetched = { statusLists: new Map([[LIST_A, { token, fetchedAt: AT }]]) };
    expectReject(await withLists(justFetched), 'STATUS_LIST_STALE');
  });

  it('ends at the expiry of the list, with the clock skew', async () => {
    const lasting = (exp: number) => statusList(w.issuerA, LIST_A, { iat: AT - 600, exp });
    expectAccept(await withLists(only(await lasting(AT - 9))));
    expectReject(await withLists(only(await lasting(AT - 10))), 'STATUS_LIST_STALE');
    expectAccept(await withLists(only(await lasting(AT + 1))));
  });

  it('does not accept a list that was issued in the future beyond the skew', async () => {
    expectAccept(await withLists(only(await statusList(w.issuerA, LIST_A, { iat: AT + 10 }))));
    const result = await withLists(only(await statusList(w.issuerA, LIST_A, { iat: AT + 11 })));
    expectReject(result, 'STATUS_LIST_INVALID');
  });

  it('reads the age again for a list that is already verified and cached', async () => {
    const cache = createStatusListCache();
    expectAccept(await withLists({ ...only(w.listA), statusCache: cache }));
    expectAccept(await withLists({ ...only(w.listA), statusCache: cache }));
    // a day and ten minutes later the same token is too old, although the cache holds it
    const { pending } = await ask(w, { now: NOW + DAY });
    const reply = await answer(w, w.olehCredential, w.oleh, pending);
    const later = warehouseContext(w, { now: NOW + DAY + 2, statusCache: cache });
    expectReject(await verifyResponseQr(reply, pending, later), 'STATUS_LIST_STALE');
  });
});

describe('what a list says about a credential', () => {
  it('rejects a revoked credential and a suspended one, each with its own reason', async () => {
    const revoked = await withLists(only(await statusList(w.issuerA, LIST_A, { iat: NOW - 600, revoked: [IDX.oleh] })));
    expectReject(revoked, 'STATUS_REVOKED');
    expect(revoked.trace[5]).toMatchObject({ name: 'status', ok: false, reason: 'STATUS_REVOKED' });
    expect(revoked.trace[6]).toMatchObject({ name: 'policy', skipped: true });
    // the operator still learns whose credential it was
    expect(revoked.credentialRef).toBe('cred-oleh-0001');

    const suspended = await withLists(
      only(await statusList(w.issuerA, LIST_A, { iat: NOW - 600, suspended: [IDX.oleh] })),
    );
    expectReject(suspended, 'STATUS_SUSPENDED');
  });

  it('accepts a credential again when the suspension is lifted in a newer list', async () => {
    const suspended = await statusList(w.issuerA, LIST_A, { iat: NOW - 600, suspended: [IDX.oleh] });
    expectReject(await withLists(only(suspended)), 'STATUS_SUSPENDED');
    const lifted = await statusList(w.issuerA, LIST_A, { iat: NOW - 300 });
    expectAccept(await withLists(only(lifted)));
  });

  it('looks at the place of this credential and at no other', async () => {
    const others = await statusList(w.issuerA, LIST_A, {
      iat: NOW - 600,
      revoked: [IDX.ivan, IDX.spare, 0, 500],
      suspended: [4, 1_023],
    });
    expectAccept(await withLists(only(others)));
  });

  it('rejects a place outside the list instead of reading it as valid', async () => {
    const outside = await credential({
      issuer: w.issuerA,
      iss: ISSUER_A,
      holder: w.oleh,
      jti: 'cred-oleh-0004',
      idx: 1_024,
      listUri: LIST_A,
      claims: {
        org: { id: 'contractor-a', name: 'Підрядник А' },
        role: { code: 'crew_lead', name: 'Керівник бригади' },
        authority: OLEH_AUTHORITY,
        delegation: { depth: 0, max_depth: 1 },
      },
      crypto: w.crypto,
    });
    expectReject(await withLists({}, outside), 'STATUS_LIST_INVALID');
  });
});

describe('a list that cannot be relied on', () => {
  it('is missing: the checkpoint holds none, and does not go to the network to find one', async () => {
    const network = vi.fn(() => Promise.reject(new Error('offline')));
    vi.stubGlobal('fetch', network);
    const none = await withLists({ statusLists: new Map() });
    expectReject(none, 'STATUS_LIST_MISSING');
    expect(none.trace[5]).toMatchObject({ name: 'status', reason: 'STATUS_LIST_MISSING' });
    expect(network).not.toHaveBeenCalled();
  });

  it('is invalid when another key signed it, even the key of another trusted issuer', async () => {
    const byB = await statusList(w.issuerB, LIST_A, { iat: NOW - 600 });
    expectReject(await withLists(only(byB)), 'STATUS_LIST_INVALID');
    const bothTrusted = [...warehouseContext(w).trusted, w.entryB];
    expectReject(await withLists({ ...only(byB), trusted: bothTrusted }), 'STATUS_LIST_INVALID');
  });

  it('is read only through the entry of the issuer of the credential, never a copycat entry naming the same list', async () => {
    // the entry of supplier B also names the list of contractor A, and comes first
    const trusted = [{ ...w.entryB, statusLists: [LIST_A] }, ...warehouseContext(w).trusted];
    const forged = await statusList(w.issuerB, LIST_A, { iat: NOW - 600 });
    expectReject(await withLists({ ...only(forged), trusted }), 'STATUS_LIST_INVALID');
    const genuine = await statusList(w.issuerA, LIST_A, { iat: NOW - 600, revoked: [IDX.oleh] });
    expectReject(await withLists({ ...only(genuine), trusted }), 'STATUS_REVOKED');
  });

  it('is invalid when it is the list of another address, whoever signed it', async () => {
    const elsewhere = await statusList(w.issuerA, 'https://issuer.example/status/contractor-a/7', { iat: NOW - 600 });
    expectReject(await withLists(only(elsewhere)), 'STATUS_LIST_INVALID');
  });

  it('is invalid when it is not a status list token at all', async () => {
    for (const token of ['', 'abc', 'a.b.c', w.olehCredential, `${w.listA}x`]) {
      expectReject(await withLists(only(token)), 'STATUS_LIST_INVALID');
    }
  });

  it('is missing for an issuer whose registry entry does not name the list', async () => {
    const unnamed = [{ ...w.entryA, statusLists: ['https://issuer.example/status/contractor-a/9'] }];
    expectReject(await withLists({ trusted: unnamed }), 'STATUS_LIST_MISSING');
  });
});

describe('a verifier that is online', () => {
  const online = (outcome: string | Error) =>
    vi.fn<(uri: string) => Promise<string>>(() =>
      outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome),
    );

  it('fetches the list it does not hold, once per decision, and verifies it like any other', async () => {
    const fetchStatusList = online(w.listA);
    const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount: 8 } });
    const reply = await answer(w, w.ivanCredential, w.ivan, pending);
    const ctx = warehouseContext(w, { statusLists: new Map(), fetchStatusList });
    const result = await verifyResponseQr(reply, pending, ctx);
    expectAccept(result);
    // the delegate and its parent are on the same list
    expect(fetchStatusList).toHaveBeenCalledTimes(1);
    expect(fetchStatusList).toHaveBeenCalledWith(LIST_A);
    expect(result.delegation).toEqual({ depth: 1, parentId: 'cred-oleh-0001' });
  });

  it('prefers the list it holds', async () => {
    const fetchStatusList = online(w.listA);
    expectAccept(await withLists({ fetchStatusList }));
    expect(fetchStatusList).not.toHaveBeenCalled();
  });

  it('rejects a fetched list that is revoked, stale or forged, and one that could not be fetched', async () => {
    const empty: Partial<VerifierContext> = { statusLists: new Map() };
    const revoked = await statusList(w.issuerA, LIST_A, { iat: NOW - 600, revoked: [IDX.oleh] });
    expectReject(await withLists({ ...empty, fetchStatusList: online(revoked) }), 'STATUS_REVOKED');

    const old = await statusList(w.issuerA, LIST_A, { iat: AT - MEDIUM_S - 1 });
    expectReject(await withLists({ ...empty, fetchStatusList: online(old) }), 'STATUS_LIST_STALE');

    const forged = await statusList(w.issuerB, LIST_A, { iat: NOW - 600 });
    expectReject(await withLists({ ...empty, fetchStatusList: online(forged) }), 'STATUS_LIST_INVALID');

    const down = await withLists({ ...empty, fetchStatusList: online(new Error('connection refused')) });
    expectReject(down, 'STATUS_LIST_MISSING');
    const notAFunction = await withLists({ ...empty, fetchStatusList: 'https://issuer.example' as never });
    expectReject(notAFunction, 'STATUS_LIST_MISSING');
  });
});

describe('the validity of the credential itself', () => {
  const lifetime = (o: { iat?: number; exp?: number; nbf?: number }): Promise<string> =>
    credential({
      issuer: w.issuerA,
      iss: ISSUER_A,
      holder: w.oleh,
      jti: 'cred-oleh-0005',
      idx: IDX.spare,
      listUri: LIST_A,
      ...o,
      claims: {
        org: { id: 'contractor-a', name: 'Підрядник А' },
        role: { code: 'crew_lead', name: 'Керівник бригади' },
        authority: OLEH_AUTHORITY,
        delegation: { depth: 0, max_depth: 1 },
      },
      crypto: w.crypto,
    });
  const verdict = async (o: { iat?: number; exp?: number; nbf?: number }): Promise<ReasonCode> => {
    const result = await withLists({}, await lifetime(o));
    return result.reasons[0]!;
  };

  it('ends at exp plus the skew', async () => {
    expect(await verdict({ exp: AT - 9 })).toBe('OK');
    expect(await verdict({ exp: AT - 10 })).toBe('CREDENTIAL_EXPIRED');
    expect(await verdict({ exp: T0 + 1, iat: T0 })).toBe('CREDENTIAL_EXPIRED');
  });

  it('starts at nbf minus the skew', async () => {
    expect(await verdict({ nbf: AT + 10 })).toBe('OK');
    expect(await verdict({ nbf: AT + 11 })).toBe('CREDENTIAL_NOT_YET_VALID');
  });

  it('does not begin before it was issued, within the skew', async () => {
    expect(await verdict({ iat: AT + 10 })).toBe('OK');
    expect(await verdict({ iat: AT + 11 })).toBe('CREDENTIAL_NOT_YET_VALID');
  });

  it('is checked before the status list is read', async () => {
    const result = await withLists({ statusLists: new Map() }, await lifetime({ exp: AT - 10 }));
    expectReject(result, 'CREDENTIAL_EXPIRED');
    expect(result.trace[5]).toMatchObject({ name: 'status', skipped: true });
  });
});
