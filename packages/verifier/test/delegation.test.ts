import { DEFAULT_POLICIES } from '@umis/policy';
import { createRequestQr, verifyResponseQr } from '../src/index.js';
import type {
  AuthorityItem,
  DelegationClaim,
  DisclosableClaim,
  PendingRequest,
  Signer,
  VerifierContext,
} from '@umis/core';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  AT,
  DAY,
  IDX,
  ISSUER_A,
  IVAN_AUTHORITY,
  LIST_A,
  NOW,
  OLEH_PARENT,
  T0,
  TEN_TONNES,
  VERIFIER_B,
  answer,
  ask,
  buildWorld,
  credential,
  expectAccept,
  expectReject,
  statusList,
  warehouseContext,
  type World,
} from './fixtures.js';

const LIST_A_PARENT = 'https://issuer.example/status/contractor-a/2';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});

/** A credential of the delegate Ivan with this authority, delegation and lifetime. */
function delegate(
  o: { authority?: AuthorityItem[]; delegation?: DelegationClaim; exp?: number; jti?: string } = {},
): Promise<string> {
  return credential({
    issuer: w.issuerA,
    iss: ISSUER_A,
    holder: w.ivan,
    jti: o.jti ?? 'cred-ivan-0002',
    idx: IDX.spare,
    listUri: LIST_A,
    iat: T0 + 60,
    exp: o.exp ?? T0 + 30 * DAY,
    claims: {
      org: { id: 'contractor-a', name: 'Підрядник А' },
      role: { code: 'crew_member', name: 'Бригадир зміни' },
      authority: o.authority ?? IVAN_AUTHORITY,
      delegation: o.delegation ?? { parent: OLEH_PARENT, depth: 1, max_depth: 1 },
    },
    crypto: w.crypto,
  });
}

interface Try {
  holder?: Signer;
  disclose?: readonly DisclosableClaim[];
  ctx?: Partial<VerifierContext>;
  amount?: number;
}

/** The warehouse asks for `amount` tonnes (8 by default) and the holder answers with this credential. */
async function decide(cred: string, o: Try = {}) {
  const { pending } = await ask(w, { authority: { ...TEN_TONNES, amount: o.amount ?? 8 } });
  const reply = await answer(
    w,
    cred,
    o.holder ?? w.ivan,
    pending,
    o.disclose === undefined ? {} : { disclose: o.disclose },
  );
  return verifyResponseQr(reply, pending, warehouseContext(w, o.ctx));
}

/** The status list of contractor A with these credentials revoked or suspended. */
async function listWith(o: { revoked?: number[]; suspended?: number[] }): Promise<Partial<VerifierContext>> {
  const token = await statusList(w.issuerA, LIST_A, { iat: NOW - 600, ...o });
  return { statusLists: new Map([[LIST_A, { token, fetchedAt: NOW - 300 }]]) };
}

const narrow = (amount: number, over: Partial<AuthorityItem> = {}): AuthorityItem => ({
  action: 'receive_materials',
  resource: 'rebar',
  limit: { amount, unit: 't', per: 'shift' },
  object: 'bridge-01',
  ...over,
});

describe('a delegate and its parent', () => {
  it('is accepted when it keeps within what the parent was given', async () => {
    const result = await decide(w.ivanCredential);
    expectAccept(result);
    expect(result.delegation).toEqual({ depth: 1, parentId: 'cred-oleh-0001' });
    expect(result.authority!.matched!.limit.amount).toBe(8);
    expect(result.trace[7]).toMatchObject({ name: 'authority', ok: true });
  });

  it('may hold less than the parent in every respect that counts', async () => {
    for (const authority of [[narrow(8)], [narrow(1)], [narrow(0)], [narrow(10)]]) {
      expectAccept(await decide(await delegate({ authority }), { amount: 0 }));
    }
    expectAccept(await decide(await delegate({ exp: T0 + 90 * DAY })));
  });

  it('is rejected when its authority is wider than the parent’s', async () => {
    const wider: AuthorityItem[][] = [
      [narrow(12)],
      [narrow(10.5)],
      [narrow(8), narrow(11, { resource: 'cement' })],
      [narrow(8, { action: 'ship_materials' })],
      [narrow(8, { limit: { amount: 8, unit: 'kg', per: 'shift' } })],
      [narrow(8, { limit: { amount: 8, unit: 't', per: 'day' } })],
      [narrow(8, { limit: { amount: 8, unit: 't' } })],
      [narrow(8, { object: 'bridge-02' })],
      [{ action: 'receive_materials', resource: 'rebar', limit: { amount: 8, unit: 't', per: 'shift' } }],
    ];
    for (const authority of wider) {
      const result = await decide(await delegate({ authority }));
      expectReject(result, 'DELEGATION_WIDER_THAN_PARENT');
      expect(result.trace[7]).toMatchObject({ name: 'authority', ok: false, reason: 'DELEGATION_WIDER_THAN_PARENT' });
    }
  });

  it('is rejected when it outlives the parent, one second is enough', async () => {
    expectReject(await decide(await delegate({ exp: T0 + 90 * DAY + 1 })), 'DELEGATION_OUTLIVES_PARENT');
    expectReject(await decide(await delegate({ exp: T0 + 120 * DAY })), 'DELEGATION_OUTLIVES_PARENT');
  });

  it('is rejected when the chain is deeper than the credential allows', async () => {
    const parent = OLEH_PARENT;
    expectReject(
      await decide(await delegate({ delegation: { parent, depth: 2, max_depth: 1 } })),
      'DELEGATION_DEPTH_EXCEEDED',
    );
    expectReject(
      await decide(await delegate({ delegation: { parent, depth: 1, max_depth: 0 } })),
      'DELEGATION_DEPTH_EXCEEDED',
    );
    expectAccept(await decide(await delegate({ delegation: { parent, depth: 1, max_depth: 3 } })));
  });

  it('reports the depth first when several rules are broken', async () => {
    const credentialWithAll = await delegate({
      authority: [narrow(12)],
      exp: T0 + 120 * DAY,
      delegation: { parent: OLEH_PARENT, depth: 2, max_depth: 1 },
    });
    expectReject(await decide(credentialWithAll), 'DELEGATION_DEPTH_EXCEEDED');
    const outlivingAndWider = await delegate({ authority: [narrow(12)], exp: T0 + 120 * DAY });
    expectReject(await decide(outlivingAndWider), 'DELEGATION_OUTLIVES_PARENT');
  });
});

describe('the delegation that a holder must show', () => {
  it('is required whenever authority is asked for, and hiding it is its own reason', async () => {
    const hidden = ['org', 'role', 'authority'] as const;
    for (const [cred, holder] of [
      [w.ivanCredential, w.ivan],
      [w.olehCredential, w.oleh],
    ] as const) {
      const result = await decide(cred, { holder, disclose: hidden });
      expectReject(result, 'DELEGATION_UNDISCLOSED');
      expect(result.trace[6]).toMatchObject({ name: 'policy', ok: false, reason: 'DELEGATION_UNDISCLOSED' });
      expect(result.claims).not.toHaveProperty('delegation');
    }
  });

  it('is required of a verifier that forgot to ask for it, because authority is shown', async () => {
    const { pending } = await ask(w);
    const forgetful: PendingRequest = { ...pending, claims: ['org', 'role', 'authority'] };
    const reply = await answer(w, w.ivanCredential, w.ivan, forgetful);
    expectReject(await verifyResponseQr(reply, forgetful, warehouseContext(w)), 'DELEGATION_UNDISCLOSED');
  });

  it('is not hidden by a delegate that shows no parent', async () => {
    const orphan = await delegate({ delegation: { depth: 1, max_depth: 1 } });
    expectReject(await decide(orphan), 'DELEGATION_UNDISCLOSED');
    const root = await delegate({ delegation: { depth: 0, max_depth: 1 } });
    expectAccept(await decide(root));
  });

  it('is demanded of a holder who shows authority, whatever the request asked for', async () => {
    const { pending } = await createRequestQr({
      deviceSigner: w.deviceB,
      audience: VERIFIER_B,
      claims: ['org', 'role'],
      now: NOW,
      crypto: w.crypto,
    });
    const policy = structuredClone(DEFAULT_POLICIES.mutual_medium);
    // a delegate who shows its authority has to show the chain, even when nobody asked for an amount
    const reply = await answer(w, w.ivanCredential, w.ivan, pending, { disclose: ['org', 'role', 'authority'] });
    const result = await verifyResponseQr(reply, pending, warehouseContext(w, { policy }));
    expectReject(result, 'DELEGATION_UNDISCLOSED');
  });
});

describe('the parent of a delegate', () => {
  it('is looked up in the status list of the issuer, and a revoked or suspended parent ends the delegate', async () => {
    for (const lists of [{ revoked: [IDX.oleh] }, { suspended: [IDX.oleh] }]) {
      const result = await decide(w.ivanCredential, { ctx: await listWith(lists) });
      expectReject(result, 'PARENT_REVOKED');
      expect(result.trace[5]).toMatchObject({ name: 'status', ok: true });
      expect(result.trace[7]).toMatchObject({ name: 'authority', ok: false, reason: 'PARENT_REVOKED' });
    }
  });

  it('does not end the parent itself, nor a delegate whose own place is in the list', async () => {
    expectReject(
      await decide(w.olehCredential, { holder: w.oleh, amount: 10, ctx: await listWith({ revoked: [IDX.oleh] }) }),
      'STATUS_REVOKED',
    );
    expectReject(await decide(w.ivanCredential, { ctx: await listWith({ revoked: [IDX.ivan] }) }), 'STATUS_REVOKED');
    expectReject(
      await decide(w.ivanCredential, { ctx: await listWith({ suspended: [IDX.ivan] }) }),
      'STATUS_SUSPENDED',
    );
    // other people in the list change nothing
    expectAccept(await decide(w.ivanCredential, { ctx: await listWith({ revoked: [IDX.spare], suspended: [9] }) }));
  });

  it('is checked even when the amount is not what is asked for', async () => {
    const { pending } = await createRequestQr({
      deviceSigner: w.deviceB,
      audience: VERIFIER_B,
      claims: ['org', 'role', 'authority', 'delegation'],
      now: NOW,
      crypto: w.crypto,
    });
    const policy = () => structuredClone(DEFAULT_POLICIES.mutual_medium);
    const reply = await answer(w, w.ivanCredential, w.ivan, pending);
    const revoked = await verifyResponseQr(
      reply,
      pending,
      warehouseContext(w, { policy: policy(), ...(await listWith({ revoked: [IDX.oleh] })) }),
    );
    expectReject(revoked, 'PARENT_REVOKED');
    expect(revoked.authority).toBeUndefined();

    expectAccept(await verifyResponseQr(reply, pending, warehouseContext(w, { policy: policy() })));
  });

  it('is rejected when its list is not known to the verifier', async () => {
    const lost = { ...OLEH_PARENT, status: { idx: 1, uri: LIST_A_PARENT } };
    const cred = await delegate({ delegation: { parent: lost, depth: 1, max_depth: 1 } });
    const result = await decide(cred);
    expectReject(result, 'STATUS_LIST_MISSING');
    expect(result.trace[7]).toMatchObject({ name: 'authority', reason: 'STATUS_LIST_MISSING' });
  });

  it('is rejected when its list is stale, or was not signed by the issuer, or has no such place', async () => {
    const lost = { ...OLEH_PARENT, status: { idx: 1, uri: LIST_A_PARENT } };
    const cred = await delegate({ delegation: { parent: lost, depth: 1, max_depth: 1 } });
    const trusted = [{ ...w.entryA, statusLists: [LIST_A, LIST_A_PARENT] }];
    const withParentList = async (token: string): Promise<Partial<VerifierContext>> => ({
      trusted,
      statusLists: new Map([
        [LIST_A, { token: w.listA, fetchedAt: NOW - 300 }],
        [LIST_A_PARENT, { token, fetchedAt: NOW - 300 }],
      ]),
    });
    const day = DEFAULT_POLICIES.warehouse_medium.maxStatusAgeSeconds;

    const fresh = await statusList(w.issuerA, LIST_A_PARENT, { iat: AT - day });
    expectAccept(await decide(cred, { ctx: await withParentList(fresh) }));

    const stale = await statusList(w.issuerA, LIST_A_PARENT, { iat: AT - day - 1 });
    expectReject(await decide(cred, { ctx: await withParentList(stale) }), 'STATUS_LIST_STALE');

    const foreign = await statusList(w.issuerB, LIST_A_PARENT, { iat: AT - 60 });
    expectReject(await decide(cred, { ctx: await withParentList(foreign) }), 'STATUS_LIST_INVALID');

    const farAway = { ...OLEH_PARENT, status: { idx: 5_000, uri: LIST_A_PARENT } };
    const beyond = await delegate({ delegation: { parent: farAway, depth: 1, max_depth: 1 } });
    const valid = await statusList(w.issuerA, LIST_A_PARENT, { iat: AT - 60 });
    expectReject(await decide(beyond, { ctx: await withParentList(valid) }), 'STATUS_LIST_INVALID');
  });
});
