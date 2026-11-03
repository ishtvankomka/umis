import { URN_PREFIX, UmisError, VCT, decodeCredential } from '@umis/core';
import type { AuthorityLedger, PendingRequest, ReasonCode, VerificationResult, VerifierContext } from '@umis/core';
import { createMemoryLedger } from '@umis/policy';
import { createRequestQr, verifyAtCheckpoint, verifyCounterparty, verifyResponseQr } from '@umis/verifier';
import { createOneWayQr, createResponseQr, disclosurePlan, parseRequestQr } from '@umis/wallet';
import { createDemoWorld } from './world.js';
import type { DemoPerson, DemoWorld } from './world.js';

export interface HeroStepResult {
  step: 1 | 2 | 3 | 4;
  name: string;
  /** Who presented, and the organisation that decided: `Олег Бондар → Коворкінг В`. */
  actor: string;
  decision: 'accept' | 'reject';
  reasons: ReasonCode[];
  /** How long the verifier took to decide, in milliseconds of real time (the clock of the world does not enter). */
  ms: number;
  /** Length of the QR text that was checked. */
  frameChars?: number;
  /** The QR text that was checked. */
  frame?: string;
  /** What the scenario expects at this row, so that a run can say whether it came out as it should. */
  expected?: Expected;
}

/** The outcome the hero scenario expects at one row. */
export interface Expected {
  decision: 'accept' | 'reject';
  reason: ReasonCode;
}

/** One verification: the text that was shown, what the verifier decided with, and what it decided. */
export interface Decision {
  frame: string;
  context: VerifierContext;
  result: VerificationResult;
}

/** A verification that answers a request: the request and the record that checks the answer come with it. */
export interface AskedDecision extends Decision {
  request: string;
  pending: PendingRequest;
}

/** Seconds of simulated time between a frame being made and being read, and between a request and the holder's answer. */
const SCAN_DELAY_S = 2;
const ANSWER_DELAY_S = 3;

/** What the warehouse asks for in the hero scenario: rebar, counted in tonnes. */
const REBAR = { action: 'receive_materials', resource: 'rebar', unit: 't' } as const;

const ACCEPTED: Expected = { decision: 'accept', reason: 'OK' };
const OVER_LIMIT: Expected = { decision: 'reject', reason: 'AUTHORITY_LIMIT_EXCEEDED' };

/** A credential of a person in the world; a world that lacks it is a mistake of the caller. */
export function credentialOf(
  world: DemoWorld,
  person: keyof DemoWorld['people'],
  kind: keyof DemoPerson['credentials'],
): string {
  const credential = world.people[person].credentials[kind];
  if (credential === undefined) throw new UmisError('INVALID_ARGUMENT', `${person} holds no ${kind} credential`);
  return credential;
}

/** Hero step 1: Олег shows a one-way QR code at the door of Коворкінг В, which decides from its member cache. */
export async function oneWayAtDoor(world: DemoWorld): Promise<Decision> {
  const { holder } = world.people.oleg;
  const frame = await createOneWayQr({
    sdJwtVc: credentialOf(world, 'oleg', 'coworkingMember'),
    signer: holder,
    now: world.clock.now(),
    ctr: 1,
  });
  world.clock.advance(SCAN_DELAY_S);
  const context = world.context({ org: 'kovorking-v', policy: 'door_low' });
  return { frame, context, result: await verifyAtCheckpoint(frame, context) };
}

/**
 * Hero step 2: the warehouse of Постачальник Б asks `holder` for the power to receive `amount` tonnes of rebar and
 * decides on the answer, offline, against the registry of Постачальник Б. Олег holds 10 t, Іван 8 t delegated from him.
 */
export async function authorityCheck(
  world: DemoWorld,
  o: { holder: 'oleg' | 'ivan'; amount: number; ledger?: AuthorityLedger },
): Promise<AskedDecision> {
  const { clock, crypto } = world;
  const supplier = world.orgs['postachalnyk-b'];
  const person = world.people[o.holder];
  const credential = credentialOf(world, o.holder, o.holder === 'oleg' ? 'roleAuthority' : 'delegated');

  const asked = await createRequestQr({
    deviceSigner: supplier.verifierSigner,
    audience: `${URN_PREFIX.verifier}${supplier.slug}-warehouse-1`,
    claims: ['org', 'role', 'authority'],
    vct: [VCT.roleAuthority],
    authority: { ...REBAR, amount: o.amount },
    policy: { id: 'warehouse_medium', v: 1, risk: 'medium' },
    verifier: { name: supplier.name },
    now: clock.now(),
    crypto,
  });
  clock.advance(SCAN_DELAY_S);
  const request = await parseRequestQr(asked.qr, {
    verifierKeys: [supplier.verifierSigner.publicJwk],
    now: clock.now(),
    crypto,
  });
  clock.advance(ANSWER_DELAY_S);
  const response = await createResponseQr({
    request,
    sdJwtVc: credential,
    disclose: disclosurePlan(request, decodeCredential(credential)).disclose,
    signer: person.holder,
    now: clock.now(),
    crypto,
  });
  clock.advance(SCAN_DELAY_S);
  const context = world.context({ org: supplier.slug, policy: 'warehouse_medium', ledger: o.ledger });
  return {
    request: asked.qr,
    pending: asked.pending,
    frame: response,
    context,
    result: await verifyResponseQr(response, asked.pending, context),
  };
}

/**
 * Hero step 3: Олег opens a mutual exchange with the QR code of his phone, Марія's side checks his role-authority
 * credential, then Марія answers with her own credential and Олег's side checks that. `opening` is the first decision,
 * `reply` the second.
 */
export async function mutualExchange(world: DemoWorld): Promise<{
  opening: Decision & { pending: PendingRequest };
  reply: Decision & { pending: PendingRequest };
}> {
  const { clock, crypto } = world;
  const oleg = world.people.oleg;
  const maria = world.people.maria;
  const claims = ['org', 'role', 'display'] as const;

  const asked = await createRequestQr({
    deviceSigner: oleg.holder,
    audience: `${URN_PREFIX.wallet}${oleg.key}`,
    claims,
    policy: { id: 'mutual_medium', v: 1, risk: 'medium' },
    verifier: { name: oleg.name, org: world.orgs['pidriadnyk-a'].name },
    mutual: { sdJwtVc: credentialOf(world, 'oleg', 'roleAuthority'), disclose: claims, holderSigner: oleg.holder },
    now: clock.now(),
    crypto,
  });
  clock.advance(SCAN_DELAY_S);
  const request = await parseRequestQr(asked.qr, { now: clock.now(), crypto });
  const openingContext = world.context({ org: 'postachalnyk-b', policy: 'mutual_medium' });
  const opening = await verifyCounterparty(request, openingContext);

  clock.advance(ANSWER_DELAY_S);
  const replyFrame = await createResponseQr({
    request,
    sdJwtVc: credentialOf(world, 'maria', 'supplierMember'),
    disclose: claims,
    signer: maria.holder,
    now: clock.now(),
    crypto,
  });
  clock.advance(SCAN_DELAY_S);
  const replyContext = world.context({ org: 'pidriadnyk-a', policy: 'mutual_medium' });
  const reply = await verifyResponseQr(replyFrame, asked.pending, replyContext);
  return {
    opening: { frame: asked.qr, context: openingContext, result: opening, pending: asked.pending },
    reply: { frame: replyFrame, context: replyContext, result: reply, pending: asked.pending },
  };
}

function rowOf(step: 1 | 2 | 3, name: string, actor: string, decision: Decision, expected: Expected): HeroStepResult {
  const { result, frame } = decision;
  return {
    step,
    name,
    actor,
    decision: result.decision,
    reasons: [...result.reasons],
    ms: result.timings.totalMs,
    frameChars: frame.length,
    frame,
    expected,
  };
}

function stepsOf(requested: ReadonlyArray<1 | 2 | 3 | 4> | undefined): Array<1 | 2 | 3> {
  if (requested === undefined) return [1, 2, 3];
  const chosen = new Set<number>();
  for (const step of requested) {
    if (step !== 1 && step !== 2 && step !== 3)
      throw new UmisError('INVALID_ARGUMENT', 'the steps to run are 1, 2 and 3');
    chosen.add(step);
  }
  return ([1, 2, 3] as const).filter((step) => chosen.has(step));
}

/**
 * Runs hero steps 1 to 3 on the demo world, offline: Олег opens the door of Коворкінг В, Постачальник Б checks the power
 * of authority of Олег (10 t, accepted) and of Іван (8 t, rejected for 10 t), and Олег and Марія exchange roles. The
 * steps run in order whatever the order of `steps`. The clock of the world moves on by a few seconds at each exchange.
 */
export async function runHero(
  o: { world?: DemoWorld; steps?: ReadonlyArray<1 | 2 | 3 | 4> } = {},
): Promise<HeroStepResult[]> {
  const steps = stepsOf(o.steps);
  const world = o.world ?? (await createDemoWorld());
  const { oleg, ivan, maria } = world.people;
  const orgs = world.orgs;
  const rows: HeroStepResult[] = [];

  for (const step of steps) {
    if (step === 1) {
      const door = await oneWayAtDoor(world);
      rows.push(rowOf(1, 'Access', `${oleg.name} → ${orgs['kovorking-v'].name}`, door, ACCEPTED));
    } else if (step === 2) {
      // one budget per shift at the warehouse, shared by Олег and the colleague he delegated to
      const ledger = createMemoryLedger();
      for (const holder of ['oleg', 'ivan'] as const) {
        const name = holder === 'oleg' ? oleg.name : ivan.name;
        const asked = await authorityCheck(world, { holder, amount: 10, ledger });
        const expected = holder === 'oleg' ? ACCEPTED : OVER_LIMIT;
        rows.push(rowOf(2, 'Authority check', `${name} → ${orgs['postachalnyk-b'].name}`, asked, expected));
      }
    } else {
      const { opening, reply } = await mutualExchange(world);
      rows.push(rowOf(3, 'Mutual exchange', `${oleg.name} → ${orgs['postachalnyk-b'].name}`, opening, ACCEPTED));
      rows.push(rowOf(3, 'Mutual exchange', `${maria.name} → ${orgs['pidriadnyk-a'].name}`, reply, ACCEPTED));
    }
  }
  return rows;
}
