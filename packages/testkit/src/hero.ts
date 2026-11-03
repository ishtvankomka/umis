import { URN_PREFIX, UmisError, VCT, decodeCredential, parseQuery, randomId } from '@umis/core';
import type {
  AuthorityLedger,
  CryptoProvider,
  FetchLike,
  ParsedRequest,
  PendingRequest,
  ReasonCode,
  ReplayStore,
  VerificationResult,
  VerifierContext,
} from '@umis/core';
import { createMemoryLedger } from '@umis/policy';
import {
  createMemoryReplayStore,
  createRequestQr,
  verifyAtCheckpoint,
  verifyCounterparty,
  verifyResponseQr,
} from '@umis/verifier';
import { createVpRequest, umisDcqlQuery, verifyVpResponse } from '@umis/verifier/oid4vp';
import { createOneWayQr, createResponseQr, disclosurePlan, parseRequestQr } from '@umis/wallet';
import { respondToVpRequest } from '@umis/wallet/oid4vp';
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

/**
 * Seconds of simulated time from the first thing made in an exchange to the decision on it, so that a caller who wants a
 * decision at an exact instant sets the clock to that instant minus the delay before it starts the exchange.
 */
export const DECISION_DELAY_S = {
  door: SCAN_DELAY_S,
  authority: 2 * SCAN_DELAY_S + ANSWER_DELAY_S,
  login: SCAN_DELAY_S + ANSWER_DELAY_S,
} as const;

/** The relying party of hero step 4 and the address its provider listens on; invented, like the rest of the demo. */
const INTRANET = {
  name: 'Acme Intranet',
  responseUri: 'https://login.example.test/oid4vp/response',
  continueUri: 'https://intranet.example.test/signed-in',
} as const;

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

/** The texts of an authority check and what the warehouse decides with: everything except the decision. */
export interface AskedFrames {
  /** The QR code of the warehouse, the request. */
  request: string;
  pending: PendingRequest;
  /** The QR code of the holder, the answer. */
  frame: string;
  context: VerifierContext;
}

/**
 * The request of the warehouse of Постачальник Б for the power to receive `amount` tonnes of rebar, and the answer of
 * `holder` to it, made as Олег and Іван would make them. Nothing is decided: the context is new, and its replay store is
 * empty. The clock of the world moves on by `DECISION_DELAY_S.authority`, which is the time of the decision.
 */
export async function authorityFrames(
  world: DemoWorld,
  o: { holder: 'oleg' | 'ivan'; amount: number; ledger?: AuthorityLedger },
): Promise<AskedFrames> {
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
  return { request: asked.qr, pending: asked.pending, frame: response, context };
}

/**
 * Hero step 2: the warehouse of Постачальник Б asks `holder` for the power to receive `amount` tonnes of rebar and
 * decides on the answer, offline, against the registry of Постачальник Б. Олег holds 10 t, Іван 8 t delegated from him.
 */
export async function authorityCheck(
  world: DemoWorld,
  o: { holder: 'oleg' | 'ivan'; amount: number; ledger?: AuthorityLedger },
): Promise<AskedDecision> {
  const asked = await authorityFrames(world, o);
  return { ...asked, result: await verifyResponseQr(asked.frame, asked.pending, asked.context) };
}

/** The texts of a mutual exchange and what each side decides with: everything except the two decisions. */
export interface MutualFrames {
  /** Олег opens the exchange with the QR code of his phone; `request` is that code as Марія's wallet has read it. */
  opening: { frame: string; request: ParsedRequest; context: VerifierContext; pending: PendingRequest };
  /** Марія answers with her own credential. */
  reply: { frame: string; context: VerifierContext; pending: PendingRequest };
}

/**
 * Олег opens a mutual exchange with the QR code of his phone, Марія's wallet reads it and she answers with her own
 * credential. Nothing is decided: the two contexts are new and their replay stores are empty. The clock of the world
 * moves on by seven seconds.
 */
export async function mutualFrames(world: DemoWorld): Promise<MutualFrames> {
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
  return {
    opening: { frame: asked.qr, request, context: openingContext, pending: asked.pending },
    reply: { frame: replyFrame, context: replyContext, pending: asked.pending },
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
  const { opening, reply } = await mutualFrames(world);
  return {
    opening: {
      frame: opening.frame,
      context: opening.context,
      result: await verifyCounterparty(opening.request, opening.context),
      pending: opening.pending,
    },
    reply: {
      frame: reply.frame,
      context: reply.context,
      result: await verifyResponseQr(reply.frame, reply.pending, reply.context),
      pending: reply.pending,
    },
  };
}

/** A login as the relying party starts it: the request it shows as a QR code, and what its provider decides with. */
export interface LoginRequest {
  /** The `openid4vp://` link of the request: the text of the QR code on the login page. */
  walletUri: string;
  nonce: string;
  state: string;
  /** The client identifier of the request, prefix included: the audience of the answer. */
  audience: string;
  /** The trusted issuers and status lists the provider decides with: the registry of Підрядник А. */
  context: VerifierContext;
}

/** One login, decided: the request, the answer of the provider to the wallet and the decision it took. */
export interface LoginDecision extends Decision {
  login: LoginRequest;
  /** The HTTP status the provider answered the wallet with. */
  status: number;
  /** Where the provider asked the wallet to continue, after an accept. */
  redirectUri?: string;
}

/** The relying party asks for the organisation and the role of whoever signs in; the request is OpenID4VP 1.0 by value. */
export async function loginRequest(world: DemoWorld): Promise<LoginRequest> {
  const { crypto } = world;
  const context = world.context({ org: 'pidriadnyk-a', policy: 'login_oid4vp' });
  const nonce = randomId(16, crypto);
  const state = randomId(12, crypto);
  const { requestObject, walletUri } = await createVpRequest({
    responseUri: INTRANET.responseUri,
    nonce,
    state,
    dcql: umisDcqlQuery({ vcts: [VCT.roleAuthority], claims: ['org', 'role'] }),
    clientName: INTRANET.name,
  });
  return { walletUri, nonce, state, audience: requestObject.client_id, context };
}

/**
 * The wallet of Олег reads the login QR code and answers it by posting to `fetch`, as the request says. The clock of the
 * world moves on by the time it takes to scan and to confirm.
 */
export async function answerLogin(
  world: DemoWorld,
  login: LoginRequest,
  fetch: FetchLike,
): Promise<{ status: number; redirectUri?: string }> {
  const { clock, crypto } = world;
  clock.advance(DECISION_DELAY_S.login);
  return respondToVpRequest({
    walletUri: login.walletUri,
    sdJwtVc: credentialOf(world, 'oleg', 'roleAuthority'),
    disclose: ['org', 'role'],
    signer: world.people.oleg.holder,
    now: clock.now(),
    fetch,
    crypto,
  });
}

/**
 * The provider's decision on a posted answer (`body` is the form the wallet sent): the presentation goes through the nine
 * steps for the channel `oid4vp`, against the trusted issuers of the login, with the status lists fetched from memory.
 * `replay` is the store that accepts the nonce once.
 */
export function decideLogin(
  login: LoginRequest,
  body: Record<string, string>,
  o: { now: number; replay?: ReplayStore; crypto?: CryptoProvider },
): Promise<VerificationResult> {
  const { context } = login;
  return verifyVpResponse({
    body,
    nonce: login.nonce,
    state: login.state,
    audience: login.audience,
    trusted: context.trusted,
    fetchStatusList: (uri) => {
      const held = context.statusLists.get(uri);
      return held === undefined ? Promise.reject(new Error(`no status list at ${uri}`)) : Promise.resolve(held.token);
    },
    now: o.now,
    policy: context.policy,
    replay: o.replay,
    crypto: o.crypto,
  });
}

function httpAnswer(status: number, body: Record<string, string>): Awaited<ReturnType<FetchLike>> {
  return { status, headers: { get: () => null }, text: () => Promise.resolve(JSON.stringify(body)) };
}

/**
 * A login up to the moment the provider would decide: the request, and the form that the wallet of Олег posted in answer
 * to it, as the text that went over the wire (`text`) and read into its fields (`body`). Nothing is decided and nothing is
 * remembered. The clock of the world moves on by `DECISION_DELAY_S.login`, which is the time of the decision.
 */
export async function postedLogin(
  world: DemoWorld,
): Promise<{ login: LoginRequest; text: string; body: Record<string, string> }> {
  const login = await loginRequest(world);
  let posted: string | undefined;
  const capture: FetchLike = (_url, init) => {
    posted = init?.body;
    return Promise.resolve(httpAnswer(200, { redirect_uri: INTRANET.continueUri }));
  };
  await answerLogin(world, login, capture);
  if (posted === undefined) throw new UmisError('PROTOCOL', 'the wallet posted no answer');
  return { login, text: posted, body: parseQuery(posted) };
}

/**
 * Hero step 4: Олег signs in to the intranet of Підрядник А with his role-authority credential. The relying party shows
 * a login QR code, his wallet answers it, and the provider, a function in this process that stands where an HTTPS
 * endpoint would, decides on the answer and tells the wallet where to continue. Nothing leaves the process.
 */
export async function loginAtIntranet(world: DemoWorld): Promise<LoginDecision> {
  const { clock, crypto } = world;
  const login = await loginRequest(world);
  const replay = createMemoryReplayStore();
  const decided: { result?: VerificationResult } = {};

  const provider: FetchLike = async (url, init) => {
    if (url !== INTRANET.responseUri || init?.method !== 'POST') return httpAnswer(404, { error: 'not_found' });
    decided.result = await decideLogin(login, parseQuery(init.body ?? ''), { now: clock.now(), replay, crypto });
    return decided.result.decision === 'accept'
      ? httpAnswer(200, { redirect_uri: INTRANET.continueUri })
      : httpAnswer(400, { error: 'invalid_request' });
  };

  const sent = await answerLogin(world, login, provider);
  if (decided.result === undefined) throw new UmisError('PROTOCOL', 'the provider received no answer from the wallet');
  const outcome: LoginDecision = {
    frame: login.walletUri,
    context: { ...login.context, now: clock.now() },
    result: decided.result,
    login,
    status: sent.status,
  };
  if (sent.redirectUri !== undefined) outcome.redirectUri = sent.redirectUri;
  return outcome;
}

function rowOf(
  step: 1 | 2 | 3 | 4,
  name: string,
  actor: string,
  decision: Decision,
  expected: Expected,
): HeroStepResult {
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

function stepsOf(requested: ReadonlyArray<1 | 2 | 3 | 4> | undefined): Array<1 | 2 | 3 | 4> {
  if (requested === undefined) return [1, 2, 3, 4];
  const chosen = new Set<number>();
  for (const step of requested) {
    if (step !== 1 && step !== 2 && step !== 3 && step !== 4)
      throw new UmisError('INVALID_ARGUMENT', 'the steps to run are 1, 2, 3 and 4');
    chosen.add(step);
  }
  return ([1, 2, 3, 4] as const).filter((step) => chosen.has(step));
}

/**
 * Runs the hero scenario on the demo world, in one process and without a network: Олег opens the door of Коворкінг В,
 * Постачальник Б checks the power of authority of Олег (10 t, accepted) and of Іван (8 t, rejected for 10 t), Олег and
 * Марія exchange roles, and Олег signs in to the intranet of Підрядник А with his credential. All four steps run unless
 * `steps` names some; they run in order whatever the order of `steps`. The clock of the world moves on by a few seconds
 * at each exchange.
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
    } else if (step === 3) {
      const { opening, reply } = await mutualExchange(world);
      rows.push(rowOf(3, 'Mutual exchange', `${oleg.name} → ${orgs['postachalnyk-b'].name}`, opening, ACCEPTED));
      rows.push(rowOf(3, 'Mutual exchange', `${maria.name} → ${orgs['pidriadnyk-a'].name}`, reply, ACCEPTED));
    } else {
      const login = await loginAtIntranet(world);
      rows.push(rowOf(4, 'Login', `${oleg.name} → ${INTRANET.name}`, login, ACCEPTED));
    }
  }
  return rows;
}
