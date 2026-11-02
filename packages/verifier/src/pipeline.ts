import {
  FRAME_KINDS,
  LIMITS,
  UmisError,
  VCT,
  checkCredentialTimes,
  checkDelegation,
  decodeFrame,
  ledgerKey,
  matchAuthority,
  parseSdJwt,
  periodWindow,
  verifyIssuerSignature,
  verifyKeyBinding,
} from '@umis/core';
import type {
  AuthorityLedger,
  AuthorityRequest,
  Channel,
  CheckStep,
  CryptoProvider,
  DisclosableClaim,
  EcPublicJwk,
  Frame,
  FrameKind,
  MemberCacheEntry,
  ParsedSdJwt,
  ParsedStatusList,
  ReasonCode,
  StatusRef,
  StepName,
  TrustedIssuerEntryV1,
  UmisClaimSet,
  VerificationResult,
  VerifierContext,
} from '@umis/core';
import { isChannelAllowed } from '@umis/policy';
import { entryForStatusList, resolveIssuer } from '@umis/registry';
import { checkStatus, verifyStatusListToken } from '@umis/status-list';
import { jsonCopy } from './context.js';
import { observeTime } from './replay.js';

// ---------------------------------------------------------------------------------------------------------------
// the shape of one decision
// ---------------------------------------------------------------------------------------------------------------

/** What a step reports: nothing when it passed, SKIP when it does not apply, else the one reason for rejecting. */
export type StepResult = ReasonCode | typeof SKIP | undefined;
export const SKIP = 'SKIP' as const;

type StepFn = (s: State) => StepResult | Promise<StepResult>;

const STEP_NAMES: readonly StepName[] = [
  'parse',
  'issuer_trust',
  'issuer_signature',
  'holder_binding',
  'validity',
  'status',
  'policy',
  'authority',
  'decision',
];

/** What the verifier asks of the presentation beyond its policy. */
export interface Spec {
  /** Claims the presentation must disclose; the policy's `requestedClaims` when absent. */
  readonly requiredClaims?: readonly DisclosableClaim[];
  /** The authority to check; the policy's fixed authority when absent. */
  readonly authority?: AuthorityRequest;
  /** Credential types that were asked for; every type the policy accepts when absent. */
  readonly vctAllowed?: readonly string[];
}

/** The credential as steps 5 to 9 see it, whether it came with a presentation or from the member cache. */
export interface Subject {
  readonly issuer: string;
  readonly vct: string;
  readonly credentialRef: string;
  readonly sub?: string;
  readonly iat?: number;
  readonly exp: number;
  readonly nbf?: number;
  readonly status: StatusRef;
  readonly claims: Partial<UmisClaimSet>;
}

/** Steps 2 to 4, which differ between a presentation and a one-way token. */
export interface Front {
  trust(s: State): StepResult | Promise<StepResult>;
  signature(s: State): StepResult | Promise<StepResult>;
  binding(s: State): StepResult | Promise<StepResult>;
}

type ListOutcome =
  | { readonly ok: true; readonly list: ParsedStatusList; readonly ageSeconds: number }
  | { readonly ok: false; readonly reason: ReasonCode };

/** The working state of one decision. Steps read and fill it; the result is built from it at the end. */
export interface State {
  readonly ctx: VerifierContext;
  readonly spec: Spec;
  readonly skew: number;
  readonly crypto: CryptoProvider | undefined;
  channel: Channel;
  front: Front | undefined;
  parsed: ParsedSdJwt | undefined;
  entry: TrustedIssuerEntryV1 | undefined;
  key: EcPublicJwk | undefined;
  cached: MemberCacheEntry | undefined;
  subject: Subject | undefined;
  exposed: boolean;
  statusAge: number | undefined;
  authority: VerificationResult['authority'];
  commit: (() => Promise<void>) | undefined;
  release: (() => void) | undefined;
  lists: Map<string, ListOutcome>;
}

const clock = (): number => (typeof performance === 'undefined' ? 0 : performance.now());

function createState(ctx: VerifierContext, channel: Channel, spec: Spec): State {
  const held = ctx as Partial<VerifierContext> | null | undefined;
  return {
    ctx,
    spec,
    skew: held?.skewSeconds ?? LIMITS.defaultSkewS,
    crypto: held?.crypto,
    channel,
    front: undefined,
    parsed: undefined,
    entry: undefined,
    key: undefined,
    cached: undefined,
    subject: undefined,
    exposed: false,
    statusAge: undefined,
    authority: undefined,
    commit: undefined,
    release: undefined,
    lists: new Map(),
  };
}

/** Whether the context cannot be decided with: a missing part, or a number that is not one (NaN passes every `<`). */
function contextProblem(s: State): boolean {
  const { ctx } = s;
  const ok =
    typeof ctx === 'object' &&
    ctx !== null &&
    Number.isFinite(ctx.now) &&
    Number.isFinite(s.skew) &&
    s.skew >= 0 &&
    typeof ctx.policy === 'object' &&
    ctx.policy !== null &&
    Number.isFinite(ctx.policy.oneWayTokenMaxAgeSeconds) &&
    Number.isFinite(ctx.policy.maxStatusAgeSeconds) &&
    Array.isArray(ctx.audiences) &&
    Array.isArray(ctx.trusted) &&
    typeof ctx.statusLists?.get === 'function' &&
    typeof ctx.replay?.checkAndRemember === 'function';
  return !ok;
}

function isFormatCode(code: string): code is 'MALFORMED' | 'UNSUPPORTED_FORMAT' {
  return code === 'MALFORMED' || code === 'UNSUPPORTED_FORMAT';
}

function frontOf(s: State): Front {
  if (s.front === undefined) throw new UmisError('PROTOCOL', 'the parse step chose no verification path');
  return s.front;
}

async function runSteps(s: State, parse: StepFn, trace: CheckStep[]): Promise<ReasonCode | undefined> {
  const steps: StepFn[] = [
    (st) => (contextProblem(st) ? 'MALFORMED' : parse(st)),
    (st) => frontOf(st).trust(st),
    (st) => frontOf(st).signature(st),
    (st) => frontOf(st).binding(st),
    validityStep,
    statusStep,
    policyStep,
    authorityStep,
    decisionStep,
  ];
  for (let index = 0; index < steps.length; index++) {
    const started = clock();
    let outcome: StepResult;
    try {
      outcome = await steps[index]!(s);
    } catch (error) {
      // only a parse can tell the format apart; whatever else goes wrong is reported as malformed input
      outcome = index === 0 && error instanceof UmisError && isFormatCode(error.code) ? error.code : 'MALFORMED';
    }
    const ms = clock() - started;
    const step = (index + 1) as CheckStep['step'];
    const name = STEP_NAMES[index]!;
    if (outcome === undefined) {
      trace.push({ step, name, ok: true, ms });
    } else if (outcome === SKIP) {
      trace.push({ step, name, ok: true, ms, skipped: true });
    } else {
      trace.push({ step, name, ok: false, ms, reason: outcome });
      for (let rest = index + 1; rest < steps.length; rest++) {
        trace.push({ step: (rest + 1) as CheckStep['step'], name: STEP_NAMES[rest]!, ok: false, ms: 0, skipped: true });
      }
      return outcome;
    }
  }
  return undefined;
}

function finish(s: State, trace: CheckStep[], reason: ReasonCode | undefined, totalMs: number): VerificationResult {
  const ctx = s.ctx as Partial<VerifierContext> | null | undefined;
  const result: VerificationResult = {
    decision: reason === undefined ? 'accept' : 'reject',
    reasons: [reason ?? 'OK'],
    channel: s.channel,
    at: typeof ctx?.now === 'number' && Number.isFinite(ctx.now) ? ctx.now : 0,
    timings: { totalMs },
    trace,
  };
  // what the credential says is shown only once its issuer is trusted and its signature (or the cache) vouches for it
  const subject = s.subject;
  if (s.exposed && subject !== undefined) {
    result.issuer = subject.issuer;
    result.vct = subject.vct;
    result.credentialRef = subject.credentialRef;
    result.claims = subject.sub === undefined ? subject.claims : { ...subject.claims, sub: subject.sub };
    const delegation = subject.claims.delegation;
    if (delegation !== undefined) {
      result.delegation =
        delegation.parent === undefined
          ? { depth: delegation.depth }
          : { depth: delegation.depth, parentId: delegation.parent.id };
    }
  }
  if (s.statusAge !== undefined) result.statusListAgeSeconds = s.statusAge;
  if (s.authority !== undefined) result.authority = s.authority;
  if (ctx?.pointId !== undefined) result.pointId = ctx.pointId;
  if (ctx?.policyVersion !== undefined) result.policyVersion = ctx.policyVersion;
  return result;
}

/**
 * Runs the nine steps over `parse`, which is step 1 and chooses the path for steps 2 to 4. It never throws: an
 * exception in a step rejects the credential as MALFORMED at that step, and the first failing step ends the decision
 * with its one reason. The trace always has nine entries.
 */
export async function execute(
  ctx: VerifierContext,
  channel: Channel,
  spec: Spec,
  parse: StepFn,
): Promise<VerificationResult> {
  const started = clock();
  const state = createState(ctx, channel, spec);
  const trace: CheckStep[] = [];
  let reason: ReasonCode | undefined;
  try {
    reason = await runSteps(state, parse, trace);
  } catch {
    reason = 'MALFORMED';
  } finally {
    state.release?.();
  }
  while (trace.length < STEP_NAMES.length) {
    const index = trace.length;
    trace.push({ step: (index + 1) as CheckStep['step'], name: STEP_NAMES[index]!, ok: false, ms: 0, skipped: true });
  }
  return finish(state, trace, reason, clock() - started);
}

// ---------------------------------------------------------------------------------------------------------------
// helpers shared by the entry points
// ---------------------------------------------------------------------------------------------------------------

const TOKEN_COUNT: Readonly<Record<FrameKind, number>> = {
  oneway: 1,
  full: 1,
  request: 1,
  response: 1,
  mutual_init: 2,
  mutual_reply: 1,
};

/**
 * A frame from what a scanner or a transport hands over: the text of a QR code is decoded, a Frame object is checked
 * for a known kind and the right number of text tokens. Throws MALFORMED or UNSUPPORTED_FORMAT.
 */
export function toFrame(input: unknown): Frame {
  if (typeof input === 'string') return decodeFrame(input);
  if (typeof input !== 'object' || input === null) {
    throw new UmisError('MALFORMED', 'a frame is the text of a QR code or a Frame object');
  }
  const { kind, tokens } = input as { kind?: unknown; tokens?: unknown };
  if (typeof kind !== 'string' || !(FRAME_KINDS as readonly string[]).includes(kind)) {
    throw new UmisError('UNSUPPORTED_FORMAT', 'unknown frame kind');
  }
  const known = kind as FrameKind;
  if (!Array.isArray(tokens) || tokens.length !== TOKEN_COUNT[known] || !tokens.every((t) => typeof t === 'string')) {
    throw new UmisError('MALFORMED', `a ${known} frame carries ${TOKEN_COUNT[known]} token(s)`);
  }
  return { kind: known, tokens: [...(tokens as string[])] };
}

/** The id under which a presentation is remembered: parts joined by `|`, with `|` and `%` inside a part escaped. */
export function replayKey(prefix: string, ...parts: Array<string | number>): string {
  return prefix + parts.map((part) => String(part).replaceAll('%', '%25').replaceAll('|', '%7C')).join('|');
}

/** Asks the replay store whether the id is new. Anything but a plain `true` counts as seen. */
export async function remember(s: State, id: string, expiresAt: number): Promise<boolean> {
  observeTime(s.ctx.replay, s.ctx.now);
  return (await s.ctx.replay.checkAndRemember(id, expiresAt)) === true;
}

/** The age a holder-made proof (one-way token or key-binding JWT) may have: the policy's, never above the profile's. */
export function holderMaxAge(ctx: VerifierContext): number {
  return Math.min(ctx.policy.oneWayTokenMaxAgeSeconds, LIMITS.oneWayMaxTtlS);
}

// ---------------------------------------------------------------------------------------------------------------
// steps 2 to 4 for an SD-JWT presentation
// ---------------------------------------------------------------------------------------------------------------

/** How a presentation is bound to the verifier: the checks of step 4 in the form each channel needs them. */
export interface Binding {
  readonly aud: string | readonly string[];
  /** The nonce the presentation must carry; without one the holder's own is accepted and remembered. */
  readonly nonce?: string;
  readonly maxAgeSeconds: number;
  readonly notBefore?: number;
  readonly replayKey: (nonce: string, subject: Subject) => string;
  readonly replayExpiresAt: number;
  /** A check that runs before the key-binding JWT is examined. */
  readonly before?: (s: State) => Promise<ReasonCode | undefined>;
  /** A check that runs after the key-binding JWT passed and before the replay store is asked. */
  readonly after?: (s: State, kb: { iat: number; nonce: string }) => ReasonCode | undefined;
}

export function sdJwtFront(b: Binding): Front {
  return {
    trust(s) {
      const parsed = s.parsed!;
      const payload = parsed.issuerJwt.payload;
      const resolved = resolveIssuer(s.ctx.trusted, {
        issuer: payload.iss,
        vct: payload.vct,
        kid: parsed.issuerJwt.header.kid,
        now: s.ctx.now,
      });
      if (!resolved.ok) return resolved.reason;
      s.entry = resolved.entry;
      s.key = resolved.key;
      return undefined;
    },

    async signature(s) {
      const parsed = s.parsed!;
      if (!(await verifyIssuerSignature(parsed, s.key!, s.crypto))) return 'SIGNATURE_INVALID';
      const payload = parsed.issuerJwt.payload;
      s.subject = {
        issuer: payload.iss,
        vct: payload.vct,
        credentialRef: payload.jti,
        sub: payload.sub,
        iat: payload.iat,
        exp: payload.exp,
        ...(payload.nbf === undefined ? {} : { nbf: payload.nbf }),
        status: payload.status.status_list,
        claims: parsed.claims,
      };
      s.exposed = true;
      return undefined;
    },

    async binding(s) {
      const subject = s.subject!;
      if (b.before !== undefined) {
        const early = await b.before(s);
        if (early !== undefined) return early;
      }
      const kb = await verifyKeyBinding(s.parsed!, {
        aud: b.aud,
        nonce: b.nonce,
        now: s.ctx.now,
        maxAgeSeconds: b.maxAgeSeconds,
        skewSeconds: s.skew,
        notBefore: b.notBefore,
        crypto: s.crypto,
      });
      if (!kb.ok) return kb.reason;
      if (b.after !== undefined) {
        const late = b.after(s, kb);
        if (late !== undefined) return late;
      }
      return (await remember(s, b.replayKey(kb.nonce, subject), b.replayExpiresAt)) ? undefined : 'REPLAY';
    },
  };
}

/**
 * The shared decision for an SD-JWT presentation with a key-binding JWT: the nine steps for any channel. `o` says how
 * the presentation is bound to this verifier (audience, nonce, age, the id it is remembered under) and what is asked
 * of it; the context supplies the policy, the trusted issuers, the status lists and the stores. It never throws.
 */
export function verifyPresentation(
  presentation: string,
  ctx: VerifierContext,
  o: {
    channel: Channel;
    aud: string | readonly string[];
    nonce?: string;
    maxAgeSeconds: number;
    notBefore?: number;
    requiredClaims?: readonly DisclosableClaim[];
    authority?: AuthorityRequest;
    replayKey: (nonce: string) => string;
    replayExpiresAt: number;
  },
): Promise<VerificationResult> {
  return execute(ctx, o?.channel, { requiredClaims: o?.requiredClaims, authority: o?.authority }, async (s) => {
    s.parsed = await parseSdJwt(presentation, s.crypto);
    s.front = sdJwtFront({
      aud: o.aud,
      nonce: o.nonce,
      maxAgeSeconds: o.maxAgeSeconds,
      notBefore: o.notBefore,
      replayKey: (nonce) => o.replayKey(nonce),
      replayExpiresAt: o.replayExpiresAt,
    });
    return undefined;
  });
}

// ---------------------------------------------------------------------------------------------------------------
// steps 5 to 9, shared by every path
// ---------------------------------------------------------------------------------------------------------------

function validityStep(s: State): StepResult {
  const subject = s.subject!;
  // a cached credential has no iat or nbf of its own; its expiry is all that is known
  const verdict = checkCredentialTimes(
    { iat: subject.iat ?? Number.NEGATIVE_INFINITY, exp: subject.exp, nbf: subject.nbf },
    s.ctx.now,
    s.skew,
  );
  if (verdict === undefined) return undefined;
  // an issue time ahead of the clock, beyond the skew, means that the credential has not started
  return verdict === 'CLOCK_SKEW' ? 'CREDENTIAL_NOT_YET_VALID' : verdict;
}

async function fetchList(s: State, uri: string): Promise<string | undefined> {
  if (typeof s.ctx.fetchStatusList !== 'function') return undefined;
  try {
    return await s.ctx.fetchStatusList(uri);
  } catch {
    return undefined;
  }
}

/** The verified status list `ref` points to, from the issuer's own entry and keys; held in the context or fetched. */
async function loadList(s: State, issuer: string, ref: StatusRef): Promise<ListOutcome> {
  const known = s.lists.get(ref.uri);
  if (known !== undefined) return known;

  const outcome = await resolveList(s, issuer, ref);
  s.lists.set(ref.uri, outcome);
  return outcome;
}

async function resolveList(s: State, issuer: string, ref: StatusRef): Promise<ListOutcome> {
  const missing: ListOutcome = { ok: false, reason: 'STATUS_LIST_MISSING' };
  const entry = entryForStatusList(s.ctx.trusted, issuer, ref.uri);
  if (entry === undefined) return missing;
  const token = s.ctx.statusLists.get(ref.uri)?.token ?? (await fetchList(s, ref.uri));
  if (token === undefined) return missing;

  const verdict = await verifyStatusListToken(token, {
    keys: entry.jwks.keys,
    expectedUri: ref.uri,
    now: s.ctx.now,
    maxAgeSeconds: s.ctx.policy.maxStatusAgeSeconds,
    skewSeconds: s.skew,
    cache: s.ctx.statusCache,
    crypto: s.crypto,
  });
  return verdict.ok ? verdict : { ok: false, reason: verdict.reason };
}

async function statusStep(s: State): Promise<StepResult> {
  const subject = s.subject!;
  const loaded = await loadList(s, subject.issuer, subject.status);
  if (!loaded.ok) return loaded.reason;
  s.statusAge = loaded.ageSeconds;
  switch (checkStatus(subject.status, loaded.list)) {
    case 'VALID':
      return undefined;
    case 'REVOKED':
      return 'STATUS_REVOKED';
    case 'SUSPENDED':
      return 'STATUS_SUSPENDED';
    default:
      return 'STATUS_LIST_INVALID';
  }
}

function admits(rule: 'self' | 'registry' | string[], issuer: string, selfIssuer: string | undefined): boolean {
  if (rule === 'registry') return true;
  if (rule === 'self') return selfIssuer !== undefined && issuer === selfIssuer;
  return Array.isArray(rule) && rule.includes(issuer);
}

function policyStep(s: State): StepResult {
  const { policy, selfIssuer } = s.ctx;
  const subject = s.subject!;

  const rules = policy.accepted.filter((rule) => rule.vct === subject.vct);
  if (rules.length === 0) return 'VCT_NOT_ALLOWED';
  if (s.spec.vctAllowed !== undefined && !s.spec.vctAllowed.includes(subject.vct)) return 'VCT_NOT_ALLOWED';
  if (!rules.some((rule) => admits(rule.issuers, subject.issuer, selfIssuer))) return 'ISSUER_UNTRUSTED';
  if (!isChannelAllowed(policy, s.channel)) return 'CHANNEL_NOT_ALLOWED';

  // the delegation claim has its own rule below: a hidden delegation is not a claim that is merely missing
  const required = s.spec.requiredClaims ?? policy.requestedClaims;
  for (const name of required) {
    if (name !== 'delegation' && subject.claims[name] === undefined) return 'CLAIM_MISSING';
  }
  const delegation = subject.claims.delegation;
  if (subject.vct === VCT.roleAuthority) {
    const linkNeeded = subject.claims.authority !== undefined || required.includes('delegation');
    if (delegation === undefined && linkNeeded) return 'DELEGATION_UNDISCLOSED';
    // a delegate that shows no parent hides the link as well
    if (delegation !== undefined && delegation.depth > 0 && delegation.parent === undefined) {
      return 'DELEGATION_UNDISCLOSED';
    }
  } else if (required.includes('delegation') && delegation === undefined) {
    return 'CLAIM_MISSING';
  }
  return undefined;
}

/** The authority to check: the one the verifier asked for, else the policy's fixed authority. */
function authorityRequest(s: State): AuthorityRequest | undefined {
  if (s.spec.authority !== undefined) return s.spec.authority;
  const configured = s.ctx.policy.authority;
  if (
    configured?.amountSource === 'fixed' &&
    typeof configured.fixedAmount === 'number' &&
    Number.isFinite(configured.fixedAmount)
  ) {
    return {
      action: configured.action,
      resource: configured.resource,
      amount: configured.fixedAmount,
      unit: configured.unit,
    };
  }
  return undefined;
}

const queues = new WeakMap<AuthorityLedger, Map<string, Promise<void>>>();

/** Lets one decision at a time work on a budget of a ledger, so that two scans cannot spend the same remainder. */
async function lockBudget(ledger: AuthorityLedger, key: string): Promise<() => void> {
  let perLedger = queues.get(ledger);
  if (perLedger === undefined) {
    perLedger = new Map();
    queues.set(ledger, perLedger);
  }
  const waiting = perLedger.get(key) ?? Promise.resolve();
  let open!: () => void;
  const turn = new Promise<void>((resolve) => {
    open = resolve;
  });
  const tail = waiting.then(() => turn);
  perLedger.set(key, tail);
  await waiting;
  return () => {
    open();
    if (perLedger.get(key) === tail) perLedger.delete(key);
  };
}

async function authorityStep(s: State): Promise<StepResult> {
  const { ctx } = s;
  const subject = s.subject!;
  const delegation = subject.claims.delegation;
  const parent = delegation?.parent;
  const asked = s.spec.authority !== undefined || ctx.policy.authority !== undefined;
  if (parent === undefined && !asked) return SKIP;

  if (delegation !== undefined && parent !== undefined) {
    const lineage = checkDelegation({
      parent: {
        authority: parent.authority,
        exp: parent.exp,
        depth: delegation.depth - 1,
        maxDepth: delegation.max_depth,
      },
      child: { authority: subject.claims.authority ?? [], exp: subject.exp },
    });
    if (!lineage.ok) return lineage.reason;

    const parentList = await loadList(s, subject.issuer, parent.status);
    if (!parentList.ok) return parentList.reason;
    switch (checkStatus(parent.status, parentList.list)) {
      case 'VALID':
        break;
      case 'REVOKED':
      case 'SUSPENDED':
        return 'PARENT_REVOKED';
      default:
        return 'STATUS_LIST_INVALID';
    }
  }
  if (!asked) return undefined;

  const request = authorityRequest(s);
  if (request === undefined) return 'AUTHORITY_MISSING';
  s.authority = { requested: { ...request } };
  const match = matchAuthority(subject.claims.authority, request, ctx.now);
  if (!match.ok) {
    if (match.item !== undefined) s.authority.matched = jsonCopy(match.item);
    return match.reason;
  }
  s.authority.matched = jsonCopy(match.item);

  const per = match.item.limit.per;
  if (ctx.ledger !== undefined && per !== undefined && per !== 'operation') {
    const ledger = ctx.ledger;
    const key = ledgerKey({ iss: subject.issuer, jti: subject.credentialRef, delegation, req: request });
    const window = periodWindow(per, ctx.now);
    s.release = await lockBudget(ledger, key);
    const used = await ledger.used(key, window);
    s.authority.usedInPeriod = used;
    if (!(used + request.amount <= match.item.limit.amount)) return 'AUTHORITY_PERIOD_EXCEEDED';
    s.commit = () => ledger.add(key, window, request.amount);
  }
  return undefined;
}

/** The accepting step: the only place where an accepted amount is booked against its period. */
async function decisionStep(s: State): Promise<StepResult> {
  await s.commit?.();
  return undefined;
}
