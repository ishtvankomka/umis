import { LIMITS, UmisError, frameKindOf } from '@umis/core';
import type { Channel, CheckStep, StepName, VerificationResult, VerifierContext } from '@umis/core';
import { verifyAtCheckpoint } from '@umis/verifier';
import type { RelayClient } from './shelly.js';

/** Seconds a relay stays open when neither the gateway nor the policy of the checkpoint says otherwise. */
const DEFAULT_OPEN_SECONDS = 3;
/** Room above the longest QR code for what a scanner adds around it. */
const INPUT_SLACK_CHARS = 16;
/** The characters of QR alphanumeric mode: digits, capital letters, space and `$ % * + - . / :`. */
const QR_ALPHANUMERIC = /^[0-9A-Z $%*+\-./:]*$/;

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

/** What a gateway does with a scanned text: the decision and, when the relay was asked to open, how that went. */
export interface Gateway {
  handle(text: string): Promise<{ result: VerificationResult; relay?: { ok: boolean; status: number } }>;
}

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

/** The reject for a text that was turned away before anything was decoded: the parse step failed, the rest did not run. */
function turnedAway(channel: Channel, at: number): VerificationResult {
  const trace: CheckStep[] = STEP_NAMES.map((name, index) => {
    const step = (index + 1) as CheckStep['step'];
    return index === 0
      ? { step, name, ok: false, ms: 0, reason: 'MALFORMED' }
      : { step, name, ok: false, ms: 0, skipped: true };
  });
  return { decision: 'reject', reasons: ['MALFORMED'], channel, at, timings: { totalMs: 0 }, trace };
}

function positive(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0;
}

/**
 * The gateway of a checkpoint: it takes the text of a scanned QR code, decides on it offline with `verifyAtCheckpoint`
 * and, only when the decision is an accept, asks the relay to open for `openSeconds` (else the `relay.openSeconds` of the
 * checkpoint policy, else 3). `context` supplies the verifier context for each scan; its clock is replaced by `now`, the
 * clock of the gateway, so that the decision and the relay command agree. A text longer than `maxInputChars` (the longest
 * QR code plus 16 by default) or with a character that QR alphanumeric mode cannot carry is MALFORMED and is turned away
 * before it is decoded. A relay that fails or does not answer never changes the decision. `onDecision` hears every
 * decision, accepted or not, before the relay is asked; what it does cannot change the outcome either. When `context()`
 * fails the gateway throws PROTOCOL, opens nothing and returns no decision.
 */
export function createGateway(i: {
  context: () => VerifierContext | Promise<VerifierContext>;
  relay?: RelayClient;
  switchId?: number;
  openSeconds?: number;
  maxInputChars?: number;
  now: () => number;
  onDecision?: (r: VerificationResult) => void;
}): Gateway {
  if (typeof i !== 'object' || i === null) throw invalid('createGateway needs its input object');
  if (typeof i.context !== 'function') throw invalid('context must be a function that returns the verifier context');
  if (typeof i.now !== 'function') throw invalid('now must be a function that returns seconds');
  const switchId = i.switchId ?? 0;
  if (!Number.isSafeInteger(switchId) || switchId < 0) throw invalid('switchId must be a non-negative integer');
  if (i.openSeconds !== undefined && !positive(i.openSeconds)) throw invalid('openSeconds must be above 0');
  const maxInputChars = i.maxInputChars ?? LIMITS.qrMaxChars + INPUT_SLACK_CHARS;
  if (!Number.isSafeInteger(maxInputChars) || maxInputChars < 1)
    throw invalid('maxInputChars must be a positive integer');

  function announce(result: VerificationResult): void {
    if (i.onDecision === undefined) return;
    try {
      const returned: unknown = i.onDecision(result);
      // a listener written as an async function must not turn its own failure into an unhandled rejection
      if (typeof (returned as { then?: unknown } | undefined)?.then === 'function') {
        void (returned as Promise<unknown>).then(undefined, () => undefined);
      }
    } catch {
      // the listener is an observer: the decision stands whatever it does
    }
  }

  function readClock(): number {
    const at = i.now();
    if (typeof at !== 'number' || !Number.isFinite(at)) throw invalid('now must return a number of seconds');
    return at;
  }

  async function open(seconds: number): Promise<{ ok: boolean; status: number }> {
    try {
      const outcome = await i.relay!.open({ switchId, seconds, now: readClock() });
      return { ok: outcome.ok === true, status: Number.isFinite(outcome.status) ? outcome.status : 0 };
    } catch {
      return { ok: false, status: 0 };
    }
  }

  return {
    async handle(text) {
      const at = readClock();
      const scanned = typeof text === 'string' ? text.trim() : undefined;
      if (scanned === undefined || scanned.length > maxInputChars || !QR_ALPHANUMERIC.test(scanned)) {
        const channel: Channel = scanned !== undefined && frameKindOf(scanned) === 'oneway' ? 'qr_oneway' : 'qr_full';
        const result = turnedAway(channel, at);
        announce(result);
        return { result };
      }

      let context: VerifierContext;
      try {
        context = await i.context();
      } catch (cause) {
        throw new UmisError('PROTOCOL', 'the verifier context could not be built', { cause });
      }
      const result = await verifyAtCheckpoint(scanned, { ...context, now: at });
      announce(result);
      if (result.decision !== 'accept' || i.relay === undefined) return { result };

      const seconds = i.openSeconds ?? context.policy?.relay?.openSeconds;
      return { result, relay: await open(positive(seconds) ? seconds : DEFAULT_OPEN_SECONDS) };
    },
  };
}
