import {
  DISCLOSABLE_CLAIMS,
  LIMITS,
  MUTUAL_AUD,
  UmisError,
  VCT,
  encodeFrame,
  parseSdJwt,
  presentCredential,
  randomId,
  signPresentationRequest,
} from '@umis/core';
import type {
  AuthorityRequest,
  CryptoProvider,
  DisclosableClaim,
  Frame,
  PendingRequest,
  PresentationRequestPayloadV1,
  RiskClass,
  Signer,
  VerificationResult,
  VerifierContext,
} from '@umis/core';
import { execute, replayKey, sdJwtFront, toFrame } from './pipeline.js';

/** How long a request stays answerable unless the caller says otherwise. */
export const DEFAULT_REQUEST_TTL_S = 60;

export interface CreateRequestInput {
  /** Signs the request; for a mutual exchange the holder key signs instead (see `mutual`). */
  deviceSigner: Signer;
  /** Who asks: `urn:umis:verifier:<id>` or `urn:umis:wallet:<id>`. The answer is bound to it. */
  audience: string;
  claims: readonly DisclosableClaim[];
  /** Credential types asked for; both UMIS types when absent. */
  vct?: readonly string[];
  authority?: AuthorityRequest;
  policy?: { id: string; v: number; risk: RiskClass };
  verifier?: { name: string; org?: string };
  /** Turns the request into the opening of a mutual exchange: the asker shows its own credential too. */
  mutual?: { sdJwtVc: string; disclose: readonly DisclosableClaim[]; holderSigner: Signer };
  now: number;
  ttlSeconds?: number;
  crypto?: CryptoProvider;
}

function invalid(message: string): UmisError {
  return new UmisError('INVALID_ARGUMENT', message);
}

/** What the asker keeps to check the answer, and the frame to show. */
async function buildRequest(i: CreateRequestInput): Promise<{ frame: Frame; pending: PendingRequest }> {
  if (typeof i !== 'object' || i === null) throw invalid('the request input is missing');
  if (typeof i.audience !== 'string' || i.audience === '') throw invalid('audience must name the asker');
  if (typeof i.now !== 'number' || !Number.isFinite(i.now)) throw invalid('now must be a finite number of seconds');
  if (!Array.isArray(i.claims) || i.claims.length === 0) throw invalid('claims must name at least one claim');
  const ttl = i.ttlSeconds ?? DEFAULT_REQUEST_TTL_S;
  if (typeof ttl !== 'number' || !(ttl > 0 && ttl <= LIMITS.requestMaxTtlS)) {
    throw invalid(`ttlSeconds is more than 0 and at most ${LIMITS.requestMaxTtlS}`);
  }
  for (const name of i.claims) {
    if (!(DISCLOSABLE_CLAIMS as readonly string[]).includes(name))
      throw invalid(`"${String(name)}" is not a UMIS claim`);
  }

  // an authority check without its delegation chain could be passed by hiding the chain
  const claims = [...new Set(i.claims)];
  if (i.authority !== undefined) {
    for (const name of ['authority', 'delegation'] as const) {
      if (!claims.includes(name)) claims.push(name);
    }
  }
  const vct = i.vct === undefined ? [VCT.orgMember, VCT.roleAuthority] : [...i.vct];
  const nonce = randomId(LIMITS.nonceBytes, i.crypto);
  const exp = i.now + ttl;

  const payload: PresentationRequestPayloadV1 = { v: 1, nonce, aud: i.audience, iat: i.now, exp, vct, claims };
  if (i.authority !== undefined) payload.authority = { ...i.authority };
  if (i.policy !== undefined) payload.policy = { ...i.policy };
  if (i.verifier !== undefined) payload.verifier = { ...i.verifier };

  let frame: Frame;
  if (i.mutual === undefined) {
    frame = { kind: 'request', tokens: [await signPresentationRequest(payload, i.deviceSigner)] };
  } else {
    payload.mutual = true;
    const jws = await signPresentationRequest(payload, i.mutual.holderSigner);
    const presentation = await presentCredential({
      credential: i.mutual.sdJwtVc,
      disclose: i.mutual.disclose,
      kb: { signer: i.mutual.holderSigner, aud: MUTUAL_AUD, nonce, iat: i.now },
      crypto: i.crypto,
    });
    frame = { kind: 'mutual_init', tokens: [jws, presentation] };
  }

  const pending: PendingRequest = {
    nonce,
    aud: i.audience,
    iat: i.now,
    exp,
    vct,
    claims,
    mutual: i.mutual !== undefined,
  };
  if (i.authority !== undefined) pending.authority = { ...i.authority };
  if (i.policy !== undefined) pending.policyId = i.policy.id;
  return { frame, pending };
}

/**
 * A request for a presentation as the text of a QR code, with the record to check the answer against. The nonce is 16
 * random bytes and the request lives `ttlSeconds` (60 by default, 120 at most) from `now`. A request for `authority`
 * also asks for `delegation`, so that a chain of delegation cannot be left out of the answer. With `mutual` the request
 * is signed by the asker's holder key and carries the asker's own presentation, bound to this request only.
 */
export async function createRequestQr(i: CreateRequestInput): Promise<{ qr: string; pending: PendingRequest }> {
  const { frame, pending } = await buildRequest(i);
  return { qr: encodeFrame(frame), pending };
}

/** The same request as a Frame, for a transport such as BLE. */
export function createRequestFrame(i: CreateRequestInput): Promise<{ frame: Frame; pending: PendingRequest }> {
  return buildRequest(i);
}

function checkPending(pending: PendingRequest): PendingRequest {
  const ok =
    typeof pending === 'object' &&
    pending !== null &&
    typeof pending.nonce === 'string' &&
    pending.nonce !== '' &&
    typeof pending.aud === 'string' &&
    pending.aud !== '' &&
    typeof pending.iat === 'number' &&
    Number.isFinite(pending.iat) &&
    typeof pending.exp === 'number' &&
    Number.isFinite(pending.exp) &&
    Array.isArray(pending.vct) &&
    Array.isArray(pending.claims) &&
    typeof pending.mutual === 'boolean';
  if (!ok) throw new UmisError('MALFORMED', 'the pending request is not valid');
  return pending;
}

/**
 * Decides on the answer to a request made by {@link createRequestQr} or {@link createRequestFrame}. `input` is the
 * scanned QR text (channel `qr_reverse`) or a Frame object (channel `ble`); it must be a `response` frame, or a
 * `mutual_reply` frame when the request was mutual. The answer has to carry the request's audience and nonce, be made
 * after the request and while it is open, disclose what was asked, and is accepted once. It never throws.
 */
export function verifyResponseQr(
  input: string | Frame,
  pending: PendingRequest,
  ctx: VerifierContext,
): Promise<VerificationResult> {
  return execute(
    ctx,
    typeof input === 'string' ? 'qr_reverse' : 'ble',
    { requiredClaims: pending?.claims, authority: pending?.authority, vctAllowed: pending?.vct },
    async (s) => {
      const request = checkPending(pending);
      const frame = toFrame(input);
      if (frame.kind !== (request.mutual ? 'mutual_reply' : 'response')) return 'UNSUPPORTED_FORMAT';

      s.parsed = await parseSdJwt(frame.tokens[0]!, s.crypto);
      s.front = sdJwtFront({
        aud: request.aud,
        nonce: request.nonce,
        notBefore: request.iat,
        // a response is older than its request's lifetime only if it was made before the request, which notBefore rules out
        maxAgeSeconds: request.exp - request.iat + 2 * s.skew,
        replayKey: (nonce) => replayKey('req:', nonce),
        replayExpiresAt: request.exp + s.skew,
        after: (state) => (state.ctx.now >= request.exp + state.skew ? 'PRESENTATION_EXPIRED' : undefined),
      });
      return undefined;
    },
  );
}
