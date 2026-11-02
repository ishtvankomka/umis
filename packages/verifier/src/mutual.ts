import { MUTUAL_AUD, TYP, UmisError, decodePresentationRequest, isReasonCode, parseSdJwt, verifyJws } from '@umis/core';
import type { Channel, ParsedRequest, VerificationResult, VerifierContext } from '@umis/core';
import { execute, replayKey, sdJwtFront } from './pipeline.js';

/** The longest a counter-presentation may be held back between being made and being shown, in seconds. */
const MUTUAL_MAX_AGE_S = 30;

/**
 * Decides on the presentation that the asker of a mutual exchange shows with its request (a `mutual_init` frame, read
 * by the wallet into `request`). The counterparty is held to this verifier's own policy: the issuer must be trusted,
 * the status current, and the claims the policy asks for disclosed.
 *
 * Nothing the wallet derived from the frame is believed: the request is read again from its signed text, and that text
 * must verify with the key the presentation is bound to. The presentation's key-binding JWT must name the mutual
 * audience and this request's nonce and be at most 30 seconds old; the request must be open; and the exchange is
 * accepted once. The channel is `qr_reverse` unless `opts.channel` says otherwise. It never throws.
 */
export function verifyCounterparty(
  request: ParsedRequest,
  ctx: Omit<VerifierContext, 'memberCache'>,
  opts?: { channel?: Channel },
): Promise<VerificationResult> {
  const context: VerifierContext = { ...ctx, memberCache: undefined };
  return execute(context, opts?.channel ?? 'qr_reverse', {}, async (s) => {
    if (request.kind !== 'mutual_init') return 'UNSUPPORTED_FORMAT';
    if (typeof request.jws !== 'string' || typeof request.counterPresentation !== 'string') return 'MALFORMED';

    const signed = decodePresentationRequest(request.jws).payload;
    if (signed.mutual !== true) return 'MALFORMED';
    s.parsed = await parseSdJwt(request.counterPresentation, s.crypto);
    s.front = sdJwtFront({
      aud: MUTUAL_AUD,
      nonce: signed.nonce,
      maxAgeSeconds: MUTUAL_MAX_AGE_S,
      replayKey: (nonce) => replayKey('mutual:', nonce),
      replayExpiresAt: signed.exp + s.skew,
      before: async (state) => {
        try {
          await verifyJws(request.jws, {
            typ: TYP.request,
            key: state.parsed!.issuerJwt.payload.cnf.jwk,
            crypto: state.crypto,
          });
        } catch (error) {
          if (error instanceof UmisError && isReasonCode(error.code)) return 'HOLDER_BINDING_INVALID';
          throw error;
        }
        return undefined;
      },
      after: (state) => {
        if (signed.iat > state.ctx.now + state.skew) return 'CLOCK_SKEW';
        return state.ctx.now >= signed.exp + state.skew ? 'PRESENTATION_EXPIRED' : undefined;
      },
    });
    return undefined;
  });
}
