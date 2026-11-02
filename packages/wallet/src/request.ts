import {
  LIMITS,
  TYP,
  UmisError,
  asEcPublicJwk,
  decodeFrame,
  decodePresentationRequest,
  isReasonCode,
  parseSdJwt,
  verifyJws,
} from '@umis/core';
import type { CryptoProvider, EcPublicJwk, Frame, ParsedRequest } from '@umis/core';

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);
const malformed = (message: string): UmisError => new UmisError('MALFORMED', message);

/** The text of a QR code is decoded; a Frame object (from a transport) is checked for a request kind and its tokens. */
function requestFrame(input: unknown): { kind: ParsedRequest['kind']; tokens: string[] } {
  const frame = typeof input === 'string' ? decodeFrame(input) : input;
  if (typeof frame !== 'object' || frame === null) {
    throw malformed('a request is the text of a QR code or a Frame object');
  }
  const { kind, tokens } = frame as { kind?: unknown; tokens?: unknown };
  if (kind !== 'request' && kind !== 'mutual_init')
    throw new UmisError('UNSUPPORTED_FORMAT', 'not a presentation request');
  const count = kind === 'request' ? 1 : 2;
  if (!Array.isArray(tokens) || tokens.length !== count || !tokens.every((token) => typeof token === 'string')) {
    throw malformed(`a ${kind} frame carries ${count} token(s)`);
  }
  return { kind, tokens: [...(tokens as string[])] };
}

/** Whether `jws` verifies with one of `key`; a token that fails any check of the verification counts as not signed. */
async function signedBy(
  jws: string,
  key: EcPublicJwk | readonly EcPublicJwk[],
  crypto?: CryptoProvider,
): Promise<boolean> {
  try {
    await verifyJws(jws, { typ: TYP.request, key, crypto });
    return true;
  } catch (error) {
    if (error instanceof UmisError && isReasonCode(error.code)) return false;
    throw error;
  }
}

/**
 * Reads a presentation request from the text of a QR code or from a Frame object, for the holder to decide on. The
 * frame must be a `request` or the opening of a mutual exchange (`mutual_init`); any other kind is UNSUPPORTED_FORMAT and
 * a damaged request is MALFORMED.
 *
 * With `now`, a request that has run out (`now >= exp + skewSeconds`, 10 seconds of skew unless told otherwise) is
 * PRESENTATION_EXPIRED. `signatureVerified` says whether the signature checks out against a key the wallet can name:
 * one of `verifierKeys` for a plain request, the holder key that the attached presentation is bound to for a mutual
 * opening. It is false, and the request is still returned, when there are no keys to check against or none fits. A
 * request that is not signed by a known key may come from anyone; whether to answer it is for the holder to decide.
 */
export async function parseRequestQr(
  input: string | Frame,
  opts: {
    verifierKeys?: readonly EcPublicJwk[];
    now?: number;
    skewSeconds?: number;
    crypto?: CryptoProvider;
  } = {},
): Promise<ParsedRequest> {
  if (typeof opts !== 'object' || opts === null) throw invalid('the options must be an object');
  const frame = requestFrame(input);
  const jws = frame.tokens[0]!;
  const { header, payload } = decodePresentationRequest(jws);

  if (opts.now !== undefined) {
    const skew = opts.skewSeconds ?? LIMITS.defaultSkewS;
    if (typeof opts.now !== 'number' || !Number.isFinite(opts.now))
      throw invalid('now must be a finite number of seconds');
    if (typeof skew !== 'number' || !Number.isFinite(skew) || skew < 0) throw invalid('skewSeconds must be 0 or more');
    if (opts.now >= payload.exp + skew) throw new UmisError('PRESENTATION_EXPIRED', 'the request has expired');
  }

  let signatureVerified: boolean;
  let counterPresentation: string | undefined;
  if (frame.kind === 'request') {
    if (opts.verifierKeys !== undefined && !Array.isArray(opts.verifierKeys))
      throw invalid('verifierKeys must be an array');
    const keys = (opts.verifierKeys ?? []).map((key) => asEcPublicJwk(key));
    signatureVerified = keys.length > 0 && (await signedBy(jws, keys, opts.crypto));
  } else {
    counterPresentation = frame.tokens[1]!;
    const presentation = await parseSdJwt(counterPresentation, opts.crypto);
    signatureVerified = await signedBy(jws, presentation.issuerJwt.payload.cnf.jwk, opts.crypto);
  }

  const request: ParsedRequest = { ...payload, kind: frame.kind, jws, signatureVerified };
  if (header.kid !== undefined) request.kid = header.kid;
  if (counterPresentation !== undefined) request.counterPresentation = counterPresentation;
  return request;
}
