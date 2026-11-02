import {
  LIMITS,
  TYP,
  UmisError,
  decodeJwsUnverified,
  frameKindOf,
  isReasonCode,
  parseSdJwt,
  verifyJws,
} from '@umis/core';
import type { Channel, Frame, OneWayTokenPayload, VerificationResult, VerifierContext } from '@umis/core';
import { resolveIssuer } from '@umis/registry';
import { jsonCopy } from './context.js';
import { SKIP, execute, holderMaxAge, remember, replayKey, sdJwtFront, toFrame } from './pipeline.js';
import type { Front } from './pipeline.js';

/** Header members a one-way token may carry; its key comes from the member cache, so `kid` is only informative. */
const ONE_WAY_HEADER_MEMBERS: ReadonlySet<string> = new Set(['alg', 'typ', 'kid']);

const malformed = (message: string): UmisError => new UmisError('MALFORMED', message);

function own(object: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

/** Reads an `umis-ow+jwt` by structure alone: nothing in it is trusted before step 4. */
function readOneWayToken(token: string): OneWayTokenPayload {
  if (token.length > LIMITS.frameMaxBytes) throw malformed('the token exceeds the size limit');
  const decoded = decodeJwsUnverified<Record<string, unknown>>(token);
  for (const name of Object.keys(decoded.header)) {
    if (!ONE_WAY_HEADER_MEMBERS.has(name)) throw malformed(`unexpected one-way header member "${name}"`);
  }
  if (decoded.header.typ !== TYP.oneWay) throw new UmisError('UNSUPPORTED_FORMAT', 'not a one-way token');

  const payload = decoded.payload;
  const credRef = own(payload, 'cred_ref');
  const aud = own(payload, 'aud');
  const iat = own(payload, 'iat');
  const exp = own(payload, 'exp');
  const ctr = own(payload, 'ctr');
  if (typeof credRef !== 'string' || credRef === '') throw malformed('cred_ref must be a non-empty string');
  if (typeof aud !== 'string' || aud === '') throw malformed('aud must be a non-empty string');
  if (typeof iat !== 'number' || !Number.isFinite(iat)) throw malformed('iat must be a finite number');
  if (typeof exp !== 'number' || !Number.isFinite(exp) || !(exp > iat)) throw malformed('exp must be after iat');
  if (typeof ctr !== 'number' || !Number.isSafeInteger(ctr) || ctr < 0) throw malformed('ctr must be a counter');
  return { cred_ref: credRef, aud, iat, exp, ctr };
}

/** Steps 2 to 4 for a one-way token: the credential is known from the member cache and was verified when it went in. */
function oneWayFront(token: string, payload: OneWayTokenPayload): Front {
  return {
    trust(s) {
      const cached = s.ctx.memberCache?.get(payload.cred_ref);
      if (cached === undefined || cached.credRef !== payload.cred_ref) return 'UNKNOWN_CREDENTIAL_REF';
      // the token names no key id, so the issuer is resolved without one
      const resolved = resolveIssuer(s.ctx.trusted, { issuer: cached.issuer, vct: cached.vct, now: s.ctx.now });
      if (!resolved.ok) return resolved.reason;
      s.cached = cached;
      s.subject = {
        issuer: cached.issuer,
        vct: cached.vct,
        credentialRef: cached.credRef,
        exp: cached.exp,
        status: cached.status,
        claims: jsonCopy(cached.claims),
      };
      s.exposed = true;
      return undefined;
    },

    signature: () => SKIP,

    async binding(s) {
      const cached = s.cached!;
      try {
        await verifyJws(token, { typ: TYP.oneWay, key: cached.cnfJwk, crypto: s.crypto });
      } catch (error) {
        if (error instanceof UmisError && isReasonCode(error.code)) return 'HOLDER_BINDING_INVALID';
        throw error;
      }
      const { ctx, skew } = s;
      if (!ctx.audiences.includes(payload.aud)) return 'AUDIENCE_MISMATCH';
      if (payload.exp - payload.iat > holderMaxAge(ctx)) return 'PRESENTATION_TOO_LONG_LIVED';
      if (payload.iat > ctx.now + skew) return 'CLOCK_SKEW';
      if (ctx.now >= payload.exp + skew) return 'PRESENTATION_EXPIRED';

      const id = replayKey('ow:', payload.cred_ref, payload.iat, payload.ctr);
      return (await remember(s, id, payload.exp + skew)) ? undefined : 'REPLAY';
    },
  };
}

/**
 * Decides at a checkpoint whether a presented credential is accepted, in nine steps, offline. `input` is the text of a
 * scanned QR code, or a Frame object that came over a transport (channel `ble`). A one-way token (channel
 * `qr_oneway`) is checked against the member cache; a full presentation (channel `qr_full`, `ble` for a Frame object)
 * is verified in full. Every other kind of frame is UNSUPPORTED_FORMAT.
 *
 * The result has exactly one reason and a trace of the nine steps; the claims, issuer and credential reference appear
 * in it only once the issuer is trusted and the credential is vouched for. The function never throws.
 */
export function verifyAtCheckpoint(input: string | Frame, ctx: VerifierContext): Promise<VerificationResult> {
  const fromText = typeof input === 'string';
  const announced = fromText ? frameKindOf(input) : (input as { kind?: unknown } | null)?.kind;
  const channel: Channel = announced === 'oneway' ? 'qr_oneway' : fromText ? 'qr_full' : 'ble';
  return execute(ctx, channel, {}, async (s) => {
    const frame = toFrame(input);
    if (frame.kind === 'oneway') {
      const token = frame.tokens[0]!;
      s.channel = 'qr_oneway';
      s.front = oneWayFront(token, readOneWayToken(token));
      return undefined;
    }
    if (frame.kind === 'full') {
      s.channel = fromText ? 'qr_full' : 'ble';
      s.parsed = await parseSdJwt(frame.tokens[0]!, s.crypto);
      const maxAge = holderMaxAge(s.ctx);
      s.front = sdJwtFront({
        aud: s.ctx.audiences,
        maxAgeSeconds: maxAge,
        replayKey: (nonce, subject) => replayKey('kb:', subject.issuer, subject.credentialRef, nonce),
        // the key-binding JWT is accepted for at most `maxAge` after its iat, which is at most `skew` ahead of now
        replayExpiresAt: s.ctx.now + maxAge + s.skew,
      });
      return undefined;
    }
    return 'UNSUPPORTED_FORMAT';
  });
}
