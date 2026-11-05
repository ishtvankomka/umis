import {
  LIMITS,
  TYP,
  UmisError,
  base64urlEncode,
  decodeJwsUnverified,
  getDefaultCrypto,
  randomId,
  signJws,
  utf8Encode,
  verifyJws,
} from '@umis/core';
import type { CryptoProvider, EcPublicJwk, ReplayStore, Signer } from '@umis/core';
import { observeTime } from '@umis/verifier';

/** The claims of a relay command: who sent it, for which relay, when, its single-use id and the hash of the body. */
export interface RelayCommandPayload {
  iss?: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  bh: string;
}

/** Seconds a relay command lives unless the signer asks for another lifetime. */
const DEFAULT_TTL_S = 10;
/** The longest lifetime a relay command may have, in seconds. */
const MAX_TTL_S = 30;
/** A relay command is three short segments; a longer text is refused before it is parsed. */
const MAX_COMMAND_CHARS = 4_096;
/** Longest text of `aud`, `iss` and `jti` that a command may carry. */
const MAX_CLAIM_CHARS = 512;
/** Trusted keys tried for one command (the bound `verifyJws` applies too); the keys the `kid` names are tried first. */
const MAX_KEYS_TRIED = 8;

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

/**
 * Signs a relay command: an `umis-relay-cmd+jwt` that authorises exactly one HTTP body for one relay. It carries the
 * relay it is meant for (`aud`), its lifetime (`ttlSeconds`, 10 by default and 30 at most), a random single-use `jti` of
 * 16 bytes and `bh`, the SHA-256 of the UTF-8 body as base64url, so that the body cannot be swapped after signing.
 * `iss` names the station or device that sends the command. The result goes into the `X-Umis-Command` header of the
 * request whose body is `body`. The function runs in browsers: signing and hashing go through the crypto provider.
 */
export async function signRelayCommand(i: {
  signer: Signer;
  relayAud: string;
  body: string;
  now: number;
  iss?: string;
  ttlSeconds?: number;
  crypto?: CryptoProvider;
}): Promise<string> {
  if (typeof i !== 'object' || i === null) throw invalid('signRelayCommand needs its input object');
  if (typeof i.relayAud !== 'string' || i.relayAud === '') throw invalid('relayAud must name the relay');
  if (typeof i.body !== 'string') throw invalid('body must be the text of the request body');
  if (typeof i.now !== 'number' || !Number.isFinite(i.now)) throw invalid('now must be a number of seconds');
  if (i.iss !== undefined && (typeof i.iss !== 'string' || i.iss === '')) throw invalid('iss must be a non-empty text');
  const ttl = i.ttlSeconds ?? DEFAULT_TTL_S;
  if (typeof ttl !== 'number' || !Number.isFinite(ttl) || ttl <= 0 || ttl > MAX_TTL_S) {
    throw invalid(`ttlSeconds is more than 0 and at most ${MAX_TTL_S}`);
  }

  const crypto = i.crypto ?? getDefaultCrypto();
  const iat = Math.floor(i.now);
  const payload: RelayCommandPayload = {
    ...(i.iss === undefined ? {} : { iss: i.iss }),
    aud: i.relayAud,
    iat,
    exp: iat + ttl,
    jti: randomId(LIMITS.nonceBytes, crypto),
    bh: base64urlEncode(await crypto.sha256(utf8Encode(i.body))),
  };
  return signJws({ header: { typ: TYP.relayCommand }, payload, signer: i.signer });
}

function own(object: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

function isText(value: unknown): value is string {
  return typeof value === 'string' && value !== '' && value.length <= MAX_CLAIM_CHARS;
}

/**
 * Checks the signature against the trusted keys. The `kid` of the header only decides which key is tried first: a
 * trusted key that carries no `kid` verifies as well, and a `kid` that names no trusted key is not an error by itself.
 * Token-level mistakes (structure, algorithm, `typ`, header members) are thrown; a key that does not verify is skipped.
 */
async function verifySignature(
  jws: string,
  keys: readonly EcPublicJwk[],
  crypto: CryptoProvider,
): Promise<Record<string, unknown>> {
  const { kid } = decodeJwsUnverified(jws).header;
  const named = kid === undefined ? [] : keys.filter((key) => key?.kid === kid);
  const others = keys.filter((key) => !named.includes(key));
  for (const key of [...named, ...others].slice(0, MAX_KEYS_TRIED)) {
    try {
      return (await verifyJws(jws, { typ: TYP.relayCommand, key, crypto })).payload;
    } catch (error) {
      if (error instanceof UmisError && (error.code === 'MALFORMED' || error.code === 'UNSUPPORTED_FORMAT'))
        throw error;
    }
  }
  throw new UmisError('SIGNATURE_INVALID', 'no trusted key verifies the relay command');
}

const reject = (reason: Extract<Verdict, { ok: false }>['reason']): Verdict => ({ ok: false, reason });

type Verdict = Awaited<ReturnType<typeof verifyRelayCommand>>;
type VerifyInput = Parameters<typeof verifyRelayCommand>[2];

async function check(jws: string, body: string, i: VerifyInput): Promise<Verdict> {
  const skew = i.skewSeconds ?? LIMITS.defaultSkewS;
  // a number that is not one passes every comparison below, so the inputs are checked before anything is trusted
  const usable =
    typeof jws === 'string' &&
    jws !== '' &&
    jws.length <= MAX_COMMAND_CHARS &&
    typeof body === 'string' &&
    Number.isFinite(i.now) &&
    Number.isFinite(skew) &&
    skew >= 0 &&
    Array.isArray(i.keys) &&
    Array.isArray(i.audiences) &&
    typeof i.replay?.checkAndRemember === 'function';
  if (!usable) return reject('MALFORMED');
  const crypto = i.crypto ?? getDefaultCrypto();

  let claims: Record<string, unknown>;
  try {
    claims = await verifySignature(jws, i.keys, crypto);
  } catch (error) {
    return reject(error instanceof UmisError && error.code === 'SIGNATURE_INVALID' ? 'SIGNATURE_INVALID' : 'MALFORMED');
  }

  const iss = own(claims, 'iss');
  const aud = own(claims, 'aud');
  const iat = own(claims, 'iat');
  const exp = own(claims, 'exp');
  const jti = own(claims, 'jti');
  const bh = own(claims, 'bh');
  if (iss !== undefined && !isText(iss)) return reject('MALFORMED');
  if (!isText(aud) || !isText(jti) || typeof bh !== 'string') return reject('MALFORMED');
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return reject('MALFORMED');
  if (typeof exp !== 'number' || !Number.isFinite(exp) || !(exp > iat)) return reject('MALFORMED');

  // the command authorises this body and no other
  if (bh !== base64urlEncode(await crypto.sha256(utf8Encode(body)))) return reject('SIGNATURE_INVALID');
  if (!i.audiences.includes(aud)) return reject('AUDIENCE_MISMATCH');
  if (exp - iat > MAX_TTL_S) return reject('PRESENTATION_TOO_LONG_LIVED');
  if (iat > i.now + skew) return reject('CLOCK_SKEW');
  if (i.now >= exp + skew) return reject('PRESENTATION_EXPIRED');
  // a store without a clock of its own learns the time here, so that it can forget the ids that have expired
  observeTime(i.replay, i.now);
  // last, so that only a command that passed every other check is remembered; anything but a plain true counts as seen
  if ((await i.replay.checkAndRemember(`relay:${jti}`, exp + skew)) !== true) return reject('REPLAY');

  return { ok: true, payload: { ...(iss === undefined ? {} : { iss }), aud, iat, exp, jti, bh } };
}

/**
 * Verifies the `X-Umis-Command` of a request against the exact body text. In this order: the input, the signature (a
 * trusted key, `typ` `umis-relay-cmd+jwt`), the hash of the body (`bh`, a difference is SIGNATURE_INVALID), the relay
 * (`aud` must be listed), the lifetime (`exp - iat` at most 30 s), the clock (`iat` at most `skewSeconds` ahead,
 * `now` before `exp + skew`) and the replay store (a `jti` is accepted once). A structure, algorithm or `typ` the relay
 * does not know is MALFORMED; a key that is not trusted is SIGNATURE_INVALID. It never throws.
 *
 * At most eight trusted keys are tried per command, the key named by `kid` first, then the others in the order given; a
 * command signed by a key beyond the eighth that no `kid` names is SIGNATURE_INVALID.
 *
 * The replay id is `relay:<jti>`, remembered until `exp + skew`; it is claimed last, so a command refused for another
 * reason is not used up. A replay store without its own clock learns the time from this call.
 */
export async function verifyRelayCommand(
  jws: string,
  body: string,
  i: {
    keys: readonly EcPublicJwk[];
    audiences: readonly string[];
    now: number;
    replay: ReplayStore;
    skewSeconds?: number;
    crypto?: CryptoProvider;
  },
): Promise<
  | { ok: true; payload: RelayCommandPayload }
  | {
      ok: false;
      reason:
        | 'MALFORMED'
        | 'SIGNATURE_INVALID'
        | 'AUDIENCE_MISMATCH'
        | 'PRESENTATION_EXPIRED'
        | 'PRESENTATION_TOO_LONG_LIVED'
        | 'CLOCK_SKEW'
        | 'REPLAY';
    }
> {
  try {
    return await check(jws, body, i);
  } catch {
    return reject('MALFORMED');
  }
}
