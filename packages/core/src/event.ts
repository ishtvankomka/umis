import { sha256 } from '@noble/hashes/sha2.js';
import canonicalize from 'canonicalize';
import { concatBytes, hexDecode, hexEncode, utf8Encode } from './bytes.js';
import type { CryptoProvider } from './crypto/provider.js';
import { signJws, verifyJws } from './jws.js';
import { CHANNELS, TYP, type Channel } from './profile.js';
import { UmisError, isReasonCode, type ReasonCode } from './reasons.js';
import type { DecisionEventV1, EcPublicJwk, Signer } from './types.js';

const HASH_BYTES = 32;
const HEX_HASH_PATTERN = /^[0-9a-f]{64}$/;
/** Deeper than any event; also stops a self-referencing structure before the stack does. */
const MAX_JSON_DEPTH = 64;

type Json = Record<string, unknown>;

const invalid = (message: string, cause?: unknown): UmisError => new UmisError('INVALID_ARGUMENT', message, { cause });
const malformed = (message: string): UmisError => new UmisError('MALFORMED', message);

/** The first link of every chain: 32 zero bytes. */
export const GENESIS_HASH: Uint8Array = new Uint8Array(HASH_BYTES);
const GENESIS_HEX = '0'.repeat(2 * HASH_BYTES);

// ---------------------------------------------------------------------------------------------------------------
// canonical JSON and the hash chain
// ---------------------------------------------------------------------------------------------------------------

function assertJsonValue(value: unknown, depth: number): void {
  if (depth > MAX_JSON_DEPTH) throw invalid('the value is nested too deeply');
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return;
    case 'number':
      if (!Number.isFinite(value)) throw invalid('NaN and infinite numbers have no JSON form');
      return;
    case 'object': {
      if (value === null) return;
      if (Array.isArray(value)) {
        for (let index = 0; index < value.length; index++) assertJsonValue(value[index], depth + 1);
        return;
      }
      const prototype: unknown = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) throw invalid('only plain objects have a JSON form');
      for (const member of Object.values(value)) assertJsonValue(member, depth + 1);
      return;
    }
    default:
      throw invalid(`a ${typeof value} value has no JSON form`);
  }
}

/**
 * The JSON Canonicalization Scheme text of `value` (RFC 8785): members sorted by UTF-16 code units, no whitespace,
 * numbers as ECMAScript prints them. What JSON cannot say is INVALID_ARGUMENT: `undefined` (also as a member or array
 * item), NaN, infinite numbers, functions, symbols, bigints, and objects that are not plain.
 */
export function canonicalJson(value: unknown): string {
  assertJsonValue(value, 0);
  let result: string | undefined;
  try {
    result = canonicalize(value);
  } catch (cause) {
    throw invalid('the value cannot be canonicalized', cause);
  }
  if (result === undefined) throw invalid('the value cannot be canonicalized');
  return result;
}

/** `SHA-256(prev ‖ UTF-8(JCS(event)))`, synchronously. `prev` is the previous hash (32 bytes). */
export function chainHash(prev: Uint8Array, event: object): Uint8Array {
  if (!(prev instanceof Uint8Array) || prev.length !== HASH_BYTES) throw invalid('the previous hash is 32 bytes');
  if (typeof event !== 'object' || event === null || Array.isArray(event)) throw invalid('an event is a JSON object');
  return sha256(concatBytes(prev, utf8Encode(canonicalJson(event))));
}

// ---------------------------------------------------------------------------------------------------------------
// the event
// ---------------------------------------------------------------------------------------------------------------

function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

function text(value: unknown, what: string): string {
  if (typeof value !== 'string' || value === '') throw malformed(`${what} must be a non-empty string`);
  return value;
}

function nonNegative(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw malformed(`${what} must be a non-negative number`);
  }
  return value;
}

function counter(value: unknown, what: string, minimum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    throw malformed(`${what} must be an integer of at least ${minimum}`);
  }
  return value;
}

/** Applies the shape of a decision event and returns a clean copy without unknown or undefined members. */
function readEvent(value: unknown): DecisionEventV1 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw malformed('an event is a JSON object');
  const raw = value as Json;
  const channel = own(raw, 'ch');
  if (typeof channel !== 'string' || !(CHANNELS as readonly string[]).includes(channel)) {
    throw malformed('ch is not a channel');
  }
  const decision = own(raw, 'dec');
  if (decision !== 'accept' && decision !== 'reject') throw malformed('dec must be accept or reject');
  const reasons = own(raw, 'rsn');
  if (!Array.isArray(reasons) || reasons.length === 0 || !reasons.every((reason) => isReasonCode(reason))) {
    throw malformed('rsn must be a non-empty list of reason codes');
  }

  const event: DecisionEventV1 = {
    iss: text(own(raw, 'iss'), 'iss'),
    seq: counter(own(raw, 'seq'), 'seq', 1),
    iat: nonNegative(own(raw, 'iat'), 'iat'),
    chk: text(own(raw, 'chk'), 'chk'),
    ch: channel as Channel,
    dec: decision,
    rsn: [...(reasons as ReasonCode[])],
    lat: nonNegative(own(raw, 'lat'), 'lat'),
  };
  for (const name of ['vct', 'ciss', 'cref'] as const) {
    if (own(raw, name) !== undefined) event[name] = text(own(raw, name), name);
  }
  if (own(raw, 'sla') !== undefined) event.sla = nonNegative(own(raw, 'sla'), 'sla');
  if (own(raw, 'pv') !== undefined) event.pv = counter(own(raw, 'pv'), 'pv', 0);
  return event;
}

function readEventToSign(value: unknown): DecisionEventV1 {
  try {
    return readEvent(value);
  } catch (error) {
    throw error instanceof UmisError ? invalid(error.message, error) : error;
  }
}

/** Signs a decision event as an `umis-event+jwt` with the verifier's device key. */
export function signEvent(e: DecisionEventV1, signer: Signer): Promise<string> {
  return signJws({ header: { typ: TYP.event }, payload: readEventToSign(e), signer });
}

/** Verifies the signature of an event JWS with `key` and returns the event; MALFORMED when its shape is wrong. */
export async function verifyEvent(jws: string, key: EcPublicJwk, crypto?: CryptoProvider): Promise<DecisionEventV1> {
  const decoded = await verifyJws<Json>(jws, { typ: TYP.event, key, crypto });
  return readEvent(decoded.payload);
}

// ---------------------------------------------------------------------------------------------------------------
// the journal
// ---------------------------------------------------------------------------------------------------------------

export interface JournalEntry {
  event: DecisionEventV1;
  /** Lowercase hex of the previous hash; 64 zeros for the first entry. */
  prevHash: string;
  /** Lowercase hex of `chainHash(prevHash, event)`. */
  hash: string;
}

export interface Journal {
  append(e: DecisionEventV1): JournalEntry;
  entries(): readonly JournalEntry[];
  /** The hash of the last entry, 64 zeros while the journal is empty. */
  head(): string;
}

function freezeEvent(event: DecisionEventV1): DecisionEventV1 {
  Object.freeze(event.rsn);
  return Object.freeze(event);
}

/**
 * An in-memory, append-only journal of decision events, chained by hash. `seq` must be one more than the previous
 * event's, starting at 1 (INVALID_ARGUMENT otherwise). Events and entries are frozen copies.
 */
export function createMemoryJournal(): Journal {
  const list: JournalEntry[] = [];
  let head = GENESIS_HEX;
  return {
    append(e: DecisionEventV1): JournalEntry {
      const event = readEventToSign(e);
      if (event.seq !== list.length + 1) throw invalid(`the next event must have seq ${list.length + 1}`);
      const hash = hexEncode(chainHash(hexDecode(head), event));
      const entry = Object.freeze({ event: freezeEvent(event), prevHash: head, hash });
      list.push(entry);
      head = hash;
      return entry;
    },
    entries(): readonly JournalEntry[] {
      return Object.freeze(list.slice());
    },
    head(): string {
      return head;
    },
  };
}

/**
 * Recomputes the chain from the genesis hash. Returns `{ok: true}`, or `{ok: false, index}` for the first entry that is
 * malformed, does not continue the chain (`prevHash`), or whose `hash` is not the hash of its event exactly as stored.
 * Never throws.
 */
export function verifyJournal(entries: readonly JournalEntry[]): { ok: true } | { ok: false; index: number } {
  if (!Array.isArray(entries)) return { ok: false, index: 0 };
  let expectedPrev = GENESIS_HEX;
  for (let index = 0; index < entries.length; index++) {
    const entry: unknown = entries[index];
    try {
      if (typeof entry !== 'object' || entry === null) return { ok: false, index };
      const { event, prevHash, hash } = entry as Partial<JournalEntry>;
      if (typeof prevHash !== 'string' || typeof hash !== 'string' || !HEX_HASH_PATTERN.test(hash)) {
        return { ok: false, index };
      }
      if (prevHash !== expectedPrev) return { ok: false, index };
      readEvent(event); // the shape; the hash below covers the event exactly as stored
      if (hexEncode(chainHash(hexDecode(prevHash), event as object)) !== hash) return { ok: false, index };
      expectedPrev = hash;
    } catch {
      return { ok: false, index };
    }
  }
  return { ok: true };
}
