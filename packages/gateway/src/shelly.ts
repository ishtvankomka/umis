import { UmisError } from '@umis/core';
import type { FetchLike, Signer } from '@umis/core';
import { signRelayCommand } from './relay-command.js';

/** The header that carries the signed relay command next to the Shelly request. */
const COMMAND_HEADER = 'x-umis-command';
/** Milliseconds the client waits for the relay before it reports the failure and leaves the decision as it is. */
const DEFAULT_TIMEOUT_MS = 1_000;
/** The answer of a relay is a short JSON document; a longer one is not looked at. */
const MAX_ANSWER_CHARS = 8_192;
/** `src` of the requests when the caller names none. */
const DEFAULT_SRC = 'umis-gateway';

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

function counter(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw invalid(`${what} must be a non-negative integer`);
  }
  return value;
}

/**
 * The body of a Shelly Gen3 `Switch.Set` call as JSON-RPC text, ready to be signed and posted to `/rpc`:
 * `{"id":1,"src":"station","method":"Switch.Set","params":{"id":0,"on":true,"toggle_after":3}}`. `toggleAfter` is the
 * flip-back timer in seconds: a relay switched on with it falls back to off by itself.
 */
export function shellySwitchSetBody(i: {
  rpcId: number;
  switchId: number;
  on: boolean;
  toggleAfter?: number;
  src?: string;
}): string {
  if (typeof i !== 'object' || i === null) throw invalid('shellySwitchSetBody needs its input object');
  const id = counter(i.rpcId, 'rpcId');
  const switchId = counter(i.switchId, 'switchId');
  if (typeof i.on !== 'boolean') throw invalid('on must be true or false');
  if (i.src !== undefined && (typeof i.src !== 'string' || i.src === '')) throw invalid('src must be a non-empty text');
  if (i.toggleAfter !== undefined) {
    if (typeof i.toggleAfter !== 'number' || !Number.isFinite(i.toggleAfter) || i.toggleAfter <= 0) {
      throw invalid('toggleAfter must be a number of seconds above 0');
    }
  }
  return JSON.stringify({
    id,
    ...(i.src === undefined ? {} : { src: i.src }),
    method: 'Switch.Set',
    params: {
      id: switchId,
      on: i.on,
      ...(i.toggleAfter === undefined ? {} : { toggle_after: i.toggleAfter }),
    },
  });
}

/**
 * Opens a relay for a number of seconds. The answer says whether the relay took the command (`ok`), the HTTP status of its
 * reply (0 when there was none) and, on failure, a short reason. The call does not throw for anything the relay or the
 * network does.
 */
export interface RelayClient {
  open(i: { switchId: number; seconds: number; now: number }): Promise<{ ok: boolean; status: number; error?: string }>;
}

type Outcome = { ok: boolean; status: number; error?: string };

const failure = (error: string, status = 0): Outcome => ({ ok: false, status, error });

/** Whether the JSON text of a reply carries an RPC error; an unreadable text carries none. */
function rpcErrorCode(answer: string): number | undefined {
  if (answer.length === 0 || answer.length > MAX_ANSWER_CHARS) return undefined;
  try {
    const parsed: unknown = JSON.parse(answer);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
    const error = (parsed as { error?: unknown }).error;
    if (error === undefined || error === null) return undefined;
    const code = typeof error === 'object' ? (error as { code?: unknown }).code : undefined;
    return typeof code === 'number' && Number.isFinite(code) ? code : 0;
  } catch {
    return undefined;
  }
}

/**
 * A client for a Shelly Gen3 relay (or the emulator that stands in for one). `open` posts a signed `Switch.Set` with
 * `on: true` and the flip-back timer to `url`, the full address of the `/rpc` endpoint, with the command in the
 * `X-Umis-Command` header. `relayAud` is the identity of the relay that the command is meant for (its origin, as the
 * relay lists it) and `iss` names the sender. The JSON-RPC source of every request is the `src` option, else `iss`,
 * else `umis-gateway`. A relay that does not answer within `timeoutMs` (1 000 by default) counts as down. The function
 * runs in browsers: it uses `fetch`, or the `fetch` it is given.
 *
 * A failed `open` says why in `error` with one of four tokens: `timeout` (no answer within `timeoutMs`),
 * `network error` (the request itself failed), `HTTP <status>` (a status outside 200-299) or `RPC error <code>` (a
 * 2xx answer that carries a JSON-RPC error; the code is 0 when the error has no numeric one). A command that cannot be
 * made at all, because the signer or the arguments of `open` fail, is `command could not be made`.
 */
export function shellyRpcRelay(i: {
  url: string;
  signer: Signer;
  relayAud: string;
  iss?: string;
  src?: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}): RelayClient {
  if (typeof i !== 'object' || i === null) throw invalid('shellyRpcRelay needs its input object');
  if (typeof i.url !== 'string' || i.url === '') throw invalid('url must be the address of the relay');
  if (typeof i.relayAud !== 'string' || i.relayAud === '') throw invalid('relayAud must name the relay');
  const timeoutMs = i.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw invalid('timeoutMs must be a number of milliseconds above 0');
  }
  let send = i.fetch;
  if (send === undefined) {
    if (typeof globalThis.fetch !== 'function') throw new UmisError('NETWORK', 'no fetch function is available');
    send = (url, init) => globalThis.fetch(url, init);
  }
  const post = send;
  const src = i.src ?? i.iss ?? DEFAULT_SRC;
  let rpcId = 0;

  async function exchange(
    call: { switchId: number; seconds: number; now: number },
    signal?: AbortSignal,
  ): Promise<Outcome> {
    rpcId += 1;
    let body: string;
    let command: string;
    try {
      body = shellySwitchSetBody({
        rpcId,
        switchId: call.switchId,
        on: true,
        toggleAfter: call.seconds,
        src,
      });
      command = await signRelayCommand({
        signer: i.signer,
        relayAud: i.relayAud,
        body,
        now: call.now,
        iss: i.iss,
      });
    } catch {
      return failure('command could not be made');
    }
    const response = await post(i.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', [COMMAND_HEADER]: command },
      body,
      signal,
    });
    if (response.status < 200 || response.status >= 300) return failure(`HTTP ${response.status}`, response.status);
    const rpcCode = rpcErrorCode(await response.text());
    if (rpcCode !== undefined) return failure(`RPC error ${rpcCode}`, response.status);
    return { ok: true, status: response.status };
  }

  return {
    async open(call) {
      const controller = typeof AbortController === 'function' ? new AbortController() : undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<Outcome>((resolve) => {
        timer = setTimeout(() => resolve(failure('timeout')), timeoutMs);
      });
      const attempt = exchange(call, controller?.signal).catch(() => failure('network error'));
      try {
        const outcome = await Promise.race([attempt, deadline]);
        if (outcome.error === 'timeout') controller?.abort();
        return outcome;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
