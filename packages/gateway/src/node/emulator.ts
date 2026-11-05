import { timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { URN_PREFIX, UmisError, asEcPublicJwk, randomId, utf8Decode } from '@umis/core';
import type { EcPublicJwk } from '@umis/core';
import { createMemoryReplayStore } from '@umis/verifier';
import { computeDigestResponse } from '../digest.js';
import { verifyRelayCommand } from '../relay-command.js';
import { STATUS_PAGE } from './status-page.js';

export interface RelayEmulatorOptions {
  port: number;
  /** Address to listen on, 127.0.0.1 unless told otherwise. */
  host?: string;
  /** Public keys whose relay commands the emulator obeys. */
  trust: readonly EcPublicJwk[];
  /** Relay identities a command may name; replaces the defaults (the emulator's own addresses) when given. */
  audiences?: readonly string[];
  /** Exact origins (`https://host[:port]`, no path, no wildcard) that browser pages may call the emulator from. */
  cors?: readonly string[];
  /** Whether `Switch.Set` needs a valid `X-Umis-Command`. True unless told otherwise. */
  requireSignature?: boolean;
  /** Name of the environment variable that holds the Shelly digest password; when set, `Switch.Set` needs digest auth too. */
  digestPasswordEnv?: string;
  /** The clock, in seconds. */
  now: () => number;
  /** Receives one line for each command and each refused request. */
  log?: (line: string) => void;
}

export interface RelayEmulator {
  url: string;
  state(): { on: boolean; until?: number; last?: { at: number; jti: string; iss?: string } };
  close(): Promise<void>;
}

const DEVICE_ID = 'umis-relay-emu';
const SWITCH_ID = 0;
const MAX_BODY_BYTES = 8 * 1024;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_TOGGLE_AFTER_S = 86_400;
const MAX_ECHO_CHARS = 128;
const DIGEST_USER = 'admin';
const DIGEST_NONCE_TTL_S = 60;
const DIGEST_MAX_NONCES = 256;
const DIGEST_MAX_HEADER_CHARS = 1_024;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
/** An origin as a browser sends it: no path and no `*`, since no browser puts a wildcard into its `Origin`. */
const ORIGIN = /^https?:\/\/[^\s/?#*]+$/i;
const LOGGED_ID_CHARS = 8;
type Json = Record<string, unknown>;

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function own(object: Json, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

/** Text that came from a client, made safe for one line of a log: control and line-separator characters become `?`. */
function printable(value: string, max = 64): string {
  let out = '';
  for (const character of value.slice(0, max)) {
    const code = character.codePointAt(0) ?? 0;
    out += code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029 ? '?' : character;
  }
  return out;
}

function equalHex(a: string, b: string): boolean {
  const left = Buffer.from(a.toLowerCase(), 'hex');
  const right = Buffer.from(b.toLowerCase(), 'hex');
  return left.length === right.length && timingSafeEqual(left, right);
}

/** The fields of a Digest `Authorization` header. */
function digestFields(header: string): Map<string, string> {
  const fields = new Map<string, string>();
  const pattern = /([a-zA-Z][a-zA-Z0-9_-]*)=(?:"((?:[^"\\]|\\.){0,512})"|([^\s,"]{1,512}))/g;
  for (const match of header.matchAll(pattern)) {
    const quoted = match[2];
    fields.set(match[1]!.toLowerCase(), quoted !== undefined ? quoted.replace(/\\(.)/g, '$1') : (match[3] ?? ''));
  }
  return fields;
}

interface Settings {
  host: string;
  port: number;
  keys: EcPublicJwk[];
  audiences: string[] | undefined;
  cors: Set<string>;
  requireSignature: boolean;
  password: string | undefined;
  now: () => number;
}

/** Checks the options and reads the digest password from the environment. Nothing here prints a secret. */
function settingsOf(o: RelayEmulatorOptions): Settings {
  if (typeof o !== 'object' || o === null) throw invalid('startShellyEmulator needs its options');
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65_535)
    throw invalid('port must be an integer from 0 to 65535');
  if (o.host !== undefined && (typeof o.host !== 'string' || o.host === ''))
    throw invalid('host must be a non-empty text');
  if (typeof o.now !== 'function') throw invalid('now must be a function that returns seconds');
  if (o.log !== undefined && typeof o.log !== 'function') throw invalid('log must be a function');
  const requireSignature = o.requireSignature ?? true;

  if (!Array.isArray(o.trust)) throw invalid('trust must be a list of public keys');
  const keys = o.trust.map((key) => asEcPublicJwk(key));
  if (requireSignature && keys.length === 0) throw invalid('at least one trusted key is needed to check commands');

  let audiences: string[] | undefined;
  if (o.audiences !== undefined) {
    if (
      !Array.isArray(o.audiences) ||
      o.audiences.length === 0 ||
      !o.audiences.every((a) => typeof a === 'string' && a !== '')
    ) {
      throw invalid('audiences must be a non-empty list of relay identities');
    }
    audiences = [...o.audiences];
  }

  const cors = new Set<string>();
  for (const origin of o.cors ?? []) {
    if (typeof origin !== 'string' || !ORIGIN.test(origin)) {
      const shown = typeof origin === 'string' ? ` "${printable(origin, MAX_ECHO_CHARS)}"` : '';
      throw invalid(`the CORS origin${shown} must look like https://host or http://host:port, with no path and no *`);
    }
    cors.add(origin.toLowerCase());
  }

  let password: string | undefined;
  if (o.digestPasswordEnv !== undefined) {
    if (typeof o.digestPasswordEnv !== 'string' || !ENV_NAME.test(o.digestPasswordEnv)) {
      throw invalid('digestPasswordEnv must be the name of an environment variable');
    }
    password = process.env[o.digestPasswordEnv];
    if (password === undefined || password === '') {
      throw invalid(`the environment variable ${o.digestPasswordEnv} is not set`);
    }
  }
  return { host: o.host ?? '127.0.0.1', port: o.port, keys, audiences, cors, requireSignature, password, now: o.now };
}

type Body = { kind: 'body'; bytes: Buffer } | { kind: 'too_large' } | { kind: 'aborted' };

/** The body of a request. A body above the cap is not read to its end, and a client that leaves midway is `aborted`. */
function readBody(req: IncomingMessage): Promise<Body> {
  return new Promise((resolve) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      resolve({ kind: 'too_large' });
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    const finish = (outcome: Body): void => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onGone);
      req.off('close', onGone);
      resolve(outcome);
    };
    const onData = (chunk: Buffer): void => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        req.pause();
        finish({ kind: 'too_large' });
      } else {
        chunks.push(chunk);
      }
    };
    const onEnd = (): void => finish({ kind: 'body', bytes: Buffer.concat(chunks) });
    const onGone = (): void => finish({ kind: 'aborted' });
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onGone);
    req.on('close', onGone);
  });
}

/**
 * Starts an emulator of a Shelly Gen3 relay with one switch (id 0) that only opens for a signed command. It answers
 * JSON-RPC at `POST /rpc` (`Switch.Set`, `Switch.GetStatus`, `Shelly.GetDeviceInfo`) and serves a status page at `GET /`.
 *
 * `Switch.Set` needs an `X-Umis-Command` header whose signature comes from a trusted key and covers the exact body
 * (checked with `verifyRelayCommand`); a command works once. The output is derived from the clock, never from timers: it
 * is on while `now` is before the instant the flip-back timer ends. With `digestPasswordEnv` the call needs Shelly digest
 * authentication as well (user `admin`, SHA-256). `Switch.GetStatus` and `Shelly.GetDeviceInfo` need neither, so that
 * the status page can poll without credentials; they change nothing. Browser pages can call the emulator from the
 * origins in `cors` only.
 */
export async function startShellyEmulator(o: RelayEmulatorOptions): Promise<RelayEmulator> {
  const settings = settingsOf(o);
  const { now, password, requireSignature } = settings;
  const replay = createMemoryReplayStore({ now });
  const nonces = new Map<string, { issuedAt: number; lastCount: number }>();
  let audiences: readonly string[] = settings.audiences ?? [];

  // the output level the last command set, and the flip-back that follows it: the state is a function of the clock
  let level = false;
  let flipAt: number | undefined;
  let timerStartedAt = 0;
  let timerDuration = 0;
  let last: { at: number; jti: string; iss?: string } | undefined;
  const outputAt = (t: number): boolean => (flipAt !== undefined && t >= flipAt ? !level : level);

  function log(line: string): void {
    try {
      o.log?.(line);
    } catch {
      // a failing log sink must not take the emulator down
    }
  }

  // ---- HTTP helpers ------------------------------------------------------------------------------------------------

  function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
    const text = JSON.stringify(body);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(text),
      ...headers,
    });
    res.end(text);
  }

  const answer = (id: unknown, dst: string | undefined, rest: Json): Json => ({
    id,
    src: DEVICE_ID,
    ...(dst === undefined ? {} : { dst }),
    ...rest,
  });
  const failure = (id: unknown, dst: string | undefined, code: number, message: string): Json =>
    answer(id, dst, { error: { code, message } });

  // ---- digest authentication ---------------------------------------------------------------------------------------

  function challenge(t: number): Record<string, string> {
    for (const [nonce, entry] of nonces) {
      if (t - entry.issuedAt <= DIGEST_NONCE_TTL_S && nonces.size < DIGEST_MAX_NONCES) break;
      nonces.delete(nonce);
    }
    const nonce = randomId(16);
    nonces.set(nonce, { issuedAt: t, lastCount: 0 });
    return { 'www-authenticate': `Digest qop="auth", realm="${DEVICE_ID}", nonce="${nonce}", algorithm=SHA-256` };
  }

  async function digestAccepted(req: IncomingMessage, t: number): Promise<boolean> {
    if (password === undefined) return true;
    const header = req.headers.authorization;
    if (typeof header !== 'string' || header.length > DIGEST_MAX_HEADER_CHARS || !/^digest\s/i.test(header))
      return false;
    const fields = digestFields(header.slice('digest'.length));
    const nonce = fields.get('nonce');
    const nc = fields.get('nc');
    const cnonce = fields.get('cnonce');
    const response = fields.get('response');
    const issued = nonce === undefined ? undefined : nonces.get(nonce);
    if (nonce === undefined || issued === undefined || t - issued.issuedAt > DIGEST_NONCE_TTL_S) return false;
    if (fields.get('username') !== DIGEST_USER || fields.get('realm') !== DEVICE_ID) return false;
    if (fields.get('qop') !== 'auth' || fields.get('algorithm')?.toUpperCase() !== 'SHA-256') return false;
    if (fields.get('uri') !== req.url) return false;
    if (nc === undefined || !/^[0-9a-f]{8}$/i.test(nc) || cnonce === undefined || cnonce === '') return false;
    if (response === undefined || !/^[0-9a-f]{64}$/i.test(response)) return false;
    const count = Number.parseInt(nc, 16);
    if (count <= issued.lastCount) return false;
    const expected = await computeDigestResponse({
      username: DIGEST_USER,
      realm: DEVICE_ID,
      password,
      method: req.method ?? 'POST',
      uri: req.url ?? '',
      nonce,
      cnonce,
      nc,
      qop: 'auth',
    });
    if (!equalHex(expected, response)) return false;
    issued.lastCount = count;
    return true;
  }

  // ---- RPC ---------------------------------------------------------------------------------------------------------

  function deviceInfo(): Json {
    return {
      name: DEVICE_ID,
      id: DEVICE_ID,
      mac: '02554D495301',
      model: 'UMIS-EMU',
      gen: 3,
      fw_id: '20261101-000000/1.0.0-umis-emu',
      ver: '1.0.0',
      app: 'UmisRelayEmu',
      auth_en: password !== undefined,
    };
  }

  function switchStatus(t: number): Json {
    const timerRunning = flipAt !== undefined && t < flipAt;
    return {
      id: SWITCH_ID,
      source: last === undefined ? 'init' : flipAt !== undefined && t >= flipAt ? 'timer' : 'HTTP',
      output: outputAt(t),
      ...(timerRunning ? { timer_started_at: timerStartedAt, timer_duration: timerDuration } : {}),
      // not part of the Shelly status: the emulator's clock and the last command, which the status page shows
      umis_now: t,
      ...(last === undefined
        ? {}
        : {
            umis_last: {
              at: last.at,
              jti: last.jti.slice(0, LOGGED_ID_CHARS),
              ...(last.iss === undefined ? {} : { iss: last.iss }),
            },
          }),
    };
  }

  /** What is wrong with the switch id of a call, if anything: the log text and the answer. */
  function switchProblem(params: Json, id: unknown, dst: string | undefined): { log: string; body: Json } | undefined {
    const value = own(params, 'id');
    if (value === undefined) {
      return { log: 'INVALID_ARGUMENT id', body: failure(id, dst, -103, "Missing required argument 'id'!") };
    }
    if (typeof value !== 'number' || !Number.isInteger(value)) {
      return { log: 'INVALID_ARGUMENT id', body: failure(id, dst, -103, "Invalid argument 'id': not an integer!") };
    }
    if (value !== SWITCH_ID) {
      return { log: 'NOT_FOUND id', body: failure(id, dst, -105, `Argument 'id', value '${value}' not found!`) };
    }
    return undefined;
  }

  async function switchSet(
    req: IncomingMessage,
    res: ServerResponse,
    text: string,
    request: Json,
    params: Json,
  ): Promise<void> {
    const id = own(request, 'id');
    const src = own(request, 'src');
    const dst = typeof src === 'string' && src.length <= MAX_ECHO_CHARS ? src : undefined;
    const t = now();

    const refuse = (reason: string, headers: Record<string, string> = {}): void => {
      log(`401 ${reason}`);
      send(res, 401, failure(id, dst, 401, 'Unauthorized'), headers);
    };
    if (password !== undefined && !(await digestAccepted(req, t))) {
      refuse('DIGEST', challenge(t));
      return;
    }
    let command: { jti: string; iss?: string } | undefined;
    if (requireSignature) {
      const header = req.headers['x-umis-command'];
      if (typeof header !== 'string' || header === '') {
        refuse('MISSING_COMMAND');
        return;
      }
      const verdict = await verifyRelayCommand(header, text, { keys: settings.keys, audiences, now: t, replay });
      if (!verdict.ok) {
        refuse(verdict.reason);
        return;
      }
      command = verdict.payload;
    }

    const problem = switchProblem(params, id, dst);
    const on = own(params, 'on');
    const toggleAfter = own(params, 'toggle_after');
    if (problem !== undefined) {
      log(`400 ${problem.log}`);
      send(res, 400, problem.body);
      return;
    }
    const timer = toggleAfter === undefined ? undefined : toggleAfter;
    const timerValid =
      timer === undefined ||
      (typeof timer === 'number' && Number.isFinite(timer) && timer > 0 && timer <= MAX_TOGGLE_AFTER_S);
    if (typeof on !== 'boolean' || !timerValid) {
      log('400 INVALID_ARGUMENT');
      send(res, 400, failure(id, dst, -103, "Invalid argument 'on' or 'toggle_after'"));
      return;
    }

    const wasOn = outputAt(t);
    level = on;
    if (typeof timer === 'number') {
      flipAt = t + timer;
      timerStartedAt = t;
      timerDuration = timer;
    } else {
      flipAt = undefined;
    }
    last = { at: t, jti: command?.jti ?? '', ...(command?.iss === undefined ? {} : { iss: command.iss }) };

    const action = `${on ? 'OPEN' : 'CLOSE'}${typeof timer === 'number' ? ` ${timer} s` : ''}`;
    const sender =
      command === undefined
        ? 'unsigned'
        : `jti ${printable(command.jti, LOGGED_ID_CHARS)}${command.iss === undefined ? '' : ` · iss ${printable(command.iss)}`}`;
    log(`${action} · ${sender}`);
    send(res, 200, answer(id, dst, { result: { was_on: wasOn } }));
  }

  async function rpc(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    if (body.kind === 'aborted') return;
    if (body.kind === 'too_large') {
      log('413 TOO_LARGE');
      res.once('finish', () => req.destroy());
      send(res, 413, failure(null, undefined, 413, 'Payload Too Large'), { connection: 'close' });
      return;
    }
    let text: string;
    let request: unknown;
    try {
      text = utf8Decode(body.bytes);
      request = JSON.parse(text);
    } catch {
      log('400 PARSE_ERROR');
      send(res, 400, failure(null, undefined, -32700, 'Parse error'));
      return;
    }
    const id = isRecord(request) ? own(request, 'id') : undefined;
    const method = isRecord(request) ? own(request, 'method') : undefined;
    if (
      !isRecord(request) ||
      typeof method !== 'string' ||
      method === '' ||
      (typeof id !== 'number' && typeof id !== 'string')
    ) {
      log('400 INVALID_REQUEST');
      send(res, 400, failure(null, undefined, -32600, 'Invalid request'));
      return;
    }
    const src = own(request, 'src');
    const dst = typeof src === 'string' && src.length <= MAX_ECHO_CHARS ? src : undefined;
    const params = own(request, 'params') ?? {};
    if (!isRecord(params)) {
      log('400 INVALID_ARGUMENT params');
      send(res, 400, failure(id, dst, -103, "Invalid argument 'params'"));
      return;
    }

    switch (method) {
      case 'Shelly.GetDeviceInfo':
        send(res, 200, answer(id, dst, { result: deviceInfo() }));
        return;
      case 'Switch.GetStatus': {
        const problem = switchProblem(params, id, dst);
        if (problem !== undefined) send(res, 400, problem.body);
        else send(res, 200, answer(id, dst, { result: switchStatus(now()) }));
        return;
      }
      case 'Switch.Set':
        await switchSet(req, res, text, request, params);
        return;
      default:
        log(`404 NO_HANDLER ${printable(method)}`);
        send(res, 404, failure(id, dst, 404, `No handler for ${printable(method)}`));
    }
  }

  // ---- routing and CORS --------------------------------------------------------------------------------------------

  async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const origin = req.headers.origin;
    const allowed = typeof origin === 'string' && settings.cors.has(origin.toLowerCase());
    res.setHeader('vary', 'Origin');
    res.setHeader('x-content-type-options', 'nosniff');
    if (allowed) res.setHeader('access-control-allow-origin', origin);

    const method = req.method ?? 'GET';
    const target = req.url ?? '/';
    const path = target.split('?', 1)[0];

    if (method === 'OPTIONS') {
      if (allowed) {
        res.setHeader('access-control-allow-methods', 'POST, GET, OPTIONS');
        res.setHeader('access-control-allow-headers', 'content-type, x-umis-command');
        res.setHeader('access-control-max-age', '600');
        if (req.headers['access-control-request-private-network'] === 'true') {
          res.setHeader('access-control-allow-private-network', 'true');
        }
      }
      res.writeHead(204);
      res.end();
      return;
    }
    if (path === '/') {
      if (method !== 'GET') {
        send(res, 405, failure(null, undefined, 405, 'Method Not Allowed'), { allow: 'GET, OPTIONS' });
        return;
      }
      res.writeHead(200, STATUS_PAGE.headers);
      res.end(STATUS_PAGE.html);
      return;
    }
    if (path === '/rpc') {
      if (method !== 'POST') {
        send(res, 405, failure(null, undefined, 405, 'Method Not Allowed'), { allow: 'POST, OPTIONS' });
        return;
      }
      await rpc(req, res);
      return;
    }
    send(res, 404, failure(null, undefined, 404, 'Not Found'));
  }

  // ---- the server --------------------------------------------------------------------------------------------------

  const server = createServer({ maxHeaderSize: MAX_HEADER_BYTES }, (req, res) => {
    serve(req, res).catch(() => {
      log('500 INTERNAL');
      if (res.headersSent) res.destroy();
      else send(res, 500, failure(null, undefined, 500, 'Internal error'));
    });
  });
  server.headersTimeout = 5_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;

  await new Promise<void>((resolve, reject) => {
    const onError = (error: NodeJS.ErrnoException): void => {
      reject(
        new UmisError('NETWORK', `cannot listen on ${settings.host}:${settings.port} (${error.code ?? 'error'})`, {
          cause: error,
        }),
      );
    };
    server.once('error', onError);
    server.listen(settings.port, settings.host, () => {
      server.off('error', onError);
      resolve();
    });
  });
  server.on('error', (error: NodeJS.ErrnoException) => log(`error ${error.code ?? 'server'}`));

  const address = server.address() as AddressInfo;
  const hostText = address.family === 'IPv6' ? `[${address.address}]` : address.address;
  const url = `http://${hostText}:${address.port}`;
  if (settings.audiences === undefined) {
    audiences = [
      ...new Set([
        `${URN_PREFIX.relay}emu`,
        url,
        `http://127.0.0.1:${address.port}`,
        `http://localhost:${address.port}`,
      ]),
    ];
  }

  let closing: Promise<void> | undefined;
  return {
    url,
    state() {
      const t = now();
      const until = level && flipAt !== undefined && t < flipAt ? flipAt : undefined;
      return {
        on: outputAt(t),
        ...(until === undefined ? {} : { until }),
        ...(last === undefined ? {} : { last: { ...last } }),
      };
    },
    close() {
      closing ??= new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
        server.closeAllConnections();
      });
      return closing;
    },
  };
}
