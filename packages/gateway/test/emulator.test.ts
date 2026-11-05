import { createHash } from 'node:crypto';
import { request } from 'node:http';
import type { IncomingHttpHeaders } from 'node:http';
import { decodeJwsUnverified, generateSigner, randomId } from '@umis/core';
import type { Signer } from '@umis/core';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { computeDigestResponse, shellySwitchSetBody, signRelayCommand } from '../src/index.js';
import { startShellyEmulator } from '../src/node/index.js';
import type { RelayEmulator, RelayEmulatorOptions } from '../src/node/index.js';
import { STATION_ISS, T0 } from './fixtures.js';

const ADMIN_ORIGIN = 'https://admin.example.test';
const OPEN_3S = shellySwitchSetBody({ rpcId: 1, switchId: 0, on: true, toggleAfter: 3, src: STATION_ISS });

interface Reply {
  status: number;
  headers: IncomingHttpHeaders;
  text: string;
  json: any;
}

/** One HTTP exchange with the emulator, over node:http so that every header can be set and read as sent. */
function call(
  base: string,
  init: { method: string; path: string; headers?: Record<string, string>; body?: string },
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const target = new URL(base);
    const req = request(
      { host: target.hostname, port: target.port, method: init.method, path: init.path, headers: init.headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: unknown;
          try {
            json = JSON.parse(text);
          } catch {
            json = undefined;
          }
          resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json });
        });
      },
    );
    req.on('error', reject);
    req.end(init.body);
  });
}

let station: Signer;
let clock = T0;
let logs: string[] = [];
let emulator: RelayEmulator | undefined;

beforeAll(async () => {
  station = await generateSigner();
});

afterEach(async () => {
  await emulator?.close();
  emulator = undefined;
});

async function start(over: Partial<RelayEmulatorOptions> = {}): Promise<RelayEmulator> {
  clock = T0;
  logs = [];
  emulator = await startShellyEmulator({
    port: 0,
    trust: [station.publicJwk],
    now: () => clock,
    log: (line) => logs.push(line),
    ...over,
  });
  return emulator;
}

const rpc = (emu: RelayEmulator, body: string, headers: Record<string, string> = {}): Promise<Reply> =>
  call(emu.url, { method: 'POST', path: '/rpc', headers: { 'content-type': 'application/json', ...headers }, body });

const command = (
  emu: RelayEmulator,
  body: string,
  over: { signer?: Signer; relayAud?: string } = {},
): Promise<string> =>
  signRelayCommand({
    signer: over.signer ?? station,
    relayAud: over.relayAud ?? emu.url,
    body,
    now: clock,
    iss: STATION_ISS,
  });

const status = (emu: RelayEmulator): Promise<Reply> =>
  rpc(emu, JSON.stringify({ id: 9, method: 'Switch.GetStatus', params: { id: 0 } }));

describe('relay emulator: only a signed command moves the switch', () => {
  it('refuses an unsigned Switch.Set, obeys a signed one until the flip-back time, then closes by the clock', async () => {
    const emu = await start();
    const unsigned = await rpc(emu, OPEN_3S);
    expect(unsigned.status).toBe(401);
    expect(unsigned.json).toMatchObject({ id: 1, src: 'umis-relay-emu', dst: STATION_ISS, error: { code: 401 } });
    expect(emu.state()).toEqual({ on: false });
    expect(logs).toEqual(['401 MISSING_COMMAND']);

    const signed = await rpc(emu, OPEN_3S, { 'x-umis-command': await command(emu, OPEN_3S) });
    expect(signed.status).toBe(200);
    expect(signed.json).toEqual({ id: 1, src: 'umis-relay-emu', dst: STATION_ISS, result: { was_on: false } });
    expect(emu.state()).toMatchObject({ on: true, until: T0 + 3, last: { at: T0, iss: STATION_ISS } });
    expect(emu.state().last?.jti).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(logs[1]).toMatch(/^OPEN 3 s · jti [A-Za-z0-9_-]{8} · iss umis-station-7$/);

    clock = T0 + 2;
    expect((await status(emu)).json.result).toMatchObject({
      id: 0,
      source: 'HTTP',
      output: true,
      timer_started_at: T0,
      timer_duration: 3,
      umis_now: T0 + 2,
    });
    clock = T0 + 3; // nothing was scheduled: the output is a function of the clock
    expect(emu.state().on).toBe(false);
    const closed = (await status(emu)).json.result;
    expect(closed).toMatchObject({ output: false, source: 'timer' });
    expect(closed).not.toHaveProperty('timer_started_at');
  });

  it('reports the last command as umis_last in Switch.GetStatus: its time, jti prefix and iss', async () => {
    const emu = await start();
    expect((await status(emu)).json.result).not.toHaveProperty('umis_last');

    const signed = await command(emu, OPEN_3S);
    expect((await rpc(emu, OPEN_3S, { 'x-umis-command': signed })).status).toBe(200);
    // the first eight characters of the jti, as the log shows them
    const jti = decodeJwsUnverified<{ jti: string }>(signed).payload.jti;
    expect((await status(emu)).json.result.umis_last).toEqual({ at: T0, jti: jti.slice(0, 8), iss: STATION_ISS });

    // a command without iss leaves the member out
    clock = T0 + 10;
    const body = OPEN_3S.replace('"id":1', '"id":2');
    const anonymous = await signRelayCommand({ signer: station, relayAud: emu.url, body, now: clock });
    expect((await rpc(emu, body, { 'x-umis-command': anonymous })).status).toBe(200);
    const last = (await status(emu)).json.result.umis_last;
    expect(last).toEqual({ at: T0 + 10, jti: decodeJwsUnverified<{ jti: string }>(anonymous).payload.jti.slice(0, 8) });
    expect(last).not.toHaveProperty('iss');
  });

  it('refuses a replayed command, a changed body, another relay and a key that is not trusted', async () => {
    const emu = await start();
    const jws = await command(emu, OPEN_3S);
    expect((await rpc(emu, OPEN_3S, { 'x-umis-command': jws })).status).toBe(200);
    clock = T0 + 3;
    expect(emu.state().on).toBe(false);

    const replayed = await rpc(emu, OPEN_3S, { 'x-umis-command': jws });
    expect(replayed.status).toBe(401);
    expect(replayed.json.error).toEqual({ code: 401, message: 'Unauthorized' });
    expect(emu.state().on).toBe(false);

    const longer = OPEN_3S.replace('"toggle_after":3', '"toggle_after":9');
    expect((await rpc(emu, longer, { 'x-umis-command': await command(emu, OPEN_3S) })).status).toBe(401);
    expect(
      (
        await rpc(emu, OPEN_3S, {
          'x-umis-command': await command(emu, OPEN_3S, { relayAud: 'http://elsewhere.test' }),
        })
      ).status,
    ).toBe(401);
    const stranger = await generateSigner();
    expect(
      (await rpc(emu, OPEN_3S, { 'x-umis-command': await command(emu, OPEN_3S, { signer: stranger }) })).status,
    ).toBe(401);
    expect(emu.state().on).toBe(false);
    expect(logs.slice(1)).toEqual([
      '401 REPLAY',
      '401 SIGNATURE_INVALID',
      '401 AUDIENCE_MISMATCH',
      '401 SIGNATURE_INVALID',
    ]);
  });

  it('checks a command against the body as it was sent: one trailing space is enough to refuse it', async () => {
    const emu = await start();
    const jws = await command(emu, OPEN_3S);
    const padded = await rpc(emu, `${OPEN_3S} `, { 'x-umis-command': jws });
    expect(padded.status).toBe(401);
    expect(logs).toEqual(['401 SIGNATURE_INVALID']);
    expect(emu.state().on).toBe(false);
    // the refusal did not use the command up: with the body it was signed for, it opens
    expect((await rpc(emu, OPEN_3S, { 'x-umis-command': jws })).status).toBe(200);
  });

  it('accepts the relay by its own addresses and urn:umis:relay:emu, or by the audiences it is given instead', async () => {
    const emu = await start();
    const port = new URL(emu.url).port;
    for (const aud of ['urn:umis:relay:emu', emu.url, `http://127.0.0.1:${port}`, `http://localhost:${port}`]) {
      const body = OPEN_3S.replace('"id":1', `"id":${aud.length}`);
      const reply = await rpc(emu, body, { 'x-umis-command': await command(emu, body, { relayAud: aud }) });
      expect(reply.status, aud).toBe(200);
    }
    await emulator?.close();
    const narrow = await start({ audiences: ['gate-7'] });
    expect((await rpc(narrow, OPEN_3S, { 'x-umis-command': await command(narrow, OPEN_3S) })).status).toBe(401);
    expect(
      (await rpc(narrow, OPEN_3S, { 'x-umis-command': await command(narrow, OPEN_3S, { relayAud: 'gate-7' }) })).status,
    ).toBe(200);
  });

  it('opens on an unsigned command only when signatures are switched off', async () => {
    const emu = await start({ requireSignature: false, trust: [] });
    const reply = await rpc(emu, OPEN_3S);
    expect(reply.status).toBe(200);
    expect(emu.state()).toMatchObject({ on: true, until: T0 + 3 });
    expect(logs).toEqual(['OPEN 3 s · unsigned']);
    await emulator?.close();
    await expect(startShellyEmulator({ port: 0, trust: [], now: () => clock })).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
  });
});

describe('relay emulator: Shelly Gen3 RPC and input bounds', () => {
  it('answers GetDeviceInfo as a Gen3 device and rejects what is not a call it knows', async () => {
    const emu = await start();
    const info = await rpc(emu, JSON.stringify({ id: 5, src: 'probe', method: 'Shelly.GetDeviceInfo' }));
    expect(info.status).toBe(200);
    expect(info.json).toMatchObject({
      id: 5,
      src: 'umis-relay-emu',
      dst: 'probe',
      result: { gen: 3, model: 'UMIS-EMU', app: 'UmisRelayEmu', auth_en: false },
    });
    expect(Object.keys(info.json.result).sort()).toEqual([
      'app',
      'auth_en',
      'fw_id',
      'gen',
      'id',
      'mac',
      'model',
      'name',
      'ver',
    ]);

    expect((await rpc(emu, JSON.stringify({ id: 1, method: 'Switch.Toggle', params: { id: 0 } }))).status).toBe(404);
    expect((await rpc(emu, '{not json')).json.error.code).toBe(-32700);
    expect((await rpc(emu, JSON.stringify({ method: 'Switch.GetStatus' }))).json.error.code).toBe(-32600);
    expect(
      (await rpc(emu, JSON.stringify({ id: 1, method: 'Switch.GetStatus', params: { id: 3 } }))).json.error.code,
    ).toBe(-105);
    expect((await call(emu.url, { method: 'GET', path: '/rpc' })).status).toBe(405);
    expect((await call(emu.url, { method: 'GET', path: '/nothing' })).status).toBe(404);
  });

  it('refuses a body above 8 KiB with 413 before reading it all, and a body that is not UTF-8 JSON', async () => {
    const emu = await start();
    const big = await rpc(
      emu,
      JSON.stringify({ id: 1, method: 'Switch.GetStatus', params: { id: 0 }, pad: 'x'.repeat(9_000) }),
    );
    expect(big.status).toBe(413);
    const edge = JSON.stringify({ id: 1, method: 'Switch.GetStatus', params: { id: 0 } });
    expect((await rpc(emu, edge.slice(0, -1) + ',"p":"' + 'x'.repeat(8_192 - edge.length - 8) + '"}')).status).toBe(
      200,
    );
    expect((await call(emu.url, { method: 'POST', path: '/rpc', body: '\uFEFF' + edge })).status).toBe(400);
    expect(logs).toContain('413 TOO_LARGE');
  });

  it('answers a preflight from an allowed origin with the private-network header, and gives other origins nothing', async () => {
    const emu = await start({ cors: [ADMIN_ORIGIN] });
    const preflight = (origin: string, extra: Record<string, string> = {}) =>
      call(emu.url, {
        method: 'OPTIONS',
        path: '/rpc',
        headers: {
          origin,
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'content-type, x-umis-command',
          ...extra,
        },
      });

    const allowed = await preflight(ADMIN_ORIGIN, { 'access-control-request-private-network': 'true' });
    expect(allowed.status).toBe(204);
    expect(allowed.headers).toMatchObject({
      'access-control-allow-origin': ADMIN_ORIGIN,
      'access-control-allow-methods': 'POST, GET, OPTIONS',
      'access-control-allow-headers': 'content-type, x-umis-command',
      'access-control-allow-private-network': 'true',
    });
    expect((await preflight(ADMIN_ORIGIN)).headers).not.toHaveProperty('access-control-allow-private-network');

    for (const foreign of ['https://evil.example', 'https://admin.example.test.evil.example', 'null']) {
      const refused = await preflight(foreign, { 'access-control-request-private-network': 'true' });
      expect(Object.keys(refused.headers).filter((name) => name.startsWith('access-control-'))).toEqual([]);
    }

    // the answer to the call itself names the origin too, and a foreign origin gets no CORS header there either
    const post = (origin: string) => rpc(emu, JSON.stringify({ id: 1, method: 'Shelly.GetDeviceInfo' }), { origin });
    expect((await post(ADMIN_ORIGIN)).headers['access-control-allow-origin']).toBe(ADMIN_ORIGIN);
    expect((await post('https://evil.example')).headers).not.toHaveProperty('access-control-allow-origin');
    expect((await rpc(emu, JSON.stringify({ id: 1, method: 'Shelly.GetDeviceInfo' }))).headers['vary']).toBe('Origin');

    await emulator?.close();
    for (const bad of ['*', 'https://admin.example.test/', 'admin.example.test']) {
      await expect(
        startShellyEmulator({ port: 0, trust: [station.publicJwk], now: () => clock, cors: [bad] }),
      ).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
      });
    }
  });

  it('serves a status page that needs nothing from outside and can only run its own script', async () => {
    const emu = await start();
    const page = await call(emu.url, { method: 'GET', path: '/' });
    expect(page.status).toBe(200);
    expect(page.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(page.text).toContain('Switch.GetStatus');
    expect(page.text).not.toMatch(/https?:\/\//);
    expect(page.text).not.toMatch(/<(img|iframe|link|script)[^>]*\s(src|href)="(?!data:)/);

    const policy = String(page.headers['content-security-policy']);
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("connect-src 'self'");
    // the policy names the hash of the inline script and style that the page really carries
    const hash = (text: string) => `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`;
    const script = /<script>([\s\S]*)<\/script>/.exec(page.text)![1]!;
    const style = /<style>([\s\S]*)<\/style>/.exec(page.text)![1]!;
    expect(policy).toContain(`script-src ${hash(script)}`);
    expect(policy).toContain(`style-src ${hash(style)}`);
    expect(page.headers['x-content-type-options']).toBe('nosniff');
  });
});

describe('relay emulator: Shelly digest authentication', () => {
  const NAME = 'UMIS_TEST_RELAY_DIGEST_PASSWORD';
  afterEach(() => {
    delete process.env[NAME];
  });

  it('asks for a digest on Switch.Set when a password variable is named, and keeps the password out of every output', async () => {
    const secret = randomId(24);
    process.env[NAME] = secret;
    const emu = await start({ digestPasswordEnv: NAME });
    expect((await rpc(emu, JSON.stringify({ id: 1, method: 'Shelly.GetDeviceInfo' }))).json.result.auth_en).toBe(true);

    const first = await rpc(emu, OPEN_3S, { 'x-umis-command': await command(emu, OPEN_3S) });
    expect(first.status).toBe(401);
    const challenge = String(first.headers['www-authenticate']);
    const nonce = /nonce="([^"]+)"/.exec(challenge)![1]!;
    const realm = /realm="([^"]+)"/.exec(challenge)![1]!;
    expect(challenge).toMatch(/^Digest /);
    expect(challenge).toContain('algorithm=SHA-256');
    expect(emu.state().on).toBe(false);

    const authorization = async (password: string, nc: string) => {
      const cnonce = randomId(12);
      const response = await computeDigestResponse({
        username: 'admin',
        realm,
        password,
        method: 'POST',
        uri: '/rpc',
        nonce,
        cnonce,
        nc,
        qop: 'auth',
      });
      return `Digest username="admin", realm="${realm}", nonce="${nonce}", uri="/rpc", algorithm=SHA-256, qop=auth, nc=${nc}, cnonce="${cnonce}", response="${response}"`;
    };
    const attempt = async (password: string, nc: string, body = OPEN_3S) =>
      rpc(emu, body, { authorization: await authorization(password, nc), 'x-umis-command': await command(emu, body) });

    expect((await attempt('wrong-' + secret, '00000001')).status).toBe(401);
    expect(emu.state().on).toBe(false);
    const accepted = await attempt(secret, '00000001');
    expect(accepted.status).toBe(200);
    expect(emu.state().on).toBe(true);
    // the same counter again is a replayed digest, even with a new command
    expect((await attempt(secret, '00000001', OPEN_3S.replace('"id":1', '"id":2'))).status).toBe(401);
    expect((await attempt(secret, '00000002', OPEN_3S.replace('"id":1', '"id":3'))).status).toBe(200);
    // a valid digest does not replace the signed command
    const unsigned = await rpc(emu, OPEN_3S, { authorization: await authorization(secret, '00000003') });
    expect(unsigned.status).toBe(401);
    expect(logs).toContain('401 MISSING_COMMAND');

    const everything = [...logs, first.text, accepted.text, challenge, JSON.stringify(emu.state())].join('\n');
    expect(everything).not.toContain(secret);
  });

  it('does not start when the named variable is not set, and says which one without a value', async () => {
    delete process.env[NAME];
    const failure = await startShellyEmulator({
      port: 0,
      trust: [station.publicJwk],
      now: () => clock,
      digestPasswordEnv: NAME,
    }).catch((error: unknown) => error as Error);
    expect(failure).toMatchObject({ code: 'INVALID_ARGUMENT' });
    expect((failure as Error).message).toContain(NAME);
    await expect(
      startShellyEmulator({ port: 0, trust: [station.publicJwk], now: () => clock, digestPasswordEnv: 'not a name' }),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });
});
