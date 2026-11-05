import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateSigner, randomId } from '@umis/core';
import type { Signer } from '@umis/core';
import { shellySwitchSetBody, signRelayCommand } from '@umis/gateway';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RELAY_EMU_USAGE, relayEmu } from '../src/commands/relay-emu.js';

const BIN = fileURLToPath(new URL('../dist/bin.js', import.meta.url));
const ORIGIN = 'https://admin.example.test';
const OPEN_3S = shellySwitchSetBody({ rpcId: 1, switchId: 0, on: true, toggleAfter: 3, src: 'umis-station-7' });

let folder: string;
let station: Signer;
let trustFile: string;

beforeAll(async () => {
  folder = await mkdtemp(join(tmpdir(), 'umis-cli-'));
  station = await generateSigner();
  trustFile = join(folder, 'station.jwk.json');
  await writeFile(trustFile, JSON.stringify(station.publicJwk));
});
afterAll(async () => {
  await rm(folder, { recursive: true, force: true });
});

/** Runs the built tool as a process of its own and collects what it prints and how it ended. */
function umis(...args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    child.once('error', reject);
    child.once('close', (status) => resolve({ status, stdout, stderr }));
  });
}

/** Runs `umis relay-emu` inside this process with a signal that is already aborted, so that nothing keeps listening. */
async function attempt(...args: string[]): Promise<{ code: number; text: string }> {
  const lines: string[] = [];
  const code = await relayEmu(
    args,
    { out: (line) => lines.push(line), err: (line) => lines.push(line) },
    AbortSignal.abort(),
  );
  return { code, text: lines.join('\n') };
}

/** Waits for `test` to hold; a loaded machine is given a generous time. */
async function until(test: () => boolean, what: string, limitMs = 15_000): Promise<void> {
  const end = Date.now() + limitMs;
  while (!test()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

describe('umis: dispatcher and usage', () => {
  it('lists its commands, and ends with exit code 64 for a missing or unknown command', async () => {
    const [help, bare, unknown, inherited, sub, noTrust] = await Promise.all([
      umis('--help'),
      umis(),
      umis('frobnicate'),
      umis('constructor'),
      umis('relay-emu', '--help'),
      umis('relay-emu'),
    ]);
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('relay-emu');
    expect(bare.status).toBe(64);
    expect(bare.stderr).toContain('usage: umis <command>');
    expect(unknown.status).toBe(64);
    expect(unknown.stderr).toContain('unknown command "frobnicate"');
    expect(inherited.status).toBe(64);
    expect(sub.status).toBe(0);
    expect(sub.stdout).toContain('--digest-password-env <NAME>');
    expect(sub.stdout).toContain('Only Switch.Set needs the signed command');
    expect(noTrust.status).toBe(64);
    expect(noTrust.stderr).toContain('--trust <file> is required');
  }, 60_000);

  it('ends umis relay-emu with exit code 64 for a mistake in its arguments or in the files it names', async () => {
    expect((await attempt()).code).toBe(64); // no --trust
    expect((await attempt('--trust', join(folder, 'missing.json'))).code).toBe(64);
    expect((await attempt('--trust', trustFile, '--port', '70000')).code).toBe(64);
    expect((await attempt('--trust', trustFile, '--bogus')).code).toBe(64);
    expect((await attempt('--trust', trustFile, '--cors', 'https://admin.example.test/')).code).toBe(64);
    // no browser sends a wildcard host, so an origin with one could never match
    const wildcard = await attempt('--trust', trustFile, '--cors', 'https://*.example.com');
    expect(wildcard.code).toBe(64);
    expect(wildcard.text).toContain('https://*.example.com');
    const unset = await attempt('--trust', trustFile, '--digest-password-env', 'UMIS_TEST_NOT_SET_ANYWHERE');
    expect(unset.code).toBe(64);
    expect(unset.text).toContain('UMIS_TEST_NOT_SET_ANYWHERE');
  }, 30_000);
});

describe('umis relay-emu', () => {
  it('runs as a process: obeys a signed command, refuses a replay, prints one line each, stops on SIGINT', async () => {
    const child = spawn(process.execPath, [BIN, 'relay-emu', '--port', '0', '--trust', trustFile, '--cors', ORIGIN], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    const exited = new Promise<number | null>((resolve) => child.on('exit', (code) => resolve(code)));
    try {
      // the banner arrives line by line; the cors line is its last one
      await until(() => /^ {2}cors\s+\S+\n/m.test(stdout), 'the banner');
      const url = /listening on (http:\/\/\S+)/.exec(stdout)![1]!;
      expect(stdout).toMatch(/trusted keys 1 \(fingerprint [A-Z2-7]{4}(-[A-Z2-7]{4}){3}\)/);
      expect(stdout).toMatch(/cors\s+https:\/\/admin\.example\.test/);

      const preflight = await fetch(`${url}/rpc`, {
        method: 'OPTIONS',
        headers: {
          origin: ORIGIN,
          'access-control-request-method': 'POST',
          'access-control-request-private-network': 'true',
        },
      });
      expect(preflight.headers.get('access-control-allow-private-network')).toBe('true');

      const jws = await signRelayCommand({
        signer: station,
        relayAud: url,
        body: OPEN_3S,
        now: Date.now() / 1000,
        iss: 'umis-station-7',
      });
      const post = (headers: Record<string, string> = {}) =>
        fetch(`${url}/rpc`, { method: 'POST', body: OPEN_3S, headers });
      expect((await post()).status).toBe(401);
      expect((await post({ 'x-umis-command': jws })).status).toBe(200);
      expect((await post({ 'x-umis-command': jws })).status).toBe(401);

      await until(() => stdout.includes('401 REPLAY'), 'the replay line');
      expect(stdout).toContain('401 MISSING_COMMAND\n');
      expect(stdout).toMatch(/^OPEN 3 s · jti [A-Za-z0-9_-]{8} · iss umis-station-7$/m);
    } finally {
      child.kill('SIGINT');
    }
    expect(await exited).toBe(0);
  }, 30_000);

  it('reads trust files in any shape, warns about a private part and about --no-signature, and stops when aborted', async () => {
    const other = await generateSigner();
    const keyset = join(folder, 'keys.jwks.json');
    const privatePart = randomId(32);
    await writeFile(keyset, JSON.stringify({ keys: [station.publicJwk, { ...other.publicJwk, d: privatePart }] }));
    const lines: string[] = [];
    const problems: string[] = [];
    const stop = new AbortController();
    const done = relayEmu(
      ['--port', '0', '--trust', keyset, '--trust', trustFile, '--aud', 'gate-7', '--aud', 'gate-8'],
      { out: (line) => lines.push(line), err: (line) => problems.push(line) },
      stop.signal,
    );
    await until(() => lines.some((line) => line.includes('audiences')), 'the banner');
    expect(lines.join('\n')).toContain('trusted keys 3');
    expect(lines.join('\n')).toContain('audiences    gate-7, gate-8');
    expect(problems.join('\n')).toMatch(/keys\.jwks\.json holds a private key; only its public part is used/);
    stop.abort();
    expect(await done).toBe(0);
    // the warning names the file, never the private value
    expect([...lines, ...problems].join('\n')).not.toContain(privatePart);

    // with --no-signature there is nothing to trust, and the command says so
    const open: string[] = [];
    const warned: string[] = [];
    const again = new AbortController();
    const running = relayEmu(
      ['--port', '0', '--no-signature'],
      { out: (line) => open.push(line), err: (line) => warned.push(line) },
      again.signal,
    );
    await until(() => open.some((line) => line.includes('signatures are not checked')), 'the banner');
    const url = /listening on (http:\/\/\S+)/.exec(open[0]!)![1]!;
    expect((await fetch(`${url}/rpc`, { method: 'POST', body: OPEN_3S })).status).toBe(200);
    expect(open).toContain('OPEN 3 s · unsigned');
    expect(warned.join('\n')).toContain('--no-signature');
    again.abort();
    expect(await running).toBe(0);
  }, 30_000);

  it('takes several origins from a repeated --cors or a comma-separated list, with the same result', async () => {
    expect(RELAY_EMU_USAGE).toContain('repeat the option or separate origins with commas');
    const origins = ['https://a.example.com', 'https://b.example.com'];
    const banners: string[] = [];
    for (const form of [
      ['--cors', origins[0]!, '--cors', origins[1]!],
      ['--cors', origins.join(',')],
    ]) {
      const lines: string[] = [];
      const stop = new AbortController();
      let code: number | undefined;
      const running = relayEmu(
        ['--port', '0', '--trust', trustFile, ...form],
        { out: (line) => lines.push(line), err: (line) => lines.push(line) },
        stop.signal,
      ).then((value) => (code = value));
      try {
        await until(() => code !== undefined || lines.some((line) => line.startsWith('  cors')), 'the banner');
        expect(code, lines.join('\n')).toBeUndefined();
        banners.push(lines.find((line) => line.startsWith('  cors'))!);
        const url = /listening on (http:\/\/\S+)/.exec(lines[0]!)![1]!;
        for (const origin of origins) {
          const preflight = await fetch(`${url}/rpc`, {
            method: 'OPTIONS',
            headers: { origin, 'access-control-request-method': 'POST' },
          });
          expect(preflight.headers.get('access-control-allow-origin'), form.join(' ')).toBe(origin);
        }
      } finally {
        stop.abort();
      }
      expect(await running).toBe(0);
    }
    expect(banners).toEqual([`  cors         ${origins.join(', ')}`, `  cors         ${origins.join(', ')}`]);
  }, 30_000);
});
