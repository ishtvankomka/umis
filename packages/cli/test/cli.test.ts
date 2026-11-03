import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importSigner, signJws, verifyJws } from '@umis/core';
import type { EcPrivateJwk, EcPublicJwk } from '@umis/core';
import { createDemoWorld } from '@umis/testkit';
import type { DemoWorld } from '@umis/testkit';
import { serializeVerifierContext } from '@umis/verifier';
import { createOneWayQr } from '@umis/wallet';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { CommandIo } from '../src/commands/common.js';
import { demo } from '../src/commands/demo.js';
import { inspect } from '../src/commands/inspect.js';
import { keygen } from '../src/commands/keygen.js';
import { verify } from '../src/commands/verify.js';

const BIN = fileURLToPath(new URL('../dist/bin.js', import.meta.url));
const START = 1_793_606_400; // the start of the demo world

type Command = (args: readonly string[], io: CommandIo) => Promise<number>;

let folder: string;
let world: DemoWorld;
let frame: string;

beforeAll(async () => {
  folder = await mkdtemp(join(tmpdir(), 'umis-cli-commands-'));
  world = await createDemoWorld();
  // a one-way QR code that the world made at its start: the same default world is what `--demo` decides with
  const credential = world.people.oleg.credentials.coworkingMember;
  if (credential === undefined) throw new Error('the demo world has no coworking credential');
  frame = await createOneWayQr({ sdJwtVc: credential, signer: world.people.oleg.holder, now: START, ctr: 1 });
});
afterAll(async () => {
  await rm(folder, { recursive: true, force: true });
});

/** Runs a command inside this process, with `stdin` as what is piped in (nothing when it is `undefined`). */
async function run(
  command: Command,
  args: string[],
  stdin?: string,
): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await command(args, {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    stdin: () => Promise.resolve(stdin),
  });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

/** Runs the built tool as a process of its own with `input` on its standard input. */
function umis(args: string[], input: string): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    child.once('error', reject);
    child.once('close', (status) => resolve({ status, stdout, stderr }));
    child.stdin.end(input);
  });
}

describe('umis inspect', () => {
  it('prints the kind and the payload of a QR frame, and says that it checked nothing', async () => {
    const { code, out } = await run(inspect, [frame]);
    expect(code).toBe(0);
    const shown = JSON.parse(out) as {
      kind: string;
      verified: boolean;
      chars: number;
      tokens: Array<{ header: { typ: string }; payload: Record<string, unknown> }>;
    };
    expect(shown.kind).toBe('umis_oneway');
    expect(shown.verified).toBe(false);
    expect(shown.chars).toBe(frame.length);
    expect(shown.tokens[0]?.header.typ).toBe('umis-ow+jwt');
    expect(shown.tokens[0]?.payload).toMatchObject({ iat: START, ctr: 1, aud: world.orgs['kovorking-v'].issuer });
  });

  it('decodes a credential with its disclosures, and a link with its parameters', async () => {
    const credential = world.people.oleg.credentials.roleAuthority!;
    const shown = JSON.parse((await run(inspect, [credential])).out) as {
      kind: string;
      disclosures: Array<{ name: string }>;
    };
    expect(shown.kind).toBe('sd_jwt');
    expect(shown.disclosures.map((disclosure) => disclosure.name)).toEqual(
      expect.arrayContaining(['role', 'authority']),
    );

    const link =
      'openid4vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Frp.example.test%2Fcb&dcql_query=%7B%22credentials%22%3A%5B%5D%7D';
    const linked = JSON.parse((await run(inspect, [link])).out) as {
      kind: string;
      parameters: Record<string, unknown>;
    };
    expect(linked.kind).toBe('oid4vp_request');
    expect(linked.parameters).toEqual({
      client_id: 'redirect_uri:https://rp.example.test/cb',
      dcql_query: { credentials: [] },
    });
  });

  it('reads standard input for - and for no argument, and ends with 2 for what it cannot decode', async () => {
    expect(JSON.parse((await run(inspect, ['-'], `${frame}\n`)).out)).toMatchObject({ kind: 'umis_oneway' });
    expect(JSON.parse((await run(inspect, [], frame)).out)).toMatchObject({ kind: 'umis_oneway' });
    expect((await run(inspect, ['hello world'])).code).toBe(2);
    expect((await run(inspect, ['UMIS1O:NOT A FRAME.'])).code).toBe(2);
    expect((await run(inspect, [])).code).toBe(64); // nothing piped in
    expect((await run(inspect, ['a', 'b'])).code).toBe(64);
    expect((await run(inspect, ['--bogus'])).code).toBe(64);
  });
});

describe('umis verify', () => {
  it('accepts a fresh one-way frame at the demo door and rejects it two minutes later', async () => {
    const fresh = await run(verify, ['--demo', 'kovorking-v:door_low', '--now', String(START), frame]);
    expect(fresh.code).toBe(0);
    expect(JSON.parse(fresh.out)).toMatchObject({ decision: 'accept', reasons: ['OK'], channel: 'qr_oneway' });

    const late = await run(verify, ['--demo', 'kovorking-v:door_low', '--now', String(START + 120), frame]);
    expect(late.code).toBe(2);
    expect(JSON.parse(late.out)).toMatchObject({ decision: 'reject', reasons: ['PRESENTATION_EXPIRED'] });

    // without --now the demo decides at the start of its world
    expect((await run(verify, ['--demo', 'kovorking-v:door_low', frame])).code).toBe(0);
  });

  it('decides with a saved context and reads the frame from standard input', async () => {
    const file = join(folder, 'door.context.json');
    await writeFile(
      file,
      JSON.stringify(serializeVerifierContext(world.context({ org: 'kovorking-v', policy: 'door_low' }))),
    );
    expect((await run(verify, ['--context', file, '-'], frame)).code).toBe(0);
    expect((await run(verify, ['--context', file, '--now', String(START + 120), frame])).code).toBe(2);

    const broken = join(folder, 'broken.context.json');
    await writeFile(broken, '{"v":1}');
    const refused = await run(verify, ['--context', broken, frame]);
    expect(refused.code).toBe(64);
    expect(refused.err).toContain('not a serialized verifier context');
  });

  it('decides on a frame piped into the built tool', async () => {
    const { status, stdout } = await umis(['verify', '--demo', 'kovorking-v:door_low', '-'], `${frame}\n`);
    expect(status).toBe(0);
    expect(JSON.parse(stdout)).toMatchObject({ decision: 'accept' });
  }, 30_000);

  it('ends with 64 for a mistake in the arguments', async () => {
    const door = 'kovorking-v:door_low';
    for (const args of [
      [frame], // no context
      ['--demo', door, '--context', 'x.json', frame], // two contexts
      ['--demo', 'kovorking-v', frame],
      ['--demo', 'nowhere:door_low', frame],
      ['--demo', 'kovorking-v:nothing', frame],
      ['--demo', door, '--now', 'tomorrow', frame],
      ['--demo', door], // no frame
      ['--context', join(folder, 'missing.json'), frame],
    ]) {
      expect((await run(verify, args)).code, args.join(' ').slice(0, 60)).toBe(64);
    }
  });
});

describe('umis demo', () => {
  it('prints a row for every decision and ends with 0 when all are as expected', async () => {
    const { code, out, err } = await run(demo, []);
    expect(code).toBe(0);
    expect(err).toBe('');
    const rows = out.split('\n').filter((line) => /^\d [A-Z]/.test(line));
    expect(rows).toHaveLength(5);
    expect(rows.map((row) => row.split(/\s{2,}/)[2])).toEqual(['accept', 'accept', 'reject', 'accept', 'accept']);
    expect(rows[2]).toContain('AUTHORITY_LIMIT_EXCEEDED');
    expect(out).toContain('5 results, all as the scenario expects');
  });

  it('runs the steps asked for and can print JSON or QR codes', async () => {
    const json = JSON.parse((await run(demo, ['--steps', '2', '--json'])).out) as {
      ok: boolean;
      results: Array<{ step: number; decision: string; reason: string; frame: string; asExpected: boolean }>;
    };
    expect(json.ok).toBe(true);
    expect(json.results.map((row) => [row.step, row.decision, row.reason, row.asExpected])).toEqual([
      [2, 'accept', 'OK', true],
      [2, 'reject', 'AUTHORITY_LIMIT_EXCEEDED', true],
    ]);
    expect(json.results.every((row) => row.frame.startsWith('UMIS1'))).toBe(true);

    const qr = await run(demo, ['--steps', '1', '--qr']);
    expect(qr.code).toBe(0);
    expect(qr.out).toMatch(/[▀▄█]/);
  });

  it('ends with 64 for steps it does not have', async () => {
    for (const steps of ['0', '4', 'x', '1,,2', '']) {
      expect((await run(demo, ['--steps', steps])).code, steps).toBe(64);
    }
    expect((await run(demo, ['--json', '--qr'])).code).toBe(64);
    expect((await run(demo, ['now'])).code).toBe(64);
  });
});

describe('umis keygen', () => {
  it('writes a private key readable by its owner only and prints nothing secret', async () => {
    const dir = join(folder, 'keys', 'station');
    const { code, out } = await run(keygen, ['--out', dir]);
    expect(code).toBe(0);

    const privateKey = JSON.parse(await readFile(join(dir, 'key.private.jwk.json'), 'utf8')) as EcPrivateJwk;
    const publicKey = JSON.parse(await readFile(join(dir, 'key.public.jwk.json'), 'utf8')) as EcPublicJwk;
    expect((await stat(join(dir, 'key.private.jwk.json'))).mode & 0o777).toBe(0o600);
    expect(Object.keys(publicKey).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y']);
    expect(privateKey).toMatchObject(publicKey);
    expect(privateKey.d).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // the output has the public key, the key id and the fingerprint, and nothing of the private key
    expect(out).not.toContain(privateKey.d);
    expect(out).toContain(JSON.stringify(publicKey));
    expect(out).toContain(`kid          ${publicKey.kid}`);
    expect(out).toMatch(/fingerprint {2}[A-Z2-7]{4}(-[A-Z2-7]{4}){3}/);

    // the two files are one pair: what the private key signs, the public key verifies
    const signer = await importSigner(privateKey);
    const token = await signJws({ header: { typ: 'test+jwt' }, payload: { hello: 'world' }, signer });
    await expect(verifyJws(token, { typ: 'test+jwt', key: publicKey })).resolves.toMatchObject({
      payload: { hello: 'world' },
    });
  });

  it('keeps the keys it wrote, and needs a directory', async () => {
    const dir = join(folder, 'keys', 'kept');
    expect((await run(keygen, ['--out', dir])).code).toBe(0);
    const before = await readFile(join(dir, 'key.private.jwk.json'), 'utf8');
    const again = await run(keygen, ['--out', dir]);
    expect(again.code).toBe(64);
    expect(again.err).toContain('exists already');
    expect(await readFile(join(dir, 'key.private.jwk.json'), 'utf8')).toBe(before);
    expect((await run(keygen, [])).code).toBe(64);
  });
});
