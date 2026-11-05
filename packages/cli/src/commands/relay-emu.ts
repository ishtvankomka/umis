import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { UmisError, asEcPublicJwk, keyFingerprint } from '@umis/core';
import type { EcPublicJwk } from '@umis/core';
import { startShellyEmulator } from '@umis/gateway/node';
import type { RelayEmulator } from '@umis/gateway/node';
import { UsageError } from './common.js';
import type { CommandIo } from './common.js';

export const RELAY_EMU_USAGE = `usage: umis relay-emu --trust <file> [options]

Runs an emulator of a Shelly Gen3 relay that opens only for relay commands signed by a trusted key.

options:
  --port <n>                    port to listen on (default 8089; 0 picks a free one)
  --host <address>              address to listen on (default 127.0.0.1)
  --trust <file>                public key of a station: a JWK, a JWKS or an array of JWKs; repeat for more files
  --cors <origin>[,<origin>]    browser origins that may call the emulator, e.g. https://admin.example.com
                                (repeat the option or separate origins with commas)
  --aud <id>                    relay identity a command may name; repeat for more (replaces the defaults)
  --digest-password-env <NAME>  name of the environment variable that holds the Shelly digest password
  --no-signature                accept Switch.Set without a signature (for a closed test network only)
  -h, --help                    show this text

The status page is served at / and the JSON-RPC endpoint at POST /rpc.

Only Switch.Set needs the signed command and, with --digest-password-env, the digest. Switch.GetStatus and
Shelly.GetDeviceInfo answer without either, so that the status page can poll the switch without credentials; neither
changes the switch. A real Shelly with authentication enabled asks for the digest on its status calls too.`;

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const DEFAULT_PORT = 8089;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Reads the public keys of a trust file: a JWK, a JWKS (`{"keys": [...]}`) or an array of JWKs. */
async function readTrustFile(file: string, io: CommandIo): Promise<EcPublicJwk[]> {
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    throw new UsageError(`cannot read the trust file ${file}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new UsageError(`${file} is not JSON`);
  }
  const list: unknown[] = Array.isArray(parsed)
    ? parsed
    : isRecord(parsed) && Array.isArray(parsed.keys)
      ? parsed.keys
      : [parsed];
  if (list.length === 0) throw new UsageError(`${file} holds no key`);
  if (list.some((key) => isRecord(key) && Object.hasOwn(key, 'd'))) {
    io.err(`warning: ${file} holds a private key; only its public part is used`);
  }
  try {
    return list.map((key) => asEcPublicJwk(key));
  } catch (error) {
    throw new UsageError(`${file}: ${error instanceof Error ? error.message : 'not a P-256 public key'}`);
  }
}

function portOf(text: string | undefined): number {
  const port = text === undefined ? DEFAULT_PORT : Number(text);
  if (!Number.isInteger(port) || port < 0 || port > 65_535)
    throw new UsageError('--port must be an integer from 0 to 65535');
  return port;
}

/**
 * `umis relay-emu`: starts the relay emulator, prints its address and then one line for every command it obeys
 * (`OPEN 3 s · jti … · iss …`) or refuses (`401 <reason>`), until `signal` is aborted. Returns the exit code: 0 after
 * a normal stop, 64 for a mistake in the arguments or the trust files, 1 when the emulator cannot start.
 */
export async function relayEmu(args: readonly string[], io: CommandIo, signal: AbortSignal): Promise<number> {
  let emulator: RelayEmulator | undefined;
  try {
    const { values } = parseArgs({
      args: [...args],
      allowPositionals: false,
      strict: true,
      options: {
        port: { type: 'string' },
        host: { type: 'string' },
        trust: { type: 'string', multiple: true },
        cors: { type: 'string', multiple: true },
        aud: { type: 'string', multiple: true },
        'digest-password-env': { type: 'string' },
        'no-signature': { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
    });
    if (values.help === true) {
      io.out(RELAY_EMU_USAGE);
      return 0;
    }

    const requireSignature = values['no-signature'] !== true;
    const files = values.trust ?? [];
    if (requireSignature && files.length === 0) throw new UsageError('--trust <file> is required (or --no-signature)');
    const digestEnv = values['digest-password-env'];
    if (digestEnv !== undefined && !ENV_NAME.test(digestEnv)) {
      throw new UsageError('--digest-password-env takes the NAME of an environment variable');
    }
    const keys: EcPublicJwk[] = [];
    for (const file of files) keys.push(...(await readTrustFile(file, io)));
    const cors = (values.cors ?? [])
      .flatMap((entry) => entry.split(','))
      .map((origin) => origin.trim())
      .filter((origin) => origin !== '');
    const audiences = values.aud;
    const port = portOf(values.port);

    try {
      emulator = await startShellyEmulator({
        port,
        host: values.host,
        trust: keys,
        audiences,
        cors,
        requireSignature,
        digestPasswordEnv: digestEnv,
        now: () => Date.now() / 1000,
        log: (line) => io.out(line),
      });
    } catch (error) {
      if (error instanceof UmisError && error.code === 'INVALID_ARGUMENT') throw new UsageError(error.message);
      throw error;
    }

    io.out(`umis relay-emu listening on ${emulator.url}`);
    io.out(`  status page  ${emulator.url}/`);
    io.out(`  rpc          POST ${emulator.url}/rpc`);
    io.out(
      requireSignature
        ? `  trusted keys ${keys.length} (fingerprint ${await keyFingerprint(keys)})`
        : '  trusted keys none: signatures are not checked',
    );
    io.out(
      `  audiences    ${audiences === undefined ? "urn:umis:relay:emu and this server's own addresses" : audiences.join(', ')}`,
    );
    if (cors.length > 0) io.out(`  cors         ${cors.join(', ')}`);
    if (digestEnv !== undefined) io.out(`  digest auth  on, password from ${digestEnv}`);
    if (!requireSignature) {
      io.err('warning: --no-signature: Switch.Set is obeyed without a signature; use it on a closed network only');
    }

    if (!signal.aborted)
      await new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }));
    await emulator.close();
    return 0;
  } catch (error) {
    await emulator?.close().catch(() => undefined);
    if (
      error instanceof UsageError ||
      (error instanceof TypeError && 'code' in error && String(error.code).startsWith('ERR_PARSE_ARGS'))
    ) {
      io.err(`umis relay-emu: ${error.message}`);
      io.err('run "umis relay-emu --help" for the options');
      return 64;
    }
    io.err(`umis relay-emu: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}
