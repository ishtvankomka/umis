import { mkdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { asEcPublicJwk, jwkThumbprint, keyFingerprint } from '@umis/core';
import type { EcPublicJwk } from '@umis/core';
import { EXIT, UsageError, runCommand } from './common.js';
import type { CommandIo } from './common.js';

export const KEYGEN_USAGE = `usage: umis keygen --out <dir>

Makes a P-256 signing key pair. Writes the private key to <dir>/key.private.jwk.json (readable by you only, mode 0600) and
the public key to <dir>/key.public.jwk.json, and prints the public key, its key id and its fingerprint. The private key
is never printed. Existing key files are not overwritten.

The public file is what a station gives to "umis relay-emu --trust" and to a registry.

options:
  --out <dir>  directory for the two files; it is created when it does not exist
  -h, --help   show this text

Exit code 0 on success, 64 for a mistake in the arguments, 1 when the files cannot be written.`;

const PRIVATE_FILE = 'key.private.jwk.json';
const PUBLIC_FILE = 'key.public.jwk.json';

async function exists(file: string): Promise<boolean> {
  try {
    await stat(file);
    return true;
  } catch {
    return false;
  }
}

/** A new key pair from the WebCrypto of the runtime: the public JWK with its thumbprint as `kid`, and the private member `d`. */
async function newKey(): Promise<{ publicJwk: EcPublicJwk; d: string }> {
  const pair = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const exported = await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey);
  if (typeof exported.d !== 'string') throw new Error('the key pair has no private part');
  const bare = asEcPublicJwk(exported);
  const publicJwk: EcPublicJwk = { ...bare, kid: await jwkThumbprint(bare), alg: 'ES256', use: 'sig' };
  return { publicJwk, d: exported.d };
}

/**
 * `umis keygen`: writes a fresh P-256 key pair into a directory and prints only the public key, its id and its
 * fingerprint. Returns 0 on success, 64 for a mistake in the arguments or when a key file is already there.
 */
export async function keygen(args: readonly string[], io: CommandIo): Promise<number> {
  return runCommand('keygen', io, async () => {
    const { values } = parseArgs({
      args: [...args],
      allowPositionals: false,
      strict: true,
      options: { out: { type: 'string' }, help: { type: 'boolean', short: 'h' } },
    });
    if (values.help === true) {
      io.out(KEYGEN_USAGE);
      return EXIT.ok;
    }
    if (values.out === undefined || values.out === '') throw new UsageError('--out <dir> is required');
    const privatePath = join(values.out, PRIVATE_FILE);
    const publicPath = join(values.out, PUBLIC_FILE);
    for (const path of [privatePath, publicPath]) {
      if (await exists(path)) throw new UsageError(`${path} exists already; remove it or choose another directory`);
    }

    const { publicJwk, d } = await newKey();
    await mkdir(values.out, { recursive: true, mode: 0o700 });
    // 'wx' fails rather than overwrite, and the private file is created readable by its owner only
    await writeFile(privatePath, `${JSON.stringify({ ...publicJwk, d }, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    await writeFile(publicPath, `${JSON.stringify(publicJwk, null, 2)}\n`, { flag: 'wx', mode: 0o644 });

    io.out(`public key   ${JSON.stringify(publicJwk)}`);
    io.out(`kid          ${publicJwk.kid}`);
    io.out(`fingerprint  ${await keyFingerprint([publicJwk])}`);
    io.out(`wrote        ${publicPath}`);
    io.out(`             ${privatePath} (mode 0600, keep it secret)`);
    return EXIT.ok;
  });
}
