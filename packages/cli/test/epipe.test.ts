import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const BIN = fileURLToPath(new URL('../dist/bin.js', import.meta.url));

describe('umis: a reader that stops reading', () => {
  it('ends with exit code 0 and no stack trace when its standard output is closed early', async () => {
    if (!existsSync(BIN)) throw new Error('dist/bin.js is missing: run pnpm build first');
    const child = spawn(process.execPath, [BIN, 'demo', '--qr'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    // like `| head -2`: take the first chunk, then close the pipe while the QR codes are still being written
    child.stdout.once('data', () => child.stdout.destroy());
    const status = await new Promise<number | null>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code) => resolve(code));
    });
    expect(stderr).not.toContain('EPIPE');
    expect(stderr).not.toMatch(/^\s+at /m);
    expect(status).toBe(0);
  }, 30_000);
});
