import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { gitState } from '../src/bench/env.js';

const CHECKOUT = fileURLToPath(new URL('../../..', import.meta.url));
const MANIFEST = join('packages', 'testkit', 'package.json');

/** Runs git in `folder` with an identity of its own, so that no test depends on the configuration of the machine. */
function git(folder: string, ...args: string[]): string {
  const identity = ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false'];
  return execFileSync('git', [...identity, ...args], {
    cwd: folder,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

describe('the git member of the environment record', () => {
  const folders: string[] = [];
  afterEach(async () => {
    for (const folder of folders.splice(0)) await rm(folder, { recursive: true, force: true });
  });

  /** A new work tree with one commit that holds `files`, given as paths and texts. */
  async function workTree(files: Record<string, string>): Promise<string> {
    const folder = await mkdtemp(join(tmpdir(), 'umis-env-git-'));
    folders.push(folder);
    git(folder, 'init', '-q');
    for (const [name, text] of Object.entries(files)) {
      await mkdir(dirname(join(folder, name)), { recursive: true });
      await writeFile(join(folder, name), text);
    }
    git(folder, 'add', '--all');
    git(folder, 'commit', '-q', '--allow-empty', '-m', 'one');
    return folder;
  }

  it.skipIf(!existsSync(join(CHECKOUT, '.git')))('gives the commit of this checkout', () => {
    const state = gitState();
    expect(state.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(typeof state.dirty).toBe('boolean');
  });

  it('records nothing of a work tree that is not this repository', async () => {
    const other = await workTree({ 'README.md': 'another project' });
    expect(gitState(other)).toEqual({ commit: null, dirty: null });
  });

  it('gives the commit of a work tree that holds packages/testkit, and whether tracked files changed', async () => {
    const tree = await workTree({ [MANIFEST]: '{"name":"@umis/testkit"}\n' });
    expect(gitState(tree)).toEqual({ commit: git(tree, 'rev-parse', 'HEAD'), dirty: false });

    await writeFile(join(tree, 'untracked.txt'), 'not counted');
    expect(gitState(tree).dirty).toBe(false);
    await writeFile(join(tree, MANIFEST), '{"name":"@umis/testkit","version":"1.0.0"}\n');
    expect(gitState(tree).dirty).toBe(true);
  });
});
