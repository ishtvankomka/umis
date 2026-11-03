// Links the built `umis` command into this package's own node_modules/.bin, which pnpm does not do for the bin of the
// package itself, so that `pnpm -F cli exec umis demo` works in a clone after `pnpm build`. Installing the package
// from a registry links its bin as usual. The link is a declared output of the build task (turbo.json in this
// package), so a cached build restores it together with dist. A failure here only costs that convenience, so it never
// fails the build.
import { chmod, mkdir, rm, symlink } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const target = join(root, 'dist', 'bin.js');
const folder = join(root, 'node_modules', '.bin');
const link = join(folder, 'umis');

try {
  await chmod(target, 0o755);
  await mkdir(folder, { recursive: true });
  await rm(link, { force: true });
  await symlink(relative(folder, target), link);
} catch (error) {
  console.warn(
    `umis: the command is not linked into node_modules/.bin (${error instanceof Error ? error.message : error})`,
  );
}
