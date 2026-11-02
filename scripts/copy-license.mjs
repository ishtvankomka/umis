#!/usr/bin/env node
// Copies the repository LICENSE and NOTICE into the package that is being packed.
// Runs from each package's `prepack` script, so the working directory is the package directory.

import { copyFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = path.resolve(process.cwd());

if (target === root) {
  console.error('copy-license: run this from a package directory (it is meant for the "prepack" script)');
  process.exit(1);
}

for (const name of ['LICENSE', 'NOTICE']) {
  copyFileSync(path.join(root, name), path.join(target, name));
}
