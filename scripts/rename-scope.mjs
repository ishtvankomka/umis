#!/usr/bin/env node
// Renames the npm scope everywhere in one pass.
//
//   pnpm rename-scope @new [--dry-run]
//
// Rewrites workspace package names and dependency keys, import specifiers (*.ts, *.mts, *.mjs and the like), *.md,
// llms*.txt, workflow files, .changeset/*.json and typedoc.json, and finally scope.config.json, which is the only place
// the scope is configured. With --dry-run it lists the files that would change and writes nothing. pnpm-lock.yaml is
// left alone: run `pnpm install` afterwards to refresh it.

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCOPE_PATTERN = /^@[a-z0-9~][a-z0-9._~-]*$/;
const SKIPPED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  '.turbo',
  'coverage',
  '.pnpm-store',
  'bench-results',
  '.tmp',
]);
const SKIPPED_PATHS = new Set(['scripts', 'docs/api']);
const CONFIG_FILE = 'scope.config.json';

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const positional = args.filter((arg) => !arg.startsWith('--'));
const unknownFlags = args.filter((arg) => arg.startsWith('--') && arg !== '--dry-run');

function fail(message) {
  console.error(`rename-scope: ${message}`);
  console.error('usage: pnpm rename-scope @new-scope [--dry-run]');
  process.exit(1);
}

if (unknownFlags.length > 0) fail(`unknown option ${unknownFlags.join(' ')}`);
if (positional.length !== 1) fail('expected exactly one new scope');
const newScope = positional[0];
if (!SCOPE_PATTERN.test(newScope))
  fail(`"${newScope}" is not a valid npm scope (lowercase letters, digits, "-", "_", ".", "~")`);

const config = JSON.parse(readFileSync(path.join(root, CONFIG_FILE), 'utf8'));
const oldScope = config.scope;
if (typeof oldScope !== 'string' || !SCOPE_PATTERN.test(oldScope)) fail(`${CONFIG_FILE} has no valid "scope"`);
if (newScope === oldScope) fail(`the scope is already ${oldScope}`);

const escaped = oldScope.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// `@umis-platform` and `name@umis.systems` are not the scope: a lookbehind rules out a leading word character and the
// lookaheads rule out "-" or ".word" after it. Code and JSON only carry the `@scope/name` form; prose may name the scope.
const SLASH_FORM = new RegExp(`(?<![\\w@])${escaped}(?=/)`, 'g');
const PROSE_FORM = new RegExp(`(?<![\\w@])${escaped}(?![\\w~-]|\\.\\w)`, 'g');

function kindOf(rel) {
  const base = path.posix.basename(rel);
  if (rel === CONFIG_FILE) return null;
  if (/\.(?:[cm]?[jt]s|tsx)$/.test(base)) return 'code';
  if (/\.(?:md|mdx)$/.test(base) || /^llms.*\.txt$/.test(base)) return 'prose';
  if (/\.ya?ml$/.test(base) && base !== 'pnpm-lock.yaml') return 'code';
  if (base === 'package.json' || base === 'typedoc.json' || (rel.startsWith('.changeset/') && base.endsWith('.json'))) {
    return 'code';
  }
  return null;
}

function* walk(dir, rel = '') {
  for (const entry of readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const child = rel === '' ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name) && !SKIPPED_PATHS.has(child)) yield* walk(dir, child);
    } else if (entry.isFile()) {
      yield child;
    }
  }
}

const changes = [];
for (const rel of walk(root)) {
  const kind = kindOf(rel);
  if (kind === null) continue;
  const file = path.join(root, rel);
  const before = readFileSync(file, 'utf8');
  const after = before.replace(kind === 'prose' ? PROSE_FORM : SLASH_FORM, () => newScope);
  if (after !== before) {
    changes.push(rel);
    if (!dryRun) writeFileSync(file, after);
  }
}

// scope.config.json goes last, so an interrupted run can simply be started again.
changes.push(CONFIG_FILE);
if (!dryRun) {
  writeFileSync(path.join(root, CONFIG_FILE), `${JSON.stringify({ ...config, scope: newScope }, null, 2)}\n`);
}

console.log(`rename-scope: ${oldScope} -> ${newScope}${dryRun ? ' (dry run)' : ''}`);
for (const rel of changes) console.log(`  ${dryRun ? 'would change' : 'changed'} ${rel}`);
console.log(
  dryRun
    ? `rename-scope: ${changes.length} files would change; nothing was written`
    : `rename-scope: ${changes.length} files changed; run "pnpm install" to refresh pnpm-lock.yaml`,
);
