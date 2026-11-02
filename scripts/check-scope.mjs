#!/usr/bin/env node
// Fails when a workspace package, a workspace dependency or an import of a workspace package uses a scope other than
// the one configured in scope.config.json. A repository that was only partly renamed is caught here.
//
//   node scripts/check-scope.mjs              check this repository; exit 0 when clean, 1 otherwise
//   node scripts/check-scope.mjs --self-test  check two built-in workspaces, one correct and one with stale scopes;
//                                             exit 1 = the checker works, exit 2 = it does not

import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const DEPENDENCY_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
const SOURCE_FILE = /\.(?:[cm]?[jt]s|tsx)$/;
const SKIPPED_DIRS = new Set(['node_modules', 'dist', '.turbo', 'coverage', '.git']);
const SCOPE_PATTERN = /^@[a-z0-9~][a-z0-9._~-]*$/;
// from '@x/y' · import('@x/y') · import '@x/y' · require('@x/y')
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)(['"])(@[^'"\s]+)\1/g;

const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name)) yield* walk(path.join(dir, entry.name));
    } else if (entry.isFile()) {
      yield path.join(dir, entry.name);
    }
  }
}

/** Reads the `packages:` list of pnpm-workspace.yaml; only `dir/*` globs are used in this repository. */
function workspaceGlobs(root) {
  const globs = [];
  let inPackages = false;
  for (const line of readFileSync(path.join(root, 'pnpm-workspace.yaml'), 'utf8').split('\n')) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
    } else if (inPackages) {
      const item = line.match(/^\s+-\s+['"]?([^'"#\s]+)['"]?\s*(?:#.*)?$/);
      if (item) globs.push(item[1]);
      else if (line.trim() !== '' && !line.trim().startsWith('#')) inPackages = false;
    }
  }
  return globs;
}

function workspacePackages(root) {
  const packages = [];
  for (const glob of workspaceGlobs(root)) {
    if (!glob.endsWith('/*')) continue;
    const group = glob.slice(0, -2);
    const groupDir = path.join(root, group);
    if (!existsSync(groupDir)) continue;
    for (const entry of readdirSync(groupDir, { withFileTypes: true })) {
      const manifestFile = path.join(groupDir, entry.name, 'package.json');
      if (entry.isDirectory() && existsSync(manifestFile)) {
        packages.push({ group, folder: entry.name, rel: `${group}/${entry.name}`, manifest: readJson(manifestFile) });
      }
    }
  }
  return packages;
}

/** Returns a list of human-readable problems; empty when the repository uses the configured scope everywhere. */
function checkScope(root) {
  const { scope } = readJson(path.join(root, 'scope.config.json'));
  if (typeof scope !== 'string' || !SCOPE_PATTERN.test(scope)) {
    return ['scope.config.json: "scope" must look like @name'];
  }
  const problems = [];
  const packages = workspacePackages(root);
  const names = new Set(packages.map((item) => item.manifest.name));
  const folders = new Set(packages.map((item) => item.folder));
  const manifests = [
    { rel: 'package.json', manifest: readJson(path.join(root, 'package.json')) },
    ...packages.map((item) => ({ rel: `${item.rel}/package.json`, manifest: item.manifest })),
  ];

  // third-party packages declared anywhere (they may share a folder name with a workspace package, e.g. @sd-jwt/core)
  const external = new Set();
  for (const { manifest } of manifests) {
    for (const field of DEPENDENCY_FIELDS) {
      for (const [name, range] of Object.entries(manifest[field] ?? {})) {
        if (!String(range).startsWith('workspace:')) external.add(name);
      }
    }
  }

  for (const item of packages) {
    const name = item.manifest.name;
    if (item.group === 'packages') {
      if (name !== `${scope}/${item.folder}`) {
        problems.push(`${item.rel}/package.json: name "${name}" must be "${scope}/${item.folder}"`);
      }
    } else if (typeof name === 'string' && name.startsWith('@') && !name.startsWith(`${scope}/`)) {
      problems.push(`${item.rel}/package.json: name "${name}" uses a scope other than ${scope}`);
    }
  }

  for (const { rel, manifest } of manifests) {
    for (const field of DEPENDENCY_FIELDS) {
      for (const [name, range] of Object.entries(manifest[field] ?? {})) {
        if (String(range).startsWith('workspace:') && !names.has(name)) {
          problems.push(`${rel}: ${field} "${name}" is a workspace reference but no workspace package has that name`);
        }
      }
    }
  }

  for (const item of packages) {
    for (const file of walk(path.join(root, item.rel))) {
      if (!SOURCE_FILE.test(file)) continue;
      const text = readFileSync(file, 'utf8');
      for (const match of text.matchAll(SPECIFIER)) {
        const specifier = match[2];
        const [specifierScope, base] = specifier.split('/');
        if (base === undefined || specifierScope === scope) continue;
        if (folders.has(base) && !external.has(`${specifierScope}/${base}`)) {
          const line = text.slice(0, match.index).split('\n').length;
          problems.push(
            `${path.relative(root, file)}:${line}: import "${specifier}" uses scope ${specifierScope}, configured scope is ${scope}`,
          );
        }
      }
    }
  }

  const changesetConfig = path.join(root, '.changeset', 'config.json');
  if (existsSync(changesetConfig)) {
    const config = readJson(changesetConfig);
    for (const key of ['fixed', 'linked']) {
      for (const group of config[key] ?? []) {
        for (const pattern of group) {
          if (!pattern.startsWith(`${scope}/`)) {
            problems.push(`.changeset/config.json: ${key} entry "${pattern}" is outside ${scope}`);
          }
        }
      }
    }
  }
  return problems;
}

function writeTree(root, files) {
  for (const [rel, content] of Object.entries(files)) {
    const file = path.join(root, rel);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, typeof content === 'string' ? content : `${JSON.stringify(content, null, 2)}\n`);
  }
}

/** A tiny workspace; `stale` is the scope that a half-renamed repository would still carry. */
function fixtureTree(stale) {
  const scope = '@fx';
  const verifierScope = stale ?? scope;
  return {
    'scope.config.json': { scope, repo: 'example/fixture' },
    'package.json': { name: 'fixture', private: true },
    'pnpm-workspace.yaml': 'packages:\n  - packages/*\n',
    '.changeset/config.json': { fixed: [[`${verifierScope}/*`]] },
    'packages/core/package.json': { name: `${scope}/core`, dependencies: { '@sd-jwt/core': '1.0.0' } },
    'packages/core/src/index.ts': "import { x } from '@sd-jwt/core';\nexport { x };\n",
    'packages/verifier/package.json': {
      name: `${verifierScope}/verifier`,
      dependencies: { [`${verifierScope}/core`]: 'workspace:*' },
    },
    'packages/verifier/src/index.ts': `import { a } from '${verifierScope}/core';\nexport { a };\n`,
  };
}

function selfTest() {
  const dir = mkdtempSync(path.join(tmpdir(), 'umis-check-scope-'));
  try {
    const good = path.join(dir, 'good');
    const bad = path.join(dir, 'bad');
    writeTree(good, fixtureTree(undefined));
    writeTree(bad, fixtureTree('@old'));
    const goodProblems = checkScope(good);
    const badProblems = checkScope(bad);
    const expected = [/name "@old\/verifier"/, /workspace reference/, /import "@old\/core"/, /fixed entry "@old\/\*"/];
    const missing = expected.filter((pattern) => !badProblems.some((problem) => pattern.test(problem)));
    const falsePositive = [...goodProblems, ...badProblems].find((problem) => problem.includes('@sd-jwt'));
    if (goodProblems.length > 0 || missing.length > 0 || falsePositive) {
      console.error('check-scope self-test FAILED');
      for (const problem of goodProblems) console.error(`  unexpected on the correct workspace: ${problem}`);
      for (const pattern of missing) console.error(`  not reported on the stale workspace: ${pattern}`);
      if (falsePositive) console.error(`  third-party package flagged: ${falsePositive}`);
      return 2;
    }
    console.error('check-scope self-test: stale scopes rejected as expected, correct workspace accepted');
    for (const problem of badProblems) console.error(`  ${problem}`);
    return 1;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function main() {
  const problems = checkScope(repoRoot);
  if (problems.length === 0) {
    const { scope } = readJson(path.join(repoRoot, 'scope.config.json'));
    console.log(`check-scope: every workspace package, dependency and import uses ${scope}`);
    return 0;
  }
  for (const problem of problems) console.error(`check-scope: ${problem}`);
  console.error(`check-scope: ${problems.length} problem(s)`);
  return 1;
}

try {
  process.exitCode = process.argv.includes('--self-test') ? selfTest() : main();
} catch (error) {
  console.error(`check-scope: ${error instanceof Error ? error.message : error}`);
  process.exitCode = 1;
}
