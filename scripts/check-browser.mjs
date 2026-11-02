#!/usr/bin/env node
// Verifies that the built entries of the browser-safe packages contain no Node built-in imports.
//
// Every entry is bundled in memory with Vite (library mode, browser resolve conditions). A plugin that runs before
// Vite's own resolver records each `node:` specifier and each bare Node built-in reachable from the entry,
// workspace packages and third-party code included.
//
//   node scripts/check-browser.mjs              check the real entries; exit 0 when clean, 1 otherwise
//   node scripts/check-browser.mjs --self-test  check scripts/fixtures/node-import.mjs, which must be rejected:
//                                               exit 1 = the checker works, exit 2 = the fixture slipped through

import { existsSync } from 'node:fs';
import { isBuiltin } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const BROWSER_SAFE_PACKAGES = [
  'core',
  'status-list',
  'policy',
  'registry',
  'issuer',
  'verifier',
  'wallet',
  'wallet-rn',
  'transports',
  'gateway',
];

const ENTRIES = [
  ...BROWSER_SAFE_PACKAGES.map((name) => `packages/${name}/dist/index.js`),
  'packages/core/dist/noble.js',
  'packages/verifier/dist/oid4vp.js',
  'packages/wallet/dist/oid4vp.js',
];

const FIXTURE = 'scripts/fixtures/node-import.mjs';

/** Bundles one entry and returns every Node built-in import found in its module graph. */
async function findNodeImports(entry) {
  const found = [];
  const guard = {
    name: 'umis:node-builtin-guard',
    enforce: 'pre',
    resolveId(source, importer) {
      if (source.startsWith('node:') || isBuiltin(source)) {
        found.push({ specifier: source, importer: importer ? path.relative(root, importer) : entry });
        return { id: source, external: true };
      }
      return null;
    },
  };
  await build({
    configFile: false,
    root,
    logLevel: 'silent',
    publicDir: false,
    resolve: { conditions: ['browser', 'module'] },
    plugins: [guard],
    build: {
      write: false,
      minify: false,
      target: 'es2022',
      reportCompressedSize: false,
      lib: { entry: path.join(root, entry), formats: ['es'], fileName: 'bundle' },
    },
  });
  return found;
}

function describe(found) {
  const unique = new Map();
  for (const { specifier, importer } of found) unique.set(`${specifier}\u0000${importer}`, { specifier, importer });
  return [...unique.values()].map(({ specifier, importer }) => `    imports ${specifier} (from ${importer})`);
}

async function selfTest() {
  const found = await findNodeImports(FIXTURE);
  const specifiers = new Set(found.map((item) => item.specifier));
  if (!specifiers.has('node:fs') || !specifiers.has('path')) {
    console.error(
      `check-browser self-test FAILED: ${FIXTURE} was not fully rejected (found: ${[...specifiers].join(', ') || 'nothing'})`,
    );
    return 2;
  }
  console.error(`check-browser self-test: ${FIXTURE} rejected as expected`);
  for (const line of describe(found)) console.error(line);
  return 1;
}

async function checkEntries() {
  let failures = 0;
  for (const entry of ENTRIES) {
    if (!existsSync(path.join(root, entry))) {
      console.error(`check-browser: ${entry} is missing; run "pnpm build" first`);
      failures += 1;
      continue;
    }
    try {
      const found = await findNodeImports(entry);
      if (found.length > 0) {
        console.error(`check-browser: ${entry}`);
        for (const line of describe(found)) console.error(line);
        failures += 1;
      }
    } catch (error) {
      console.error(`check-browser: ${entry} could not be bundled: ${error instanceof Error ? error.message : error}`);
      failures += 1;
    }
  }
  if (failures === 0) {
    console.log(`check-browser: ${ENTRIES.length} entries bundle without Node built-ins`);
    return 0;
  }
  console.error(`check-browser: ${failures} of ${ENTRIES.length} entries failed`);
  return 1;
}

process.exitCode = process.argv.includes('--self-test') ? await selfTest() : await checkEntries();
