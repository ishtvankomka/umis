import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { arch, cpus, loadavg, platform, release, totalmem, type as osType } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The packages a benchmark exercises; their versions go into the record of the run. */
const MEASURED_PACKAGES = [
  '@umis/core',
  '@umis/status-list',
  '@umis/policy',
  '@umis/registry',
  '@umis/issuer',
  '@umis/verifier',
  '@umis/wallet',
  '@umis/gateway',
] as const;

const HERE = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

/** What a run is told to do; the output paths are left out, because they say nothing about the measurement. */
export interface RecordedOptions {
  scenarios: readonly string[];
  n: number;
  repeats: number;
  warmup: number;
  crypto: string;
  seed: string;
}

/** The machine, the runtime, the code and the options of a run: what a table of results is read against. */
export interface BenchEnvironment {
  v: 1;
  /** When the run started, for the record; no decision of the benchmark depends on it. */
  generatedAt: string;
  node: { version: string; v8: string };
  os: { type: string; release: string; platform: string; arch: string };
  cpu: { model: string; cores: number };
  memoryBytes: number;
  /** The load average of the machine when the run started: 1, 5 and 15 minutes. */
  loadAverage: [number, number, number];
  /** The crypto provider that signed and verified. */
  crypto: string;
  /** The commit the code is at, and whether tracked files differ from it; null outside a git work tree. */
  git: { commit: string | null; dirty: boolean | null };
  packages: Record<string, string | null>;
  options: RecordedOptions;
}

function git(args: string[]): string | null {
  try {
    const out = execFileSync('git', args, {
      cwd: HERE,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10_000,
    });
    return out.trim();
  } catch {
    return null;
  }
}

function manifestVersion(file: string, name: string): string | null | undefined {
  if (!existsSync(file)) return undefined;
  const manifest = JSON.parse(readFileSync(file, 'utf8')) as { name?: unknown; version?: unknown };
  if (manifest.name !== name) return undefined;
  return typeof manifest.version === 'string' ? manifest.version : null;
}

/** The version in the package.json of an installed package, found from the file its entry point resolves to. */
function versionOf(name: string): string | null {
  try {
    let folder = dirname(require.resolve(name));
    for (let up = 0; up < 5; up++) {
      const found = manifestVersion(join(folder, 'package.json'), name);
      if (found !== undefined) return found;
      folder = dirname(folder);
    }
  } catch {
    // not installed or not built: the record says so with null
  }
  return null;
}

/** Describes the machine and the code the benchmark runs on. Nothing from the environment variables is read. */
export function describeEnvironment(options: RecordedOptions, crypto: string): BenchEnvironment {
  const commit = git(['rev-parse', 'HEAD']);
  const changes = commit === null ? null : git(['status', '--porcelain', '--untracked-files=no']);
  const [one = 0, five = 0, fifteen = 0] = loadavg();
  const packages: Record<string, string | null> = {};
  for (const name of MEASURED_PACKAGES) packages[name] = versionOf(name);
  packages['@umis/testkit'] = manifestVersion(join(HERE, '..', '..', 'package.json'), '@umis/testkit') ?? null;

  return {
    v: 1,
    generatedAt: new Date().toISOString(),
    node: { version: process.version, v8: process.versions.v8 },
    os: { type: osType(), release: release(), platform: platform(), arch: arch() },
    cpu: { model: cpus()[0]?.model ?? 'unknown', cores: cpus().length },
    memoryBytes: totalmem(),
    loadAverage: [one, five, fifteen],
    crypto,
    git: { commit, dirty: changes === null ? null : changes !== '' },
    packages,
    options: { ...options, scenarios: [...options.scenarios] },
  };
}
