// Writes the JSON Schema of the checkpoint policy to schema/, formatted like the rest of the repository, or with
// --check compares the committed file with the schema built from the code and fails when they differ.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { format, resolveConfig } from 'prettier';
import { checkpointPolicyJsonSchema } from '../src/schema.js';

const path = fileURLToPath(new URL('../schema/checkpoint-policy.v1.schema.json', import.meta.url));
const text = JSON.stringify(checkpointPolicyJsonSchema);

if (process.argv.includes('--check')) {
  let committed: unknown;
  try {
    committed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    committed = undefined;
  }
  if (!isDeepStrictEqual(committed, JSON.parse(text))) {
    console.error('schema/checkpoint-policy.v1.schema.json is out of date; run "pnpm schema:emit" in packages/policy');
    process.exit(1);
  }
  console.log('schema/checkpoint-policy.v1.schema.json is up to date');
} else {
  const options = await resolveConfig(path);
  writeFileSync(path, await format(text, { ...options, filepath: path }));
  console.log('wrote schema/checkpoint-policy.v1.schema.json');
}
