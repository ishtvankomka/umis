// Deliberately imports Node built-ins. `node scripts/check-browser.mjs --self-test` must reject this file.
import { readFileSync } from 'node:fs';
import { join } from 'path';

export const read = (dir, name) => readFileSync(join(dir, name), 'utf8');
