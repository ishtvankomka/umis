// Deliberately imports a Node built-in next to a peer dependency. The package.json in this folder declares
// `peer-example` as a peer, so the checker leaves it out of the module graph, while `node:fs` must still be rejected.
// `node scripts/check-browser.mjs --self-test` must report `node:fs` for this file and nothing else.
import { readFileSync } from 'node:fs';
import { peer } from 'peer-example';

export const read = (name) => peer(readFileSync(name, 'utf8'));
