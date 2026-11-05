import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';
import * as node from '../dist/node/index.js';

describe('@umis/gateway', () => {
  it('exposes its built entries: the browser-safe main entry and the Node entry', () => {
    // An intentional change of the exports must update this list in the same commit, together with its changeset.
    expect(Object.keys(entry).sort()).toEqual([
      'computeDigestResponse',
      'createGateway',
      'shellyRpcRelay',
      'shellySwitchSetBody',
      'signRelayCommand',
      'verifyRelayCommand',
    ]);
    expect(Object.keys(node).sort()).toEqual(['createFileJournal', 'startShellyEmulator']);
  });
});
