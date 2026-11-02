import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';

describe('@umis/wallet-rn', () => {
  it('loads its built entry and exports exactly the adapters', () => {
    expect(Object.keys(entry).sort()).toEqual([
      'createCredentialStore',
      'createKeyStore',
      'installRnPolyfills',
      'setupCrypto',
    ]);
  });
});
