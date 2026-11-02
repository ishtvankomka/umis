import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';
import * as oid4vp from '../dist/oid4vp.js';

describe('@umis/wallet', () => {
  it('exports exactly the public functions from its built entry, and its OpenID4VP entry loads', () => {
    expect(Object.keys(entry).sort()).toEqual([
      'createFullFrame',
      'createFullQr',
      'createOneWayQr',
      'createResponseFrame',
      'createResponseQr',
      'decodeCredential',
      'disclosurePlan',
      'parseRequestQr',
      'redeemOffer',
      'resolveOffer',
    ]);
    expect(oid4vp).toBeTypeOf('object');
  });
});
