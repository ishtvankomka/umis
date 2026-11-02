import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';
import * as oid4vp from '../dist/oid4vp.js';

describe('@umis/verifier', () => {
  it('loads its built entry', () => {
    expect(entry).toBeTypeOf('object');
    expect(oid4vp).toBeTypeOf('object');
  });
});
