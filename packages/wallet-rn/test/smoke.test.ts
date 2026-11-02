import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';

describe('@umis/wallet-rn', () => {
  it('loads its built entry', () => {
    expect(entry).toBeTypeOf('object');
  });
});
