import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';

describe('@umis/policy', () => {
  it('loads its built entry', () => {
    expect(entry).toBeTypeOf('object');
  });
});
