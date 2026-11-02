import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';
import * as noble from '../dist/noble.js';

describe('@umis/core', () => {
  it('loads its built entry', () => {
    expect(entry).toBeTypeOf('object');
    expect(noble).toBeTypeOf('object');
  });
});
