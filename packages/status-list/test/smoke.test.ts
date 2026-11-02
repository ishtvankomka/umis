import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';

describe('@umis/status-list', () => {
  it('loads its built entry', () => {
    expect(entry).toBeTypeOf('object');
  });
});
