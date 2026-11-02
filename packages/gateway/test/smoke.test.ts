import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';
import * as node from '../dist/node/index.js';

describe('@umis/gateway', () => {
  it('loads its built entry', () => {
    expect(entry).toBeTypeOf('object');
    expect(node).toBeTypeOf('object');
  });
});
