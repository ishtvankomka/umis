import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import * as entry from '../dist/index.js';

describe('@umis/cli', () => {
  it('loads its built entry', () => {
    expect(entry).toBeTypeOf('object');
    const bin = readFileSync(new URL('../dist/bin.js', import.meta.url), 'utf8');
    expect(bin.startsWith('#!/usr/bin/env node')).toBe(true);
  });
});
