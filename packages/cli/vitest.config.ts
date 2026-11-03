import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@umis/cli',
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // the benchmark tests sign and verify hundreds of presentations: allow for a busy machine
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
