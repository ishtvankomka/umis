import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@umis/registry',
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
