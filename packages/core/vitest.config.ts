import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@umis/core',
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
