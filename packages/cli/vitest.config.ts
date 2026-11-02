import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@umis/cli',
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
