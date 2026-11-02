import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@umis/testkit',
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
