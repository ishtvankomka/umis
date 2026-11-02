import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@umis/policy',
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
