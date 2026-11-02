import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: '@umis/wallet-rn',
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
