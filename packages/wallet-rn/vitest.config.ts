import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const mock = (name: string): string => fileURLToPath(new URL(`./test/mocks/${name}.ts`, import.meta.url));

// Expo is a peer of the app, not installed here: the tests run against in-memory stand-ins of the three modules.
export default defineConfig({
  resolve: {
    alias: {
      'expo-secure-store': mock('expo-secure-store'),
      'expo-crypto': mock('expo-crypto'),
      '@animo-id/expo-secure-environment': mock('expo-secure-environment'),
    },
  },
  test: {
    name: '@umis/wallet-rn',
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
