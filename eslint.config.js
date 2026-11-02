import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import prettier from 'eslint-config-prettier';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// Packages whose sources run in browsers and in React Native. They never import Node built-ins and never use
// Node globals. Lint enforces it on the sources, `pnpm check:browser` on the built bundles.
const BROWSER_SAFE_PACKAGES = [
  'core',
  'status-list',
  'policy',
  'registry',
  'issuer',
  'verifier',
  'wallet',
  'wallet-rn',
  'transports',
  'gateway',
];

const NODE_BUILTINS = [
  'fs',
  'path',
  'os',
  'crypto',
  'buffer',
  'zlib',
  'stream',
  'util',
  'url',
  'http',
  'https',
  'net',
  'tls',
  'child_process',
  'worker_threads',
  'events',
];

const NODE_GLOBALS = [
  'Buffer',
  'process',
  'require',
  '__dirname',
  '__filename',
  'global',
  'setImmediate',
  'URL',
  'URLSearchParams',
];

const importMessage =
  'Browser-safe packages must not import Node built-ins. Use WebCrypto, TextEncoder and other web APIs.';
const globalMessage = 'Not available in every runtime the browser-safe packages target (browsers, React Native).';

export default defineConfig([
  globalIgnores(['**/dist/**', '**/node_modules/**', '**/.turbo/**', '**/coverage/**', 'docs/api/**']),
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
    },
  },
  {
    files: ['packages/*/src/**/*.ts'],
    rules: { '@typescript-eslint/no-explicit-any': 'error' },
  },
  {
    files: ['packages/*/test/**/*.ts'],
    rules: { '@typescript-eslint/no-explicit-any': 'off' },
  },
  {
    files: BROWSER_SAFE_PACKAGES.map((name) => `packages/${name}/src/**/*.ts`),
    ignores: ['packages/gateway/src/node/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            { regex: '^node:', message: importMessage },
            { regex: `^(${NODE_BUILTINS.join('|')})(/|$)`, message: importMessage },
          ],
        },
      ],
      'no-restricted-globals': ['error', ...NODE_GLOBALS.map((name) => ({ name, message: globalMessage }))],
    },
  },
  {
    files: ['**/*.{js,mjs,cjs}'],
    languageOptions: { globals: globals.node },
  },
  prettier,
]);
