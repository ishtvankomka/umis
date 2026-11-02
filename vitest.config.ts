import { defineConfig } from 'vitest/config';

// Runs every package's tests from the repository root; packages also carry their own config.
export default defineConfig({
  test: {
    projects: ['packages/*'],
  },
});
