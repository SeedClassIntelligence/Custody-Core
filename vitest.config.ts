import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    globalSetup: ['tests/globalSetup.ts'],
    setupFiles: ['tests/setupEnv.ts'],
    // All files share one throwaway database.
    fileParallelism: false,
    testTimeout: 30000,
    hookTimeout: 120000
  }
});
