import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { defineConfig } from 'vitest/config';
import TestLoggerReporter from './tests/helpers/test-logger.reporter.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  resolve: {
    alias: {
      '@core': resolve(__dirname, './src/core'),
      '@api': resolve(__dirname, './src/api'),
      '@tests': resolve(__dirname, './tests'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    setupFiles: ['./tests/setup.ts'],
    fileParallelism: false, // Run test files sequentially to prevent database state collision and container teardown races
    testTimeout: 60000,
    hookTimeout: 60000,
    teardownTimeout: 10000,
    reporters: ['default', new TestLoggerReporter()],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/**',
        'dist/**',
        'tests/**',
        'prisma/**',
        'scripts/**',
        'tsup.config.ts',
        'prisma.config.ts',
        'eslint.config.js',
        'commitlint.config.js',
      ],
      thresholds: {
        lines: 90,
        branches: 90,
        functions: 90,
        statements: 90,
      },
    },
  },
});
