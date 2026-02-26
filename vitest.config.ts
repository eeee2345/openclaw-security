import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.test.ts',
        '**/*.spec.ts',
        '**/types.ts',
        '**/*.d.ts',
      ],
    },
    include: ['packages/**/tests/**/*.test.ts', 'tests/**/*.test.ts', 'openclaw-fork/tests/**/*.test.ts'],
    exclude: ['**/node_modules/**', 'node_modules', 'dist'],
  },
  resolve: {
    alias: {
      '@openclaw/core': resolve(__dirname, './packages/core/src'),
      '@openclaw/panguard-scan': resolve(__dirname, './packages/panguard-scan/src'),
      '@openclaw/panguard-guard': resolve(__dirname, './packages/panguard-guard/src'),
      '@openclaw/panguard-chat': resolve(__dirname, './packages/panguard-chat/src'),
      '@openclaw/panguard-trap': resolve(__dirname, './packages/panguard-trap/src'),
      '@openclaw/panguard-report': resolve(__dirname, './packages/panguard-report/src'),
      '@openclaw/security-hardening': resolve(__dirname, './openclaw-fork/src'),
      '@openclaw/panguard-web': resolve(__dirname, './packages/panguard-web/src'),
      '@openclaw/panguard-auth': resolve(__dirname, './packages/panguard-auth/src'),
    },
  },
});
