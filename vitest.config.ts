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
    include: [
      'packages/**/tests/**/*.test.ts',
      'tests/**/*.test.ts',
      'security-hardening/tests/**/*.test.ts',
    ],
    exclude: ['**/node_modules/**', 'node_modules', 'dist'],
  },
  resolve: {
    alias: {
      '@panguard-ai/core': resolve(__dirname, './packages/core/src'),
      '@panguard-ai/panguard-scan': resolve(__dirname, './packages/panguard-scan/src'),
      '@panguard-ai/panguard-guard': resolve(__dirname, './packages/panguard-guard/src'),
      '@panguard-ai/panguard-chat': resolve(__dirname, './packages/panguard-chat/src'),
      '@panguard-ai/panguard-trap': resolve(__dirname, './packages/panguard-trap/src'),
      '@panguard-ai/panguard-report': resolve(__dirname, './packages/panguard-report/src'),
      '@panguard-ai/security-hardening': resolve(__dirname, './security-hardening/src'),
      '@panguard-ai/panguard-web': resolve(__dirname, './packages/panguard-web/src'),
      '@panguard-ai/panguard-auth': resolve(__dirname, './packages/panguard-auth/src'),
    },
  },
});
