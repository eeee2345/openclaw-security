/**
 * SAST checker module unit tests
 *
 * Tests the checkSourceCode function. Built-in regex patterns have been removed;
 * SAST now requires Semgrep. Without Semgrep, checkSourceCode returns [].
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

vi.mock('@panguard-ai/core', async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    createLogger: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  };
});

import { checkSourceCode } from '../src/scanners/sast-checker.js';

async function createTempDir(files: Record<string, string>): Promise<string> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'panguard-sast-test-'));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(tmpDir, relPath);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, content, 'utf-8');
  }
  return tmpDir;
}

async function removeTempDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('sast-checker.ts - checkSourceCode', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = '';
  });

  afterEach(async () => {
    if (tmpDir) {
      await removeTempDir(tmpDir);
    }
    vi.restoreAllMocks();
  });

  it('should return empty array for non-existent directory', async () => {
    const findings = await checkSourceCode('/tmp/panguard-nonexistent-dir-99999');
    expect(findings).toEqual([]);
  });

  it('should return empty array when target is a file not a directory', async () => {
    tmpDir = await createTempDir({ 'test.ts': 'const x = 1;' });
    const filePath = path.join(tmpDir, 'test.ts');
    const findings = await checkSourceCode(filePath);
    expect(findings).toEqual([]);
  });

  it('should return empty array when semgrep is not available', async () => {
    tmpDir = await createTempDir({
      'app.js': `
const result = query("SELECT * FROM users WHERE id=" + req.body.id);
const token = Math.random().toString(36);
`,
    });

    // Without semgrep installed, checkSourceCode returns [] (no built-in fallback)
    const findings = await checkSourceCode(tmpDir);
    expect(findings).toEqual([]);
  });

  it('should return empty array for clean source files', async () => {
    tmpDir = await createTempDir({
      'clean.ts': `
export function add(a: number, b: number): number {
  return a + b;
}
`,
    });

    const findings = await checkSourceCode(tmpDir);
    expect(findings).toEqual([]);
  });

  it('should not throw on empty directory', async () => {
    tmpDir = await createTempDir({});
    const findings = await checkSourceCode(tmpDir);
    expect(findings).toEqual([]);
  });
});
