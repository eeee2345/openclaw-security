/**
 * Real integration test for code-check -- exercises actual panguard-scan scanners.
 * No mocks. Creates temp files with known vulnerabilities and verifies detection.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { checkCode } from '../src/checks/code-check.js';

describe('checkCode (real panguard-scan)', () => {
  const tempDirs: string[] = [];

  function createTempSkill(files: Record<string, string>): string {
    const dir = mkdtempSync(join(tmpdir(), 'skill-audit-real-'));
    tempDirs.push(dir);
    for (const [name, content] of Object.entries(files)) {
      const filePath = join(dir, name);
      const fileDir = join(dir, ...name.split('/').slice(0, -1));
      if (name.includes('/')) {
        mkdirSync(fileDir, { recursive: true });
      }
      writeFileSync(filePath, content);
    }
    return dir;
  }

  afterEach(() => {
    for (const dir of tempDirs) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    tempDirs.length = 0;
  });

  it('should return pass for clean code', async () => {
    const dir = createTempSkill({
      'index.ts': 'export function hello() { return "world"; }\n',
    });

    const result = await checkCode(dir);
    expect(result.status).toBe('pass');
    expect(result.findings).toHaveLength(0);
  });

  it('should detect hardcoded AWS access key', async () => {
    const dir = createTempSkill({
      'config.ts': `
        const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
        export default { key: AWS_KEY };
      `,
    });

    const result = await checkCode(dir);
    // Should find at least one secret
    const secretFindings = result.findings.filter(f => f.category === 'secrets');
    expect(secretFindings.length).toBeGreaterThanOrEqual(1);
    expect(result.status).not.toBe('pass');
  });

  it('should detect eval with user input', async () => {
    const dir = createTempSkill({
      'handler.js': `
        function processInput(userInput) {
          return eval(userInput);
        }
        module.exports = { processInput };
      `,
    });

    const result = await checkCode(dir);
    const codeFindings = result.findings.filter(f => f.category === 'code');
    expect(codeFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect hardcoded GitHub token', async () => {
    const dir = createTempSkill({
      'auth.ts': `
        const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde12345";
        export default token;
      `,
    });

    const result = await checkCode(dir);
    const secretFindings = result.findings.filter(f => f.category === 'secrets');
    expect(secretFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle empty directory gracefully', async () => {
    const dir = createTempSkill({});

    const result = await checkCode(dir);
    // Should not crash, should return pass or warn about no code
    expect(['pass', 'warn']).toContain(result.status);
  });
});
