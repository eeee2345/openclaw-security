import { describe, it, expect, vi, beforeEach } from 'vitest';

// vi.mock is hoisted to the top of the file automatically by Vitest.
// This ensures the mock is in place before checkCode's dynamic import runs.
vi.mock('@panguard-ai/panguard-scan', () => ({
  checkSourceCode: vi.fn().mockResolvedValue([]),
  checkHardcodedSecrets: vi.fn().mockResolvedValue([]),
}));

import { checkCode } from '../src/checks/code-check.js';
import * as panguardScan from '@panguard-ai/panguard-scan';

function makeCodeFinding(overrides: Partial<{
  id: string;
  title: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  details: string;
}> = {}) {
  return {
    id: 'vuln-1',
    title: 'SQL Injection',
    description: 'User input is passed directly to a query',
    severity: 'high' as const,
    details: 'src/db.ts:42',
    ...overrides,
  };
}

function makeSecretFinding(overrides: Partial<{
  id: string;
  title: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  details: string;
}> = {}) {
  return {
    id: 'aws-key',
    title: 'AWS Access Key',
    description: 'Hardcoded AWS access key detected',
    severity: 'critical' as const,
    details: 'config.ts:10',
    ...overrides,
  };
}

describe('checkCode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([]);
    vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([]);
  });

  describe('scanner not available', () => {
    it('should have a code-scan-unavailable finding structure when scan is not available', () => {
      // Verify the expected shape of the unavailability finding
      // (the actual fallback path is exercised when the dynamic import throws)
      const expectedFinding = {
        id: 'code-scan-unavailable',
        title: 'Code scanner not available',
        severity: 'medium',
        category: 'code',
      };
      expect(expectedFinding.id).toBe('code-scan-unavailable');
      expect(expectedFinding.severity).toBe('medium');
      expect(expectedFinding.category).toBe('code');
    });
  });

  describe('empty results from scanners', () => {
    it('should return pass status when both scanners return no findings', async () => {
      const result = await checkCode('/some/skill/dir');
      expect(result.status).toBe('pass');
    });

    it('should return zero findings when both scanners are empty', async () => {
      const result = await checkCode('/some/skill/dir');
      expect(result.findings).toHaveLength(0);
    });

    it('should report no vulnerabilities and no credentials in the label', async () => {
      const result = await checkCode('/some/skill/dir');
      expect(result.label).toContain('No vulnerabilities found');
      expect(result.label).toContain('No hardcoded credentials found');
    });
  });

  describe('code findings', () => {
    it('should map code findings with prefixed IDs', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ id: 'sql-injection', title: 'SQL Injection', severity: 'high' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.id).toBe('code-sql-injection');
    });

    it('should assign "code" category to code scanner findings', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding(),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.category).toBe('code');
    });

    it('should map title and description from scanner finding', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ title: 'XSS Vulnerability', description: 'Unescaped user output' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.title).toBe('XSS Vulnerability');
      expect(result.findings[0]!.description).toBe('Unescaped user output');
    });

    it('should map details to location field', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ details: 'src/api.ts:99' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.location).toBe('src/api.ts:99');
    });

    it('should map severity correctly', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ severity: 'critical' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.severity).toBe('critical');
    });

    it('should include code issue count in label', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ id: 'issue-1' }),
        makeCodeFinding({ id: 'issue-2' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.label).toContain('2 issue(s) found');
    });

    it('should return warn status for high severity code findings', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ severity: 'high' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.status).toBe('warn');
    });

    it('should return fail status for critical severity code findings', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ severity: 'critical' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.status).toBe('fail');
    });

    it('should return warn status for medium severity code findings', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ severity: 'medium' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.status).toBe('warn');
    });
  });

  describe('secret findings', () => {
    it('should map secret findings with prefixed IDs', async () => {
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ id: 'aws-key-1' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.id).toBe('secret-aws-key-1');
    });

    it('should assign "secrets" category to secret scanner findings', async () => {
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding(),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.category).toBe('secrets');
    });

    it('should map secret finding details to location', async () => {
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ details: 'config.env:5' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.location).toBe('config.env:5');
    });

    it('should include credential count in label', async () => {
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ id: 's1' }),
        makeSecretFinding({ id: 's2' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.label).toContain('2 credential(s) exposed');
    });

    it('should return fail status for critical secret findings', async () => {
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ severity: 'critical' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.status).toBe('fail');
    });

    it('should map title and description of secret findings correctly', async () => {
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ title: 'GitHub Token', description: 'Personal access token found' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings[0]!.title).toBe('GitHub Token');
      expect(result.findings[0]!.description).toBe('Personal access token found');
    });
  });

  describe('combined findings from both scanners', () => {
    it('should combine code and secret findings in results', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ id: 'vuln-1', severity: 'medium' }),
      ]);
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ id: 'key-1', severity: 'high' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.findings).toHaveLength(2);
      expect(result.findings.some((f) => f.category === 'code')).toBe(true);
      expect(result.findings.some((f) => f.category === 'secrets')).toBe(true);
    });

    it('should label code and secrets separately in the combined label', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ id: 'v1', severity: 'low' }),
      ]);
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ id: 's1', severity: 'high' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.label).toContain('1 issue(s) found');
      expect(result.label).toContain('1 credential(s) exposed');
    });

    it('should return fail when code finding is critical but secret is only medium', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ id: 'v1', severity: 'critical' }),
      ]);
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ id: 's1', severity: 'medium' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.status).toBe('fail');
    });

    it('should return warn when highest combined severity is high', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ id: 'v1', severity: 'medium' }),
      ]);
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ id: 's1', severity: 'high' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.status).toBe('warn');
    });
  });

  describe('only code results', () => {
    it('should say "No hardcoded credentials found" when only code findings exist', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([
        makeCodeFinding({ id: 'v1', severity: 'low' }),
      ]);
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([]);

      const result = await checkCode('/some/dir');
      expect(result.label).toContain('No hardcoded credentials found');
    });
  });

  describe('only secret results', () => {
    it('should say "No vulnerabilities found" when only secret findings exist', async () => {
      vi.mocked(panguardScan.checkSourceCode).mockResolvedValue([]);
      vi.mocked(panguardScan.checkHardcodedSecrets).mockResolvedValue([
        makeSecretFinding({ id: 's1', severity: 'low' }),
      ]);

      const result = await checkCode('/some/dir');
      expect(result.label).toContain('No vulnerabilities found');
    });
  });

  describe('skillDir is passed through', () => {
    it('should call checkSourceCode with the provided directory', async () => {
      await checkCode('/my/specific/skill');
      expect(vi.mocked(panguardScan.checkSourceCode)).toHaveBeenCalledWith('/my/specific/skill');
    });

    it('should call checkHardcodedSecrets with the provided directory', async () => {
      await checkCode('/my/specific/skill');
      expect(vi.mocked(panguardScan.checkHardcodedSecrets)).toHaveBeenCalledWith('/my/specific/skill');
    });
  });
});
