import { describe, it, expect } from 'vitest';
import { checkManifest } from '../src/checks/manifest-check.js';
import type { SkillManifest } from '../src/types.js';

function makeManifest(overrides: Partial<SkillManifest> = {}): SkillManifest {
  return {
    name: 'Test Skill',
    description: 'A test skill that does something useful for users',
    license: 'MIT',
    instructions: 'This is a detailed instruction set that exceeds the minimum character threshold for validation.',
    ...overrides,
  };
}

describe('checkManifest', () => {
  describe('null manifest', () => {
    it('should return critical finding when manifest is null', () => {
      const result = checkManifest(null);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].id).toBe('manifest-missing');
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].category).toBe('manifest');
    });

    it('should return fail status when manifest is null', () => {
      const result = checkManifest(null);
      expect(result.status).toBe('fail');
    });

    it('should include SKILL.md in the label when manifest is null', () => {
      const result = checkManifest(null);
      expect(result.label).toContain('SKILL.md');
    });
  });

  describe('empty name', () => {
    it('should return high severity finding when name is empty string', () => {
      const result = checkManifest(makeManifest({ name: '' }));
      const finding = result.findings.find((f) => f.id === 'manifest-no-name');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should return high severity finding when name is whitespace only', () => {
      const result = checkManifest(makeManifest({ name: '   ' }));
      const finding = result.findings.find((f) => f.id === 'manifest-no-name');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should return fail status when name is empty (high severity)', () => {
      const result = checkManifest(makeManifest({ name: '' }));
      expect(result.status).toBe('fail');
    });
  });

  describe('empty description', () => {
    it('should return medium severity finding when description is empty string', () => {
      const result = checkManifest(makeManifest({ description: '' }));
      const finding = result.findings.find((f) => f.id === 'manifest-no-description');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should return medium severity finding when description is whitespace only', () => {
      const result = checkManifest(makeManifest({ description: '  ' }));
      const finding = result.findings.find((f) => f.id === 'manifest-no-description');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should not flag description with actual content', () => {
      const result = checkManifest(makeManifest({ description: 'A real description' }));
      const finding = result.findings.find((f) => f.id === 'manifest-no-description');
      expect(finding).toBeUndefined();
    });
  });

  describe('missing license', () => {
    it('should return low severity finding when license is undefined', () => {
      const result = checkManifest(makeManifest({ license: undefined }));
      const finding = result.findings.find((f) => f.id === 'manifest-no-license');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('low');
    });

    it('should not flag when license is present', () => {
      const result = checkManifest(makeManifest({ license: 'MIT' }));
      const finding = result.findings.find((f) => f.id === 'manifest-no-license');
      expect(finding).toBeUndefined();
    });

    it('should not flag Apache-2.0 license', () => {
      const result = checkManifest(makeManifest({ license: 'Apache-2.0' }));
      const finding = result.findings.find((f) => f.id === 'manifest-no-license');
      expect(finding).toBeUndefined();
    });
  });

  describe('short instructions', () => {
    it('should return medium finding when instructions are under 50 chars', () => {
      const result = checkManifest(makeManifest({ instructions: 'Too short.' }));
      const finding = result.findings.find((f) => f.id === 'manifest-short-instructions');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should return medium finding when instructions are empty', () => {
      const result = checkManifest(makeManifest({ instructions: '' }));
      const finding = result.findings.find((f) => f.id === 'manifest-short-instructions');
      expect(finding).toBeDefined();
    });

    it('should include character count in the description', () => {
      const shortText = 'Short.';
      const result = checkManifest(makeManifest({ instructions: shortText }));
      const finding = result.findings.find((f) => f.id === 'manifest-short-instructions');
      expect(finding!.description).toContain(String(shortText.trim().length));
    });

    it('should not flag instructions of exactly 50 characters', () => {
      const exactly50 = 'x'.repeat(50);
      const result = checkManifest(makeManifest({ instructions: exactly50 }));
      const finding = result.findings.find((f) => f.id === 'manifest-short-instructions');
      expect(finding).toBeUndefined();
    });

    it('should not flag instructions over 50 characters', () => {
      const long = 'This is a sufficiently detailed instruction that is well over the minimum threshold required.';
      const result = checkManifest(makeManifest({ instructions: long }));
      const finding = result.findings.find((f) => f.id === 'manifest-short-instructions');
      expect(finding).toBeUndefined();
    });

    it('should trim whitespace before checking length', () => {
      const paddedShort = '   Short.   ';
      const result = checkManifest(makeManifest({ instructions: paddedShort }));
      const finding = result.findings.find((f) => f.id === 'manifest-short-instructions');
      expect(finding).toBeDefined();
    });
  });

  describe('invalid semver version', () => {
    it('should return low finding when version does not follow semver', () => {
      const result = checkManifest(makeManifest({ metadata: { version: 'v1.0' } }));
      const finding = result.findings.find((f) => f.id === 'manifest-bad-version');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('low');
    });

    it('should include the bad version string in the description', () => {
      const result = checkManifest(makeManifest({ metadata: { version: 'latest' } }));
      const finding = result.findings.find((f) => f.id === 'manifest-bad-version');
      expect(finding!.description).toContain('latest');
    });

    it('should not flag a valid 1.0.0 version', () => {
      const result = checkManifest(makeManifest({ metadata: { version: '1.0.0' } }));
      const finding = result.findings.find((f) => f.id === 'manifest-bad-version');
      expect(finding).toBeUndefined();
    });

    it('should not flag a valid 0.1.2 version', () => {
      const result = checkManifest(makeManifest({ metadata: { version: '0.1.2' } }));
      const finding = result.findings.find((f) => f.id === 'manifest-bad-version');
      expect(finding).toBeUndefined();
    });

    it('should not flag a prerelease version like 1.0.0-beta.1', () => {
      const result = checkManifest(makeManifest({ metadata: { version: '1.0.0-beta.1' } }));
      const finding = result.findings.find((f) => f.id === 'manifest-bad-version');
      expect(finding).toBeUndefined();
    });

    it('should not flag version check when metadata has no version field', () => {
      const result = checkManifest(makeManifest({ metadata: { author: 'Alice' } }));
      const finding = result.findings.find((f) => f.id === 'manifest-bad-version');
      expect(finding).toBeUndefined();
    });

    it('should not flag version check when metadata is undefined', () => {
      const result = checkManifest(makeManifest({ metadata: undefined }));
      const finding = result.findings.find((f) => f.id === 'manifest-bad-version');
      expect(finding).toBeUndefined();
    });
  });

  describe('valid manifest', () => {
    it('should return pass status with no findings for a fully valid manifest', () => {
      const result = checkManifest(makeManifest());
      expect(result.status).toBe('pass');
      expect(result.findings).toHaveLength(0);
    });

    it('should include a positive label for a valid manifest', () => {
      const result = checkManifest(makeManifest());
      expect(result.label).toContain('Valid');
    });
  });

  describe('status determination', () => {
    it('should return warn status when only medium/low findings exist', () => {
      // Only missing license (low) and empty description (medium) — no high/critical
      const result = checkManifest(makeManifest({ description: '', license: undefined }));
      expect(result.status).toBe('warn');
    });

    it('should include findings count in the label when issues exist', () => {
      const result = checkManifest(makeManifest({ description: '', license: undefined }));
      expect(result.label).toContain('issue(s)');
    });
  });

  describe('multiple issues', () => {
    it('should collect all findings for a manifest with multiple issues', () => {
      const result = checkManifest(makeManifest({
        name: '',
        description: '',
        license: undefined,
        instructions: 'Short.',
        metadata: { version: 'bad-version' },
      }));
      const ids = result.findings.map((f) => f.id);
      expect(ids).toContain('manifest-no-name');
      expect(ids).toContain('manifest-no-description');
      expect(ids).toContain('manifest-no-license');
      expect(ids).toContain('manifest-short-instructions');
      expect(ids).toContain('manifest-bad-version');
      expect(result.findings.length).toBe(5);
    });

    it('should assign fail status when multiple issues include a high severity one', () => {
      const result = checkManifest(makeManifest({ name: '', description: '' }));
      expect(result.status).toBe('fail');
    });
  });
});
