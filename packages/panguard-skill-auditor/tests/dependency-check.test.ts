import { describe, it, expect } from 'vitest';
import { checkDependencies } from '../src/checks/dependency-check.js';
import type { SkillManifest } from '../src/types.js';

function makeManifest(overrides: Partial<SkillManifest> = {}): SkillManifest {
  return {
    name: 'Test Skill',
    description: 'A test skill',
    instructions: '',
    ...overrides,
  };
}

describe('checkDependencies', () => {
  describe('no URLs', () => {
    it('should return pass status when instructions contain no URLs', () => {
      const result = checkDependencies(makeManifest({ instructions: 'Just plain text with no links.' }));
      expect(result.status).toBe('pass');
    });

    it('should return no findings when instructions have no URLs', () => {
      const result = checkDependencies(makeManifest({ instructions: 'Nothing external here.' }));
      expect(result.findings).toHaveLength(0);
    });

    it('should return "No external references found" label when no URLs exist', () => {
      const result = checkDependencies(makeManifest({ instructions: 'No URLs anywhere.' }));
      expect(result.label).toContain('No external references found');
    });
  });

  describe('safe domain URLs', () => {
    it('should not flag github.com URLs', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Clone from https://github.com/user/repo',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      expect(finding).toBeUndefined();
    });

    it('should not flag npmjs.com URLs', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'See the package at https://npmjs.com/package/my-lib',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      expect(finding).toBeUndefined();
    });

    it('should not flag pypi.org URLs', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'See https://pypi.org/project/requests for more info.',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      expect(finding).toBeUndefined();
    });

    it('should not flag googleapis.com URLs', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Use https://www.googleapis.com/auth/token for authentication.',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      expect(finding).toBeUndefined();
    });

    it('should not flag developer.mozilla.org URLs', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Refer to https://developer.mozilla.org/en-US/docs/Web for reference.',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      expect(finding).toBeUndefined();
    });

    it('should include URL count in label when URLs exist', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Use https://github.com/user/repo for the code.',
      }));
      expect(result.label).toContain('1 URL(s)');
    });
  });

  describe('external unknown domain', () => {
    it('should return low finding when instructions reference an unknown external domain', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Download from https://suspicious-site.io/tool',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('low');
    });

    it('should include the domain name in the finding description', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Fetch from https://evil-domain.xyz/payload',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      expect(finding!.description).toContain('evil-domain.xyz');
    });

    it('should report dep-external-urls category as dependency', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Get data from https://random-api.net/endpoint',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      expect(finding!.category).toBe('dependency');
    });

    it('should return warn status when external domain found', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Fetch https://untrusted.example.org/stuff',
      }));
      expect(result.status).toBe('warn');
    });
  });

  describe('invalid URL handling', () => {
    it('should not crash on text that starts with http but is not a valid URL', async () => {
      // "http://" alone won't cause a URL parse error but malformed ones might
      const result = checkDependencies(makeManifest({
        instructions: 'See http://[invalid for reference.',
      }));
      // Should complete without throwing
      expect(result).toBeDefined();
    });
  });

  describe('npm install detection', () => {
    it('should return medium finding when npm install is detected', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Run npm install lodash to get started.',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-package-installs');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should include the package name in the finding description', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Install with npm install express',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-package-installs');
      expect(finding!.description).toContain('npm:express');
    });

    it('should detect npm install -g variant', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Install globally: npm install -g typescript',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-package-installs');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('npm:typescript');
    });

    it('should detect npm install -D variant', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Run npm install -D vitest for dev dependencies.',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-package-installs');
      expect(finding).toBeDefined();
    });

    it('should return warn status when npm install is detected', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'npm install some-package',
      }));
      expect(result.status).toBe('warn');
    });
  });

  describe('pip install detection', () => {
    it('should return medium finding when pip install is detected', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Run pip install requests to install the library.',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-package-installs');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should include pip package in the finding description', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'pip install flask',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-package-installs');
      expect(finding!.description).toContain('pip:flask');
    });

    it('should combine npm and pip packages in a single finding', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'npm install axios then pip install httpx',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-package-installs');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('npm:axios');
      expect(finding!.description).toContain('pip:httpx');
    });
  });

  describe('openclaw requires bins', () => {
    it('should return low finding when required binaries are specified', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Do something.',
        metadata: {
          openclaw: {
            requires: {
              bins: ['git', 'curl'],
            },
          },
        },
      }));
      const finding = result.findings.find((f) => f.id === 'dep-required-bins');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('low');
    });

    it('should include binary names in the finding description', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Needs binaries.',
        metadata: {
          openclaw: {
            requires: {
              bins: ['docker', 'kubectl'],
            },
          },
        },
      }));
      const finding = result.findings.find((f) => f.id === 'dep-required-bins');
      expect(finding!.description).toContain('docker');
      expect(finding!.description).toContain('kubectl');
    });

    it('should not flag when bins array is empty', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'No bins needed.',
        metadata: {
          openclaw: {
            requires: {
              bins: [],
            },
          },
        },
      }));
      const finding = result.findings.find((f) => f.id === 'dep-required-bins');
      expect(finding).toBeUndefined();
    });
  });

  describe('openclaw requires env', () => {
    it('should return low finding when required env vars are specified', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Needs env vars.',
        metadata: {
          openclaw: {
            requires: {
              env: ['API_KEY', 'SECRET_TOKEN'],
            },
          },
        },
      }));
      const finding = result.findings.find((f) => f.id === 'dep-required-env');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('low');
    });

    it('should include env var names in the finding description', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Uses env.',
        metadata: {
          openclaw: {
            requires: {
              env: ['DATABASE_URL', 'OPENAI_KEY'],
            },
          },
        },
      }));
      const finding = result.findings.find((f) => f.id === 'dep-required-env');
      expect(finding!.description).toContain('DATABASE_URL');
      expect(finding!.description).toContain('OPENAI_KEY');
    });

    it('should not flag when env array is empty', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'No env vars.',
        metadata: {
          openclaw: {
            requires: {
              env: [],
            },
          },
        },
      }));
      const finding = result.findings.find((f) => f.id === 'dep-required-env');
      expect(finding).toBeUndefined();
    });
  });

  describe('multiple external domains', () => {
    it('should produce a single finding listing all external domains', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'Use https://domain1.io/a and https://domain2.xyz/b for processing.',
      }));
      const externalFindings = result.findings.filter((f) => f.id === 'dep-external-urls');
      expect(externalFindings).toHaveLength(1);
      expect(externalFindings[0]!.description).toContain('domain1.io');
      expect(externalFindings[0]!.description).toContain('domain2.xyz');
    });

    it('should deduplicate repeated references to the exact same URL', () => {
      const result = checkDependencies(makeManifest({
        // The same exact URL repeated twice should only count once for URL dedup
        instructions: 'Use https://same-domain.io/path and https://same-domain.io/path again',
      }));
      const finding = result.findings.find((f) => f.id === 'dep-external-urls');
      // One unique URL, one external domain
      expect(finding!.title).toContain('1');
    });
  });

  describe('label format with URLs', () => {
    it('should report URL count in label', () => {
      const result = checkDependencies(makeManifest({
        instructions: 'See https://unknown-domain.org/path for details.',
      }));
      expect(result.label).toContain('1 URL(s)');
      expect(result.label).toContain('1 external domain(s)');
    });
  });
});
