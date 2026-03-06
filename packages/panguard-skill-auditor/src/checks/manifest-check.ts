/**
 * Manifest structure validation
 * 清單結構驗證
 */

import type { SkillManifest, AuditFinding, CheckResult } from '../types.js';

export function checkManifest(manifest: SkillManifest | null): CheckResult {
  const findings: AuditFinding[] = [];

  if (!manifest) {
    findings.push({
      id: 'manifest-missing',
      title: 'SKILL.md not found',
      description: 'No SKILL.md file found in the skill directory. This is required for all valid skills.',
      severity: 'critical',
      category: 'manifest',
    });
    return { status: 'fail', label: 'Manifest: SKILL.md not found', findings };
  }

  if (!manifest.name || manifest.name.trim() === '') {
    findings.push({
      id: 'manifest-no-name',
      title: 'Missing skill name',
      description: 'SKILL.md frontmatter must include a "name" field.',
      severity: 'high',
      category: 'manifest',
    });
  }

  if (!manifest.description || manifest.description.trim() === '') {
    findings.push({
      id: 'manifest-no-description',
      title: 'Missing skill description',
      description: 'SKILL.md frontmatter should include a "description" field.',
      severity: 'medium',
      category: 'manifest',
    });
  }

  if (!manifest.license) {
    findings.push({
      id: 'manifest-no-license',
      title: 'No license declared',
      description: 'Skill does not declare a license. Consider adding one for trust and legal clarity.',
      severity: 'low',
      category: 'manifest',
    });
  }

  if (manifest.instructions.trim().length < 50) {
    findings.push({
      id: 'manifest-short-instructions',
      title: 'Suspiciously short instructions',
      description: `Skill instructions are only ${manifest.instructions.trim().length} characters. This may indicate an incomplete or placeholder skill.`,
      severity: 'medium',
      category: 'manifest',
    });
  }

  if (manifest.metadata?.version) {
    const semverRe = /^\d+\.\d+\.\d+(-[\w.]+)?$/;
    if (!semverRe.test(manifest.metadata.version)) {
      findings.push({
        id: 'manifest-bad-version',
        title: 'Invalid version format',
        description: `Version "${manifest.metadata.version}" is not valid semver (expected X.Y.Z).`,
        severity: 'low',
        category: 'manifest',
      });
    }
  }

  const status = findings.some((f) => f.severity === 'critical' || f.severity === 'high')
    ? 'fail'
    : findings.length > 0
      ? 'warn'
      : 'pass';

  const label = status === 'pass'
    ? 'Manifest: Valid SKILL.md with all required fields'
    : `Manifest: ${findings.length} issue(s) found`;

  return { status, label, findings };
}
