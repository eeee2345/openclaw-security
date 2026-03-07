/**
 * Code security check - wraps panguard-scan SAST + secrets scanners
 * 程式碼安全檢查 - 包裝 panguard-scan 的 SAST 和密鑰掃描器
 */

import type { AuditFinding, CheckResult } from '../types.js';
import type { Severity } from '@panguard-ai/core';

export async function checkCode(skillDir: string): Promise<CheckResult> {
  const findings: AuditFinding[] = [];

  // Dynamic import to handle case where panguard-scan is not available
  let checkSourceCode: ((dir: string) => Promise<Array<{ id: string; title: string; description: string; severity: Severity; details?: string }>>) | null = null;
  let checkHardcodedSecrets: ((dir: string) => Promise<Array<{ id: string; title: string; description: string; severity: Severity; details?: string }>>) | null = null;

  try {
    const scan = await import('@panguard-ai/panguard-scan');
    if (typeof scan.checkSourceCode === 'function') {
      checkSourceCode = scan.checkSourceCode;
    }
    if (typeof scan.checkHardcodedSecrets === 'function') {
      checkHardcodedSecrets = scan.checkHardcodedSecrets;
    }
  } catch {
    return {
      status: 'warn',
      label: 'Code: panguard-scan not available, code analysis skipped',
      findings: [{
        id: 'code-scan-unavailable',
        title: 'Code scanner not available',
        description: 'panguard-scan module could not be loaded. Code vulnerabilities and hardcoded secrets were NOT checked. Install @panguard-ai/panguard-scan for full coverage.',
        severity: 'medium',
        category: 'code',
      }],
    };
  }

  const [codeResults, secretResults] = await Promise.all([
    checkSourceCode ? checkSourceCode(skillDir) : Promise.resolve([]),
    checkHardcodedSecrets ? checkHardcodedSecrets(skillDir) : Promise.resolve([]),
  ]);

  for (const finding of codeResults) {
    findings.push({
      id: `code-${finding.id}`,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      category: 'code',
      location: finding.details,
    });
  }

  for (const finding of secretResults) {
    findings.push({
      id: `secret-${finding.id}`,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      category: 'secrets',
      location: finding.details,
    });
  }

  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasHigh = findings.some((f) => f.severity === 'high');
  const status = hasCritical ? 'fail' : hasHigh ? 'warn' : findings.length > 0 ? 'warn' : 'pass';

  const codeLabel = findings.filter((f) => f.category === 'code').length === 0
    ? `Code: No vulnerabilities found`
    : `Code: ${findings.filter((f) => f.category === 'code').length} issue(s) found`;

  const secretLabel = findings.filter((f) => f.category === 'secrets').length === 0
    ? 'Secrets: No hardcoded credentials found'
    : `Secrets: ${findings.filter((f) => f.category === 'secrets').length} credential(s) exposed`;

  return {
    status,
    label: `${codeLabel}; ${secretLabel}`,
    findings,
  };
}
