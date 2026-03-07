/**
 * Risk scoring engine
 *
 * Calculates a 0-100 risk score from audit findings.
 * Deduplicates findings by ID — only the highest severity instance counts.
 */

import type { AuditFinding, AuditReport } from './types.js';

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 1,
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Calculate risk score (0-100) from findings.
 * Deduplicates by finding ID — keeps the highest severity instance.
 */
export function calculateRiskScore(findings: AuditFinding[]): { score: number; level: AuditReport['riskLevel'] } {
  // Deduplicate: keep highest severity per finding ID
  const deduped = new Map<string, AuditFinding>();
  for (const finding of findings) {
    const existing = deduped.get(finding.id);
    if (!existing || (SEVERITY_RANK[finding.severity] ?? 0) > (SEVERITY_RANK[existing.severity] ?? 0)) {
      deduped.set(finding.id, finding);
    }
  }

  let rawScore = 0;
  for (const finding of deduped.values()) {
    rawScore += SEVERITY_WEIGHTS[finding.severity] ?? 0;
  }

  const score = Math.min(100, rawScore);

  let level: AuditReport['riskLevel'];
  if (score >= 70) level = 'CRITICAL';
  else if (score >= 40) level = 'HIGH';
  else if (score >= 15) level = 'MEDIUM';
  else level = 'LOW';

  return { score, level };
}
