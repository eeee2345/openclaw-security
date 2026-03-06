/**
 * Risk scoring engine
 * 風險評分引擎
 *
 * Calculates a 0-100 risk score from audit findings.
 * 根據審計發現計算 0-100 風險評分。
 */

import type { AuditFinding, AuditReport } from './types.js';

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 1,
};

/**
 * Calculate risk score (0-100) from findings.
 * Higher score = higher risk.
 */
export function calculateRiskScore(findings: AuditFinding[]): { score: number; level: AuditReport['riskLevel'] } {
  let rawScore = 0;

  for (const finding of findings) {
    rawScore += SEVERITY_WEIGHTS[finding.severity] ?? 0;
  }

  // Cap at 100
  const score = Math.min(100, rawScore);

  let level: AuditReport['riskLevel'];
  if (score >= 70) level = 'CRITICAL';
  else if (score >= 40) level = 'HIGH';
  else if (score >= 15) level = 'MEDIUM';
  else level = 'LOW';

  return { score, level };
}
