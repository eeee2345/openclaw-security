/**
 * Panguard Skill Auditor - Main entry
 * Panguard 技能審計器 - 主入口
 *
 * Security auditor for OpenClaw/AgentSkills SKILL.md files.
 * Checks manifest validity, prompt injection, code security,
 * dependencies, and permissions.
 *
 * @module @panguard-ai/panguard-skill-auditor
 */

import { parseSkillManifest } from './manifest-parser.js';
import { checkManifest } from './checks/manifest-check.js';
import { checkInstructions } from './checks/instruction-check.js';
import { checkCode } from './checks/code-check.js';
import { checkDependencies } from './checks/dependency-check.js';
import { checkPermissions } from './checks/permission-check.js';
import { calculateRiskScore } from './risk-scorer.js';
import type { AuditReport, CheckResult } from './types.js';

export type { AuditReport, AuditFinding, CheckResult, SkillManifest } from './types.js';
export { parseSkillManifest } from './manifest-parser.js';

/**
 * Audit a skill directory for security issues.
 * 審計技能目錄的安全問題。
 *
 * @param skillDir - Path to the skill directory containing SKILL.md
 * @returns Complete audit report
 */
export async function auditSkill(skillDir: string): Promise<AuditReport> {
  const startTime = Date.now();

  // 1. Parse manifest
  const manifest = await parseSkillManifest(skillDir);

  // 2. Run all checks
  const checks: CheckResult[] = [];

  // Manifest validation
  checks.push(checkManifest(manifest));

  if (manifest) {
    // Prompt injection + tool poisoning
    checks.push(checkInstructions(manifest.instructions));

    // Dependencies
    checks.push(checkDependencies(manifest));

    // Permissions
    checks.push(checkPermissions(manifest));
  }

  // Code security (SAST + secrets) — always run on directory
  checks.push(await checkCode(skillDir));

  // 3. Aggregate findings
  const allFindings = checks.flatMap((c) => c.findings);

  // 4. Calculate risk score
  const { score, level } = calculateRiskScore(allFindings);

  return {
    skillPath: skillDir,
    manifest,
    riskScore: score,
    riskLevel: level,
    checks,
    findings: allFindings,
    auditedAt: new Date().toISOString(),
    durationMs: Date.now() - startTime,
  };
}
