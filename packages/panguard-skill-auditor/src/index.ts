/**
 * Panguard Skill Auditor - Main entry
 *
 * Three-layer security analysis for AI agent skills:
 *   Layer 1: Regex pattern matching (fast, deterministic)
 *   Layer 2: LLM semantic analysis (catches social engineering, intent mismatch)
 *   Layer 3: Threat Cloud lookup (community intelligence, planned)
 *
 * @module @panguard-ai/panguard-skill-auditor
 */

import { parseSkillManifest } from './manifest-parser.js';
import { checkManifest } from './checks/manifest-check.js';
import { checkInstructions } from './checks/instruction-check.js';
import { checkCode } from './checks/code-check.js';
import { checkDependencies } from './checks/dependency-check.js';
import { checkPermissions } from './checks/permission-check.js';
import { checkWithAI } from './checks/ai-check.js';
import { checkWithATR } from './checks/atr-check.js';
import { autoDetectSkillLLM } from './checks/llm-auto-detect.js';
import { calculateRiskScore } from './risk-scorer.js';
import type { AuditReport, AuditOptions, CheckResult, AuditFinding } from './types.js';

export type {
  AuditReport,
  AuditFinding,
  CheckResult,
  SkillManifest,
  AuditOptions,
} from './types.js';
export type { SkillAnalysisLLM } from './checks/ai-check.js';
export { parseSkillManifest } from './manifest-parser.js';

/**
 * Audit a skill directory for security issues.
 *
 * @param skillDir - Path to the skill directory containing SKILL.md
 * @param options - Optional: LLM provider for AI analysis, skipAI flag
 * @returns Complete audit report
 */
export async function auditSkill(skillDir: string, options?: AuditOptions): Promise<AuditReport> {
  const startTime = Date.now();

  // 1. Parse manifest
  const manifest = await parseSkillManifest(skillDir);

  // 2. Run all checks
  const checks: CheckResult[] = [];

  // Layer 1: Regex-based checks (deterministic, fast)
  checks.push(checkManifest(manifest));

  if (manifest) {
    checks.push(checkInstructions(manifest.instructions));
    checks.push(checkDependencies(manifest));
    checks.push(checkPermissions(manifest));
  }

  // ATR pattern detection (52+ rules including CJK-aware patterns)
  if (manifest && !options?.skipATR) {
    checks.push(await checkWithATR(manifest));
  }

  // Code security (SAST + secrets)
  checks.push(await checkCode(skillDir));

  // Layer 2: AI semantic analysis (default-on, auto-detects LLM if not provided)
  if (manifest && !options?.skipAI) {
    let llm = options?.llm;

    // Auto-detect an LLM when none was explicitly provided
    if (!llm) {
      llm = (await autoDetectSkillLLM()) ?? undefined;
    }

    if (llm) {
      checks.push(await checkWithAI(manifest.instructions, manifest.description, llm));
    } else {
      // No LLM available at all — report as info finding so user knows
      const noLlmFinding: AuditFinding = {
        id: 'ai-no-llm',
        title: 'AI check skipped -- no LLM configured',
        description:
          'No LLM provider was detected. Install Ollama or set ANTHROPIC_API_KEY / OPENAI_API_KEY for deeper semantic analysis.',
        severity: 'info',
        category: 'ai-analysis',
        location: 'AI analysis',
      };
      checks.push({
        status: 'info',
        label: 'AI Analysis: Skipped (no LLM available)',
        findings: [noLlmFinding],
      });
    }
  }

  // 3. Aggregate findings
  const allFindings = checks.flatMap((c) => c.findings);

  // 4. Calculate risk score (with dedup)
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
