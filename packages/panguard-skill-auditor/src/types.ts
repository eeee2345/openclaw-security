/**
 * Panguard Skill Auditor - Type definitions
 * Panguard 技能審計器 - 型別定義
 *
 * @module @panguard-ai/panguard-skill-auditor/types
 */

import type { Severity } from '@panguard-ai/core';

/** Parsed SKILL.md manifest */
export interface SkillManifest {
  name: string;
  description: string;
  license?: string;
  homepage?: string;
  userInvocable?: boolean;
  disableModelInvocation?: boolean;
  commandDispatch?: string;
  commandTool?: string;
  metadata?: SkillMetadata;
  /** Raw instruction body (after frontmatter) */
  instructions: string;
}

export interface SkillMetadata {
  author?: string;
  version?: string;
  tags?: string[];
  triggers?: string[];
  openclaw?: {
    requires?: {
      bins?: string[];
      env?: string[];
      config?: string[];
    };
    primaryEnv?: string;
    os?: string[];
    always?: boolean;
    homepage?: string;
  };
  [key: string]: unknown;
}

/** Single audit finding */
export interface AuditFinding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category:
    | 'manifest'
    | 'prompt-injection'
    | 'tool-poisoning'
    | 'context-exfiltration'
    | 'agent-manipulation'
    | 'privilege-escalation'
    | 'excessive-autonomy'
    | 'data-poisoning'
    | 'model-abuse'
    | 'skill-compromise'
    | 'code'
    | 'secrets'
    | 'dependency'
    | 'permission'
    | 'ai-analysis'
    | 'atr';
  location?: string;
}

/** Result of a single check category */
export interface CheckResult {
  status: 'pass' | 'warn' | 'fail' | 'info';
  label: string;
  findings: AuditFinding[];
}

/** Options for auditSkill */
export interface AuditOptions {
  /**
   * LLM provider for AI semantic analysis (Layer 2).
   * When omitted, the auditor auto-detects an available provider:
   *   1. ANTHROPIC_API_KEY env var (Claude)
   *   2. OPENAI_API_KEY env var (OpenAI)
   *   3. Local Ollama instance
   * If no provider is found, an info-level finding is added to the report.
   */
  llm?: import('./checks/ai-check.js').SkillAnalysisLLM;
  /** Skip AI analysis entirely (no auto-detection, no LLM call) */
  skipAI?: boolean;
  /** Skip ATR pattern detection */
  skipATR?: boolean;
}

/** Complete audit report */
export interface AuditReport {
  skillPath: string;
  manifest: SkillManifest | null;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  checks: CheckResult[];
  findings: AuditFinding[];
  auditedAt: string;
  durationMs: number;
}
