/**
 * ATR (Agent Threat Rules) pattern detection check
 *
 * Evaluates skill manifests against the ATR rule engine (52+ rules)
 * covering prompt injection, tool poisoning, context exfiltration,
 * agent manipulation, privilege escalation, and CJK-aware patterns.
 *
 * This augments (does NOT replace) existing regex checks in instruction-check.ts.
 *
 * @module @panguard-ai/panguard-skill-auditor/checks/atr-check
 */

import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuditFinding, CheckResult, SkillManifest } from '../types.js';
import type { ATREngine as ATREngineType, AgentEvent, ATRMatch } from '@panguard-ai/atr';

const CHECK_LABEL = 'ATR Pattern Detection';

/** ATR category to AuditFinding category mapping */
const CATEGORY_MAP: Record<string, AuditFinding['category']> = {
  'prompt-injection': 'prompt-injection',
  'tool-poisoning': 'tool-poisoning',
  'context-exfiltration': 'context-exfiltration',
  'agent-manipulation': 'agent-manipulation',
  'privilege-escalation': 'privilege-escalation',
  'excessive-autonomy': 'excessive-autonomy',
  'data-poisoning': 'data-poisoning',
  'model-abuse': 'model-abuse',
  'skill-compromise': 'skill-compromise',
};

/**
 * Resolve the bundled ATR rules directory.
 * Walks up from the atr package dist/ to find rules/.
 */
function resolveRulesDir(): string {
  try {
    // Resolve from the atr package
    const atrIndex = import.meta.resolve?.('@panguard-ai/atr');
    if (atrIndex) {
      const atrDir = dirname(fileURLToPath(atrIndex));
      // dist/index.js -> go up one level to package root, then rules/
      return resolve(atrDir, '..', 'rules');
    }
  } catch {
    // Fallback: monorepo-relative path
  }
  const thisDir = dirname(fileURLToPath(import.meta.url));
  return resolve(thisDir, '..', '..', '..', 'atr', 'rules');
}

/**
 * Build an AgentEvent from instruction text for ATR evaluation.
 */
function buildLlmInputEvent(content: string, toolName?: string): AgentEvent {
  return {
    type: 'llm_input',
    timestamp: new Date().toISOString(),
    content,
    fields: {
      user_input: content,
      ...(toolName ? { tool_name: toolName } : {}),
    },
  };
}

/**
 * Build an AgentEvent from MCP tool metadata for ATR evaluation.
 */
function buildToolCallEvent(
  toolName: string,
  description: string,
  inputSchema?: unknown,
): AgentEvent {
  return {
    type: 'tool_call',
    timestamp: new Date().toISOString(),
    content: description,
    fields: {
      tool_name: toolName,
      tool_args:
        typeof inputSchema === 'string'
          ? inputSchema
          : JSON.stringify(inputSchema ?? {}),
    },
  };
}

/**
 * Convert ATR matches to AuditFinding[], deduplicating by rule ID.
 */
function matchesToFindings(matches: readonly ATRMatch[]): AuditFinding[] {
  const seen = new Set<string>();
  const findings: AuditFinding[] = [];

  for (const match of matches) {
    const ruleId = match.rule.id;
    if (seen.has(ruleId)) continue;
    seen.add(ruleId);

    const category = CATEGORY_MAP[match.rule.tags.category] ?? 'atr';
    const severity = match.rule.severity === 'informational' ? 'low' : match.rule.severity;

    findings.push({
      id: `atr-${ruleId}`,
      title: match.rule.title,
      description: match.rule.description,
      severity,
      category,
      location: match.matchedPatterns.length > 0
        ? `Matched: ${match.matchedPatterns.slice(0, 3).join(', ')}`
        : undefined,
    });
  }

  return findings;
}

/**
 * Run ATR engine checks against a parsed skill manifest.
 *
 * Evaluates:
 * 1. Skill instructions as llm_input event
 * 2. Skill description as llm_input event
 * 3. MCP tool descriptions (if present in metadata) as tool_call events
 *
 * Returns a CheckResult compatible with the Skill Auditor pipeline.
 */
export async function checkWithATR(
  manifest: SkillManifest,
): Promise<CheckResult> {
  // Dynamic import — gracefully handle missing dependency
  let ATREngine: typeof ATREngineType;
  try {
    const atr = await import('@panguard-ai/atr');
    ATREngine = atr.ATREngine;
  } catch {
    return {
      status: 'info',
      label: CHECK_LABEL,
      findings: [],
    };
  }

  try {
    const rulesDir = resolveRulesDir();
    const engine = new ATREngine({ rulesDir });
    const ruleCount = await engine.loadRules();

    if (ruleCount === 0) {
      return {
        status: 'info',
        label: `${CHECK_LABEL}: no rules loaded`,
        findings: [],
      };
    }

    const allMatches: ATRMatch[] = [];

    // 1. Scan instructions
    if (manifest.instructions) {
      const instructionMatches = engine.evaluate(
        buildLlmInputEvent(manifest.instructions, manifest.name),
      );
      allMatches.push(...instructionMatches);
    }

    // 2. Scan description
    if (manifest.description) {
      const descMatches = engine.evaluate(
        buildLlmInputEvent(manifest.description),
      );
      allMatches.push(...descMatches);
    }

    // 3. Scan MCP tool descriptions (if metadata includes them)
    const mcpTools = manifest.metadata?.['mcp_tools'];
    if (Array.isArray(mcpTools)) {
      for (const tool of mcpTools) {
        const t = tool as Record<string, unknown>;
        if (typeof t['description'] === 'string') {
          const toolMatches = engine.evaluate(
            buildToolCallEvent(
              (t['name'] as string) ?? '',
              t['description'] as string,
              t['inputSchema'],
            ),
          );
          allMatches.push(...toolMatches);
        }
      }
    }

    // Deduplicate and convert to findings
    const findings = matchesToFindings(allMatches);

    const hasCritical = findings.some((f) => f.severity === 'critical');
    const hasHigh = findings.some((f) => f.severity === 'high');

    const status = hasCritical
      ? 'fail'
      : hasHigh
        ? 'warn'
        : findings.length > 0
          ? 'warn'
          : 'pass';

    const label = findings.length === 0
      ? `${CHECK_LABEL}: clean (${ruleCount} rules evaluated)`
      : `${CHECK_LABEL}: ${findings.length} threat(s) detected`;

    return { status, label, findings };
  } catch (err) {
    return {
      status: 'info',
      label: `${CHECK_LABEL}: engine error`,
      findings: [{
        id: 'atr-engine-error',
        title: 'ATR engine failed to initialize',
        description: err instanceof Error ? err.message : String(err),
        severity: 'info',
        category: 'atr',
      }],
    };
  }
}
