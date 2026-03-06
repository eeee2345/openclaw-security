/**
 * Knowledge Distiller - Convert AI analysis results into reusable rules
 * 知識蒸餾器 - 將 AI 分析結果轉換為可重複使用的規則
 *
 * When cloud AI analyzes a new attack pattern, this module auto-generates
 * a Sigma detection rule so the same pattern is caught by rules alone
 * in future occurrences (no further AI calls needed).
 *
 * This is the key mechanism for "learn once, detect forever" —
 * AI teaches the rule engine, and the rule engine handles the rest.
 *
 * @module @panguard-ai/core/ai/knowledge-distiller
 */

import { createHash } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import type { AnalysisResult } from './types.js';

const logger = createLogger('ai:knowledge-distiller');

/** Input for distillation: the original event context + AI result */
export interface DistillationInput {
  /** Event category (e.g., 'brute_force', 'port_scan') */
  eventCategory: string;
  /** Event source type (e.g., 'network', 'process', 'auth') */
  eventSource: string;
  /** Event severity from detection */
  eventSeverity: string;
  /** MITRE ATT&CK technique if identified */
  mitreTechnique?: string;
  /** Key indicators from the event (IP, process name, port, etc.) */
  indicators: Record<string, string>;
  /** AI analysis result */
  aiResult: AnalysisResult;
}

/** A distilled Sigma rule ready to be loaded into the rule engine */
export interface DistilledRule {
  /** Unique rule ID based on pattern hash */
  ruleId: string;
  /** Pattern hash for dedup */
  patternHash: string;
  /** Sigma YAML content */
  sigmaYaml: string;
  /** Source attribution */
  source: 'ai-distilled';
  /** When the rule was created */
  createdAt: string;
  /** AI confidence that produced this rule */
  aiConfidence: number;
}

/** MITRE technique -> logsource product mapping */
const TECHNIQUE_LOGSOURCE: Record<string, { product: string; service: string }> = {
  T1110: { product: 'linux', service: 'auth' },
  T1021: { product: 'linux', service: 'auth' },
  T1046: { product: 'linux', service: 'network' },
  T1059: { product: 'linux', service: 'syslog' },
  T1190: { product: 'linux', service: 'webserver' },
  T1071: { product: 'linux', service: 'network' },
  T1048: { product: 'linux', service: 'network' },
};

/**
 * Knowledge Distiller converts AI results into Sigma rules
 */
export class KnowledgeDistiller {
  /** Previously distilled pattern hashes (dedup) */
  private readonly distilledPatterns = new Set<string>();
  private distilledCount = 0;

  /** Minimum AI confidence to create a rule (0-1) */
  private readonly minConfidence: number;

  /** Optional callback when a new rule is distilled */
  private readonly onRuleDistilled?: (rule: DistilledRule) => void;

  constructor(options?: {
    minConfidence?: number;
    onRuleDistilled?: (rule: DistilledRule) => void;
  }) {
    this.minConfidence = options?.minConfidence ?? 0.7;
    this.onRuleDistilled = options?.onRuleDistilled;
  }

  /**
   * Attempt to distill a Sigma rule from an AI analysis result.
   * Returns null if the pattern was already distilled or confidence is too low.
   */
  distill(input: DistillationInput): DistilledRule | null {
    // Skip low-confidence results
    if (input.aiResult.confidence < this.minConfidence) {
      logger.debug('Skipping distillation: AI confidence too low', {
        confidence: input.aiResult.confidence,
        threshold: this.minConfidence,
      });
      return null;
    }

    // Generate pattern hash for dedup
    const patternHash = this.computePatternHash(input);

    // Skip already-distilled patterns
    if (this.distilledPatterns.has(patternHash)) {
      logger.debug('Pattern already distilled', { patternHash });
      return null;
    }

    const ruleId = `ai-distilled-${patternHash}`;
    const sigmaYaml = this.generateSigmaRule(input, ruleId);

    const rule: DistilledRule = {
      ruleId,
      patternHash,
      sigmaYaml,
      source: 'ai-distilled',
      createdAt: new Date().toISOString(),
      aiConfidence: input.aiResult.confidence,
    };

    this.distilledPatterns.add(patternHash);
    this.distilledCount++;

    logger.info('New rule distilled from AI analysis', {
      ruleId,
      category: input.eventCategory,
      confidence: input.aiResult.confidence,
    });

    if (this.onRuleDistilled) {
      this.onRuleDistilled(rule);
    }

    return rule;
  }

  /**
   * Check if a pattern has already been distilled
   */
  isDistilled(input: DistillationInput): boolean {
    return this.distilledPatterns.has(this.computePatternHash(input));
  }

  /** Get count of distilled rules */
  getDistilledCount(): number {
    return this.distilledCount;
  }

  /** Get all distilled pattern hashes */
  getDistilledPatterns(): string[] {
    return [...this.distilledPatterns];
  }

  /**
   * Compute a stable hash for pattern dedup.
   * Based on: category + source + technique + sorted indicator keys
   */
  private computePatternHash(input: DistillationInput): string {
    const parts = [
      input.eventCategory,
      input.eventSource,
      input.mitreTechnique ?? 'unknown',
      ...Object.keys(input.indicators).sort(),
    ];
    return createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 12);
  }

  /**
   * Generate a Sigma YAML rule from AI analysis
   */
  private generateSigmaRule(input: DistillationInput, ruleId: string): string {
    const logsource = TECHNIQUE_LOGSOURCE[input.mitreTechnique ?? ''] ?? {
      product: 'panguard',
      service: 'guard',
    };

    const severity = this.mapSeverity(input.aiResult.severity);
    const technique = input.mitreTechnique ?? 'unknown';

    // Build detection selection from indicators
    const selectionEntries: string[] = [];
    selectionEntries.push(`    category: ${input.eventCategory}`);
    selectionEntries.push(`    source: ${input.eventSource}`);

    for (const [key, value] of Object.entries(input.indicators)) {
      // Sanitize YAML values
      const safeValue = value.replace(/['"]/g, '');
      if (safeValue.length > 0 && safeValue.length < 200) {
        selectionEntries.push(`    ${key}: "${safeValue}"`);
      }
    }

    const recommendations = input.aiResult.recommendations
      .slice(0, 3)
      .map((r) => `  - ${r}`)
      .join('\n');

    return [
      `title: "AI-Distilled: ${input.eventCategory} detection (${technique})"`,
      `id: ${ruleId}`,
      `status: experimental`,
      `author: Panguard AI Knowledge Distiller (auto-generated)`,
      `description: |`,
      `  Auto-generated from AI analysis with ${Math.round(input.aiResult.confidence * 100)}% confidence.`,
      `  ${input.aiResult.summary}`,
      recommendations.length > 0 ? `  Recommendations:\n${recommendations}` : '',
      `date: ${new Date().toISOString().slice(0, 10)}`,
      `logsource:`,
      `  product: ${logsource.product}`,
      `  service: ${logsource.service}`,
      `detection:`,
      `  selection:`,
      ...selectionEntries,
      `  condition: selection`,
      `level: ${severity}`,
      technique !== 'unknown'
        ? `tags:\n  - attack.${technique.toLowerCase()}`
        : '',
    ]
      .filter((line) => line.length > 0)
      .join('\n');
  }

  /** Map AI severity string to Sigma severity level */
  private mapSeverity(severity: string): string {
    const map: Record<string, string> = {
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      low: 'low',
      info: 'informational',
    };
    return map[severity.toLowerCase()] ?? 'medium';
  }
}
