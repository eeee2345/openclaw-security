/**
 * Sigma Rule Validator & Deduplicator
 * Sigma 規則驗證器與去重器
 *
 * Validates generated Sigma rules for:
 * - Required fields (title, id, detection, level, logsource)
 * - Detection block structure
 * - YAML syntax
 * - Duplicate detection against existing rules
 *
 * @module @panguard-ai/threat-cloud/threat-intel/rule-validator
 */

import { createHash } from 'node:crypto';
import type { GeneratedRule, RuleValidationResult } from './types.js';

/** Required top-level fields in a Sigma rule YAML */
const REQUIRED_FIELDS = ['title', 'id', 'detection', 'level', 'logsource'];

/** Valid Sigma levels */
const VALID_LEVELS = new Set(['informational', 'low', 'medium', 'high', 'critical']);

/** Valid Sigma statuses */
const VALID_STATUSES = new Set(['experimental', 'test', 'stable']);

export class RuleValidator {
  /** Fingerprints of existing rules for dedup (hash of detection block) */
  private readonly existingFingerprints = new Map<string, string>();

  /**
   * Register existing rules for deduplication.
   * Call this before validating new rules.
   */
  registerExistingRules(rules: Array<{ id: string; yamlContent: string }>): void {
    for (const rule of rules) {
      const fp = this.fingerprint(rule.yamlContent);
      this.existingFingerprints.set(fp, rule.id);
    }
  }

  /**
   * Validate a generated rule.
   * Checks syntax, required fields, and duplicates.
   */
  validate(rule: GeneratedRule): RuleValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const yaml = rule.yamlContent;

    // Check required fields
    for (const field of REQUIRED_FIELDS) {
      const regex = new RegExp(`^${field}:`, 'm');
      if (!regex.test(yaml)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // Check detection block has a condition
    if (!/condition:\s*.+/m.test(yaml)) {
      errors.push('Detection block missing condition');
    }

    // Check detection has at least one selection
    if (!/selection[^:]*:/m.test(yaml)) {
      errors.push('Detection block missing selection');
    }

    // Validate level
    const levelMatch = yaml.match(/^level:\s*(\S+)/m);
    if (levelMatch?.[1] && !VALID_LEVELS.has(levelMatch[1])) {
      errors.push(`Invalid level: ${levelMatch[1]}`);
    }

    // Validate status
    const statusMatch = yaml.match(/^status:\s*(\S+)/m);
    if (statusMatch?.[1] && !VALID_STATUSES.has(statusMatch[1])) {
      warnings.push(`Non-standard status: ${statusMatch[1]}`);
    }

    // Check for empty payload signatures (standalone "contains:" with no values on next lines)
    // Match lines where contains: is a standalone key (not a field modifier like cs-uri|contains:)
    if (/^\s+contains:\s*$/m.test(yaml)) {
      errors.push('Selection has empty payload list');
    }

    // Check title is not empty
    const titleMatch = yaml.match(/^title:\s*(.*)/m);
    if (titleMatch?.[1] && titleMatch[1].trim().length === 0) {
      errors.push('Title is empty');
    }

    // Validate logsource has category
    if (!/category:\s*\S+/m.test(yaml)) {
      warnings.push('Logsource missing category');
    }

    // Confidence warnings
    if (rule.confidence < 50) {
      warnings.push(`Low confidence (${rule.confidence}%) - may produce false positives`);
    }

    // Deduplication check
    const fp = this.fingerprint(yaml);
    const duplicateOf = this.existingFingerprints.get(fp) ?? null;
    const isDuplicate = duplicateOf !== null && duplicateOf !== rule.id;

    if (!isDuplicate) {
      // Register this rule for future dedup checks
      this.existingFingerprints.set(fp, rule.id);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      isDuplicate,
      duplicateOf,
    };
  }

  /**
   * Generate a fingerprint of a rule's detection block for dedup.
   * Normalizes whitespace and extracts the detection section.
   */
  private fingerprint(yaml: string): string {
    // Extract detection block (from "detection:" to next top-level key or EOF)
    const detectionMatch = yaml.match(/^detection:\s*\n([\s\S]*?)(?=^\w|\Z)/m);
    const detectionBlock = detectionMatch?.[1] ?? yaml;

    // Normalize: lowercase, collapse whitespace, trim lines
    const normalized = detectionBlock
      .toLowerCase()
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .join('\n');

    return createHash('sha256').update(normalized).digest('hex').slice(0, 16);
  }
}
