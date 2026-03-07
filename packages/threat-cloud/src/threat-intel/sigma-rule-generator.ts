/**
 * Sigma Rule Generator from Extracted Attack Patterns
 * 從萃取的攻擊模式生成 Sigma 偵測規則
 *
 * Converts extracted attack patterns into valid Sigma YAML rules
 * with proper MITRE ATT&CK tagging and detection logic.
 *
 * @module @panguard-ai/threat-cloud/threat-intel/sigma-rule-generator
 */

import { randomUUID } from 'node:crypto';
import type { ExtractedAttackPattern, ExtractionResult, GeneratedRule } from './types.js';

/** MITRE technique ID → tactic name for Sigma tags */
const TECHNIQUE_TACTIC: Record<string, string> = {
  T1190: 'initial_access',
  T1059: 'execution',
  'T1059.001': 'execution',
  'T1059.007': 'execution',
  T1068: 'privilege_escalation',
  T1071: 'command_and_control',
  T1078: 'defense_evasion',
  T1082: 'discovery',
  T1083: 'discovery',
  T1105: 'command_and_control',
  T1185: 'collection',
  T1499: 'impact',
  'T1566.002': 'initial_access',
};

/** Severity mapping from report severity to Sigma level */
const SEVERITY_TO_LEVEL: Record<string, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  none: 'informational',
};

export class SigmaRuleGenerator {
  /**
   * Generate Sigma rules from an extraction result.
   * Each pattern produces one rule.
   */
  generate(extraction: ExtractionResult): GeneratedRule[] {
    return extraction.patterns
      .filter((p) => p.payloadSignatures.length > 0 || p.endpointPatterns.length > 0)
      .map((pattern) => this.patternToRule(pattern, extraction));
  }

  /** Convert a single extracted pattern to a GeneratedRule */
  private patternToRule(
    pattern: ExtractedAttackPattern,
    extraction: ExtractionResult
  ): GeneratedRule {
    const ruleId = randomUUID();
    const status = pattern.confidence >= 70 ? 'experimental' : 'draft';
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '/');

    const yamlContent = this.buildYaml(ruleId, pattern, extraction, date);

    return {
      id: ruleId,
      yamlContent,
      sourceReportId: extraction.reportId,
      sourceReportUrl: extraction.reportUrl,
      attackType: pattern.attackType,
      confidence: pattern.confidence,
      status,
      generatedAt: new Date().toISOString(),
      reviewed: false,
      reviewDecision: 'pending',
    };
  }

  /** Build the YAML content for a Sigma rule */
  private buildYaml(
    ruleId: string,
    pattern: ExtractedAttackPattern,
    extraction: ExtractionResult,
    date: string
  ): string {
    const lines: string[] = [];

    // Header
    lines.push(`title: ${this.escapeYaml(this.buildTitle(pattern))}`);
    lines.push(`id: ${ruleId}`);
    lines.push(`status: experimental`);
    lines.push('description: |');
    lines.push(`  ${this.escapeYaml(pattern.description)}`);
    lines.push(`  Auto-generated from HackerOne report analysis.`);

    // References
    lines.push('references:');
    lines.push(`  - ${extraction.reportUrl}`);

    // Author & date
    lines.push('author: Panguard Threat Intel (auto-generated)');
    lines.push(`date: ${date}`);

    // Tags
    const tags = this.buildTags(pattern);
    if (tags.length > 0) {
      lines.push('tags:');
      for (const tag of tags) {
        lines.push(`  - ${tag}`);
      }
    }

    // Log source
    lines.push('logsource:');
    lines.push(`  category: ${pattern.logSourceCategory}`);
    if (pattern.logSourceProduct !== 'any') {
      lines.push(`  product: ${pattern.logSourceProduct}`);
    }

    // Detection
    const detection = this.buildDetection(pattern);
    lines.push('detection:');
    lines.push(detection);

    // False positives
    lines.push('falsepositives:');
    lines.push('  - Legitimate internal API calls');
    lines.push('  - Development/testing environments');

    // Level
    const level = this.inferLevel(pattern);
    lines.push(`level: ${level}`);

    return lines.join('\n');
  }

  /** Build a descriptive title */
  private buildTitle(pattern: ExtractedAttackPattern): string {
    switch (pattern.attackType) {
      case 'SSRF':
        return 'Potential SSRF via Internal Network Access';
      case 'XSS':
        return 'Potential Cross-Site Scripting (XSS) Attempt';
      case 'SQLi':
        return 'Potential SQL Injection Attempt';
      case 'Command Injection':
        return 'Potential OS Command Injection';
      case 'Path Traversal':
        return 'Potential Directory/Path Traversal Attempt';
      case 'XXE':
        return 'Potential XML External Entity (XXE) Injection';
      case 'IDOR':
        return 'Potential Insecure Direct Object Reference';
      case 'CSRF':
        return 'Potential Cross-Site Request Forgery';
      case 'File Upload':
        return 'Potential Malicious File Upload Attempt';
      case 'Open Redirect':
        return 'Potential Open Redirect Attempt';
      case 'Auth Bypass':
        return 'Potential Authentication Bypass Attempt';
      case 'Deserialization':
        return 'Potential Insecure Deserialization Attack';
      case 'Privilege Escalation':
        return 'Potential Privilege Escalation Attempt';
      default:
        return `Potential ${pattern.attackType} Attack`;
    }
  }

  /** Build MITRE ATT&CK tags */
  private buildTags(pattern: ExtractedAttackPattern): string[] {
    const tags: string[] = [];
    const addedTactics = new Set<string>();

    for (const technique of pattern.mitreTechniques) {
      const tactic = TECHNIQUE_TACTIC[technique];
      if (tactic && !addedTactics.has(tactic)) {
        tags.push(`attack.${tactic}`);
        addedTactics.add(tactic);
      }
      tags.push(`attack.${technique.toLowerCase()}`);
    }

    for (const cwe of pattern.cweIds) {
      const num = cwe.replace(/\D/g, '');
      if (num) tags.push(`cwe.${num}`);
    }

    return tags;
  }

  /** Build detection block based on attack type */
  private buildDetection(pattern: ExtractedAttackPattern): string {
    const lines: string[] = [];

    if (pattern.attackType === 'SSRF' || pattern.attackType === 'Open Redirect') {
      // URI query/body contains internal IPs or redirect targets
      lines.push('  selection:');
      lines.push('    cs-uri-query|contains:');
      for (const sig of pattern.payloadSignatures) {
        lines.push(`      - '${this.escapeYamlValue(sig)}'`);
      }
      if (pattern.endpointPatterns.length > 0) {
        lines.push('  filter_endpoint:');
        lines.push('    cs-uri-stem|contains:');
        for (const ep of pattern.endpointPatterns) {
          lines.push(`      - '${this.escapeYamlValue(ep)}'`);
        }
        lines.push('  condition: selection and filter_endpoint');
      } else {
        lines.push('  condition: selection');
      }
    } else if (pattern.attackType === 'XSS') {
      lines.push('  selection_query:');
      lines.push('    cs-uri-query|contains:');
      for (const sig of pattern.payloadSignatures.slice(0, 6)) {
        lines.push(`      - '${this.escapeYamlValue(sig)}'`);
      }
      lines.push('  selection_body:');
      lines.push('    cs-body|contains:');
      for (const sig of pattern.payloadSignatures.slice(0, 6)) {
        lines.push(`      - '${this.escapeYamlValue(sig)}'`);
      }
      lines.push('  condition: selection_query or selection_body');
    } else if (pattern.attackType === 'SQLi') {
      lines.push('  selection:');
      lines.push('    cs-uri-query|contains:');
      for (const sig of pattern.payloadSignatures) {
        lines.push(`      - '${this.escapeYamlValue(sig)}'`);
      }
      lines.push('  condition: selection');
    } else if (pattern.attackType === 'Path Traversal') {
      lines.push('  selection:');
      lines.push('    cs-uri|contains:');
      for (const sig of pattern.payloadSignatures) {
        lines.push(`      - '${this.escapeYamlValue(sig)}'`);
      }
      lines.push('  condition: selection');
    } else if (pattern.attackType === 'Command Injection') {
      lines.push('  selection:');
      lines.push('    cs-uri-query|contains:');
      for (const sig of pattern.payloadSignatures) {
        lines.push(`      - '${this.escapeYamlValue(sig)}'`);
      }
      lines.push('  condition: selection');
    } else if (pattern.attackType === 'XXE') {
      lines.push('  selection:');
      lines.push('    cs-body|contains:');
      for (const sig of pattern.payloadSignatures) {
        lines.push(`      - '${this.escapeYamlValue(sig)}'`);
      }
      lines.push('  condition: selection');
    } else if (pattern.attackType === 'File Upload') {
      lines.push('  selection_method:');
      lines.push("    cs-method: 'POST'");
      lines.push('  selection_ext:');
      lines.push('    cs-uri|endswith:');
      for (const sig of pattern.payloadSignatures) {
        lines.push(`      - '${this.escapeYamlValue(sig)}'`);
      }
      lines.push('  condition: selection_method and selection_ext');
    } else {
      // Generic: payload signatures in URI query
      if (pattern.payloadSignatures.length > 0) {
        lines.push('  selection:');
        lines.push('    cs-uri-query|contains:');
        for (const sig of pattern.payloadSignatures) {
          lines.push(`      - '${this.escapeYamlValue(sig)}'`);
        }
        lines.push('  condition: selection');
      } else if (pattern.endpointPatterns.length > 0) {
        lines.push('  selection:');
        lines.push('    cs-uri-stem|contains:');
        for (const ep of pattern.endpointPatterns) {
          lines.push(`      - '${this.escapeYamlValue(ep)}'`);
        }
        lines.push('  condition: selection');
      } else {
        lines.push('  selection:');
        lines.push("    cs-uri-query|contains: '*'");
        lines.push('  condition: selection');
      }
    }

    return lines.join('\n');
  }

  /** Infer Sigma level from pattern confidence and attack type */
  private inferLevel(pattern: ExtractedAttackPattern): string {
    if (pattern.confidence >= 80) return 'high';
    if (pattern.confidence >= 60) return 'medium';
    return 'low';
  }

  /** Escape YAML special characters in values */
  private escapeYaml(value: string): string {
    if (/[:#{}[\],&*?|>!%@`]/.test(value) || value.startsWith("'") || value.startsWith('"')) {
      return `"${value.replace(/"/g, '\\"')}"`;
    }
    return value;
  }

  /** Escape a value for use inside single-quoted YAML string */
  private escapeYamlValue(value: string): string {
    return value.replace(/'/g, "''");
  }
}
