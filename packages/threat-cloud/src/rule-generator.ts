/**
 * Automatic Sigma Rule Generator
 * 自動 Sigma 規則產生器
 *
 * Analyzes enriched threat events, detects recurring patterns,
 * and generates Sigma detection rules automatically.
 *
 * @module @panguard-ai/threat-cloud/rule-generator
 */

import { createHash } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { DetectedPattern, RuleGenerationResult, RuleGeneratorConfig } from './types.js';

/** MITRE technique → tactic mapping (simplified) */
const TECHNIQUE_TACTIC_MAP: Record<string, string> = {
  T1110: 'credential_access',
  T1021: 'lateral_movement',
  T1046: 'discovery',
  T1059: 'execution',
  T1486: 'impact',
  T1190: 'initial_access',
  T1078: 'defense_evasion',
  T1071: 'command_and_control',
  T1048: 'exfiltration',
  T1569: 'execution',
  T1053: 'execution',
  T1543: 'persistence',
  T1547: 'persistence',
  T1098: 'persistence',
  T1027: 'defense_evasion',
  T1070: 'defense_evasion',
  T1562: 'defense_evasion',
  T1018: 'discovery',
  T1057: 'discovery',
  T1082: 'discovery',
  T1560: 'collection',
};

/** Severity mapping for pattern analysis */
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

/** Default configuration */
const DEFAULT_CONFIG: RuleGeneratorConfig = {
  minOccurrences: 10,
  analysisWindowHours: 168, // 7 days
  minDistinctIPs: 3,
};

export class RuleGenerator {
  private readonly config: RuleGeneratorConfig;

  constructor(
    private readonly db: Database.Database,
    config?: Partial<RuleGeneratorConfig>
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Analyze recent events and generate rules for recurring patterns.
   * 分析近期事件並為反覆出現的模式產生規則
   */
  generateRules(): RuleGenerationResult {
    const startTime = Date.now();

    const patterns = this.detectPatterns();
    let rulesGenerated = 0;
    let rulesUpdated = 0;

    this.db.transaction(() => {
      for (const pattern of patterns) {
        const existing = this.db
          .prepare('SELECT pattern_hash FROM generated_patterns WHERE pattern_hash = ?')
          .get(pattern.patternHash) as { pattern_hash: string } | undefined;

        if (existing) {
          this.updatePattern(pattern);
          rulesUpdated++;
        } else {
          this.createRuleFromPattern(pattern);
          rulesGenerated++;
        }
      }
    })();

    return {
      patternsAnalyzed: patterns.length,
      rulesGenerated,
      rulesUpdated,
      duration: Date.now() - startTime,
    };
  }

  /**
   * Detect recurring patterns in enriched threat events.
   * 偵測豐富化威脅事件中的反覆模式
   */
  detectPatterns(): DetectedPattern[] {
    const sinceDate = new Date(
      Date.now() - this.config.analysisWindowHours * 60 * 60 * 1000
    ).toISOString();

    const rows = this.db
      .prepare(
        `SELECT attack_type, mitre_techniques, attack_source_ip, region, severity, timestamp
         FROM enriched_threats
         WHERE received_at > ?
         ORDER BY timestamp ASC`
      )
      .all(sinceDate) as Array<{
      attack_type: string;
      mitre_techniques: string;
      attack_source_ip: string;
      region: string;
      severity: string;
      timestamp: string;
    }>;

    // Group by (attack_type, sorted mitre_techniques)
    const grouped = new Map<
      string,
      {
        attackType: string;
        techniques: string[];
        ips: Set<string>;
        regions: Set<string>;
        severityCounts: Record<string, number>;
        occurrences: number;
        firstSeen: string;
        lastSeen: string;
      }
    >();

    for (const row of rows) {
      const techniques = (JSON.parse(row.mitre_techniques) as string[]).sort();
      const key = `${row.attack_type}|${techniques.join(',')}`;

      let group = grouped.get(key);
      if (!group) {
        group = {
          attackType: row.attack_type,
          techniques,
          ips: new Set<string>(),
          regions: new Set<string>(),
          severityCounts: {},
          occurrences: 0,
          firstSeen: row.timestamp,
          lastSeen: row.timestamp,
        };
        grouped.set(key, group);
      }

      group.ips.add(row.attack_source_ip);
      group.regions.add(row.region);
      group.severityCounts[row.severity] = (group.severityCounts[row.severity] ?? 0) + 1;
      group.occurrences++;
      if (row.timestamp > group.lastSeen) group.lastSeen = row.timestamp;
    }

    // Filter by thresholds
    const patterns: DetectedPattern[] = [];
    for (const group of grouped.values()) {
      if (
        group.occurrences >= this.config.minOccurrences &&
        group.ips.size >= this.config.minDistinctIPs
      ) {
        const patternHash = createHash('sha256')
          .update(group.attackType + group.techniques.join(','))
          .digest('hex')
          .slice(0, 16);

        patterns.push({
          attackType: group.attackType,
          mitreTechniques: group.techniques,
          patternHash,
          occurrences: group.occurrences,
          distinctIPs: group.ips.size,
          regions: [...group.regions],
          severityCounts: group.severityCounts,
          firstSeen: group.firstSeen,
          lastSeen: group.lastSeen,
        });
      }
    }

    return patterns;
  }

  /**
   * Get all generated patterns.
   * 取得所有已產生的模式
   */
  getGeneratedPatterns(): Array<{
    patternHash: string;
    attackType: string;
    mitreTechniques: string[];
    ruleId: string;
    occurrences: number;
    distinctIPs: number;
  }> {
    const rows = this.db
      .prepare(
        `SELECT pattern_hash, attack_type, mitre_techniques, rule_id, occurrences, distinct_ips
         FROM generated_patterns
         ORDER BY occurrences DESC`
      )
      .all() as Array<{
      pattern_hash: string;
      attack_type: string;
      mitre_techniques: string;
      rule_id: string;
      occurrences: number;
      distinct_ips: number;
    }>;

    return rows.map((r) => ({
      patternHash: r.pattern_hash,
      attackType: r.attack_type,
      mitreTechniques: JSON.parse(r.mitre_techniques) as string[],
      ruleId: r.rule_id,
      occurrences: r.occurrences,
      distinctIPs: r.distinct_ips,
    }));
  }

  // -------------------------------------------------------------------------
  // Private helpers / 私有輔助方法
  // -------------------------------------------------------------------------

  /** Create a new rule from a detected pattern */
  private createRuleFromPattern(pattern: DetectedPattern): void {
    const ruleId = `tc-auto-${pattern.patternHash}`;
    const severity = this.pickMaxSeverity(pattern.severityCounts);
    const sigmaYaml = this.generateSigmaYaml(pattern, ruleId, severity);

    // Insert into rules table
    this.db
      .prepare(
        `INSERT INTO rules (rule_id, rule_content, published_at, source)
         VALUES (?, ?, datetime('now'), 'threat-cloud-auto')
         ON CONFLICT(rule_id) DO UPDATE SET
           rule_content = excluded.rule_content,
           published_at = excluded.published_at,
           updated_at = datetime('now')`
      )
      .run(ruleId, sigmaYaml);

    // Insert into generated_patterns table
    this.db
      .prepare(
        `INSERT INTO generated_patterns
          (pattern_hash, attack_type, mitre_techniques, rule_id, occurrences, distinct_ips, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        pattern.patternHash,
        pattern.attackType,
        JSON.stringify(pattern.mitreTechniques),
        ruleId,
        pattern.occurrences,
        pattern.distinctIPs,
        pattern.firstSeen,
        pattern.lastSeen
      );
  }

  /** Update an existing pattern's statistics */
  private updatePattern(pattern: DetectedPattern): void {
    this.db
      .prepare(
        `UPDATE generated_patterns SET
           occurrences = ?,
           distinct_ips = ?,
           last_seen = ?,
           updated_at = datetime('now')
         WHERE pattern_hash = ?`
      )
      .run(pattern.occurrences, pattern.distinctIPs, pattern.lastSeen, pattern.patternHash);

    // Also update the rule content
    const ruleId = `tc-auto-${pattern.patternHash}`;
    const severity = this.pickMaxSeverity(pattern.severityCounts);
    const sigmaYaml = this.generateSigmaYaml(pattern, ruleId, severity);

    this.db
      .prepare(
        `UPDATE rules SET rule_content = ?, published_at = datetime('now'), updated_at = datetime('now')
         WHERE rule_id = ?`
      )
      .run(sigmaYaml, ruleId);
  }

  /** Generate Sigma YAML rule content */
  private generateSigmaYaml(pattern: DetectedPattern, ruleId: string, severity: string): string {
    const tags = pattern.mitreTechniques.map((t) => {
      const tactic = TECHNIQUE_TACTIC_MAP[t] ?? 'unknown';
      return `  - attack.${tactic}\n  - attack.${t.toLowerCase()}`;
    });

    const regionList = pattern.regions.join(', ');

    return [
      `title: "Threat Cloud Auto: ${pattern.attackType} via ${pattern.mitreTechniques.join(', ')}"`,
      `id: ${ruleId}`,
      `status: experimental`,
      `author: Panguard Threat Cloud (auto-generated)`,
      `description: |`,
      `  Pattern observed ${pattern.occurrences} times from ${pattern.distinctIPs} distinct IPs across ${regionList}.`,
      `date: ${new Date().toISOString().slice(0, 10)}`,
      `detection:`,
      `  selection:`,
      `    EventType: ${pattern.attackType}`,
      `  condition: selection`,
      `level: ${severity}`,
      `tags:`,
      ...tags,
    ].join('\n');
  }

  /** Pick highest severity from counts */
  private pickMaxSeverity(severityCounts: Record<string, number>): string {
    for (const s of SEVERITY_ORDER) {
      if (severityCounts[s] && severityCounts[s] > 0) return s;
    }
    return 'medium';
  }
}
