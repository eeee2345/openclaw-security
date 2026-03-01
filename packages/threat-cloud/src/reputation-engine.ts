/**
 * IoC Reputation Scoring Engine
 * IoC 信譽評分引擎
 *
 * Calculates reputation scores using a weighted formula:
 *   sighting frequency, severity, recency (time-decay), source diversity, confidence.
 *
 * @module @panguard-ai/threat-cloud/reputation-engine
 */

import type Database from 'better-sqlite3';
import type { ReputationConfig } from './types.js';

/** Severity numeric mapping / 嚴重度數值對映 */
const SEVERITY_MAP: Record<string, number> = {
  critical: 100,
  high: 75,
  medium: 50,
  low: 25,
};

/** Default config / 預設配置 */
const DEFAULT_CONFIG: ReputationConfig = {
  halfLifeDays: 30,
  weights: {
    sighting: 0.3,
    severity: 0.25,
    recency: 0.2,
    diversity: 0.15,
    confidence: 0.1,
  },
};

/** Associated threat summary for an IoC / IoC 的關聯威脅摘要 */
interface AssociatedThreatSummary {
  totalThreats: number;
  severityCounts: Record<string, number>;
  uniqueSources: number;
  maxConfidence: number;
  latestTimestamp: string;
}

export class ReputationEngine {
  private readonly config: ReputationConfig;

  constructor(
    private readonly db: Database.Database,
    config?: Partial<ReputationConfig>
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    if (config?.weights) {
      this.config.weights = { ...DEFAULT_CONFIG.weights, ...config.weights };
    }
  }

  /**
   * Recalculate reputation scores for all active IoCs.
   * 重新計算所有活躍 IoC 的信譽分數
   */
  recalculateAll(): { updated: number; duration: number } {
    const startTime = Date.now();

    const iocs = this.db
      .prepare("SELECT id, sightings, confidence, last_seen FROM iocs WHERE status = 'active'")
      .all() as Array<{
      id: number;
      sightings: number;
      confidence: number;
      last_seen: string;
    }>;

    const updateStmt = this.db.prepare(
      "UPDATE iocs SET reputation_score = ?, updated_at = datetime('now') WHERE id = ?"
    );

    const updateAll = this.db.transaction(() => {
      for (const ioc of iocs) {
        const score = this.calculateScore(ioc);
        updateStmt.run(score, ioc.id);
      }
    });

    updateAll();

    return {
      updated: iocs.length,
      duration: Date.now() - startTime,
    };
  }

  /**
   * Calculate reputation for a single IoC by ID.
   * 計算單一 IoC 的信譽分數
   */
  calculateForIoC(iocId: number): number {
    const ioc = this.db
      .prepare(
        'SELECT id, sightings, confidence, last_seen, type, normalized_value FROM iocs WHERE id = ?'
      )
      .get(iocId) as
      | {
          id: number;
          sightings: number;
          confidence: number;
          last_seen: string;
          type: string;
          normalized_value: string;
        }
      | undefined;

    if (!ioc) return 0;
    return this.calculateScore(ioc);
  }

  /**
   * Core scoring algorithm.
   * 核心評分演算法
   */
  private calculateScore(ioc: {
    id: number;
    sightings: number;
    confidence: number;
    last_seen: string;
  }): number {
    const summary = this.getAssociatedThreats(ioc.id);
    const w = this.config.weights;

    // Sighting score: each sighting adds 5 pts, capped at 100
    const sightingScore = Math.min(100, ioc.sightings * 5);

    // Severity score: weighted average of associated threats
    const severityScore = this.computeSeverityScore(summary.severityCounts, summary.totalThreats);

    // Recency score: exponential decay with configurable half-life
    const recencyScore = this.computeRecencyScore(ioc.last_seen);

    // Diversity score: each unique source adds 25 pts, capped at 100
    const diversityScore = Math.min(100, summary.uniqueSources * 25);

    // Confidence score: max confidence across sightings
    const confidenceScore = Math.max(ioc.confidence, summary.maxConfidence);

    const rawScore =
      sightingScore * w.sighting +
      severityScore * w.severity +
      recencyScore * w.recency +
      diversityScore * w.diversity +
      confidenceScore * w.confidence;

    return Math.max(0, Math.min(100, Math.round(rawScore)));
  }

  /** Compute weighted severity score / 計算加權嚴重度分數 */
  private computeSeverityScore(
    severityCounts: Record<string, number>,
    totalThreats: number
  ): number {
    if (totalThreats === 0) return 0;

    let weightedSum = 0;
    for (const [severity, count] of Object.entries(severityCounts)) {
      weightedSum += (SEVERITY_MAP[severity] ?? 50) * count;
    }
    return weightedSum / totalThreats;
  }

  /** Compute recency score with exponential decay / 計算時間衰減分數 */
  private computeRecencyScore(lastSeen: string): number {
    const now = Date.now();
    const lastSeenMs = new Date(lastSeen).getTime();
    const daysSince = Math.max(0, (now - lastSeenMs) / (1000 * 60 * 60 * 24));
    const lambda = Math.LN2 / this.config.halfLifeDays;
    return 100 * Math.exp(-lambda * daysSince);
  }

  /**
   * Get associated threat data for an IoC.
   * 取得 IoC 的關聯威脅資料
   */
  private getAssociatedThreats(iocId: number): AssociatedThreatSummary {
    // Get the IoC's normalized value for matching
    const ioc = this.db
      .prepare('SELECT type, normalized_value FROM iocs WHERE id = ?')
      .get(iocId) as { type: string; normalized_value: string } | undefined;

    if (!ioc) {
      return {
        totalThreats: 0,
        severityCounts: {},
        uniqueSources: 0,
        maxConfidence: 0,
        latestTimestamp: '',
      };
    }

    // For IP-type IoCs, match against enriched_threats.attack_source_ip
    if (ioc.type === 'ip') {
      const rows = this.db
        .prepare(
          `SELECT severity, source_type, confidence, timestamp
           FROM enriched_threats
           WHERE attack_source_ip = ?`
        )
        .all(ioc.normalized_value) as Array<{
        severity: string;
        source_type: string;
        confidence: number;
        timestamp: string;
      }>;

      const severityCounts: Record<string, number> = {};
      const sources = new Set<string>();
      let maxConfidence = 0;
      let latestTimestamp = '';

      for (const row of rows) {
        severityCounts[row.severity] = (severityCounts[row.severity] ?? 0) + 1;
        sources.add(row.source_type);
        if (row.confidence > maxConfidence) maxConfidence = row.confidence;
        if (row.timestamp > latestTimestamp) latestTimestamp = row.timestamp;
      }

      return {
        totalThreats: rows.length,
        severityCounts,
        uniqueSources: sources.size,
        maxConfidence,
        latestTimestamp,
      };
    }

    // For non-IP types, no associated threats (future: match by metadata)
    return {
      totalThreats: 0,
      severityCounts: {},
      uniqueSources: 0,
      maxConfidence: 0,
      latestTimestamp: '',
    };
  }
}
