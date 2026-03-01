/**
 * ThreatAggregator - Collects and correlates threats from multiple Guard agents
 * ThreatAggregator - 從多個 Guard 代理收集並關聯威脅
 *
 * Performs cross-agent correlation to detect coordinated attacks:
 * - Same source IP appearing across different agents
 * - Same malware hash detected on different endpoints
 * - Same MITRE ATT&CK technique from same source
 *
 * @module @panguard-ai/manager/threat-aggregator
 */

import { createLogger } from '@panguard-ai/core';
import { generateThreatId, extractSourceIP, extractFileHash } from './utils.js';
import type {
  ThreatReport,
  ThreatEvent,
  AggregatedThreat,
  CorrelationMatch,
  ThreatSummary,
} from './types.js';

const logger = createLogger('panguard-manager:aggregator');

/**
 * Index entry for fast correlation lookups.
 */
interface IndexEntry {
  readonly threatId: string;
  readonly agentId: string;
}

/**
 * Aggregates threats from multiple agents and performs cross-agent correlation.
 *
 * Uses secondary indexes (IP index, hash index) for O(1) correlation lookups
 * instead of O(n^2) pairwise comparison.
 */
export class ThreatAggregator {
  private readonly threats: Map<string, AggregatedThreat>;
  private readonly correlations: CorrelationMatch[];

  // Secondary indexes for fast correlation / 快速關聯的二級索引
  private readonly ipIndex: Map<string, IndexEntry[]>;
  private readonly hashIndex: Map<string, IndexEntry[]>;
  private readonly categoryIndex: Map<string, IndexEntry[]>;

  // Configuration / 配置
  private readonly correlationWindowMs: number;
  private readonly retentionMs: number;

  constructor(correlationWindowMs: number, retentionMs: number) {
    this.threats = new Map();
    this.correlations = [];
    this.ipIndex = new Map();
    this.hashIndex = new Map();
    this.categoryIndex = new Map();
    this.correlationWindowMs = correlationWindowMs;
    this.retentionMs = retentionMs;
  }

  /**
   * Ingest a threat report from a Guard agent.
   * Each threat event is stored as an AggregatedThreat and indexed
   * for correlation. Cross-agent matches are detected during ingestion.
   *
   * @param report - The threat report containing one or more events
   * @param hostname - The hostname of the reporting agent
   * @returns Array of newly created AggregatedThreats
   */
  ingestReport(
    report: ThreatReport,
    hostname: string
  ): readonly AggregatedThreat[] {
    const newThreats: AggregatedThreat[] = [];

    for (const threat of report.threats) {
      const threatId = generateThreatId();
      const now = new Date().toISOString();

      const aggregated: AggregatedThreat = {
        id: threatId,
        originalThreat: {
          event: { ...threat.event, metadata: { ...threat.event.metadata } },
          verdict: { ...threat.verdict },
        },
        sourceAgentId: report.agentId,
        sourceHostname: hostname,
        receivedAt: now,
        correlatedWith: [],
      };

      this.threats.set(threatId, aggregated);

      // Index for correlation / 索引以供關聯
      const indexEntry: IndexEntry = {
        threatId,
        agentId: report.agentId,
      };

      this.indexThreat(indexEntry, threat);

      // Find correlations for this new threat / 為此新威脅尋找關聯
      const correlatedIds = this.findCorrelations(
        indexEntry,
        threat,
        report.agentId
      );

      if (correlatedIds.length > 0) {
        // Update the new threat with correlation data (immutable)
        const withCorrelation: AggregatedThreat = {
          ...aggregated,
          correlatedWith: correlatedIds,
        };
        this.threats.set(threatId, withCorrelation);

        // Update each correlated threat to reference back
        for (const correlatedId of correlatedIds) {
          const existing = this.threats.get(correlatedId);
          if (existing) {
            const updated: AggregatedThreat = {
              ...existing,
              correlatedWith: [...existing.correlatedWith, threatId],
            };
            this.threats.set(correlatedId, updated);
          }
        }

        newThreats.push(withCorrelation);

        logger.warn(
          `Cross-agent correlation detected: threat ${threatId} correlates with ` +
            `[${correlatedIds.join(', ')}] / ` +
            `跨代理關聯偵測: 威脅 ${threatId} 與 [${correlatedIds.join(', ')}] 相關`
        );
      } else {
        newThreats.push(aggregated);
      }
    }

    return newThreats;
  }

  /**
   * Index a threat for correlation lookups.
   */
  private indexThreat(entry: IndexEntry, threat: ThreatEvent): void {
    const metadata = threat.event.metadata;

    // Index by source IP / 依來源 IP 索引
    const sourceIP = extractSourceIP(metadata);
    if (sourceIP) {
      const existing = this.ipIndex.get(sourceIP) ?? [];
      this.ipIndex.set(sourceIP, [...existing, entry]);
    }

    // Index by file hash / 依檔案雜湊索引
    const fileHash = extractFileHash(metadata);
    if (fileHash) {
      const existing = this.hashIndex.get(fileHash) ?? [];
      this.hashIndex.set(fileHash, [...existing, entry]);
    }

    // Index by attack category / 依攻擊類別索引
    const category = threat.event.category;
    if (category) {
      const key = `${category}:${sourceIP ?? 'unknown'}`;
      const existing = this.categoryIndex.get(key) ?? [];
      this.categoryIndex.set(key, [...existing, entry]);
    }
  }

  /**
   * Find existing threats that correlate with a new threat.
   * Only matches threats from DIFFERENT agents within the correlation window.
   */
  private findCorrelations(
    newEntry: IndexEntry,
    threat: ThreatEvent,
    agentId: string
  ): readonly string[] {
    const correlatedIds = new Set<string>();
    const metadata = threat.event.metadata;
    const now = Date.now();

    // Check IP correlation / 檢查 IP 關聯
    const sourceIP = extractSourceIP(metadata);
    if (sourceIP) {
      const ipEntries = this.ipIndex.get(sourceIP) ?? [];
      for (const entry of ipEntries) {
        if (entry.threatId === newEntry.threatId) continue;
        if (entry.agentId === agentId) continue; // Same agent, skip

        const existing = this.threats.get(entry.threatId);
        if (!existing) continue;

        const elapsed = now - new Date(existing.receivedAt).getTime();
        if (elapsed > this.correlationWindowMs) continue;

        correlatedIds.add(entry.threatId);
        this.correlations.push({
          threatIdA: newEntry.threatId,
          threatIdB: entry.threatId,
          correlationType: 'same_source_ip',
          sharedIndicator: sourceIP,
        });
      }
    }

    // Check hash correlation / 檢查雜湊關聯
    const fileHash = extractFileHash(metadata);
    if (fileHash) {
      const hashEntries = this.hashIndex.get(fileHash) ?? [];
      for (const entry of hashEntries) {
        if (entry.threatId === newEntry.threatId) continue;
        if (entry.agentId === agentId) continue;

        const existing = this.threats.get(entry.threatId);
        if (!existing) continue;

        const elapsed = now - new Date(existing.receivedAt).getTime();
        if (elapsed > this.correlationWindowMs) continue;

        if (!correlatedIds.has(entry.threatId)) {
          correlatedIds.add(entry.threatId);
          this.correlations.push({
            threatIdA: newEntry.threatId,
            threatIdB: entry.threatId,
            correlationType: 'same_malware_hash',
            sharedIndicator: fileHash,
          });
        }
      }
    }

    // Check attack pattern correlation (same category + same source IP from different agents)
    // 檢查攻擊模式關聯（相同類別 + 相同來源 IP 來自不同代理）
    const category = threat.event.category;
    if (category && sourceIP) {
      const key = `${category}:${sourceIP}`;
      const catEntries = this.categoryIndex.get(key) ?? [];
      for (const entry of catEntries) {
        if (entry.threatId === newEntry.threatId) continue;
        if (entry.agentId === agentId) continue;

        const existing = this.threats.get(entry.threatId);
        if (!existing) continue;

        const elapsed = now - new Date(existing.receivedAt).getTime();
        if (elapsed > this.correlationWindowMs) continue;

        if (!correlatedIds.has(entry.threatId)) {
          correlatedIds.add(entry.threatId);
          this.correlations.push({
            threatIdA: newEntry.threatId,
            threatIdB: entry.threatId,
            correlationType: 'same_attack_pattern',
            sharedIndicator: key,
          });
        }
      }
    }

    return Array.from(correlatedIds);
  }

  /**
   * Get all threats received since a given timestamp.
   *
   * @param since - Date threshold for filtering
   * @returns Array of immutable AggregatedThreat copies
   */
  getRecentThreats(since: Date): readonly AggregatedThreat[] {
    const sinceMs = since.getTime();
    return Array.from(this.threats.values())
      .filter((t) => new Date(t.receivedAt).getTime() >= sinceMs)
      .map((t) => ({
        ...t,
        correlatedWith: [...t.correlatedWith],
      }));
  }

  /**
   * Get all threats reported by a specific agent.
   *
   * @param agentId - The agent's unique identifier
   * @returns Array of immutable AggregatedThreat copies
   */
  getThreatsByAgent(agentId: string): readonly AggregatedThreat[] {
    return Array.from(this.threats.values())
      .filter((t) => t.sourceAgentId === agentId)
      .map((t) => ({
        ...t,
        correlatedWith: [...t.correlatedWith],
      }));
  }

  /**
   * Get all correlation matches.
   *
   * @returns Immutable array of correlation match records
   */
  getCorrelations(): readonly CorrelationMatch[] {
    return this.correlations.map((c) => ({ ...c }));
  }

  /**
   * Generate a summary of the current threat landscape.
   *
   * @returns Immutable threat summary object
   */
  getSummary(): ThreatSummary {
    let criticalCount = 0;
    let highCount = 0;
    let suspiciousCount = 0;
    const uniqueAttackers = new Set<string>();
    const affectedAgentIds = new Set<string>();
    const correlatedGroups = new Set<string>();

    for (const threat of this.threats.values()) {
      const verdict = threat.originalThreat.verdict;
      const severity = threat.originalThreat.event.severity;

      if (severity === 'critical') criticalCount++;
      if (severity === 'high') highCount++;
      if (verdict.conclusion === 'suspicious') suspiciousCount++;

      const sourceIP = extractSourceIP(threat.originalThreat.event.metadata);
      if (sourceIP) {
        uniqueAttackers.add(sourceIP);
      }

      affectedAgentIds.add(threat.sourceAgentId);

      // Track correlated groups (use sorted pair as key)
      for (const correlatedId of threat.correlatedWith) {
        const groupKey = [threat.id, correlatedId].sort().join(':');
        correlatedGroups.add(groupKey);
      }
    }

    return {
      totalThreats: this.threats.size,
      criticalCount,
      highCount,
      suspiciousCount,
      uniqueAttackers: uniqueAttackers.size,
      affectedAgents: affectedAgentIds.size,
      correlatedGroups: correlatedGroups.size,
    };
  }

  /**
   * Purge threats older than the retention period.
   * Also cleans up corresponding index entries.
   *
   * @returns Number of threats purged
   */
  purgeExpired(): number {
    const cutoff = Date.now() - this.retentionMs;
    const toRemove: string[] = [];

    for (const [id, threat] of this.threats.entries()) {
      if (new Date(threat.receivedAt).getTime() <= cutoff) {
        toRemove.push(id);
      }
    }

    for (const id of toRemove) {
      this.threats.delete(id);
    }

    // Rebuild indexes after purge if significant portion removed
    if (toRemove.length > 0) {
      this.rebuildIndexes();
    }

    if (toRemove.length > 0) {
      logger.info(
        `Purged ${toRemove.length} expired threats / ` +
          `清除了 ${toRemove.length} 個過期威脅`
      );
    }

    return toRemove.length;
  }

  /**
   * Rebuild all secondary indexes from the current threat data.
   */
  private rebuildIndexes(): void {
    this.ipIndex.clear();
    this.hashIndex.clear();
    this.categoryIndex.clear();

    for (const [, threat] of this.threats.entries()) {
      const entry: IndexEntry = {
        threatId: threat.id,
        agentId: threat.sourceAgentId,
      };
      this.indexThreat(entry, threat.originalThreat);
    }
  }

  /**
   * Get the total number of tracked threats.
   */
  get size(): number {
    return this.threats.size;
  }
}
