/**
 * Threat Correlation Engine
 * 威脅關聯引擎
 *
 * Groups related threat events into campaigns based on:
 * 1. Same source IP within a time window (IP cluster)
 * 2. Same attack pattern across multiple IPs (pattern cluster)
 *
 * @module @panguard-ai/threat-cloud/correlation-engine
 */

import { createHash } from 'node:crypto';
import type Database from 'better-sqlite3';
import type {
  CorrelationConfig,
  Campaign,
  CampaignScanResult,
  CampaignStats,
  PaginationParams,
  PaginatedResponse,
  EnrichedThreatEvent,
} from './types.js';

/** Default config / 預設配置 */
const DEFAULT_CONFIG: CorrelationConfig = {
  timeWindowMinutes: 60,
  minEventsForCampaign: 3,
  minIPsForPatternCampaign: 5,
  scanWindowHours: 24,
};

/** Raw campaign row from DB / DB 回傳的原始 campaign 列 */
interface CampaignRow {
  campaign_id: string;
  name: string;
  campaign_type: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  unique_ips: number;
  attack_types: string;
  mitre_techniques: string;
  regions: string;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
}

/** Convert DB row to Campaign / 轉換 DB 列 */
function rowToCampaign(row: CampaignRow): Campaign {
  return {
    campaignId: row.campaign_id,
    name: row.name,
    campaignType: row.campaign_type as Campaign['campaignType'],
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    eventCount: row.event_count,
    uniqueIPs: row.unique_ips,
    attackTypes: JSON.parse(row.attack_types) as string[],
    mitreTechniques: JSON.parse(row.mitre_techniques) as string[],
    regions: JSON.parse(row.regions) as string[],
    severity: row.severity,
    status: row.status as Campaign['status'],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class CorrelationEngine {
  private readonly config: CorrelationConfig;

  constructor(
    private readonly db: Database.Database,
    config?: Partial<CorrelationConfig>
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.ensureTable();
  }

  /** Create campaigns table if not exists / 建立 campaigns 表 */
  private ensureTable(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS campaigns (
        campaign_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        campaign_type TEXT NOT NULL CHECK(campaign_type IN ('ip_cluster','pattern_cluster','manual')),
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        event_count INTEGER NOT NULL DEFAULT 0,
        unique_ips INTEGER NOT NULL DEFAULT 0,
        attack_types TEXT NOT NULL DEFAULT '[]',
        mitre_techniques TEXT NOT NULL DEFAULT '[]',
        regions TEXT NOT NULL DEFAULT '[]',
        severity TEXT NOT NULL DEFAULT 'medium',
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','resolved','false_positive')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
      CREATE INDEX IF NOT EXISTS idx_campaigns_last_seen ON campaigns(last_seen);
    `);
  }

  /**
   * Scan for new campaigns in uncorrelated events.
   * 掃描未關聯的事件，建立新的攻擊活動
   */
  scanForCampaigns(): CampaignScanResult {
    const startTime = Date.now();
    let newCampaigns = 0;
    const updatedCampaigns = 0;
    let eventsCorrelated = 0;

    const sinceDate = new Date(
      Date.now() - this.config.scanWindowHours * 60 * 60 * 1000
    ).toISOString();

    // Fetch uncorrelated events within scan window
    const events = this.db
      .prepare(
        `SELECT id, attack_source_ip, attack_type, mitre_techniques, timestamp, region, severity
         FROM enriched_threats
         WHERE campaign_id IS NULL AND received_at > ?
         ORDER BY timestamp ASC`
      )
      .all(sinceDate) as Array<{
      id: number;
      attack_source_ip: string;
      attack_type: string;
      mitre_techniques: string;
      timestamp: string;
      region: string;
      severity: string;
    }>;

    if (events.length === 0) {
      return {
        newCampaigns: 0,
        updatedCampaigns: 0,
        eventsCorrelated: 0,
        duration: Date.now() - startTime,
      };
    }

    // --- IP Cluster detection ---
    const byIP = new Map<string, typeof events>();
    for (const e of events) {
      const list = byIP.get(e.attack_source_ip) ?? [];
      list.push(e);
      byIP.set(e.attack_source_ip, list);
    }

    const assignedIds = new Set<number>();
    const updateCampaignId = this.db.prepare(
      'UPDATE enriched_threats SET campaign_id = ? WHERE id = ?'
    );

    this.db.transaction(() => {
      for (const [ip, ipEvents] of byIP) {
        if (ipEvents.length < this.config.minEventsForCampaign) continue;

        // Check time window clustering
        const clustered = this.clusterByTimeWindow(ipEvents);
        for (const cluster of clustered) {
          if (cluster.length < this.config.minEventsForCampaign) continue;

          const campaignId = this.generateCampaignId(cluster.map((e) => e.id));
          const attackTypes = [...new Set(cluster.map((e) => e.attack_type))];
          const allTechniques = cluster.flatMap((e) => JSON.parse(e.mitre_techniques) as string[]);
          const techniques = [...new Set(allTechniques)];
          const regions = [...new Set(cluster.map((e) => e.region))];
          const timestamps = cluster.map((e) => e.timestamp).sort();
          const maxSeverity = this.pickMaxSeverity(cluster.map((e) => e.severity));

          this.upsertCampaign({
            campaignId,
            name: `IP ${ip}: ${attackTypes.join(', ')}`,
            campaignType: 'ip_cluster',
            firstSeen: timestamps[0]!,
            lastSeen: timestamps[timestamps.length - 1]!,
            eventCount: cluster.length,
            uniqueIPs: 1,
            attackTypes,
            mitreTechniques: techniques,
            regions,
            severity: maxSeverity,
          });

          for (const e of cluster) {
            updateCampaignId.run(campaignId, e.id);
            assignedIds.add(e.id);
          }
          newCampaigns++;
          eventsCorrelated += cluster.length;
        }
      }

      // --- Pattern Cluster detection ---
      const unassigned = events.filter((e) => !assignedIds.has(e.id));
      const byPattern = new Map<string, typeof events>();
      for (const e of unassigned) {
        const techniques = (JSON.parse(e.mitre_techniques) as string[]).sort().join(',');
        const key = `${e.attack_type}|${techniques}`;
        const list = byPattern.get(key) ?? [];
        list.push(e);
        byPattern.set(key, list);
      }

      for (const [pattern, patternEvents] of byPattern) {
        const distinctIPs = new Set(patternEvents.map((e) => e.attack_source_ip));
        if (distinctIPs.size < this.config.minIPsForPatternCampaign) continue;

        const campaignId = this.generateCampaignId(patternEvents.map((e) => e.id));
        const [attackType] = pattern.split('|');
        const allTechniques = patternEvents.flatMap(
          (e) => JSON.parse(e.mitre_techniques) as string[]
        );
        const techniques = [...new Set(allTechniques)];
        const regions = [...new Set(patternEvents.map((e) => e.region))];
        const timestamps = patternEvents.map((e) => e.timestamp).sort();
        const maxSeverity = this.pickMaxSeverity(patternEvents.map((e) => e.severity));

        this.upsertCampaign({
          campaignId,
          name: `Pattern: ${attackType} from ${distinctIPs.size} IPs`,
          campaignType: 'pattern_cluster',
          firstSeen: timestamps[0]!,
          lastSeen: timestamps[timestamps.length - 1]!,
          eventCount: patternEvents.length,
          uniqueIPs: distinctIPs.size,
          attackTypes: [attackType!],
          mitreTechniques: techniques,
          regions,
          severity: maxSeverity,
        });

        for (const e of patternEvents) {
          updateCampaignId.run(campaignId, e.id);
        }
        newCampaigns++;
        eventsCorrelated += patternEvents.length;
      }
    })();

    return {
      newCampaigns,
      updatedCampaigns,
      eventsCorrelated,
      duration: Date.now() - startTime,
    };
  }

  /** Get campaign by ID / 取得 campaign */
  getCampaign(campaignId: string): Campaign | null {
    const row = this.db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(campaignId) as
      | CampaignRow
      | undefined;
    return row ? rowToCampaign(row) : null;
  }

  /** List campaigns / 列表 campaigns */
  listCampaigns(pagination: PaginationParams, status?: string): PaginatedResponse<Campaign> {
    const where = status ? 'WHERE status = ?' : '';
    const params: unknown[] = status ? [status] : [];
    const safeLimit = Math.min(Math.max(1, pagination.limit), 1000);
    const offset = (Math.max(1, pagination.page) - 1) * safeLimit;

    const total = (
      this.db.prepare(`SELECT COUNT(*) as count FROM campaigns ${where}`).get(...params) as {
        count: number;
      }
    ).count;

    const rows = this.db
      .prepare(`SELECT * FROM campaigns ${where} ORDER BY last_seen DESC LIMIT ? OFFSET ?`)
      .all(...params, safeLimit, offset) as CampaignRow[];

    return {
      items: rows.map(rowToCampaign),
      total,
      page: pagination.page,
      limit: safeLimit,
      hasMore: offset + safeLimit < total,
    };
  }

  /** Get campaign events / 取得 campaign 事件 */
  getCampaignEvents(campaignId: string): EnrichedThreatEvent[] {
    const rows = this.db
      .prepare('SELECT * FROM enriched_threats WHERE campaign_id = ? ORDER BY timestamp ASC')
      .all(campaignId) as Array<Record<string, unknown>>;

    return rows.map((r) => ({
      id: r['id'] as number,
      sourceType: r['source_type'] as EnrichedThreatEvent['sourceType'],
      attackSourceIP: r['attack_source_ip'] as string,
      attackType: r['attack_type'] as string,
      mitreTechniques: JSON.parse(r['mitre_techniques'] as string) as string[],
      sigmaRuleMatched: r['sigma_rule_matched'] as string,
      timestamp: r['timestamp'] as string,
      industry: r['industry'] as string | undefined,
      region: r['region'] as string,
      confidence: r['confidence'] as number,
      severity: r['severity'] as string,
      serviceType: r['service_type'] as string | undefined,
      skillLevel: r['skill_level'] as string | undefined,
      intent: r['intent'] as string | undefined,
      tools: r['tools'] ? (JSON.parse(r['tools'] as string) as string[]) : undefined,
      eventHash: r['event_hash'] as string,
      receivedAt: r['received_at'] as string,
      campaignId: r['campaign_id'] as string | undefined,
    }));
  }

  /** Get campaign statistics / 取得攻擊活動統計 */
  getCampaignStats(): CampaignStats {
    const total = (
      this.db.prepare('SELECT COUNT(*) as count FROM campaigns').get() as { count: number }
    ).count;
    const active = (
      this.db.prepare("SELECT COUNT(*) as count FROM campaigns WHERE status = 'active'").get() as {
        count: number;
      }
    ).count;
    const correlated = (
      this.db
        .prepare('SELECT COUNT(*) as count FROM enriched_threats WHERE campaign_id IS NOT NULL')
        .get() as { count: number }
    ).count;

    const topTypes = this.db
      .prepare(
        `SELECT attack_type as type, COUNT(*) as count
         FROM enriched_threats WHERE campaign_id IS NOT NULL
         GROUP BY attack_type ORDER BY count DESC LIMIT 10`
      )
      .all() as Array<{ type: string; count: number }>;

    return {
      totalCampaigns: total,
      activeCampaigns: active,
      totalCorrelatedEvents: correlated,
      topAttackTypes: topTypes,
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers / 私有輔助方法
  // -------------------------------------------------------------------------

  /** Cluster events by time window / 依時間窗口聚類事件 */
  private clusterByTimeWindow<T extends { timestamp: string }>(events: T[]): T[][] {
    if (events.length === 0) return [];
    const sorted = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const windowMs = this.config.timeWindowMinutes * 60 * 1000;
    const clusters: T[][] = [[sorted[0]!]];

    for (let i = 1; i < sorted.length; i++) {
      const current = new Date(sorted[i]!.timestamp).getTime();
      const clusterStart = new Date(clusters[clusters.length - 1]![0]!.timestamp).getTime();

      if (current - clusterStart <= windowMs) {
        clusters[clusters.length - 1]!.push(sorted[i]!);
      } else {
        clusters.push([sorted[i]!]);
      }
    }

    return clusters;
  }

  /** Generate deterministic campaign ID / 產生確定性 campaign ID */
  private generateCampaignId(eventIds: number[]): string {
    const sorted = [...eventIds].sort((a, b) => a - b);
    const hash = createHash('sha256').update(sorted.join(',')).digest('hex').slice(0, 8);
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    return `C-${date}-${hash}`;
  }

  /** Pick the maximum severity / 選擇最高嚴重度 */
  private pickMaxSeverity(severities: string[]): string {
    const order = ['critical', 'high', 'medium', 'low'];
    for (const s of order) {
      if (severities.includes(s)) return s;
    }
    return 'medium';
  }

  /** Upsert campaign / 新增或更新攻擊活動 */
  private upsertCampaign(c: Omit<Campaign, 'status' | 'createdAt' | 'updatedAt'>): void {
    this.db
      .prepare(
        `INSERT INTO campaigns
          (campaign_id, name, campaign_type, first_seen, last_seen, event_count, unique_ips,
           attack_types, mitre_techniques, regions, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(campaign_id) DO UPDATE SET
          last_seen = excluded.last_seen,
          event_count = excluded.event_count,
          unique_ips = excluded.unique_ips,
          attack_types = excluded.attack_types,
          mitre_techniques = excluded.mitre_techniques,
          regions = excluded.regions,
          severity = excluded.severity,
          updated_at = datetime('now')`
      )
      .run(
        c.campaignId,
        c.name,
        c.campaignType,
        c.firstSeen,
        c.lastSeen,
        c.eventCount,
        c.uniqueIPs,
        JSON.stringify(c.attackTypes),
        JSON.stringify(c.mitreTechniques),
        JSON.stringify(c.regions),
        c.severity
      );
  }
}
