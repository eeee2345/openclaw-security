/**
 * Query Handlers for advanced analytics
 * 進階分析查詢處理器
 *
 * Provides timeseries, geo distribution, trends, and MITRE heatmap queries.
 *
 * @module @panguard-ai/threat-cloud/query-handlers
 */

import type Database from 'better-sqlite3';
import type {
  TimeSeriesPoint,
  GeoDistributionEntry,
  TrendEntry,
  MitreHeatmapEntry,
  EnhancedStats,
} from './types.js';

export class QueryHandlers {
  constructor(private readonly db: Database.Database) {}

  /**
   * Time-series query: event counts grouped by time bucket.
   * 時間序列查詢：依時間桶分組的事件計數
   */
  getTimeSeries(
    granularity: 'hour' | 'day' | 'week' = 'day',
    since?: string,
    attackType?: string
  ): TimeSeriesPoint[] {
    const sinceDate = since ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    // Whitelist granularity → strftime format to prevent SQL injection
    const GRANULARITY_FORMATS: Record<string, string> = {
      hour: '%Y-%m-%dT%H:00:00Z',
      week: '%Y-W%W',
      day: '%Y-%m-%d',
    };
    const format = GRANULARITY_FORMATS[granularity] ?? GRANULARITY_FORMATS['day']!;

    const conditions = ['timestamp > ?'];
    const params: unknown[] = [sinceDate];

    if (attackType) {
      conditions.push('attack_type = ?');
      params.push(attackType);
    }

    const where = conditions.join(' AND ');

    const rows = this.db
      .prepare(
        `SELECT strftime('${format}', timestamp) as ts, COUNT(*) as count
         FROM enriched_threats
         WHERE ${where}
         GROUP BY ts
         ORDER BY ts ASC`
      )
      .all(...params) as Array<{ ts: string; count: number }>;

    return rows.map((r) => ({ timestamp: r.ts, count: r.count }));
  }

  /**
   * Geographic distribution query.
   * 地理分佈查詢
   */
  getGeoDistribution(since?: string): GeoDistributionEntry[] {
    const sinceDate = since ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    const regionRows = this.db
      .prepare(
        `SELECT region, COUNT(*) as count, COUNT(DISTINCT attack_source_ip) as unique_ips
         FROM enriched_threats
         WHERE timestamp > ?
         GROUP BY region
         ORDER BY count DESC`
      )
      .all(sinceDate) as Array<{ region: string; count: number; unique_ips: number }>;

    return regionRows.map((r) => {
      const topTypes = this.db
        .prepare(
          `SELECT attack_type as type, COUNT(*) as count
           FROM enriched_threats
           WHERE region = ? AND timestamp > ?
           GROUP BY attack_type
           ORDER BY count DESC
           LIMIT 5`
        )
        .all(r.region, sinceDate) as Array<{ type: string; count: number }>;

      return {
        region: r.region,
        count: r.count,
        topAttackTypes: topTypes,
        uniqueIPs: r.unique_ips,
      };
    });
  }

  /**
   * Trend analysis: compare current period with previous period.
   * 趨勢分析：比較當前與前一期間
   */
  getTrends(periodDays: number = 7): TrendEntry[] {
    const now = Date.now();
    const currentStart = new Date(now - periodDays * 24 * 60 * 60 * 1000).toISOString();
    const previousStart = new Date(now - periodDays * 2 * 24 * 60 * 60 * 1000).toISOString();

    const currentCounts = this.db
      .prepare(
        `SELECT attack_type, COUNT(*) as count
         FROM enriched_threats
         WHERE timestamp > ?
         GROUP BY attack_type`
      )
      .all(currentStart) as Array<{ attack_type: string; count: number }>;

    const previousCounts = this.db
      .prepare(
        `SELECT attack_type, COUNT(*) as count
         FROM enriched_threats
         WHERE timestamp > ? AND timestamp <= ?
         GROUP BY attack_type`
      )
      .all(previousStart, currentStart) as Array<{ attack_type: string; count: number }>;

    const prevMap = new Map(previousCounts.map((r) => [r.attack_type, r.count]));
    const allTypes = new Set([
      ...currentCounts.map((r) => r.attack_type),
      ...previousCounts.map((r) => r.attack_type),
    ]);

    const trends: TrendEntry[] = [];
    for (const attackType of allTypes) {
      const currentCount = currentCounts.find((r) => r.attack_type === attackType)?.count ?? 0;
      const previousCount = prevMap.get(attackType) ?? 0;

      let changePercent = 0;
      if (previousCount > 0) {
        changePercent = Math.round(((currentCount - previousCount) / previousCount) * 100);
      } else if (currentCount > 0) {
        changePercent = 100;
      }

      let direction: TrendEntry['direction'] = 'stable';
      if (changePercent > 10) direction = 'rising';
      else if (changePercent < -10) direction = 'falling';

      trends.push({ attackType, currentCount, previousCount, changePercent, direction });
    }

    return trends.sort((a, b) => b.currentCount - a.currentCount);
  }

  /**
   * MITRE ATT&CK technique heatmap.
   * MITRE ATT&CK 技術熱力圖
   */
  getMitreHeatmap(since?: string): MitreHeatmapEntry[] {
    const sinceDate = since ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    const rows = this.db
      .prepare(
        `SELECT mitre_techniques, severity
         FROM enriched_threats
         WHERE timestamp > ?`
      )
      .all(sinceDate) as Array<{ mitre_techniques: string; severity: string }>;

    const techMap = new Map<string, { count: number; severities: string[] }>();

    for (const row of rows) {
      const techniques = JSON.parse(row.mitre_techniques) as string[];
      for (const t of techniques) {
        const entry = techMap.get(t) ?? { count: 0, severities: [] };
        entry.count++;
        entry.severities.push(row.severity);
        techMap.set(t, entry);
      }
    }

    const severityOrder = ['critical', 'high', 'medium', 'low'];

    return [...techMap.entries()]
      .map(([technique, data]) => {
        const maxSeverity = severityOrder.find((s) => data.severities.includes(s)) ?? 'medium';
        return { technique, count: data.count, severity: maxSeverity };
      })
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Enhanced stats combining all data sources.
   * 增強統計：整合所有資料來源
   */
  getEnhancedStats(): EnhancedStats {
    const totalThreats = (
      this.db.prepare('SELECT COUNT(*) as count FROM threats').get() as { count: number }
    ).count;

    const totalRules = (
      this.db.prepare('SELECT COUNT(*) as count FROM rules').get() as { count: number }
    ).count;

    const topAttackTypes = this.db
      .prepare(
        `SELECT attack_type as type, COUNT(*) as count
         FROM threats
         GROUP BY attack_type
         ORDER BY count DESC
         LIMIT 10`
      )
      .all() as Array<{ type: string; count: number }>;

    const totalIoCs = (
      this.db.prepare("SELECT COUNT(*) as count FROM iocs WHERE status = 'active'").get() as {
        count: number;
      }
    ).count;

    const iocsByTypeRows = this.db
      .prepare(`SELECT type, COUNT(*) as count FROM iocs WHERE status = 'active' GROUP BY type`)
      .all() as Array<{ type: string; count: number }>;

    const iocsByType: Record<string, number> = {};
    for (const row of iocsByTypeRows) {
      iocsByType[row.type] = row.count;
    }

    const activeCampaigns = (
      this.db.prepare("SELECT COUNT(*) as count FROM campaigns WHERE status = 'active'").get() as {
        count: number;
      }
    ).count;

    const autoGeneratedRules = (
      this.db.prepare('SELECT COUNT(*) as count FROM generated_patterns').get() as {
        count: number;
      }
    ).count;

    const trapEventsCount = (
      this.db
        .prepare("SELECT COUNT(*) as count FROM enriched_threats WHERE source_type = 'trap'")
        .get() as { count: number }
    ).count;

    const guardEventsCount = (
      this.db
        .prepare("SELECT COUNT(*) as count FROM enriched_threats WHERE source_type = 'guard'")
        .get() as { count: number }
    ).count;

    const topRegions = this.db
      .prepare(
        `SELECT region, COUNT(*) as count
         FROM enriched_threats
         GROUP BY region
         ORDER BY count DESC
         LIMIT 10`
      )
      .all() as Array<{ region: string; count: number }>;

    const topMitreTechniques = this.db
      .prepare(
        `SELECT mitre_technique as technique, COUNT(*) as count
         FROM threats
         GROUP BY mitre_technique
         ORDER BY count DESC
         LIMIT 10`
      )
      .all() as Array<{ technique: string; count: number }>;

    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const last24hThreats = (
      this.db
        .prepare('SELECT COUNT(*) as count FROM threats WHERE received_at > ?')
        .get(last24h) as {
        count: number;
      }
    ).count;

    return {
      totalThreats,
      totalRules,
      topAttackTypes,
      topMitreTechniques,
      last24hThreats,
      totalIoCs,
      iocsByType,
      activeCampaigns,
      autoGeneratedRules,
      trapEventsCount,
      guardEventsCount,
      topRegions,
    };
  }
}
