/**
 * Feed Distributor
 * 情報分發模組
 *
 * Generates blocklists, IoC feeds, and agent update packages.
 *
 * @module @panguard-ai/threat-cloud/feed-distributor
 */

import type Database from 'better-sqlite3';
import type {
  IoCFeedEntry,
  IoCFeedResponse,
  AgentUpdatePackage,
  ThreatCloudRule,
} from './types.js';

export class FeedDistributor {
  constructor(private readonly db: Database.Database) {}

  /**
   * Generate IP blocklist as plain text (one IP per line).
   * Only includes redistributable IoCs to comply with feed licenses.
   * 產生 IP 封鎖清單（僅包含可轉散佈的 IoC，遵守授權）
   */
  getIPBlocklist(minReputation: number = 70): string {
    const rows = this.db
      .prepare(
        `SELECT normalized_value
         FROM iocs
         WHERE type = 'ip' AND status = 'active' AND reputation_score >= ?
           AND (json_extract(metadata, '$.redistributable') != 'false'
                OR json_extract(metadata, '$.redistributable') IS NULL
                OR source NOT LIKE 'feed:%')
         ORDER BY reputation_score DESC`
      )
      .all(minReputation) as Array<{ normalized_value: string }>;

    return rows.map((r) => r.normalized_value).join('\n');
  }

  /**
   * Generate domain blocklist as plain text.
   * 產生 Domain 封鎖清單
   */
  getDomainBlocklist(minReputation: number = 70): string {
    const rows = this.db
      .prepare(
        `SELECT normalized_value
         FROM iocs
         WHERE type = 'domain' AND status = 'active' AND reputation_score >= ?
           AND (json_extract(metadata, '$.redistributable') != 'false'
                OR json_extract(metadata, '$.redistributable') IS NULL
                OR source NOT LIKE 'feed:%')
         ORDER BY reputation_score DESC`
      )
      .all(minReputation) as Array<{ normalized_value: string }>;

    return rows.map((r) => r.normalized_value).join('\n');
  }

  /**
   * Generate JSON IoC feed.
   * 產生 JSON IoC feed
   */
  getIoCFeed(minReputation: number = 50, limit: number = 1000, since?: string): IoCFeedResponse {
    const conditions = ["status = 'active'", 'reputation_score >= ?'];
    const params: unknown[] = [minReputation];

    if (since) {
      conditions.push('last_seen > ?');
      params.push(since);
    }

    const safeLimit = Math.min(Math.max(1, limit), 10000);
    const where = conditions.join(' AND ');

    const rows = this.db
      .prepare(
        `SELECT type, normalized_value, threat_type, reputation_score, confidence, last_seen, tags
         FROM iocs
         WHERE ${where}
         ORDER BY reputation_score DESC
         LIMIT ?`
      )
      .all(...params, safeLimit) as Array<{
      type: string;
      normalized_value: string;
      threat_type: string;
      reputation_score: number;
      confidence: number;
      last_seen: string;
      tags: string;
    }>;

    const entries: IoCFeedEntry[] = rows.map((r) => ({
      type: r.type as IoCFeedEntry['type'],
      value: r.normalized_value,
      threatType: r.threat_type,
      reputation: r.reputation_score,
      confidence: r.confidence,
      lastSeen: r.last_seen,
      tags: JSON.parse(r.tags) as string[],
    }));

    return {
      generatedAt: new Date().toISOString(),
      totalEntries: entries.length,
      entries,
    };
  }

  /**
   * Generate agent update package (rules + IoCs since a given timestamp).
   * 產生 Agent 更新包
   */
  getAgentUpdate(since?: string): AgentUpdatePackage {
    const sinceDate = since ?? new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    // Fetch new rules
    const rules = this.db
      .prepare(
        `SELECT rule_id as ruleId, rule_content as ruleContent, published_at as publishedAt, source
         FROM rules
         WHERE published_at > ?
         ORDER BY published_at ASC`
      )
      .all(sinceDate) as ThreatCloudRule[];

    // Fetch high-reputation IoCs updated since
    const iocRows = this.db
      .prepare(
        `SELECT type, normalized_value, threat_type, reputation_score, confidence, last_seen, tags
         FROM iocs
         WHERE status = 'active' AND reputation_score >= 60 AND updated_at > ?
         ORDER BY reputation_score DESC
         LIMIT 500`
      )
      .all(sinceDate) as Array<{
      type: string;
      normalized_value: string;
      threat_type: string;
      reputation_score: number;
      confidence: number;
      last_seen: string;
      tags: string;
    }>;

    const iocs: IoCFeedEntry[] = iocRows.map((r) => ({
      type: r.type as IoCFeedEntry['type'],
      value: r.normalized_value,
      threatType: r.threat_type,
      reputation: r.reputation_score,
      confidence: r.confidence,
      lastSeen: r.last_seen,
      tags: JSON.parse(r.tags) as string[],
    }));

    const totalActiveIoCs = (
      this.db.prepare("SELECT COUNT(*) as count FROM iocs WHERE status = 'active'").get() as {
        count: number;
      }
    ).count;

    return {
      generatedAt: new Date().toISOString(),
      rules,
      iocs,
      stats: {
        newRules: rules.length,
        newIoCs: iocs.length,
        totalActiveIoCs,
      },
    };
  }
}
