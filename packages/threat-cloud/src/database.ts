/**
 * SQLite database layer for Threat Cloud
 * 威脅雲 SQLite 資料庫層
 *
 * Stores anonymized threat data, enriched events, IoCs, campaigns, and rules.
 *
 * @module @panguard-ai/threat-cloud/database
 */

import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';
import type {
  AnonymizedThreatData,
  ThreatCloudRule,
  ThreatStats,
  EnrichedThreatEvent,
  TrapIntelligencePayload,
} from './types.js';

/**
 * Threat Cloud database backed by SQLite
 * 基於 SQLite 的威脅雲資料庫
 */
export class ThreatCloudDB {
  private readonly db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('busy_timeout = 15000');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('cache_size = -64000');
    this.db.pragma('temp_store = MEMORY');
    this.db.pragma('wal_autocheckpoint = 1000');
    this.db.pragma('journal_size_limit = 104857600');
    this.initialize();
    this.runMigrations();
  }

  /** Create a backup of the database / 建立資料庫備份 */
  backup(destPath: string): void {
    this.db.backup(destPath);
  }

  /** Expose underlying db for sub-modules (IoCStore, etc.) / 暴露底層 DB 給子模組 */
  getDB(): Database.Database {
    return this.db;
  }

  // -------------------------------------------------------------------------
  // Schema initialization / 資料表初始化
  // -------------------------------------------------------------------------

  /** Create original tables if they don't exist / 建立原始資料表 */
  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_source_ip TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        mitre_technique TEXT NOT NULL,
        sigma_rule_matched TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        industry TEXT,
        region TEXT NOT NULL,
        received_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS rules (
        rule_id TEXT PRIMARY KEY,
        rule_content TEXT NOT NULL,
        published_at TEXT NOT NULL,
        source TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
      CREATE INDEX IF NOT EXISTS idx_threats_attack_type ON threats(attack_type);
      CREATE INDEX IF NOT EXISTS idx_threats_mitre ON threats(mitre_technique);
      CREATE INDEX IF NOT EXISTS idx_rules_published ON rules(published_at);

      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  }

  /** Run idempotent schema migrations / 執行冪等 schema 遷移 */
  private runMigrations(): void {
    const applied = new Set(
      (
        this.db.prepare('SELECT version FROM schema_migrations').all() as Array<{ version: number }>
      ).map((r) => r.version)
    );

    const migrations: Array<{ version: number; name: string; sql: string }> = [
      {
        version: 1,
        name: 'create_iocs_table',
        sql: `
          CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL CHECK(type IN ('ip','domain','url','hash_md5','hash_sha1','hash_sha256')),
            value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 50 CHECK(confidence BETWEEN 0 AND 100),
            reputation_score INTEGER NOT NULL DEFAULT 50 CHECK(reputation_score BETWEEN 0 AND 100),
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            sightings INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','expired','revoked','under_review')),
            tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(type, normalized_value)
          );
          CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
          CREATE INDEX IF NOT EXISTS idx_iocs_normalized ON iocs(normalized_value);
          CREATE INDEX IF NOT EXISTS idx_iocs_reputation ON iocs(reputation_score DESC);
          CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);
          CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status);
          CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
        `,
      },
      {
        version: 2,
        name: 'create_enriched_threats_table',
        sql: `
          CREATE TABLE IF NOT EXISTS enriched_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_type TEXT NOT NULL CHECK(source_type IN ('guard','trap','external_feed')),
            attack_source_ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            mitre_techniques TEXT NOT NULL DEFAULT '[]',
            sigma_rule_matched TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL,
            industry TEXT,
            region TEXT NOT NULL DEFAULT 'unknown',
            confidence INTEGER NOT NULL DEFAULT 50,
            severity TEXT NOT NULL DEFAULT 'medium',
            service_type TEXT,
            skill_level TEXT,
            intent TEXT,
            tools TEXT,
            event_hash TEXT NOT NULL UNIQUE,
            received_at TEXT NOT NULL DEFAULT (datetime('now')),
            campaign_id TEXT
          );
          CREATE INDEX IF NOT EXISTS idx_enriched_timestamp ON enriched_threats(timestamp);
          CREATE INDEX IF NOT EXISTS idx_enriched_attack_type ON enriched_threats(attack_type);
          CREATE INDEX IF NOT EXISTS idx_enriched_ip ON enriched_threats(attack_source_ip);
          CREATE INDEX IF NOT EXISTS idx_enriched_campaign ON enriched_threats(campaign_id);
          CREATE INDEX IF NOT EXISTS idx_enriched_source_type ON enriched_threats(source_type);
          CREATE INDEX IF NOT EXISTS idx_enriched_region ON enriched_threats(region);
          CREATE INDEX IF NOT EXISTS idx_enriched_severity ON enriched_threats(severity);
          CREATE INDEX IF NOT EXISTS idx_enriched_received ON enriched_threats(received_at);
        `,
      },
      {
        version: 3,
        name: 'create_trap_credentials_table',
        sql: `
          CREATE TABLE IF NOT EXISTS trap_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enriched_threat_id INTEGER NOT NULL REFERENCES enriched_threats(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            attempt_count INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
          );
          CREATE INDEX IF NOT EXISTS idx_trap_creds_threat ON trap_credentials(enriched_threat_id);
          CREATE INDEX IF NOT EXISTS idx_trap_creds_username ON trap_credentials(username);
        `,
      },
      {
        version: 4,
        name: 'create_generated_patterns_table',
        sql: `
          CREATE TABLE IF NOT EXISTS generated_patterns (
            pattern_hash TEXT PRIMARY KEY,
            attack_type TEXT NOT NULL,
            mitre_techniques TEXT NOT NULL,
            rule_id TEXT NOT NULL REFERENCES rules(rule_id) ON DELETE CASCADE,
            occurrences INTEGER NOT NULL,
            distinct_ips INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
          );
          CREATE INDEX IF NOT EXISTS idx_gen_patterns_attack ON generated_patterns(attack_type);
          CREATE INDEX IF NOT EXISTS idx_gen_patterns_rule ON generated_patterns(rule_id);
        `,
      },
      {
        version: 5,
        name: 'create_daily_aggregates_table',
        sql: `
          CREATE TABLE IF NOT EXISTS daily_aggregates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            region TEXT NOT NULL,
            source_type TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            unique_ips INTEGER NOT NULL,
            avg_confidence REAL NOT NULL,
            severity_distribution TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(date, attack_type, region, source_type)
          );
          CREATE INDEX IF NOT EXISTS idx_daily_agg_date ON daily_aggregates(date);
          CREATE INDEX IF NOT EXISTS idx_daily_agg_type ON daily_aggregates(attack_type);
        `,
      },
      {
        version: 6,
        name: 'create_sightings_table',
        sql: `
          CREATE TABLE IF NOT EXISTS sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
            type TEXT NOT NULL CHECK(type IN ('positive','negative','false_positive')),
            source TEXT NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 50 CHECK(confidence BETWEEN 0 AND 100),
            details TEXT NOT NULL DEFAULT '',
            actor_hash TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
          );
          CREATE INDEX IF NOT EXISTS idx_sightings_ioc ON sightings(ioc_id);
          CREATE INDEX IF NOT EXISTS idx_sightings_type ON sightings(type);
          CREATE INDEX IF NOT EXISTS idx_sightings_created ON sightings(created_at);
        `,
      },
      {
        version: 7,
        name: 'create_audit_log_table',
        sql: `
          CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            actor_hash TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
          );
          CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
          CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
          CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
          CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_hash);
        `,
      },
      {
        version: 8,
        name: 'add_source_reliability_to_iocs',
        sql: `
          ALTER TABLE iocs ADD COLUMN source_reliability TEXT NOT NULL DEFAULT 'F'
            CHECK(source_reliability IN ('A','B','C','D','E','F'));
        `,
      },
      {
        version: 9,
        name: 'create_skill_threats_table',
        sql: `
          CREATE TABLE IF NOT EXISTS skill_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_hash TEXT NOT NULL,
            skill_name TEXT NOT NULL,
            aggregate_risk_score REAL NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'LOW',
            scan_count INTEGER NOT NULL DEFAULT 0,
            top_findings TEXT NOT NULL DEFAULT '[]',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            trust_ratio REAL NOT NULL DEFAULT 1.0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
          );
          CREATE UNIQUE INDEX IF NOT EXISTS idx_skill_threats_hash ON skill_threats(skill_hash);
        `,
      },
    ];

    const insertMigration = this.db.prepare(
      'INSERT INTO schema_migrations (version, name) VALUES (?, ?)'
    );

    for (const m of migrations) {
      if (!applied.has(m.version)) {
        this.db.transaction(() => {
          this.db.exec(m.sql);
          insertMigration.run(m.version, m.name);
        })();
      }
    }
  }

  // -------------------------------------------------------------------------
  // Legacy threat operations (backward compatible) / 原始威脅操作
  // -------------------------------------------------------------------------

  /** Insert anonymized threat data / 插入匿名化威脅數據 */
  insertThreat(data: AnonymizedThreatData): void {
    const stmt = this.db.prepare(`
      INSERT INTO threats (attack_source_ip, attack_type, mitre_technique, sigma_rule_matched, timestamp, industry, region)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      data.attackSourceIP,
      data.attackType,
      data.mitreTechnique,
      data.sigmaRuleMatched,
      data.timestamp,
      data.industry ?? null,
      data.region
    );
  }

  // -------------------------------------------------------------------------
  // Enriched threat operations / 豐富化威脅操作
  // -------------------------------------------------------------------------

  /**
   * Insert enriched threat event (deduplicates by event_hash).
   * Returns the row id if inserted, null if duplicate.
   * 插入豐富化威脅事件（以 event_hash 去重）
   */
  insertEnrichedThreat(event: Omit<EnrichedThreatEvent, 'id'>): number | null {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO enriched_threats
        (source_type, attack_source_ip, attack_type, mitre_techniques, sigma_rule_matched,
         timestamp, industry, region, confidence, severity, service_type, skill_level,
         intent, tools, event_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      event.sourceType,
      event.attackSourceIP,
      event.attackType,
      JSON.stringify(event.mitreTechniques),
      event.sigmaRuleMatched,
      event.timestamp,
      event.industry ?? null,
      event.region,
      event.confidence,
      event.severity,
      event.serviceType ?? null,
      event.skillLevel ?? null,
      event.intent ?? null,
      event.tools ? JSON.stringify(event.tools) : null,
      event.eventHash
    );
    return result.changes > 0 ? Number(result.lastInsertRowid) : null;
  }

  /**
   * Insert trap credential records.
   * Usernames are hashed (SHA-256, truncated to 16 hex chars) before storage
   * to avoid storing PII from attacker-attempted credentials.
   * 插入 Trap 憑證記錄（使用者名稱先雜湊化以避免 PII 洩漏）
   */
  insertTrapCredentials(
    enrichedThreatId: number,
    credentials: Array<{ username: string; count: number }>
  ): void {
    const stmt = this.db.prepare(
      'INSERT INTO trap_credentials (enriched_threat_id, username, attempt_count) VALUES (?, ?, ?)'
    );
    const insertAll = this.db.transaction((creds: typeof credentials) => {
      for (const c of creds) {
        const hashedUsername = createHash('sha256').update(c.username).digest('hex').slice(0, 16);
        stmt.run(enrichedThreatId, hashedUsername, c.count);
      }
    });
    insertAll(credentials);
  }

  /** Get enriched threats count by source type / 依來源類型取得豐富化威脅數量 */
  getEnrichedThreatCountBySource(): Record<string, number> {
    const rows = this.db
      .prepare('SELECT source_type, COUNT(*) as count FROM enriched_threats GROUP BY source_type')
      .all() as Array<{ source_type: string; count: number }>;
    const result: Record<string, number> = {};
    for (const r of rows) {
      result[r.source_type] = r.count;
    }
    return result;
  }

  /** Count related threats for an IP / 計算某 IP 的相關威脅數量 */
  countRelatedThreats(ip: string): number {
    return (
      this.db
        .prepare('SELECT COUNT(*) as count FROM enriched_threats WHERE attack_source_ip = ?')
        .get(ip) as { count: number }
    ).count;
  }

  // -------------------------------------------------------------------------
  // Conversion helpers / 轉換輔助函式
  // -------------------------------------------------------------------------

  /** Convert AnonymizedThreatData to EnrichedThreatEvent / 轉換 Guard 資料 */
  static guardToEnriched(data: AnonymizedThreatData): Omit<EnrichedThreatEvent, 'id'> {
    const hashInput = `${data.attackSourceIP}|${data.attackType}|${data.mitreTechnique}|${data.timestamp}`;
    const eventHash = createHash('sha256').update(hashInput).digest('hex');

    return {
      sourceType: 'guard',
      attackSourceIP: data.attackSourceIP,
      attackType: data.attackType,
      mitreTechniques: [data.mitreTechnique],
      sigmaRuleMatched: data.sigmaRuleMatched,
      timestamp: data.timestamp,
      industry: data.industry,
      region: data.region,
      confidence: 50,
      severity: 'medium',
      eventHash,
      receivedAt: new Date().toISOString(),
    };
  }

  /** Convert TrapIntelligencePayload to EnrichedThreatEvent / 轉換 Trap 資料 */
  static trapToEnriched(data: TrapIntelligencePayload): Omit<EnrichedThreatEvent, 'id'> {
    const techniques = data.mitreTechniques ?? [];
    const hashInput = `${data.sourceIP}|${data.attackType}|${techniques.join(',')}|${data.timestamp}`;
    const eventHash = createHash('sha256').update(hashInput).digest('hex');

    return {
      sourceType: 'trap',
      attackSourceIP: data.sourceIP,
      attackType: data.attackType,
      mitreTechniques: techniques,
      sigmaRuleMatched: '',
      timestamp: data.timestamp,
      region: data.region ?? 'unknown',
      confidence: 60,
      severity: data.skillLevel === 'apt' || data.skillLevel === 'advanced' ? 'high' : 'medium',
      serviceType: data.serviceType,
      skillLevel: data.skillLevel,
      intent: data.intent,
      tools: data.tools,
      eventHash,
      receivedAt: new Date().toISOString(),
    };
  }

  // -------------------------------------------------------------------------
  // Rules / 規則
  // -------------------------------------------------------------------------

  /** Insert or update a community rule / 插入或更新社群規則 */
  upsertRule(rule: ThreatCloudRule): void {
    const stmt = this.db.prepare(`
      INSERT INTO rules (rule_id, rule_content, published_at, source)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(rule_id) DO UPDATE SET
        rule_content = excluded.rule_content,
        published_at = excluded.published_at,
        source = excluded.source,
        updated_at = datetime('now')
    `);
    stmt.run(rule.ruleId, rule.ruleContent, rule.publishedAt, rule.source);
  }

  /** Fetch rules published after a given timestamp / 取得指定時間後發佈的規則 */
  getRulesSince(since: string): ThreatCloudRule[] {
    const stmt = this.db.prepare(`
      SELECT rule_id as ruleId, rule_content as ruleContent, published_at as publishedAt, source
      FROM rules
      WHERE published_at > ?
      ORDER BY published_at ASC
    `);
    return stmt.all(since) as ThreatCloudRule[];
  }

  /** Fetch all rules / 取得所有規則 */
  getAllRules(): ThreatCloudRule[] {
    const stmt = this.db.prepare(`
      SELECT rule_id as ruleId, rule_content as ruleContent, published_at as publishedAt, source
      FROM rules
      ORDER BY published_at DESC
    `);
    return stmt.all() as ThreatCloudRule[];
  }

  // -------------------------------------------------------------------------
  // Statistics / 統計
  // -------------------------------------------------------------------------

  /** Get threat statistics / 取得威脅統計 */
  getStats(): ThreatStats {
    const totalThreats = (
      this.db.prepare('SELECT COUNT(*) as count FROM threats').get() as { count: number }
    ).count;
    const totalRules = (
      this.db.prepare('SELECT COUNT(*) as count FROM rules').get() as { count: number }
    ).count;

    const last24h = (
      this.db
        .prepare(
          "SELECT COUNT(*) as count FROM threats WHERE received_at > datetime('now', '-1 day')"
        )
        .get() as { count: number }
    ).count;

    const topAttackTypes = this.db
      .prepare(
        `
      SELECT attack_type as type, COUNT(*) as count
      FROM threats
      GROUP BY attack_type
      ORDER BY count DESC
      LIMIT 10
    `
      )
      .all() as Array<{ type: string; count: number }>;

    const topMitreTechniques = this.db
      .prepare(
        `
      SELECT mitre_technique as technique, COUNT(*) as count
      FROM threats
      GROUP BY mitre_technique
      ORDER BY count DESC
      LIMIT 10
    `
      )
      .all() as Array<{ technique: string; count: number }>;

    return {
      totalThreats,
      totalRules,
      topAttackTypes,
      topMitreTechniques,
      last24hThreats: last24h,
    };
  }

  /** Close the database / 關閉資料庫 */
  close(): void {
    this.db.close();
  }
}
