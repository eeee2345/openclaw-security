/**
 * SQLite database layer for Threat Cloud
 * 威脅雲 SQLite 資料庫層
 *
 * Stores anonymized threat data and community rules using better-sqlite3.
 *
 * @module @panguard-ai/threat-cloud/database
 */

import Database from 'better-sqlite3';
import type { AnonymizedThreatData, ThreatCloudRule, ThreatStats, ATRProposal, SkillThreatSubmission } from './types.js';

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
    this.initialize();
  }

  /** Create tables if they don't exist / 建立資料表 */
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

      CREATE TABLE IF NOT EXISTS atr_proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_hash TEXT NOT NULL,
        rule_content TEXT NOT NULL,
        llm_provider TEXT NOT NULL,
        llm_model TEXT NOT NULL,
        self_review_verdict TEXT NOT NULL,
        client_id TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        confirmations INTEGER NOT NULL DEFAULT 0,
        llm_review_verdict TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS atr_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id TEXT NOT NULL,
        is_true_positive INTEGER NOT NULL,
        client_id TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS skill_threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        skill_hash TEXT NOT NULL,
        skill_name TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        finding_summaries TEXT,
        client_id TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS ioc_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL UNIQUE,
        reputation INTEGER NOT NULL DEFAULT 50,
        source TEXT,
        first_seen TEXT DEFAULT (datetime('now')),
        last_seen TEXT DEFAULT (datetime('now')),
        sighting_count INTEGER DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS skill_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        skill_name TEXT NOT NULL,
        normalized_name TEXT NOT NULL UNIQUE,
        fingerprint_hash TEXT,
        confirmations INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'pending',
        first_reported TEXT DEFAULT (datetime('now')),
        last_reported TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_atr_proposals_status ON atr_proposals(status);
      CREATE INDEX IF NOT EXISTS idx_atr_proposals_pattern ON atr_proposals(pattern_hash);
      CREATE INDEX IF NOT EXISTS idx_skill_threats_hash ON skill_threats(skill_hash);
      CREATE INDEX IF NOT EXISTS idx_atr_feedback_rule ON atr_feedback(rule_id);
      CREATE INDEX IF NOT EXISTS idx_ioc_entries_type ON ioc_entries(type);
      CREATE INDEX IF NOT EXISTS idx_ioc_entries_reputation ON ioc_entries(reputation);
      CREATE INDEX IF NOT EXISTS idx_skill_whitelist_status ON skill_whitelist(status);
      CREATE INDEX IF NOT EXISTS idx_skill_whitelist_name ON skill_whitelist(normalized_name);
    `);
  }

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
      data.region,
    );
  }

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

  /** Fetch all rules with limit / 取得所有規則（含限制） */
  getAllRules(limit = 5000): ThreatCloudRule[] {
    const stmt = this.db.prepare(`
      SELECT rule_id as ruleId, rule_content as ruleContent, published_at as publishedAt, source
      FROM rules
      ORDER BY published_at DESC
      LIMIT ?
    `);
    return stmt.all(limit) as ThreatCloudRule[];
  }

  /** Insert ATR rule proposal / 插入 ATR 規則提案 */
  insertATRProposal(proposal: ATRProposal): void {
    const stmt = this.db.prepare(`
      INSERT INTO atr_proposals (pattern_hash, rule_content, llm_provider, llm_model, self_review_verdict, client_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      proposal.patternHash,
      proposal.ruleContent,
      proposal.llmProvider,
      proposal.llmModel,
      proposal.selfReviewVerdict,
      proposal.clientId ?? null,
    );
  }

  /** Get ATR proposals, optionally filtered by status / 取得 ATR 提案 */
  getATRProposals(status?: string): unknown[] {
    if (status) {
      return this.db.prepare('SELECT * FROM atr_proposals WHERE status = ? ORDER BY created_at DESC').all(status);
    }
    return this.db.prepare('SELECT * FROM atr_proposals ORDER BY created_at DESC').all();
  }

  /** Increment confirmations for a proposal; auto-confirm at >= 3 / 增加提案確認數 */
  confirmATRProposal(patternHash: string): void {
    this.db.prepare(`
      UPDATE atr_proposals
      SET confirmations = confirmations + 1,
          status = CASE WHEN confirmations + 1 >= 3 THEN 'confirmed' ELSE status END,
          updated_at = datetime('now')
      WHERE pattern_hash = ?
    `).run(patternHash);
  }

  /** Update LLM review verdict for a proposal / 更新 LLM 審查結果 */
  updateATRProposalLLMReview(patternHash: string, verdict: string): void {
    this.db.prepare(`
      UPDATE atr_proposals SET llm_review_verdict = ?, updated_at = datetime('now') WHERE pattern_hash = ?
    `).run(verdict, patternHash);
  }

  /** Insert ATR feedback / 插入 ATR 回饋 */
  insertATRFeedback(ruleId: string, isTruePositive: boolean, clientId?: string): void {
    this.db.prepare(`
      INSERT INTO atr_feedback (rule_id, is_true_positive, client_id) VALUES (?, ?, ?)
    `).run(ruleId, isTruePositive ? 1 : 0, clientId ?? null);
  }

  /** Get feedback stats for a rule / 取得規則回饋統計 */
  getATRFeedbackStats(ruleId: string): { truePositives: number; falsePositives: number } {
    const tp = (this.db.prepare('SELECT COUNT(*) as count FROM atr_feedback WHERE rule_id = ? AND is_true_positive = 1').get(ruleId) as { count: number }).count;
    const fp = (this.db.prepare('SELECT COUNT(*) as count FROM atr_feedback WHERE rule_id = ? AND is_true_positive = 0').get(ruleId) as { count: number }).count;
    return { truePositives: tp, falsePositives: fp };
  }

  /** Insert skill threat submission / 插入技能威脅提交 */
  insertSkillThreat(submission: SkillThreatSubmission): void {
    const stmt = this.db.prepare(`
      INSERT INTO skill_threats (skill_hash, skill_name, risk_score, risk_level, finding_summaries, client_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      submission.skillHash,
      submission.skillName,
      submission.riskScore,
      submission.riskLevel,
      submission.findingSummaries ? JSON.stringify(submission.findingSummaries) : null,
      submission.clientId ?? null,
    );
  }

  /** Get recent skill threats / 取得最近技能威脅 */
  getSkillThreats(limit: number = 50): unknown[] {
    return this.db.prepare('SELECT * FROM skill_threats ORDER BY created_at DESC LIMIT ?').all(limit);
  }

  /** Get proposal statistics / 取得提案統計 */
  getProposalStats(): { pending: number; confirmed: number; rejected: number; total: number } {
    const pending = (this.db.prepare("SELECT COUNT(*) as count FROM atr_proposals WHERE status = 'pending'").get() as { count: number }).count;
    const confirmed = (this.db.prepare("SELECT COUNT(*) as count FROM atr_proposals WHERE status = 'confirmed'").get() as { count: number }).count;
    const rejected = (this.db.prepare("SELECT COUNT(*) as count FROM atr_proposals WHERE status = 'rejected'").get() as { count: number }).count;
    const total = (this.db.prepare('SELECT COUNT(*) as count FROM atr_proposals').get() as { count: number }).count;
    return { pending, confirmed, rejected, total };
  }

  /** Get threat statistics / 取得威脅統計 */
  getStats(): ThreatStats {
    const totalThreats = (this.db.prepare('SELECT COUNT(*) as count FROM threats').get() as { count: number }).count;
    const totalRules = (this.db.prepare('SELECT COUNT(*) as count FROM rules').get() as { count: number }).count;

    const last24h = (this.db.prepare(
      "SELECT COUNT(*) as count FROM threats WHERE received_at > datetime('now', '-1 day')"
    ).get() as { count: number }).count;

    const topAttackTypes = this.db.prepare(`
      SELECT attack_type as type, COUNT(*) as count
      FROM threats
      GROUP BY attack_type
      ORDER BY count DESC
      LIMIT 10
    `).all() as Array<{ type: string; count: number }>;

    const topMitreTechniques = this.db.prepare(`
      SELECT mitre_technique as technique, COUNT(*) as count
      FROM threats
      GROUP BY mitre_technique
      ORDER BY count DESC
      LIMIT 10
    `).all() as Array<{ technique: string; count: number }>;

    const proposalStats = this.getProposalStats();
    const skillThreatsTotal = (this.db.prepare('SELECT COUNT(*) as count FROM skill_threats').get() as { count: number }).count;

    return {
      totalThreats,
      totalRules,
      topAttackTypes,
      topMitreTechniques,
      last24hThreats: last24h,
      proposalStats,
      skillThreatsTotal,
    };
  }

  /** Get confirmed/promoted ATR rules, optionally filtered by date / 取得已確認 ATR 規則 */
  getConfirmedATRRules(since?: string): Array<{ ruleId: string; ruleContent: string; publishedAt: string; source: string }> {
    if (since) {
      return this.db.prepare(`
        SELECT pattern_hash as ruleId, rule_content as ruleContent, updated_at as publishedAt, 'atr-community' as source
        FROM atr_proposals
        WHERE (status = 'confirmed' OR status = 'promoted') AND updated_at > ?
        ORDER BY updated_at ASC
      `).all(since) as Array<{ ruleId: string; ruleContent: string; publishedAt: string; source: string }>;
    }
    return this.db.prepare(`
      SELECT pattern_hash as ruleId, rule_content as ruleContent, updated_at as publishedAt, 'atr-community' as source
      FROM atr_proposals
      WHERE status = 'confirmed' OR status = 'promoted'
      ORDER BY updated_at ASC
    `).all() as Array<{ ruleId: string; ruleContent: string; publishedAt: string; source: string }>;
  }

  /** Get IP blocklist from IoC entries and aggregated threat data / 取得 IP 封鎖清單 */
  getIPBlocklist(minReputation: number): string[] {
    // IoC entries with sufficient reputation
    const iocIPs = this.db.prepare(`
      SELECT value FROM ioc_entries
      WHERE type = 'ip' AND reputation >= ?
      ORDER BY reputation DESC
    `).all(minReputation) as Array<{ value: string }>;

    // Aggregate from threats table: distinct IPs with >= 3 occurrences
    const threatIPs = this.db.prepare(`
      SELECT attack_source_ip as value
      FROM threats
      GROUP BY attack_source_ip
      HAVING COUNT(*) >= 3
    `).all() as Array<{ value: string }>;

    // Merge and deduplicate
    const ipSet = new Set<string>();
    for (const row of iocIPs) ipSet.add(row.value);
    for (const row of threatIPs) ipSet.add(row.value);
    return Array.from(ipSet);
  }

  /** Get domain blocklist from IoC entries / 取得域名封鎖清單 */
  getDomainBlocklist(minReputation: number): string[] {
    const iocDomains = this.db.prepare(`
      SELECT value FROM ioc_entries
      WHERE type = 'domain' AND reputation >= ?
      ORDER BY reputation DESC
    `).all(minReputation) as Array<{ value: string }>;

    return iocDomains.map((row) => row.value);
  }

  /** Upsert an IoC entry / 插入或更新 IoC 條目 */
  upsertIoC(type: string, value: string, reputation: number, source: string): void {
    this.db.prepare(`
      INSERT INTO ioc_entries (type, value, reputation, source)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(value) DO UPDATE SET
        reputation = excluded.reputation,
        source = excluded.source,
        last_seen = datetime('now'),
        sighting_count = sighting_count + 1
    `).run(type, value, reputation, source);
  }

  /** Promote confirmed proposals with approved LLM review to rules / 推廣已確認提案為規則 */
  promoteConfirmedProposals(): number {
    const proposals = this.db.prepare(`
      SELECT pattern_hash, rule_content, llm_review_verdict
      FROM atr_proposals
      WHERE status = 'confirmed' AND llm_review_verdict IS NOT NULL
    `).all() as Array<{ pattern_hash: string; rule_content: string; llm_review_verdict: string }>;

    let promoted = 0;
    for (const proposal of proposals) {
      try {
        const verdict = JSON.parse(proposal.llm_review_verdict) as { approved?: boolean };
        if (verdict.approved !== true) continue;

        this.upsertRule({
          ruleId: proposal.pattern_hash,
          ruleContent: proposal.rule_content,
          publishedAt: new Date().toISOString(),
          source: 'atr-community',
        });

        this.db.prepare(`
          UPDATE atr_proposals SET status = 'promoted', updated_at = datetime('now')
          WHERE pattern_hash = ?
        `).run(proposal.pattern_hash);

        promoted++;
      } catch {
        // Skip proposals with unparseable verdicts
      }
    }

    return promoted;
  }

  /** Reject an ATR proposal / 拒絕 ATR 提案 */
  rejectATRProposal(patternHash: string): void {
    this.db.prepare(`
      UPDATE atr_proposals SET status = 'rejected', updated_at = datetime('now')
      WHERE pattern_hash = ?
    `).run(patternHash);
  }

  /** Get rules by source type, optionally filtered by date / 依來源取得規則 */
  getRulesBySource(source: string, since?: string): ThreatCloudRule[] {
    if (since) {
      return this.db.prepare(`
        SELECT rule_id as ruleId, rule_content as ruleContent, published_at as publishedAt, source
        FROM rules
        WHERE source = ? AND published_at > ?
        ORDER BY published_at ASC
      `).all(source, since) as ThreatCloudRule[];
    }
    return this.db.prepare(`
      SELECT rule_id as ruleId, rule_content as ruleContent, published_at as publishedAt, source
      FROM rules
      WHERE source = ?
      ORDER BY published_at ASC
    `).all(source) as ThreatCloudRule[];
  }

  /** Report a safe skill (increment confirmations, auto-confirm at 3+) / 回報安全 skill */
  reportSafeSkill(skillName: string, fingerprintHash?: string): void {
    const normalized = skillName.toLowerCase().trim().replace(/\s+/g, '-');
    this.db.prepare(`
      INSERT INTO skill_whitelist (skill_name, normalized_name, fingerprint_hash)
      VALUES (?, ?, ?)
      ON CONFLICT(normalized_name) DO UPDATE SET
        confirmations = confirmations + 1,
        status = CASE WHEN confirmations + 1 >= 3 THEN 'confirmed' ELSE status END,
        fingerprint_hash = COALESCE(excluded.fingerprint_hash, fingerprint_hash),
        last_reported = datetime('now')
    `).run(skillName, normalized, fingerprintHash ?? null);
  }

  /** Get confirmed community whitelist / 取得社群白名單 */
  getSkillWhitelist(): Array<{ name: string; hash: string | null; confirmations: number }> {
    return this.db.prepare(`
      SELECT skill_name as name, fingerprint_hash as hash, confirmations
      FROM skill_whitelist
      WHERE status = 'confirmed'
      ORDER BY confirmations DESC
    `).all() as Array<{ name: string; hash: string | null; confirmations: number }>;
  }

  /** Close the database / 關閉資料庫 */
  close(): void {
    this.db.close();
  }
}
