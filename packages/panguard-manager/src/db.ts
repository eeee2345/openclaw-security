/**
 * SQLite database layer for Panguard Manager
 * Manager SQLite 資料庫持久化層
 *
 * Persists agent registrations, aggregated threats, and policy updates
 * so data survives process restarts.
 *
 * @module @panguard-ai/manager/db
 */

import Database from 'better-sqlite3';
import type {
  AgentRegistration,
  AgentStatus,
  AggregatedThreat,
  ThreatEvent,
  PolicyUpdate,
  PolicyRule,
} from './types.js';

// -------------------------------------------------------------------------
// Row types for SQLite query results / SQLite 查詢結果列型別
// -------------------------------------------------------------------------

interface AgentRow {
  agent_id: string;
  hostname: string;
  os: string;
  arch: string;
  ip: string | null;
  version: string;
  status: string;
  last_heartbeat: string;
  registered_at: string;
  org_id: string;
}

interface ThreatRow {
  id: string;
  agent_id: string;
  source_hostname: string;
  event_json: string;
  verdict_conclusion: string;
  verdict_confidence: number;
  verdict_action: string;
  correlated_with: string;
  received_at: string;
  org_id: string;
}

interface PolicyRow {
  policy_id: string;
  version: number;
  rules_json: string;
  applied_to: string;
  updated_at: string;
  active: number;
  org_id: string;
}

interface CountRow {
  count: number;
}

// -------------------------------------------------------------------------
// Prepared statement cache type
// -------------------------------------------------------------------------

interface Statements {
  // Agent statements
  upsertAgent: Database.Statement;
  getAgent: Database.Statement;
  getAllAgents: Database.Statement;
  getAgentsByStatus: Database.Statement;
  updateAgentStatus: Database.Statement;
  updateHeartbeat: Database.Statement;
  deleteAgent: Database.Statement;
  getAgentCount: Database.Statement;
  getAgentsByOrg: Database.Statement;

  // Threat statements
  insertThreat: Database.Statement;
  getThreatsByAgent: Database.Statement;
  getRecentThreats: Database.Statement;
  getThreatCount: Database.Statement;
  purgeOldThreats: Database.Statement;
  getThreatsByOrg: Database.Statement;

  // Policy statements
  insertPolicy: Database.Statement;
  getActivePolicy: Database.Statement;
  getPolicyHistory: Database.Statement;
  deactivateAllPolicies: Database.Statement;
  getActivePolicyForOrg: Database.Statement;
}

/**
 * ManagerDB - SQLite persistence for the Panguard Manager
 * 基於 SQLite 的 Manager 資料持久化
 *
 * Follows the same pattern as ThreatCloudDB and AuthDB:
 * - WAL mode for concurrent read performance
 * - Prepared statements for all queries (no string interpolation)
 * - JSON serialization for complex fields
 */
export class ManagerDB {
  private readonly db: Database.Database;
  private readonly stmts: Statements;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);

    // Enable WAL mode and performance pragmas / 啟用 WAL 模式及效能 pragma
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('busy_timeout = 15000');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('cache_size = -64000');
    this.db.pragma('temp_store = MEMORY');

    this.initialize();
    this.stmts = this.prepareStatements();
  }

  // =========================================================================
  // Schema initialization / 資料表初始化
  // =========================================================================

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        os TEXT NOT NULL,
        arch TEXT NOT NULL,
        ip TEXT,
        version TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'online',
        last_heartbeat TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        org_id TEXT NOT NULL DEFAULT 'default'
      );

      CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        source_hostname TEXT NOT NULL,
        event_json TEXT NOT NULL,
        verdict_conclusion TEXT NOT NULL,
        verdict_confidence REAL NOT NULL,
        verdict_action TEXT NOT NULL,
        correlated_with TEXT DEFAULT '[]',
        received_at TEXT NOT NULL,
        org_id TEXT NOT NULL DEFAULT 'default',
        FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
      );

      CREATE TABLE IF NOT EXISTS policies (
        policy_id TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        rules_json TEXT NOT NULL,
        applied_to TEXT DEFAULT '[]',
        updated_at TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 0,
        org_id TEXT NOT NULL DEFAULT 'default'
      );

      CREATE INDEX IF NOT EXISTS idx_threats_agent_id ON threats(agent_id);
      CREATE INDEX IF NOT EXISTS idx_threats_received_at ON threats(received_at);
      CREATE INDEX IF NOT EXISTS idx_threats_verdict ON threats(verdict_conclusion);
      CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
      CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(active);
      CREATE INDEX IF NOT EXISTS idx_policies_version ON policies(version);
      CREATE INDEX IF NOT EXISTS idx_agents_org_id ON agents(org_id);
      CREATE INDEX IF NOT EXISTS idx_threats_org_id ON threats(org_id);
      CREATE INDEX IF NOT EXISTS idx_policies_org_id ON policies(org_id);
    `);
  }

  // =========================================================================
  // Prepared statements / 預編譯語句
  // =========================================================================

  private prepareStatements(): Statements {
    return {
      // --- Agent statements ---
      upsertAgent: this.db.prepare(`
        INSERT INTO agents (agent_id, hostname, os, arch, ip, version, status, last_heartbeat, registered_at, org_id)
        VALUES (@agent_id, @hostname, @os, @arch, @ip, @version, @status, @last_heartbeat, @registered_at, @org_id)
        ON CONFLICT(agent_id) DO UPDATE SET
          hostname = excluded.hostname,
          os = excluded.os,
          arch = excluded.arch,
          ip = excluded.ip,
          version = excluded.version,
          status = excluded.status,
          last_heartbeat = excluded.last_heartbeat,
          org_id = excluded.org_id
      `),

      getAgent: this.db.prepare(
        'SELECT * FROM agents WHERE agent_id = ?'
      ),

      getAllAgents: this.db.prepare(
        'SELECT * FROM agents ORDER BY registered_at DESC'
      ),

      getAgentsByStatus: this.db.prepare(
        'SELECT * FROM agents WHERE status = ? ORDER BY last_heartbeat DESC'
      ),

      updateAgentStatus: this.db.prepare(
        'UPDATE agents SET status = ? WHERE agent_id = ?'
      ),

      updateHeartbeat: this.db.prepare(
        'UPDATE agents SET last_heartbeat = ?, status = ? WHERE agent_id = ?'
      ),

      deleteAgent: this.db.prepare(
        'DELETE FROM agents WHERE agent_id = ?'
      ),

      getAgentCount: this.db.prepare(
        'SELECT COUNT(*) as count FROM agents'
      ),

      getAgentsByOrg: this.db.prepare(
        'SELECT * FROM agents WHERE org_id = ? ORDER BY registered_at DESC'
      ),

      // --- Threat statements ---
      insertThreat: this.db.prepare(`
        INSERT INTO threats (id, agent_id, source_hostname, event_json, verdict_conclusion, verdict_confidence, verdict_action, correlated_with, received_at, org_id)
        VALUES (@id, @agent_id, @source_hostname, @event_json, @verdict_conclusion, @verdict_confidence, @verdict_action, @correlated_with, @received_at, @org_id)
      `),

      getThreatsByAgent: this.db.prepare(
        'SELECT * FROM threats WHERE agent_id = ? ORDER BY received_at DESC'
      ),

      getRecentThreats: this.db.prepare(
        'SELECT * FROM threats WHERE received_at >= ? ORDER BY received_at DESC'
      ),

      getThreatCount: this.db.prepare(
        'SELECT COUNT(*) as count FROM threats'
      ),

      purgeOldThreats: this.db.prepare(
        'DELETE FROM threats WHERE received_at < ?'
      ),

      getThreatsByOrg: this.db.prepare(
        'SELECT * FROM threats WHERE org_id = ? ORDER BY received_at DESC'
      ),

      // --- Policy statements ---
      insertPolicy: this.db.prepare(`
        INSERT INTO policies (policy_id, version, rules_json, applied_to, updated_at, active, org_id)
        VALUES (@policy_id, @version, @rules_json, @applied_to, @updated_at, @active, @org_id)
      `),

      getActivePolicy: this.db.prepare(
        'SELECT * FROM policies WHERE active = 1 ORDER BY version DESC LIMIT 1'
      ),

      getPolicyHistory: this.db.prepare(
        'SELECT * FROM policies ORDER BY version DESC'
      ),

      deactivateAllPolicies: this.db.prepare(
        'UPDATE policies SET active = 0'
      ),

      getActivePolicyForOrg: this.db.prepare(
        'SELECT * FROM policies WHERE active = 1 AND org_id = ? ORDER BY version DESC LIMIT 1'
      ),
    };
  }

  // =========================================================================
  // Agent methods / 代理方法
  // =========================================================================

  /** Insert or update an agent registration / 插入或更新代理登錄 */
  upsertAgent(agent: AgentRegistration): void {
    this.stmts.upsertAgent.run({
      agent_id: agent.agentId,
      hostname: agent.hostname,
      os: agent.platform.os,
      arch: agent.platform.arch,
      ip: agent.platform.ip ?? null,
      version: agent.version,
      status: agent.status,
      last_heartbeat: agent.lastHeartbeat,
      registered_at: agent.registeredAt,
      org_id: agent.organizationId ?? 'default',
    });
  }

  /** Get a single agent by ID / 依 ID 取得單一代理 */
  getAgent(agentId: string): AgentRegistration | undefined {
    const row = this.stmts.getAgent.get(agentId) as AgentRow | undefined;
    return row ? this.rowToAgent(row) : undefined;
  }

  /** Get all registered agents / 取得所有已登錄代理 */
  getAllAgents(): AgentRegistration[] {
    const rows = this.stmts.getAllAgents.all() as AgentRow[];
    return rows.map((row) => this.rowToAgent(row));
  }

  /** Get agents filtered by status / 依狀態篩選代理 */
  getAgentsByStatus(status: AgentStatus): AgentRegistration[] {
    const rows = this.stmts.getAgentsByStatus.all(status) as AgentRow[];
    return rows.map((row) => this.rowToAgent(row));
  }

  /** Update an agent's status / 更新代理狀態 */
  updateAgentStatus(agentId: string, status: AgentStatus): boolean {
    const result = this.stmts.updateAgentStatus.run(status, agentId);
    return result.changes > 0;
  }

  /** Update an agent's heartbeat timestamp / 更新代理心跳時間戳 */
  updateHeartbeat(agentId: string, timestamp: string): boolean {
    const result = this.stmts.updateHeartbeat.run(timestamp, 'online', agentId);
    return result.changes > 0;
  }

  /** Delete an agent from the registry / 從登錄簿中刪除代理 */
  deleteAgent(agentId: string): boolean {
    const result = this.stmts.deleteAgent.run(agentId);
    return result.changes > 0;
  }

  /** Get total number of registered agents / 取得已登錄代理總數 */
  getAgentCount(): number {
    const row = this.stmts.getAgentCount.get() as CountRow;
    return row.count;
  }

  // =========================================================================
  // Threat methods / 威脅方法
  // =========================================================================

  /** Insert an aggregated threat / 插入聚合威脅 */
  insertThreat(threat: AggregatedThreat): void {
    this.stmts.insertThreat.run({
      id: threat.id,
      agent_id: threat.sourceAgentId,
      source_hostname: threat.sourceHostname,
      event_json: JSON.stringify(threat.originalThreat),
      verdict_conclusion: threat.originalThreat.verdict.conclusion,
      verdict_confidence: threat.originalThreat.verdict.confidence,
      verdict_action: threat.originalThreat.verdict.action,
      correlated_with: JSON.stringify(threat.correlatedWith),
      received_at: threat.receivedAt,
      org_id: threat.organizationId ?? 'default',
    });
  }

  /** Get all threats from a specific agent / 取得特定代理的所有威脅 */
  getThreatsByAgent(agentId: string): AggregatedThreat[] {
    const rows = this.stmts.getThreatsByAgent.all(agentId) as ThreatRow[];
    return rows.map((row) => this.rowToThreat(row));
  }

  /** Get threats received after a given ISO timestamp / 取得指定時間後接收的威脅 */
  getRecentThreats(since: string): AggregatedThreat[] {
    const rows = this.stmts.getRecentThreats.all(since) as ThreatRow[];
    return rows.map((row) => this.rowToThreat(row));
  }

  /** Get total number of stored threats / 取得已儲存威脅總數 */
  getThreatCount(): number {
    const row = this.stmts.getThreatCount.get() as CountRow;
    return row.count;
  }

  /** Purge threats older than a given ISO date, returns number deleted / 清除指定日期前的威脅 */
  purgeOldThreats(beforeDate: string): number {
    const result = this.stmts.purgeOldThreats.run(beforeDate);
    return result.changes;
  }

  // =========================================================================
  // Policy methods / 策略方法
  // =========================================================================

  /**
   * Insert a policy update. If active=true, deactivates all existing policies first.
   * 插入策略更新。若 active=true，先停用所有現有策略。
   */
  insertPolicy(policy: PolicyUpdate, active: boolean): void {
    const insertWithActivation = this.db.transaction(() => {
      if (active) {
        this.stmts.deactivateAllPolicies.run();
      }
      this.stmts.insertPolicy.run({
        policy_id: policy.policyId,
        version: policy.version,
        rules_json: JSON.stringify(policy.rules),
        applied_to: JSON.stringify(policy.appliedTo),
        updated_at: policy.updatedAt,
        active: active ? 1 : 0,
        org_id: policy.organizationId ?? 'default',
      });
    });
    insertWithActivation();
  }

  /** Get the currently active policy, or null if none / 取得當前啟用的策略 */
  getActivePolicy(): PolicyUpdate | null {
    const row = this.stmts.getActivePolicy.get() as PolicyRow | undefined;
    return row ? this.rowToPolicy(row) : null;
  }

  /** Get all policies ordered by version descending / 取得所有策略（依版本降冪） */
  getPolicyHistory(): PolicyUpdate[] {
    const rows = this.stmts.getPolicyHistory.all() as PolicyRow[];
    return rows.map((row) => this.rowToPolicy(row));
  }

  /** Deactivate all policies / 停用所有策略 */
  deactivateAllPolicies(): void {
    this.stmts.deactivateAllPolicies.run();
  }

  // =========================================================================
  // Organization-scoped queries / 組織範圍查詢
  // =========================================================================

  /** Get agents filtered by organization ID / 依組織 ID 篩選代理 */
  getAgentsByOrg(orgId: string): AgentRegistration[] {
    const rows = this.stmts.getAgentsByOrg.all(orgId) as AgentRow[];
    return rows.map((row) => this.rowToAgent(row));
  }

  /** Get threats filtered by organization ID / 依組織 ID 篩選威脅 */
  getThreatsByOrg(orgId: string): AggregatedThreat[] {
    const rows = this.stmts.getThreatsByOrg.all(orgId) as ThreatRow[];
    return rows.map((row) => this.rowToThreat(row));
  }

  /** Get the active policy for a specific organization / 取得特定組織的啟用策略 */
  getActivePolicyForOrg(orgId: string): PolicyUpdate | null {
    const row = this.stmts.getActivePolicyForOrg.get(orgId) as PolicyRow | undefined;
    return row ? this.rowToPolicy(row) : null;
  }

  // =========================================================================
  // Lifecycle / 生命週期
  // =========================================================================

  /** Close the database connection / 關閉資料庫連線 */
  close(): void {
    this.db.close();
  }

  // =========================================================================
  // Row-to-domain converters (private) / 列轉網域物件（私有）
  // =========================================================================

  /** Convert a database row to an AgentRegistration / 將資料庫列轉換為 AgentRegistration */
  private rowToAgent(row: AgentRow): AgentRegistration {
    return {
      agentId: row.agent_id,
      hostname: row.hostname,
      endpoint: '',
      platform: {
        os: row.os,
        arch: row.arch,
        ip: row.ip ?? undefined,
      },
      version: row.version,
      status: row.status as AgentStatus,
      lastHeartbeat: row.last_heartbeat,
      registeredAt: row.registered_at,
      organizationId: row.org_id,
    };
  }

  /** Convert a database row to an AggregatedThreat / 將資料庫列轉換為 AggregatedThreat */
  private rowToThreat(row: ThreatRow): AggregatedThreat {
    const originalThreat = JSON.parse(row.event_json) as ThreatEvent;
    const correlatedWith = JSON.parse(row.correlated_with) as string[];

    return {
      id: row.id,
      originalThreat,
      sourceAgentId: row.agent_id,
      sourceHostname: row.source_hostname,
      receivedAt: row.received_at,
      correlatedWith,
      organizationId: row.org_id,
    };
  }

  /** Convert a database row to a PolicyUpdate / 將資料庫列轉換為 PolicyUpdate */
  private rowToPolicy(row: PolicyRow): PolicyUpdate {
    const rules = JSON.parse(row.rules_json) as PolicyRule[];
    const appliedTo = JSON.parse(row.applied_to) as string[];

    return {
      policyId: row.policy_id,
      version: row.version,
      rules,
      updatedAt: row.updated_at,
      appliedTo,
      organizationId: row.org_id,
    };
  }
}
