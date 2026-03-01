/**
 * IoC (Indicator of Compromise) Store
 * IoC（入侵指標）儲存模組
 *
 * Handles CRUD, normalization, deduplication, and sighting-merge for IoCs.
 *
 * @module @panguard-ai/threat-cloud/ioc-store
 */

import type Database from 'better-sqlite3';
import type {
  IoCType,
  IoCStatus,
  IoCRecord,
  IoCInput,
  IoCLookupResult,
  PaginationParams,
  PaginatedResponse,
} from './types.js';

/** Raw IoC row from SQLite / SQLite 回傳的原始 IoC 列 */
interface IoCRow {
  id: number;
  type: string;
  value: string;
  normalized_value: string;
  threat_type: string;
  source: string;
  confidence: number;
  reputation_score: number;
  first_seen: string;
  last_seen: string;
  sightings: number;
  status: string;
  tags: string;
  metadata: string;
  created_at: string;
  updated_at: string;
}

/** Convert DB row to IoCRecord / 將 DB 列轉換為 IoCRecord */
function rowToRecord(row: IoCRow): IoCRecord {
  return {
    id: row.id,
    type: row.type as IoCType,
    value: row.value,
    normalizedValue: row.normalized_value,
    threatType: row.threat_type,
    source: row.source,
    confidence: row.confidence,
    reputationScore: row.reputation_score,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    sightings: row.sightings,
    status: row.status as IoCStatus,
    tags: JSON.parse(row.tags) as string[],
    metadata: JSON.parse(row.metadata) as Record<string, unknown>,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class IoCStore {
  constructor(private readonly db: Database.Database) {}

  // -------------------------------------------------------------------------
  // Normalization / 正規化
  // -------------------------------------------------------------------------

  /**
   * Normalize IoC value for deduplication.
   * 正規化 IoC 值以便去重
   */
  normalizeValue(type: IoCType, value: string): string {
    const trimmed = value.trim();
    switch (type) {
      case 'ip': {
        // Strip port if present (e.g., "1.2.3.4:8080" -> "1.2.3.4")
        const noPort = trimmed.replace(/:\d+$/, '');
        return noPort.toLowerCase();
      }
      case 'domain':
        // Lowercase, remove trailing dot
        return trimmed.toLowerCase().replace(/\.$/, '');
      case 'url':
        // Lowercase scheme+host, strip trailing slash
        return trimmed.toLowerCase().replace(/\/+$/, '');
      case 'hash_md5':
      case 'hash_sha1':
      case 'hash_sha256':
        return trimmed.toLowerCase();
      default:
        return trimmed.toLowerCase();
    }
  }

  /**
   * Auto-detect IoC type from value / 自動偵測 IoC 類型
   */
  detectType(value: string): IoCType {
    const v = value.trim();
    // IPv4
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(v)) return 'ip';
    // IPv6
    if (v.includes(':') && /^[0-9a-fA-F:]+$/.test(v)) return 'ip';
    // URL
    if (/^https?:\/\//i.test(v)) return 'url';
    // SHA-256
    if (/^[a-fA-F0-9]{64}$/.test(v)) return 'hash_sha256';
    // SHA-1
    if (/^[a-fA-F0-9]{40}$/.test(v)) return 'hash_sha1';
    // MD5
    if (/^[a-fA-F0-9]{32}$/.test(v)) return 'hash_md5';
    // Default to domain
    return 'domain';
  }

  // -------------------------------------------------------------------------
  // CRUD / 資料操作
  // -------------------------------------------------------------------------

  /**
   * Upsert an IoC: insert if new, merge sighting if existing.
   * Upsert IoC：新建或合併觀測
   */
  upsertIoC(input: IoCInput): IoCRecord {
    const normalized = this.normalizeValue(input.type, input.value);
    const now = new Date().toISOString();
    const tags = input.tags ?? [];
    const metadata = input.metadata ?? {};

    // Try to find existing
    const existing = this.db
      .prepare('SELECT * FROM iocs WHERE type = ? AND normalized_value = ?')
      .get(input.type, normalized) as IoCRow | undefined;

    if (existing) {
      // Merge: increment sightings, update last_seen, update confidence, merge tags
      const existingTags = JSON.parse(existing.tags) as string[];
      const mergedTags = [...new Set([...existingTags, ...tags])];
      const newConfidence = Math.max(existing.confidence, input.confidence);
      const newLastSeen = now > existing.last_seen ? now : existing.last_seen;

      this.db
        .prepare(
          `UPDATE iocs SET
            sightings = sightings + 1,
            last_seen = ?,
            confidence = ?,
            tags = ?,
            status = CASE WHEN status = 'expired' THEN 'active' ELSE status END,
            updated_at = datetime('now')
          WHERE id = ?`
        )
        .run(newLastSeen, newConfidence, JSON.stringify(mergedTags), existing.id);

      return this.getIoCById(existing.id)!;
    }

    // Insert new
    const result = this.db
      .prepare(
        `INSERT INTO iocs
          (type, value, normalized_value, threat_type, source, confidence,
           reputation_score, first_seen, last_seen, tags, metadata)
        VALUES (?, ?, ?, ?, ?, ?, 50, ?, ?, ?, ?)`
      )
      .run(
        input.type,
        input.value,
        normalized,
        input.threatType,
        input.source,
        input.confidence,
        now,
        now,
        JSON.stringify(tags),
        JSON.stringify(metadata)
      );

    return this.getIoCById(Number(result.lastInsertRowid))!;
  }

  /**
   * Lookup a single IoC by type+value / 以 type+value 查詢單一 IoC
   */
  lookupIoC(type: IoCType, value: string): IoCRecord | null {
    const normalized = this.normalizeValue(type, value);
    const row = this.db
      .prepare('SELECT * FROM iocs WHERE type = ? AND normalized_value = ?')
      .get(type, normalized) as IoCRow | undefined;
    return row ? rowToRecord(row) : null;
  }

  /**
   * Lookup IoC with related threat count / 查詢 IoC 含相關威脅數
   */
  lookupIoCWithContext(
    type: IoCType,
    value: string,
    countThreats: (ip: string) => number
  ): IoCLookupResult {
    const ioc = this.lookupIoC(type, value);
    if (!ioc) {
      return { found: false, relatedThreats: 0 };
    }
    const relatedThreats = type === 'ip' ? countThreats(ioc.normalizedValue) : 0;
    return { found: true, ioc, relatedThreats };
  }

  /**
   * Get IoC by ID / 以 ID 取得 IoC
   */
  getIoCById(id: number): IoCRecord | null {
    const row = this.db.prepare('SELECT * FROM iocs WHERE id = ?').get(id) as IoCRow | undefined;
    return row ? rowToRecord(row) : null;
  }

  /**
   * Get active IoCs by type with minimum reputation / 取得特定類型的活躍 IoC
   */
  getActiveIoCsByType(type: IoCType, minReputation: number, limit: number): IoCRecord[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM iocs
         WHERE type = ? AND status = 'active' AND reputation_score >= ?
         ORDER BY reputation_score DESC
         LIMIT ?`
      )
      .all(type, minReputation, limit) as IoCRow[];
    return rows.map(rowToRecord);
  }

  /**
   * Search IoCs with filters and pagination / 以篩選條件搜尋 IoC
   */
  searchIoCs(
    filters: {
      type?: IoCType;
      source?: string;
      minReputation?: number;
      status?: IoCStatus;
      since?: string;
      search?: string;
    },
    pagination: PaginationParams
  ): PaginatedResponse<IoCRecord> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filters.type) {
      conditions.push('type = ?');
      params.push(filters.type);
    }
    if (filters.source) {
      conditions.push('source = ?');
      params.push(filters.source);
    }
    if (filters.minReputation !== undefined) {
      conditions.push('reputation_score >= ?');
      params.push(filters.minReputation);
    }
    if (filters.status) {
      conditions.push('status = ?');
      params.push(filters.status);
    }
    if (filters.since) {
      conditions.push('updated_at > ?');
      params.push(filters.since);
    }
    if (filters.search) {
      conditions.push('normalized_value LIKE ?');
      params.push(`%${filters.search}%`);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const safePage = Math.max(1, pagination.page);
    const safeLimit = Math.min(Math.max(1, pagination.limit), 1000);
    const offset = (safePage - 1) * safeLimit;

    const total = (
      this.db.prepare(`SELECT COUNT(*) as count FROM iocs ${where}`).get(...params) as {
        count: number;
      }
    ).count;

    const rows = this.db
      .prepare(
        `SELECT * FROM iocs ${where} ORDER BY reputation_score DESC, last_seen DESC LIMIT ? OFFSET ?`
      )
      .all(...params, safeLimit, offset) as IoCRow[];

    return {
      items: rows.map(rowToRecord),
      total,
      page: safePage,
      limit: safeLimit,
      hasMore: offset + safeLimit < total,
    };
  }

  /**
   * Batch update reputation scores / 批次更新信譽分數
   */
  batchUpdateReputation(updates: Array<{ id: number; reputationScore: number }>): void {
    const stmt = this.db.prepare(
      "UPDATE iocs SET reputation_score = ?, updated_at = datetime('now') WHERE id = ?"
    );
    const updateAll = this.db.transaction((items: typeof updates) => {
      for (const u of items) {
        stmt.run(Math.max(0, Math.min(100, Math.round(u.reputationScore))), u.id);
      }
    });
    updateAll(updates);
  }

  /**
   * Expire stale IoCs / 過期未活躍的 IoC
   */
  expireStaleIoCs(olderThan: string): number {
    const result = this.db
      .prepare(
        "UPDATE iocs SET status = 'expired', updated_at = datetime('now') WHERE status = 'active' AND last_seen < ?"
      )
      .run(olderThan);
    return result.changes;
  }

  /**
   * Delete expired IoCs beyond retention / 刪除超齡的已過期 IoC
   */
  purgeExpiredIoCs(olderThan: string): number {
    const result = this.db
      .prepare("DELETE FROM iocs WHERE status = 'expired' AND updated_at < ?")
      .run(olderThan);
    return result.changes;
  }

  /**
   * Get IoC counts by type / 取得各類型 IoC 數量
   */
  getIoCCountsByType(): Record<string, number> {
    const rows = this.db
      .prepare("SELECT type, COUNT(*) as count FROM iocs WHERE status = 'active' GROUP BY type")
      .all() as Array<{ type: string; count: number }>;
    const result: Record<string, number> = {};
    for (const r of rows) {
      result[r.type] = r.count;
    }
    return result;
  }

  /**
   * Get top malicious IoCs / 取得最高威脅度 IoC
   */
  getTopMaliciousIoCs(limit: number): IoCRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM iocs WHERE status = 'active' ORDER BY reputation_score DESC LIMIT ?")
      .all(limit) as IoCRow[];
    return rows.map(rowToRecord);
  }

  /**
   * Get total active IoC count / 取得活躍 IoC 總數
   */
  getTotalActiveCount(): number {
    return (
      this.db.prepare("SELECT COUNT(*) as count FROM iocs WHERE status = 'active'").get() as {
        count: number;
      }
    ).count;
  }
}
