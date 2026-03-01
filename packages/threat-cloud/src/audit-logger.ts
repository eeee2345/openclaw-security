/**
 * Audit Logger — provenance tracking for all write operations
 * 稽核日誌 — 所有寫入操作的溯源追蹤
 *
 * Every mutation (IoC create/update, sighting, threat upload, rule publish)
 * is logged with actor, IP, timestamp, and action details.
 *
 * @module @panguard-ai/threat-cloud/audit-logger
 */

import { createHash } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { AuditAction, AuditLogEntry, AuditLogQuery, PaginatedResponse } from './types.js';

/** Raw audit log row from SQLite */
interface AuditRow {
  id: number;
  action: string;
  entity_type: string;
  entity_id: string;
  actor_hash: string;
  ip_address: string;
  details: string;
  created_at: string;
}

function rowToEntry(row: AuditRow): AuditLogEntry {
  return {
    id: row.id,
    action: row.action as AuditAction,
    entityType: row.entity_type,
    entityId: row.entity_id,
    actorHash: row.actor_hash,
    ipAddress: row.ip_address,
    details: row.details,
    createdAt: row.created_at,
  };
}

export class AuditLogger {
  private readonly insertStmt: Database.Statement;

  constructor(private readonly db: Database.Database) {
    this.insertStmt = this.db.prepare(
      `INSERT INTO audit_log (action, entity_type, entity_id, actor_hash, ip_address, details)
       VALUES (?, ?, ?, ?, ?, ?)`
    );
  }

  /**
   * Log an auditable action.
   * 記錄可稽核的操作
   */
  log(
    action: AuditAction,
    entityType: string,
    entityId: string,
    context: {
      actorHash?: string;
      ipAddress?: string;
      details?: Record<string, unknown>;
    } = {}
  ): void {
    this.insertStmt.run(
      action,
      entityType,
      entityId,
      context.actorHash ?? '',
      context.ipAddress ?? '',
      JSON.stringify(context.details ?? {})
    );
  }

  /**
   * Hash an API key for audit logging (never log raw keys).
   * 將 API key 雜湊化用於稽核日誌（永遠不記錄原始 key）
   */
  static hashApiKey(apiKey: string): string {
    if (!apiKey) return '';
    return createHash('sha256').update(apiKey).digest('hex').slice(0, 16);
  }

  /**
   * Query audit log with filters.
   * 查詢稽核日誌
   */
  query(params: AuditLogQuery): PaginatedResponse<AuditLogEntry> {
    const conditions: string[] = [];
    const values: unknown[] = [];

    if (params.action) {
      conditions.push('action = ?');
      values.push(params.action);
    }
    if (params.entityType) {
      conditions.push('entity_type = ?');
      values.push(params.entityType);
    }
    if (params.entityId) {
      conditions.push('entity_id = ?');
      values.push(params.entityId);
    }
    if (params.since) {
      conditions.push('created_at > ?');
      values.push(params.since);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const safeLimit = Math.min(Math.max(1, params.limit ?? 50), 500);

    const total = (
      this.db.prepare(`SELECT COUNT(*) as count FROM audit_log ${where}`).get(...values) as {
        count: number;
      }
    ).count;

    const rows = this.db
      .prepare(`SELECT * FROM audit_log ${where} ORDER BY created_at DESC LIMIT ?`)
      .all(...values, safeLimit) as AuditRow[];

    return {
      items: rows.map(rowToEntry),
      total,
      page: 1,
      limit: safeLimit,
      hasMore: safeLimit < total,
    };
  }

  /**
   * Get audit trail for a specific entity.
   * 取得特定實體的稽核記錄
   */
  getEntityTrail(entityType: string, entityId: string): AuditLogEntry[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM audit_log
         WHERE entity_type = ? AND entity_id = ?
         ORDER BY created_at ASC`
      )
      .all(entityType, entityId) as AuditRow[];
    return rows.map(rowToEntry);
  }

  /**
   * Purge old audit entries beyond retention.
   * 清除超齡的稽核記錄
   */
  purgeOldEntries(olderThan: string): number {
    const result = this.db.prepare('DELETE FROM audit_log WHERE created_at < ?').run(olderThan);
    return result.changes;
  }
}
