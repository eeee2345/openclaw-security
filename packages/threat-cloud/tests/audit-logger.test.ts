import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatCloudDB } from '../src/database.js';
import { AuditLogger } from '../src/audit-logger.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('AuditLogger', () => {
  let dbWrapper: ThreatCloudDB;
  let auditLogger: AuditLogger;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'audit-test-'));
    dbWrapper = new ThreatCloudDB(join(tempDir, 'test.db'));
    const db = dbWrapper.getDB();
    auditLogger = new AuditLogger(db);
  });

  afterEach(() => {
    dbWrapper.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  // -------------------------------------------------------------------------
  // Logging
  // -------------------------------------------------------------------------

  it('should log an audit entry', () => {
    auditLogger.log('threat_upload', 'enriched_threat', '123', {
      actorHash: 'abc123',
      ipAddress: '10.0.0.1',
      details: { attackType: 'brute_force' },
    });

    const result = auditLogger.query({});
    expect(result.items.length).toBe(1);
    expect(result.items[0].action).toBe('threat_upload');
    expect(result.items[0].entityType).toBe('enriched_threat');
    expect(result.items[0].entityId).toBe('123');
    expect(result.items[0].actorHash).toBe('abc123');
    expect(result.items[0].ipAddress).toBe('10.0.0.1');
  });

  it('should log with default empty context', () => {
    auditLogger.log('ioc_create', 'ioc', '42');

    const result = auditLogger.query({});
    expect(result.items.length).toBe(1);
    expect(result.items[0].actorHash).toBe('');
    expect(result.items[0].ipAddress).toBe('');
  });

  // -------------------------------------------------------------------------
  // Querying
  // -------------------------------------------------------------------------

  it('should filter by action', () => {
    auditLogger.log('threat_upload', 'threat', '1');
    auditLogger.log('rule_publish', 'rule', 'r1');
    auditLogger.log('threat_upload', 'threat', '2');

    const result = auditLogger.query({ action: 'threat_upload' });
    expect(result.items.length).toBe(2);
    expect(result.total).toBe(2);
  });

  it('should filter by entity type and id', () => {
    auditLogger.log('ioc_create', 'ioc', '10');
    auditLogger.log('ioc_update', 'ioc', '10');
    auditLogger.log('ioc_create', 'ioc', '20');

    const result = auditLogger.query({ entityType: 'ioc', entityId: '10' });
    expect(result.items.length).toBe(2);
  });

  it('should respect limit', () => {
    for (let i = 0; i < 10; i++) {
      auditLogger.log('threat_upload', 'threat', String(i));
    }

    const result = auditLogger.query({ limit: 3 });
    expect(result.items.length).toBe(3);
    expect(result.total).toBe(10);
    expect(result.hasMore).toBe(true);
  });

  it('should enforce max limit of 500', () => {
    const result = auditLogger.query({ limit: 9999 });
    expect(result.limit).toBe(500);
  });

  // -------------------------------------------------------------------------
  // Entity trail
  // -------------------------------------------------------------------------

  it('should return entity trail in chronological order', () => {
    auditLogger.log('ioc_create', 'ioc', '42', { details: { step: 1 } });
    auditLogger.log('ioc_update', 'ioc', '42', { details: { step: 2 } });
    auditLogger.log('sighting_create', 'ioc', '42', { details: { step: 3 } });

    const trail = auditLogger.getEntityTrail('ioc', '42');
    expect(trail.length).toBe(3);
    expect(trail[0].action).toBe('ioc_create');
    expect(trail[2].action).toBe('sighting_create');
  });

  // -------------------------------------------------------------------------
  // API key hashing
  // -------------------------------------------------------------------------

  it('should hash API keys consistently', () => {
    const hash1 = AuditLogger.hashApiKey('my-secret-key');
    const hash2 = AuditLogger.hashApiKey('my-secret-key');
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(16);
  });

  it('should return empty string for empty key', () => {
    expect(AuditLogger.hashApiKey('')).toBe('');
  });

  it('should produce different hashes for different keys', () => {
    const h1 = AuditLogger.hashApiKey('key-1');
    const h2 = AuditLogger.hashApiKey('key-2');
    expect(h1).not.toBe(h2);
  });

  // -------------------------------------------------------------------------
  // Purge
  // -------------------------------------------------------------------------

  it('should purge old entries', () => {
    auditLogger.log('threat_upload', 'threat', '1');

    // Purge entries older than far future — should remove nothing
    const purged0 = auditLogger.purgeOldEntries('2000-01-01T00:00:00Z');
    expect(purged0).toBe(0);

    // Purge entries older than far future — should remove all
    const purgedAll = auditLogger.purgeOldEntries('2099-01-01T00:00:00Z');
    expect(purgedAll).toBe(1);
  });
});
