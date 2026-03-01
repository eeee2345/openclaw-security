import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatCloudDB } from '../src/database.js';
import { IoCStore } from '../src/ioc-store.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { AnonymizedThreatData, TrapIntelligencePayload } from '../src/types.js';

describe('IoCStore', () => {
  let dbWrapper: ThreatCloudDB;
  let store: IoCStore;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'ioc-store-test-'));
    dbWrapper = new ThreatCloudDB(join(tempDir, 'test.db'));
    store = new IoCStore(dbWrapper.getDB());
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
  // Normalization / 正規化
  // -------------------------------------------------------------------------

  describe('normalizeValue', () => {
    it('should normalize IP by stripping port', () => {
      expect(store.normalizeValue('ip', '192.168.1.1:8080')).toBe('192.168.1.1');
    });

    it('should lowercase IP', () => {
      expect(store.normalizeValue('ip', '192.168.1.1')).toBe('192.168.1.1');
    });

    it('should normalize domain by lowercasing and stripping trailing dot', () => {
      expect(store.normalizeValue('domain', 'Example.COM.')).toBe('example.com');
    });

    it('should normalize URL by lowercasing and stripping trailing slash', () => {
      expect(store.normalizeValue('url', 'HTTP://Example.COM/path/')).toBe(
        'http://example.com/path'
      );
    });

    it('should normalize hash by lowercasing', () => {
      expect(
        store.normalizeValue(
          'hash_sha256',
          'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890'
        )
      ).toBe('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890');
    });
  });

  describe('detectType', () => {
    it('should detect IPv4', () => {
      expect(store.detectType('192.168.1.1')).toBe('ip');
    });

    it('should detect IPv4 with port', () => {
      expect(store.detectType('10.0.0.1:443')).toBe('ip');
    });

    it('should detect URL', () => {
      expect(store.detectType('https://malware.example.com/payload')).toBe('url');
    });

    it('should detect SHA-256', () => {
      expect(
        store.detectType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
      ).toBe('hash_sha256');
    });

    it('should detect MD5', () => {
      expect(store.detectType('d41d8cd98f00b204e9800998ecf8427e')).toBe('hash_md5');
    });

    it('should detect SHA-1', () => {
      expect(store.detectType('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBe('hash_sha1');
    });

    it('should default to domain', () => {
      expect(store.detectType('malware.example.com')).toBe('domain');
    });
  });

  // -------------------------------------------------------------------------
  // Upsert / 新增與合併
  // -------------------------------------------------------------------------

  describe('upsertIoC', () => {
    it('should insert a new IoC', () => {
      const ioc = store.upsertIoC({
        type: 'ip',
        value: '10.20.30.0',
        threatType: 'brute_force',
        source: 'guard',
        confidence: 70,
        tags: ['T1110'],
      });

      expect(ioc.id).toBeGreaterThan(0);
      expect(ioc.type).toBe('ip');
      expect(ioc.sightings).toBe(1);
      expect(ioc.confidence).toBe(70);
      expect(ioc.tags).toEqual(['T1110']);
      expect(ioc.status).toBe('active');
      expect(ioc.reputationScore).toBe(50);
    });

    it('should merge sightings on duplicate', () => {
      store.upsertIoC({
        type: 'ip',
        value: '10.20.30.0',
        threatType: 'brute_force',
        source: 'guard',
        confidence: 50,
        tags: ['T1110'],
      });

      const merged = store.upsertIoC({
        type: 'ip',
        value: '10.20.30.0',
        threatType: 'brute_force',
        source: 'guard',
        confidence: 80,
        tags: ['T1059'],
      });

      expect(merged.sightings).toBe(2);
      expect(merged.confidence).toBe(80); // max(50, 80)
      expect(merged.tags).toContain('T1110');
      expect(merged.tags).toContain('T1059');
    });

    it('should reactivate expired IoC on new sighting', () => {
      const ioc = store.upsertIoC({
        type: 'ip',
        value: '10.20.30.0',
        threatType: 'scanner',
        source: 'guard',
        confidence: 50,
      });

      // Manually expire it
      dbWrapper.getDB().prepare("UPDATE iocs SET status = 'expired' WHERE id = ?").run(ioc.id);

      const reactivated = store.upsertIoC({
        type: 'ip',
        value: '10.20.30.0',
        threatType: 'scanner',
        source: 'guard',
        confidence: 60,
      });

      expect(reactivated.status).toBe('active');
      expect(reactivated.sightings).toBe(2);
    });

    it('should handle different types with same value separately', () => {
      store.upsertIoC({
        type: 'ip',
        value: '10.20.30.0',
        threatType: 'scanner',
        source: 'guard',
        confidence: 50,
      });

      store.upsertIoC({
        type: 'domain',
        value: '10.20.30.0',
        threatType: 'c2',
        source: 'guard',
        confidence: 50,
      });

      const counts = store.getIoCCountsByType();
      expect(counts['ip']).toBe(1);
      expect(counts['domain']).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // Lookup / 查詢
  // -------------------------------------------------------------------------

  describe('lookupIoC', () => {
    it('should find existing IoC', () => {
      store.upsertIoC({
        type: 'ip',
        value: '10.20.30.0',
        threatType: 'brute_force',
        source: 'guard',
        confidence: 70,
      });

      const found = store.lookupIoC('ip', '10.20.30.0');
      expect(found).not.toBeNull();
      expect(found!.value).toBe('10.20.30.0');
    });

    it('should return null for non-existing IoC', () => {
      expect(store.lookupIoC('ip', '99.99.99.0')).toBeNull();
    });

    it('should normalize before lookup', () => {
      store.upsertIoC({
        type: 'domain',
        value: 'malware.example.com',
        threatType: 'c2',
        source: 'guard',
        confidence: 50,
      });

      const found = store.lookupIoC('domain', 'MALWARE.EXAMPLE.COM.');
      expect(found).not.toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // Search / 搜尋
  // -------------------------------------------------------------------------

  describe('searchIoCs', () => {
    beforeEach(() => {
      store.upsertIoC({
        type: 'ip',
        value: '1.2.3.0',
        threatType: 'scanner',
        source: 'guard',
        confidence: 90,
      });
      store.upsertIoC({
        type: 'ip',
        value: '4.5.6.0',
        threatType: 'c2',
        source: 'trap',
        confidence: 80,
      });
      store.upsertIoC({
        type: 'domain',
        value: 'bad.com',
        threatType: 'malware',
        source: 'guard',
        confidence: 70,
      });
    });

    it('should return all IoCs with default pagination', () => {
      const result = store.searchIoCs({}, { page: 1, limit: 50 });
      expect(result.total).toBe(3);
      expect(result.items.length).toBe(3);
    });

    it('should filter by type', () => {
      const result = store.searchIoCs({ type: 'ip' }, { page: 1, limit: 50 });
      expect(result.total).toBe(2);
    });

    it('should filter by source', () => {
      const result = store.searchIoCs({ source: 'trap' }, { page: 1, limit: 50 });
      expect(result.total).toBe(1);
      expect(result.items[0].source).toBe('trap');
    });

    it('should filter by minimum reputation', () => {
      // Update one IoC's reputation
      dbWrapper
        .getDB()
        .prepare('UPDATE iocs SET reputation_score = 90 WHERE normalized_value = ?')
        .run('1.2.3.0');

      const result = store.searchIoCs({ minReputation: 80 }, { page: 1, limit: 50 });
      expect(result.total).toBe(1);
    });

    it('should paginate correctly', () => {
      const page1 = store.searchIoCs({}, { page: 1, limit: 2 });
      expect(page1.items.length).toBe(2);
      expect(page1.hasMore).toBe(true);

      const page2 = store.searchIoCs({}, { page: 2, limit: 2 });
      expect(page2.items.length).toBe(1);
      expect(page2.hasMore).toBe(false);
    });

    it('should search by partial value', () => {
      const result = store.searchIoCs({ search: 'bad' }, { page: 1, limit: 50 });
      expect(result.total).toBe(1);
      expect(result.items[0].type).toBe('domain');
    });

    it('should cap limit at 1000', () => {
      const result = store.searchIoCs({}, { page: 1, limit: 9999 });
      expect(result.limit).toBe(1000);
    });
  });

  // -------------------------------------------------------------------------
  // Lifecycle / 生命週期
  // -------------------------------------------------------------------------

  describe('lifecycle', () => {
    it('should expire stale IoCs', () => {
      store.upsertIoC({
        type: 'ip',
        value: '1.2.3.0',
        threatType: 'scanner',
        source: 'guard',
        confidence: 50,
      });
      // Set last_seen to old date
      dbWrapper.getDB().prepare("UPDATE iocs SET last_seen = '2020-01-01T00:00:00Z'").run();

      const expired = store.expireStaleIoCs('2025-01-01T00:00:00Z');
      expect(expired).toBe(1);

      const ioc = store.lookupIoC('ip', '1.2.3.0');
      expect(ioc!.status).toBe('expired');
    });

    it('should purge expired IoCs', () => {
      store.upsertIoC({
        type: 'ip',
        value: '1.2.3.0',
        threatType: 'scanner',
        source: 'guard',
        confidence: 50,
      });
      dbWrapper
        .getDB()
        .prepare("UPDATE iocs SET status = 'expired', updated_at = '2020-01-01T00:00:00Z'")
        .run();

      const purged = store.purgeExpiredIoCs('2025-01-01T00:00:00Z');
      expect(purged).toBe(1);
      expect(store.lookupIoC('ip', '1.2.3.0')).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // Enriched Threats / 豐富化威脅
  // -------------------------------------------------------------------------

  describe('enriched threats', () => {
    it('should insert Guard threat as enriched event', () => {
      const guardData: AnonymizedThreatData = {
        attackSourceIP: '192.168.1.0',
        attackType: 'brute_force',
        mitreTechnique: 'T1110',
        sigmaRuleMatched: 'rule-001',
        timestamp: '2026-02-28T10:00:00Z',
        region: 'TW',
      };

      const enriched = ThreatCloudDB.guardToEnriched(guardData);
      const id = dbWrapper.insertEnrichedThreat(enriched);
      expect(id).not.toBeNull();
      expect(id).toBeGreaterThan(0);
    });

    it('should deduplicate enriched threats by event_hash', () => {
      const guardData: AnonymizedThreatData = {
        attackSourceIP: '192.168.1.0',
        attackType: 'brute_force',
        mitreTechnique: 'T1110',
        sigmaRuleMatched: 'rule-001',
        timestamp: '2026-02-28T10:00:00Z',
        region: 'TW',
      };

      const enriched = ThreatCloudDB.guardToEnriched(guardData);
      const id1 = dbWrapper.insertEnrichedThreat(enriched);
      const id2 = dbWrapper.insertEnrichedThreat(enriched);

      expect(id1).not.toBeNull();
      expect(id2).toBeNull(); // duplicate
    });

    it('should convert Trap intel to enriched event', () => {
      const trapData: TrapIntelligencePayload = {
        timestamp: '2026-02-28T10:00:00Z',
        serviceType: 'ssh',
        sourceIP: '10.20.30.0',
        attackType: 'brute_force',
        mitreTechniques: ['T1110', 'T1021'],
        skillLevel: 'intermediate',
        intent: 'credential_harvesting',
        tools: ['hydra'],
        topCredentials: [{ username: 'root', count: 50 }],
        region: 'JP',
      };

      const enriched = ThreatCloudDB.trapToEnriched(trapData);
      expect(enriched.sourceType).toBe('trap');
      expect(enriched.mitreTechniques).toEqual(['T1110', 'T1021']);
      expect(enriched.serviceType).toBe('ssh');
      expect(enriched.skillLevel).toBe('intermediate');
      expect(enriched.tools).toEqual(['hydra']);

      const id = dbWrapper.insertEnrichedThreat(enriched);
      expect(id).not.toBeNull();
    });

    it('should insert trap credentials', () => {
      const trapData: TrapIntelligencePayload = {
        timestamp: '2026-02-28T10:00:00Z',
        serviceType: 'ssh',
        sourceIP: '10.20.30.0',
        attackType: 'brute_force',
        mitreTechniques: ['T1110'],
        skillLevel: 'script_kiddie',
        intent: 'credential_harvesting',
        tools: [],
        topCredentials: [
          { username: 'root', count: 50 },
          { username: 'admin', count: 30 },
        ],
      };

      const enriched = ThreatCloudDB.trapToEnriched(trapData);
      const id = dbWrapper.insertEnrichedThreat(enriched)!;

      dbWrapper.insertTrapCredentials(id, trapData.topCredentials);

      // Verify credentials stored
      const creds = dbWrapper
        .getDB()
        .prepare('SELECT * FROM trap_credentials WHERE enriched_threat_id = ?')
        .all(id) as Array<{ username: string; attempt_count: number }>;

      expect(creds.length).toBe(2);
      // Usernames are now hashed for privacy (SHA-256, 16 hex chars)
      expect(creds[0].username).toHaveLength(16);
      expect(creds[0].username).toMatch(/^[0-9a-f]{16}$/);
      expect(creds[0].attempt_count).toBe(50);
    });

    it('should count related threats by IP', () => {
      const enriched1 = ThreatCloudDB.guardToEnriched({
        attackSourceIP: '10.20.30.0',
        attackType: 'brute_force',
        mitreTechnique: 'T1110',
        sigmaRuleMatched: 'r1',
        timestamp: '2026-02-28T10:00:00Z',
        region: 'TW',
      });
      const enriched2 = ThreatCloudDB.guardToEnriched({
        attackSourceIP: '10.20.30.0',
        attackType: 'port_scan',
        mitreTechnique: 'T1046',
        sigmaRuleMatched: 'r2',
        timestamp: '2026-02-28T11:00:00Z',
        region: 'TW',
      });

      dbWrapper.insertEnrichedThreat(enriched1);
      dbWrapper.insertEnrichedThreat(enriched2);

      expect(dbWrapper.countRelatedThreats('10.20.30.0')).toBe(2);
      expect(dbWrapper.countRelatedThreats('99.99.99.0')).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Backward compatibility / 向後相容
  // -------------------------------------------------------------------------

  describe('backward compatibility', () => {
    it('should still insert into legacy threats table', () => {
      dbWrapper.insertThreat({
        attackSourceIP: '192.168.1.0',
        attackType: 'brute_force',
        mitreTechnique: 'T1110',
        sigmaRuleMatched: 'panguard-001',
        timestamp: '2026-02-28T10:00:00Z',
        region: 'TW',
      });

      const stats = dbWrapper.getStats();
      expect(stats.totalThreats).toBe(1);
    });
  });
});
