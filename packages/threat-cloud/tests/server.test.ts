import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatCloudDB } from '../src/database.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { AnonymizedThreatData, ThreatCloudRule } from '../src/types.js';

describe('ThreatCloudDB', () => {
  let db: ThreatCloudDB;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'threat-cloud-test-'));
    db = new ThreatCloudDB(join(tempDir, 'test.db'));
  });

  afterEach(() => {
    db.close();
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  describe('Threat Data', () => {
    const sampleThreat: AnonymizedThreatData = {
      attackSourceIP: '192.168.1.0',
      attackType: 'brute_force',
      mitreTechnique: 'T1110',
      sigmaRuleMatched: 'panguard-001',
      timestamp: '2026-02-25T10:00:00Z',
      industry: 'finance',
      region: 'TW',
    };

    it('should insert and count threats', () => {
      db.insertThreat(sampleThreat);
      db.insertThreat({ ...sampleThreat, attackType: 'lateral_movement', mitreTechnique: 'T1021' });
      db.insertThreat({ ...sampleThreat, attackType: 'brute_force' });

      const stats = db.getStats();
      expect(stats.totalThreats).toBe(3);
    });

    it('should track top attack types', () => {
      db.insertThreat(sampleThreat);
      db.insertThreat(sampleThreat);
      db.insertThreat({ ...sampleThreat, attackType: 'lateral_movement' });

      const stats = db.getStats();
      expect(stats.topAttackTypes.length).toBeGreaterThan(0);
      expect(stats.topAttackTypes[0].type).toBe('brute_force');
      expect(stats.topAttackTypes[0].count).toBe(2);
    });

    it('should track top MITRE techniques', () => {
      db.insertThreat(sampleThreat);
      db.insertThreat({ ...sampleThreat, mitreTechnique: 'T1059' });
      db.insertThreat({ ...sampleThreat, mitreTechnique: 'T1059' });

      const stats = db.getStats();
      expect(stats.topMitreTechniques[0].technique).toBe('T1059');
      expect(stats.topMitreTechniques[0].count).toBe(2);
    });

    it('should handle threat without optional industry field', () => {
      const noIndustry = { ...sampleThreat, industry: undefined };
      db.insertThreat(noIndustry);
      expect(db.getStats().totalThreats).toBe(1);
    });
  });

  describe('Rules', () => {
    const sampleRule: ThreatCloudRule = {
      ruleId: 'community-001',
      ruleContent: JSON.stringify({ title: 'Test Rule', detection: {} }),
      publishedAt: '2026-02-25T10:00:00Z',
      source: 'community',
    };

    it('should insert and retrieve rules', () => {
      db.upsertRule(sampleRule);
      const rules = db.getAllRules();
      expect(rules.length).toBe(1);
      expect(rules[0].ruleId).toBe('community-001');
      expect(rules[0].source).toBe('community');
    });

    it('should upsert rules (update on conflict)', () => {
      db.upsertRule(sampleRule);
      db.upsertRule({ ...sampleRule, ruleContent: '{"updated": true}' });

      const rules = db.getAllRules();
      expect(rules.length).toBe(1);
      expect(rules[0].ruleContent).toBe('{"updated": true}');
    });

    it('should filter rules by since timestamp', () => {
      db.upsertRule(sampleRule);
      db.upsertRule({
        ruleId: 'community-002',
        ruleContent: '{}',
        publishedAt: '2026-02-26T10:00:00Z',
        source: 'community',
      });

      const allRules = db.getAllRules();
      expect(allRules.length).toBe(2);

      const newRules = db.getRulesSince('2026-02-25T12:00:00Z');
      expect(newRules.length).toBe(1);
      expect(newRules[0].ruleId).toBe('community-002');
    });

    it('should return empty array when no rules match since filter', () => {
      db.upsertRule(sampleRule);
      const rules = db.getRulesSince('2099-01-01T00:00:00Z');
      expect(rules.length).toBe(0);
    });
  });

  describe('Stats', () => {
    it('should return zero stats on empty database', () => {
      const stats = db.getStats();
      expect(stats.totalThreats).toBe(0);
      expect(stats.totalRules).toBe(0);
      expect(stats.topAttackTypes).toEqual([]);
      expect(stats.topMitreTechniques).toEqual([]);
      expect(stats.last24hThreats).toBe(0);
    });

    it('should count rules in stats', () => {
      db.upsertRule({
        ruleId: 'r1',
        ruleContent: '{}',
        publishedAt: '2026-02-25T10:00:00Z',
        source: 'test',
      });
      db.upsertRule({
        ruleId: 'r2',
        ruleContent: '{}',
        publishedAt: '2026-02-25T11:00:00Z',
        source: 'test',
      });
      expect(db.getStats().totalRules).toBe(2);
    });
  });
});
