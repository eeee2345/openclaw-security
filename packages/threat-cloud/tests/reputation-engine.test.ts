import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatCloudDB } from '../src/database.js';
import { IoCStore } from '../src/ioc-store.js';
import { ReputationEngine } from '../src/reputation-engine.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('ReputationEngine', () => {
  let dbWrapper: ThreatCloudDB;
  let store: IoCStore;
  let engine: ReputationEngine;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'reputation-test-'));
    dbWrapper = new ThreatCloudDB(join(tempDir, 'test.db'));
    const db = dbWrapper.getDB();
    store = new IoCStore(db);
    engine = new ReputationEngine(db);
  });

  afterEach(() => {
    dbWrapper.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it('should recalculate reputation for all active IoCs', () => {
    store.upsertIoC({
      type: 'ip',
      value: '1.2.3.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 70,
    });
    store.upsertIoC({
      type: 'ip',
      value: '4.5.6.0',
      threatType: 'c2',
      source: 'trap',
      confidence: 90,
    });

    const result = engine.recalculateAll();
    expect(result.updated).toBe(2);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('should increase score with more sightings', () => {
    const ioc = store.upsertIoC({
      type: 'ip',
      value: '1.2.3.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 50,
    });
    const scoreBefore = engine.calculateForIoC(ioc.id);

    // Add more sightings
    store.upsertIoC({
      type: 'ip',
      value: '1.2.3.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 50,
    });
    store.upsertIoC({
      type: 'ip',
      value: '1.2.3.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 50,
    });

    const scoreAfter = engine.calculateForIoC(ioc.id);
    expect(scoreAfter).toBeGreaterThan(scoreBefore);
  });

  it('should decrease score for stale IoCs (time decay)', () => {
    const ioc = store.upsertIoC({
      type: 'ip',
      value: '1.2.3.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 50,
    });
    const scoreRecent = engine.calculateForIoC(ioc.id);

    // Set last_seen to 90 days ago
    dbWrapper
      .getDB()
      .prepare("UPDATE iocs SET last_seen = datetime('now', '-90 days') WHERE id = ?")
      .run(ioc.id);

    const scoreOld = engine.calculateForIoC(ioc.id);
    expect(scoreOld).toBeLessThan(scoreRecent);
  });

  it('should increase score with higher severity threats', () => {
    const ioc = store.upsertIoC({
      type: 'ip',
      value: '1.2.3.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 50,
    });

    // Add a low severity threat
    const lowEvent = ThreatCloudDB.guardToEnriched({
      attackSourceIP: '1.2.3.0',
      attackType: 'scan',
      mitreTechnique: 'T1046',
      sigmaRuleMatched: 'r1',
      timestamp: new Date().toISOString(),
      region: 'TW',
    });
    dbWrapper.insertEnrichedThreat({ ...lowEvent, severity: 'low' });
    const scoreLow = engine.calculateForIoC(ioc.id);

    // Add a critical severity threat
    const critEvent = ThreatCloudDB.guardToEnriched({
      attackSourceIP: '1.2.3.0',
      attackType: 'ransomware',
      mitreTechnique: 'T1486',
      sigmaRuleMatched: 'r2',
      timestamp: new Date(Date.now() + 1000).toISOString(),
      region: 'TW',
    });
    dbWrapper.insertEnrichedThreat({ ...critEvent, severity: 'critical' });
    const scoreHigh = engine.calculateForIoC(ioc.id);

    expect(scoreHigh).toBeGreaterThan(scoreLow);
  });

  it('should increase score with diverse sources', () => {
    const ioc = store.upsertIoC({
      type: 'ip',
      value: '1.2.3.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 50,
    });

    // One source
    dbWrapper.insertEnrichedThreat({
      ...ThreatCloudDB.guardToEnriched({
        attackSourceIP: '1.2.3.0',
        attackType: 'scan',
        mitreTechnique: 'T1046',
        sigmaRuleMatched: 'r1',
        timestamp: new Date().toISOString(),
        region: 'TW',
      }),
      sourceType: 'guard',
    });
    const scoreOneSrc = engine.calculateForIoC(ioc.id);

    // Add from trap source
    const trapEnriched = ThreatCloudDB.trapToEnriched({
      sourceIP: '1.2.3.0',
      attackType: 'brute_force',
      mitreTechniques: ['T1110'],
      timestamp: new Date(Date.now() + 2000).toISOString(),
      serviceType: 'ssh',
      skillLevel: 'intermediate',
      intent: 'credential_harvesting',
      tools: [],
      topCredentials: [],
    });
    dbWrapper.insertEnrichedThreat(trapEnriched);
    const scoreTwoSrc = engine.calculateForIoC(ioc.id);

    expect(scoreTwoSrc).toBeGreaterThan(scoreOneSrc);
  });

  it('should return 0 for non-existing IoC', () => {
    expect(engine.calculateForIoC(99999)).toBe(0);
  });

  it('should handle empty database', () => {
    const result = engine.recalculateAll();
    expect(result.updated).toBe(0);
  });

  it('should clamp score between 0 and 100', () => {
    // Create IoC with max sightings
    for (let i = 0; i < 25; i++) {
      store.upsertIoC({
        type: 'ip',
        value: '1.2.3.0',
        threatType: 'scanner',
        source: `src${i}`,
        confidence: 100,
      });
    }
    const ioc = store.lookupIoC('ip', '1.2.3.0')!;
    const score = engine.calculateForIoC(ioc.id);
    expect(score).toBeLessThanOrEqual(100);
    expect(score).toBeGreaterThanOrEqual(0);
  });
});
