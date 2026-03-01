import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatCloudDB } from '../src/database.js';
import { IoCStore } from '../src/ioc-store.js';
import { Scheduler } from '../src/scheduler.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('Scheduler', () => {
  let dbWrapper: ThreatCloudDB;
  let store: IoCStore;
  let scheduler: Scheduler;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'scheduler-test-'));
    dbWrapper = new ThreatCloudDB(join(tempDir, 'test.db'));
    const db = dbWrapper.getDB();
    store = new IoCStore(db);
    scheduler = new Scheduler(db, {
      reputationIntervalMs: 100_000, // long intervals so they don't fire during tests
      correlationIntervalMs: 100_000,
      ruleGenerationIntervalMs: 100_000,
      aggregationIntervalMs: 100_000,
      threatRetentionDays: 90,
      iocRetentionDays: 365,
    });
  });

  afterEach(() => {
    scheduler.stop();
    dbWrapper.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it('should start and stop without errors', () => {
    scheduler.start();
    expect(scheduler.isRunning()).toBe(true);
    scheduler.stop();
    expect(scheduler.isRunning()).toBe(false);
  });

  it('should not start twice', () => {
    scheduler.start();
    scheduler.start(); // second call is a no-op
    expect(scheduler.isRunning()).toBe(true);
    scheduler.stop();
  });

  it('should run correlation manually', () => {
    // Insert some events
    const baseTime = new Date();
    for (let i = 0; i < 4; i++) {
      dbWrapper.insertEnrichedThreat(
        ThreatCloudDB.guardToEnriched({
          attackSourceIP: '10.0.0.1',
          attackType: 'brute_force',
          mitreTechnique: 'T1110',
          sigmaRuleMatched: `r-${i}`,
          timestamp: new Date(baseTime.getTime() + i * 60_000).toISOString(),
          region: 'TW',
        })
      );
    }

    const result = scheduler.runCorrelation();
    expect(result.newCampaigns).toBe(1);
    expect(result.eventsCorrelated).toBe(4);
  });

  it('should run reputation recalculation manually', () => {
    store.upsertIoC({
      type: 'ip',
      value: '10.0.0.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 70,
    });
    store.upsertIoC({
      type: 'ip',
      value: '10.0.1.0',
      threatType: 'c2',
      source: 'trap',
      confidence: 90,
    });

    const result = scheduler.runReputation();
    expect(result.updated).toBe(2);
  });

  it('should run rule generation manually', () => {
    const result = scheduler.runRuleGeneration();
    expect(result.rulesGenerated).toBe(0);
    expect(result.rulesUpdated).toBe(0);
  });

  it('should run lifecycle cleanup manually', () => {
    // Insert an IoC and expire it
    store.upsertIoC({
      type: 'ip',
      value: '10.0.0.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 50,
    });
    dbWrapper.getDB().prepare("UPDATE iocs SET last_seen = '2020-01-01T00:00:00Z'").run();

    const result = scheduler.runLifecycle();
    expect(result).toHaveProperty('expired');
    expect(result).toHaveProperty('purged');
    expect(result).toHaveProperty('vacuumed');
  });
});
