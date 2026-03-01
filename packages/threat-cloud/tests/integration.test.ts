import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatCloudDB } from '../src/database.js';
import { IoCStore } from '../src/ioc-store.js';
import { ReputationEngine } from '../src/reputation-engine.js';
import { CorrelationEngine } from '../src/correlation-engine.js';
import { RuleGenerator } from '../src/rule-generator.js';
import { QueryHandlers } from '../src/query-handlers.js';
import { FeedDistributor } from '../src/feed-distributor.js';
import { Scheduler } from '../src/scheduler.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('Integration Tests', () => {
  let dbWrapper: ThreatCloudDB;
  let store: IoCStore;
  let reputation: ReputationEngine;
  let correlation: CorrelationEngine;
  let ruleGen: RuleGenerator;
  let queryHandlers: QueryHandlers;
  let feedDistributor: FeedDistributor;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'integration-test-'));
    dbWrapper = new ThreatCloudDB(join(tempDir, 'test.db'));
    const db = dbWrapper.getDB();
    store = new IoCStore(db);
    reputation = new ReputationEngine(db);
    correlation = new CorrelationEngine(db, {
      minEventsForCampaign: 3,
      minIPsForPatternCampaign: 3,
      timeWindowMinutes: 60,
      scanWindowHours: 24,
    });
    ruleGen = new RuleGenerator(db, {
      minOccurrences: 3,
      minDistinctIPs: 2,
      analysisWindowHours: 24,
    });
    queryHandlers = new QueryHandlers(db);
    feedDistributor = new FeedDistributor(db);
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
  // End-to-End: Guard threat → IoC → reputation → correlation → rule → feed
  // -------------------------------------------------------------------------

  it('should process Guard threat end-to-end: IoC + reputation + correlation + rule + blocklist', () => {
    const baseTime = new Date();

    // Step 1: Ingest multiple Guard threats from the same IP
    for (let i = 0; i < 5; i++) {
      const enriched = ThreatCloudDB.guardToEnriched({
        attackSourceIP: '10.0.0.1',
        attackType: 'brute_force',
        mitreTechnique: 'T1110',
        sigmaRuleMatched: `rule-${i}`,
        timestamp: new Date(baseTime.getTime() + i * 60_000).toISOString(),
        region: 'TW',
      });
      dbWrapper.insertEnrichedThreat(enriched);

      // Auto-extract IoC
      store.upsertIoC({
        type: 'ip',
        value: '10.0.0.1',
        threatType: 'brute_force',
        source: 'guard',
        confidence: 50,
        tags: ['T1110'],
      });
    }

    // Step 2: Verify IoC created and sightings merged
    const ioc = store.lookupIoC('ip', '10.0.0.1');
    expect(ioc).not.toBeNull();
    expect(ioc!.sightings).toBe(5);

    // Step 3: Recalculate reputation
    const repResult = reputation.recalculateAll();
    expect(repResult.updated).toBe(1);

    const score = reputation.calculateForIoC(ioc!.id);
    expect(score).toBeGreaterThan(0);

    // Step 4: Run correlation
    const corrResult = correlation.scanForCampaigns();
    expect(corrResult.newCampaigns).toBe(1);
    expect(corrResult.eventsCorrelated).toBe(5);

    // Step 5: Verify campaign created
    const campaigns = correlation.listCampaigns({ page: 1, limit: 10 });
    expect(campaigns.items.length).toBe(1);
    expect(campaigns.items[0].campaignType).toBe('ip_cluster');

    // Step 6: Add more events from different IPs (same pattern) to trigger rule gen
    for (let i = 0; i < 3; i++) {
      dbWrapper.insertEnrichedThreat(
        ThreatCloudDB.guardToEnriched({
          attackSourceIP: `192.168.1.${i + 1}`,
          attackType: 'brute_force',
          mitreTechnique: 'T1110',
          sigmaRuleMatched: `rule-extra-${i}`,
          timestamp: new Date(baseTime.getTime() + (i + 10) * 60_000).toISOString(),
          region: 'JP',
        })
      );
    }

    // Step 7: Generate rules
    const ruleResult = ruleGen.generateRules();
    expect(ruleResult.rulesGenerated).toBe(1);

    // Step 8: Verify rule exists
    const rules = dbWrapper.getAllRules();
    const autoRule = rules.find((r) => r.ruleId.startsWith('tc-auto-'));
    expect(autoRule).toBeDefined();
    expect(autoRule!.ruleContent).toContain('brute_force');

    // Step 9: Update IoC reputation to make it appear in blocklist
    dbWrapper
      .getDB()
      .prepare('UPDATE iocs SET reputation_score = 85 WHERE normalized_value = ?')
      .run('10.0.0.1');

    // Step 10: Verify IP appears in blocklist
    const blocklist = feedDistributor.getIPBlocklist(70);
    expect(blocklist).toContain('10.0.0.1');

    // Step 11: Verify agent update includes rule and IoC
    const update = feedDistributor.getAgentUpdate();
    expect(update.rules.length).toBeGreaterThanOrEqual(1);
    expect(update.stats.totalActiveIoCs).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // End-to-End: Trap intel flow
  // -------------------------------------------------------------------------

  it('should process Trap intelligence end-to-end', () => {
    const trapData = {
      timestamp: new Date().toISOString(),
      serviceType: 'ssh',
      sourceIP: '172.16.0.1',
      attackType: 'brute_force',
      mitreTechniques: ['T1110', 'T1021'],
      skillLevel: 'intermediate',
      intent: 'credential_harvesting',
      tools: ['hydra'],
      topCredentials: [
        { username: 'root', count: 50 },
        { username: 'admin', count: 30 },
      ],
    };

    // Step 1: Convert and insert enriched threat
    const enriched = ThreatCloudDB.trapToEnriched(trapData);
    expect(enriched.sourceType).toBe('trap');
    expect(enriched.mitreTechniques).toEqual(['T1110', 'T1021']);

    const enrichedId = dbWrapper.insertEnrichedThreat(enriched);
    expect(enrichedId).not.toBeNull();

    // Step 2: Insert credentials
    dbWrapper.insertTrapCredentials(enrichedId!, trapData.topCredentials);

    // Step 3: Extract IoC
    store.upsertIoC({
      type: 'ip',
      value: '172.16.0.1',
      threatType: 'brute_force',
      source: 'trap',
      confidence: 60,
      tags: ['T1110', 'T1021'],
    });

    // Step 4: Verify IoC in feed
    const feed = feedDistributor.getIoCFeed(40);
    expect(feed.entries.some((e) => e.value === '172.16.0.1')).toBe(true);

    // Step 5: Verify credentials stored
    const creds = dbWrapper
      .getDB()
      .prepare('SELECT * FROM trap_credentials WHERE enriched_threat_id = ?')
      .all(enrichedId!) as Array<{ username: string; attempt_count: number }>;
    expect(creds.length).toBe(2);
  });

  // -------------------------------------------------------------------------
  // Mixed sources → same campaign
  // -------------------------------------------------------------------------

  it('should correlate Guard + Trap events from same IP into single campaign', () => {
    const baseTime = new Date();

    // Guard events
    for (let i = 0; i < 2; i++) {
      dbWrapper.insertEnrichedThreat(
        ThreatCloudDB.guardToEnriched({
          attackSourceIP: '10.0.0.1',
          attackType: 'brute_force',
          mitreTechnique: 'T1110',
          sigmaRuleMatched: `guard-${i}`,
          timestamp: new Date(baseTime.getTime() + i * 60_000).toISOString(),
          region: 'TW',
        })
      );
    }

    // Trap event from same IP
    dbWrapper.insertEnrichedThreat(
      ThreatCloudDB.trapToEnriched({
        sourceIP: '10.0.0.1',
        attackType: 'brute_force',
        mitreTechniques: ['T1110'],
        timestamp: new Date(baseTime.getTime() + 3 * 60_000).toISOString(),
        serviceType: 'ssh',
        skillLevel: 'intermediate',
        intent: 'credential_harvesting',
        tools: [],
        topCredentials: [],
      })
    );

    const result = correlation.scanForCampaigns();
    expect(result.newCampaigns).toBe(1);
    expect(result.eventsCorrelated).toBe(3);
  });

  // -------------------------------------------------------------------------
  // Deduplication
  // -------------------------------------------------------------------------

  it('should deduplicate identical enriched threat events', () => {
    const guardData = {
      attackSourceIP: '10.0.0.1',
      attackType: 'brute_force',
      mitreTechnique: 'T1110',
      sigmaRuleMatched: 'rule-1',
      timestamp: '2026-02-28T10:00:00Z',
      region: 'TW',
    };

    const enriched = ThreatCloudDB.guardToEnriched(guardData);
    const id1 = dbWrapper.insertEnrichedThreat(enriched);
    const id2 = dbWrapper.insertEnrichedThreat(enriched);

    expect(id1).not.toBeNull();
    expect(id2).toBeNull(); // duplicate

    const count = (
      dbWrapper.getDB().prepare('SELECT COUNT(*) as count FROM enriched_threats').get() as {
        count: number;
      }
    ).count;
    expect(count).toBe(1);
  });

  // -------------------------------------------------------------------------
  // Data lifecycle
  // -------------------------------------------------------------------------

  it('should expire and purge stale IoCs via scheduler lifecycle', () => {
    store.upsertIoC({
      type: 'ip',
      value: '10.0.0.1',
      threatType: 'scanner',
      source: 'guard',
      confidence: 50,
    });

    // Make it old
    dbWrapper
      .getDB()
      .prepare(
        "UPDATE iocs SET last_seen = '2020-01-01T00:00:00Z', updated_at = '2020-01-01T00:00:00Z'"
      )
      .run();

    const scheduler = new Scheduler(dbWrapper.getDB(), {
      reputationIntervalMs: 100_000,
      correlationIntervalMs: 100_000,
      ruleGenerationIntervalMs: 100_000,
      aggregationIntervalMs: 100_000,
      threatRetentionDays: 90,
      iocRetentionDays: 1, // 1 day for testing
    });

    const result = scheduler.runLifecycle();
    expect(result.expired).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Query analytics with data
  // -------------------------------------------------------------------------

  it('should provide consistent analytics across query endpoints', () => {
    const baseTime = new Date();
    const regions = ['TW', 'JP', 'US'];

    // Insert diverse threats
    for (let i = 0; i < 6; i++) {
      dbWrapper.insertEnrichedThreat({
        ...ThreatCloudDB.guardToEnriched({
          attackSourceIP: `10.0.${i}.1`,
          attackType: i < 3 ? 'brute_force' : 'scan',
          mitreTechnique: i < 3 ? 'T1110' : 'T1046',
          sigmaRuleMatched: `r-${i}`,
          timestamp: new Date(baseTime.getTime() + i * 60_000).toISOString(),
          region: regions[i % 3],
        }),
        severity: i < 2 ? 'critical' : 'medium',
      });
    }

    // Time series
    const timeSeries = queryHandlers.getTimeSeries('day');
    const totalFromTs = timeSeries.reduce((sum, p) => sum + p.count, 0);
    expect(totalFromTs).toBe(6);

    // Geo distribution
    const geo = queryHandlers.getGeoDistribution();
    const totalFromGeo = geo.reduce((sum, g) => sum + g.count, 0);
    expect(totalFromGeo).toBe(6);
    expect(geo.length).toBe(3);

    // Trends
    const trends = queryHandlers.getTrends(7);
    expect(trends.length).toBe(2);

    // MITRE heatmap
    const heatmap = queryHandlers.getMitreHeatmap();
    expect(heatmap.length).toBe(2);
    const totalFromHm = heatmap.reduce((sum, h) => sum + h.count, 0);
    expect(totalFromHm).toBe(6);
  });

  // -------------------------------------------------------------------------
  // Backward compatibility
  // -------------------------------------------------------------------------

  it('should maintain backward compatibility with legacy threats table', () => {
    // Legacy insert
    dbWrapper.insertThreat({
      attackSourceIP: '192.168.1.1',
      attackType: 'brute_force',
      mitreTechnique: 'T1110',
      sigmaRuleMatched: 'rule-1',
      timestamp: new Date().toISOString(),
      region: 'TW',
    });

    const stats = dbWrapper.getStats();
    expect(stats.totalThreats).toBe(1);
    expect(stats.topAttackTypes[0].type).toBe('brute_force');

    // Enhanced stats should also include legacy data
    const enhanced = queryHandlers.getEnhancedStats();
    expect(enhanced.totalThreats).toBe(1);
  });

  // -------------------------------------------------------------------------
  // Full pipeline simulation
  // -------------------------------------------------------------------------

  it('should run the full scheduler pipeline without errors', () => {
    const baseTime = new Date();

    // Seed data: 5 events from same IP (for correlation + rule gen)
    for (let i = 0; i < 5; i++) {
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

      store.upsertIoC({
        type: 'ip',
        value: '10.0.0.1',
        threatType: 'brute_force',
        source: 'guard',
        confidence: 50,
      });
    }

    const scheduler = new Scheduler(dbWrapper.getDB(), {
      reputationIntervalMs: 100_000,
      correlationIntervalMs: 100_000,
      ruleGenerationIntervalMs: 100_000,
      aggregationIntervalMs: 100_000,
      threatRetentionDays: 90,
      iocRetentionDays: 365,
    });

    // Run all pipeline steps manually
    const corrResult = scheduler.runCorrelation();
    expect(corrResult.newCampaigns).toBeGreaterThanOrEqual(1);

    const repResult = scheduler.runReputation();
    expect(repResult.updated).toBeGreaterThanOrEqual(1);

    const ruleResult = scheduler.runRuleGeneration();
    // May or may not generate rules depending on thresholds
    expect(ruleResult).toHaveProperty('rulesGenerated');

    const lifecycleResult = scheduler.runLifecycle();
    expect(lifecycleResult).toHaveProperty('vacuumed');
  });
});
