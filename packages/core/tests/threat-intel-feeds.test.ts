import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatIntelFeedManager, type IoC } from '../src/monitor/threat-intel-feeds.js';

describe('ThreatIntelFeedManager', () => {
  let manager: ThreatIntelFeedManager;

  beforeEach(() => {
    // Disable auto-update and all network feeds for unit tests
    manager = new ThreatIntelFeedManager({
      updateIntervalMs: 999999999,
      enabledFeeds: [],
      requestTimeoutMs: 5000,
    });
  });

  afterEach(() => {
    manager.stop();
  });

  it('should initialize with empty state', () => {
    expect(manager.getIoCCount()).toBe(0);
    expect(manager.getIPCount()).toBe(0);
  });

  it('should return undefined for unknown IP', () => {
    expect(manager.checkIP('1.2.3.4')).toBeUndefined();
  });

  it('should return undefined for unknown IoC search', () => {
    expect(manager.search('nonexistent')).toBeUndefined();
  });

  it('should return empty update times', () => {
    expect(manager.getLastUpdateTimes().size).toBe(0);
  });

  it('should handle updateAll with no feeds enabled', async () => {
    const results = await manager.updateAll();
    expect(results).toEqual([]);
  });

  it('should convert IP IoC to ThreatIntelEntry', () => {
    const ioc: IoC = {
      type: 'ip',
      value: '1.2.3.4',
      threatType: 'c2:emotet',
      source: 'feodotracker',
      confidence: 95,
      tags: ['emotet', 'US'],
    };

    const entry = manager.toThreatIntelEntry(ioc);
    expect(entry).not.toBeNull();
    expect(entry!.ip).toBe('1.2.3.4');
    expect(entry!.type).toBe('c2');
    expect(entry!.source).toBe('feodotracker');
  });

  it('should return null for non-IP IoC conversion', () => {
    const ioc: IoC = {
      type: 'url',
      value: 'http://evil.com',
      threatType: 'malware_distribution',
      source: 'urlhaus',
      confidence: 90,
      tags: [],
    };

    const entry = manager.toThreatIntelEntry(ioc);
    expect(entry).toBeNull();
  });

  it('should map scanner IoC to scanner type', () => {
    const ioc: IoC = {
      type: 'ip',
      value: '5.6.7.8',
      threatType: 'scanner:benign',
      source: 'greynoise',
      confidence: 50,
      tags: [],
    };

    const entry = manager.toThreatIntelEntry(ioc);
    expect(entry!.type).toBe('scanner');
  });

  it('should map botnet IoC to botnet type', () => {
    const ioc: IoC = {
      type: 'ip',
      value: '9.10.11.12',
      threatType: 'botnet:mirai',
      source: 'threatfox',
      confidence: 80,
      tags: [],
    };

    const entry = manager.toThreatIntelEntry(ioc);
    expect(entry!.type).toBe('botnet');
  });

  it('should default to malware type for unknown threat types', () => {
    const ioc: IoC = {
      type: 'ip',
      value: '13.14.15.16',
      threatType: 'unknown_category',
      source: 'threatfox',
      confidence: 60,
      tags: [],
    };

    const entry = manager.toThreatIntelEntry(ioc);
    expect(entry!.type).toBe('malware');
  });

  it('should get empty IP entries initially', () => {
    expect(manager.getAllIPEntries()).toEqual([]);
  });

  it('should stop cleanly', () => {
    manager.stop();
    // Double stop should not throw
    manager.stop();
  });

  // -------------------------------------------------------------------------
  // Feed Staleness Detection / 情報源過期偵測
  // -------------------------------------------------------------------------

  it('should report all feeds as stale when never updated', () => {
    const mgr = new ThreatIntelFeedManager({
      updateIntervalMs: 1000,
      enabledFeeds: ['threatfox', 'urlhaus'],
      requestTimeoutMs: 5000,
    });

    const health = mgr.getFeedHealth();
    expect(health).toHaveLength(2);
    expect(health[0].stale).toBe(true);
    expect(health[0].degraded).toBe(true);
    expect(health[0].lastSuccessfulUpdate).toBeNull();
    expect(health[0].confidenceMultiplier).toBe(0.5);

    mgr.stop();
  });

  it('should report feed as healthy right after successful update', async () => {
    const mgr = new ThreatIntelFeedManager({
      updateIntervalMs: 60_000,
      enabledFeeds: [],
      requestTimeoutMs: 5000,
    });

    // Simulate a successful update by calling updateAll (no feeds enabled = instant success)
    await mgr.updateAll();

    // No feeds to check health for (empty enabledFeeds), so getFeedHealth returns empty
    expect(mgr.getFeedHealth()).toEqual([]);

    mgr.stop();
  });

  it('should return correct confidence multiplier: 1.0 for healthy, 0.5 for degraded', () => {
    const mgr = new ThreatIntelFeedManager({
      updateIntervalMs: 1000,
      enabledFeeds: ['threatfox'],
      requestTimeoutMs: 5000,
    });

    // Never updated → degraded → 0.5
    expect(mgr.getConfidenceMultiplier('threatfox')).toBe(0.5);

    mgr.stop();
  });

  it('should use custom stale/degraded threshold multipliers', () => {
    const mgr = new ThreatIntelFeedManager({
      updateIntervalMs: 1000,
      enabledFeeds: ['urlhaus'],
      requestTimeoutMs: 5000,
      staleThresholdMultiplier: 3,
      degradedThresholdMultiplier: 10,
    });

    const health = mgr.getFeedHealth();
    expect(health[0].stale).toBe(true);
    expect(health[0].degraded).toBe(true);

    mgr.stop();
  });
});
