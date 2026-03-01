import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatCloudDB } from '../src/database.js';
import { IoCStore } from '../src/ioc-store.js';
import { FeedDistributor } from '../src/feed-distributor.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('FeedDistributor', () => {
  let dbWrapper: ThreatCloudDB;
  let store: IoCStore;
  let distributor: FeedDistributor;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'feed-test-'));
    dbWrapper = new ThreatCloudDB(join(tempDir, 'test.db'));
    const db = dbWrapper.getDB();
    store = new IoCStore(db);
    distributor = new FeedDistributor(db);
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
  // IP Blocklist
  // -------------------------------------------------------------------------

  it('should return IP blocklist with high reputation IPs', () => {
    store.upsertIoC({
      type: 'ip',
      value: '10.0.0.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 90,
    });
    store.upsertIoC({
      type: 'ip',
      value: '10.0.1.0',
      threatType: 'c2',
      source: 'trap',
      confidence: 50,
    });

    // Set high reputation for first IP
    dbWrapper
      .getDB()
      .prepare('UPDATE iocs SET reputation_score = 85 WHERE normalized_value = ?')
      .run('10.0.0.0');

    const blocklist = distributor.getIPBlocklist(70);
    expect(blocklist).toContain('10.0.0.0');
    expect(blocklist).not.toContain('10.0.1.0');
  });

  it('should return empty blocklist when no IPs qualify', () => {
    const blocklist = distributor.getIPBlocklist(70);
    expect(blocklist).toBe('');
  });

  // -------------------------------------------------------------------------
  // Domain Blocklist
  // -------------------------------------------------------------------------

  it('should return domain blocklist', () => {
    store.upsertIoC({
      type: 'domain',
      value: 'evil.com',
      threatType: 'malware',
      source: 'guard',
      confidence: 90,
    });
    dbWrapper
      .getDB()
      .prepare('UPDATE iocs SET reputation_score = 80 WHERE normalized_value = ?')
      .run('evil.com');

    const blocklist = distributor.getDomainBlocklist(70);
    expect(blocklist).toContain('evil.com');
  });

  // -------------------------------------------------------------------------
  // IoC Feed
  // -------------------------------------------------------------------------

  it('should return IoC feed as JSON', () => {
    store.upsertIoC({
      type: 'ip',
      value: '10.0.0.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 70,
    });
    store.upsertIoC({
      type: 'domain',
      value: 'bad.com',
      threatType: 'c2',
      source: 'trap',
      confidence: 80,
    });

    const feed = distributor.getIoCFeed(40);
    expect(feed.totalEntries).toBe(2);
    expect(feed.entries[0]).toHaveProperty('type');
    expect(feed.entries[0]).toHaveProperty('value');
    expect(feed.entries[0]).toHaveProperty('reputation');
    expect(feed.entries[0]).toHaveProperty('tags');
    expect(feed).toHaveProperty('generatedAt');
  });

  it('should filter IoC feed by minimum reputation', () => {
    store.upsertIoC({
      type: 'ip',
      value: '10.0.0.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 90,
    });
    dbWrapper
      .getDB()
      .prepare('UPDATE iocs SET reputation_score = 90 WHERE normalized_value = ?')
      .run('10.0.0.0');
    store.upsertIoC({
      type: 'ip',
      value: '10.0.1.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 30,
    });
    dbWrapper
      .getDB()
      .prepare('UPDATE iocs SET reputation_score = 20 WHERE normalized_value = ?')
      .run('10.0.1.0');

    const feed = distributor.getIoCFeed(80);
    expect(feed.totalEntries).toBe(1);
    expect(feed.entries[0].value).toBe('10.0.0.0');
  });

  it('should limit IoC feed entries', () => {
    for (let i = 0; i < 5; i++) {
      store.upsertIoC({
        type: 'ip',
        value: `10.0.${i}.0`,
        threatType: 'scanner',
        source: 'guard',
        confidence: 70,
      });
    }

    const feed = distributor.getIoCFeed(40, 3);
    expect(feed.totalEntries).toBe(3);
  });

  // -------------------------------------------------------------------------
  // Agent Update
  // -------------------------------------------------------------------------

  it('should return agent update package', () => {
    // Add a rule
    dbWrapper.upsertRule({
      ruleId: 'test-rule-1',
      ruleContent: 'test content',
      publishedAt: new Date().toISOString(),
      source: 'test',
    });

    // Add an IoC
    store.upsertIoC({
      type: 'ip',
      value: '10.0.0.0',
      threatType: 'scanner',
      source: 'guard',
      confidence: 70,
    });
    dbWrapper
      .getDB()
      .prepare('UPDATE iocs SET reputation_score = 70 WHERE normalized_value = ?')
      .run('10.0.0.0');

    const update = distributor.getAgentUpdate();
    expect(update).toHaveProperty('generatedAt');
    expect(update).toHaveProperty('rules');
    expect(update).toHaveProperty('iocs');
    expect(update).toHaveProperty('stats');
    expect(update.stats.totalActiveIoCs).toBeGreaterThan(0);
  });

  it('should filter agent update by since timestamp', () => {
    // Add a rule from yesterday
    dbWrapper.upsertRule({
      ruleId: 'old-rule',
      ruleContent: 'old',
      publishedAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
      source: 'test',
    });

    // Add a rule now
    dbWrapper.upsertRule({
      ruleId: 'new-rule',
      ruleContent: 'new',
      publishedAt: new Date().toISOString(),
      source: 'test',
    });

    const since = new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString();
    const update = distributor.getAgentUpdate(since);
    expect(update.rules.length).toBe(1);
    expect(update.rules[0].ruleId).toBe('new-rule');
  });
});
