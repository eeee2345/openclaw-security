/**
 * ThreatCloudClient tests
 * Tests upload, fetchRules, fetchBlocklist, flushQueue,
 * retry/fallback logic, and offline mode behavior.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AnonymizedThreatData } from '../src/types.js';

// Mock createLogger
vi.mock('@panguard-ai/core', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@panguard-ai/core');
  return {
    ...actual,
    createLogger: () => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }),
  };
});

// Mock client-id
vi.mock('../src/threat-cloud/client-id.js', () => ({
  getAnonymousClientId: () => 'test-client-uuid-1234',
}));

// We need to mock the https.request for HTTP calls
const mockRequestWrite = vi.fn();
const mockRequestEnd = vi.fn();
const mockRequestDestroy = vi.fn();
const mockRequestOn = vi.fn();

vi.mock('node:https', () => ({
  request: vi.fn((_opts: unknown, cb: (res: unknown) => void) => {
    // Default: simulate a successful 200 response
    const mockRes = {
      statusCode: 200,
      on: vi.fn((event: string, handler: (data?: Buffer) => void) => {
        if (event === 'data') {
          handler(Buffer.from('[]'));
        }
        if (event === 'end') {
          setTimeout(() => handler(), 0);
        }
      }),
    };

    // Defer the callback so the caller can set up event handlers first
    setTimeout(() => cb(mockRes), 0);

    return {
      write: mockRequestWrite,
      end: mockRequestEnd,
      destroy: mockRequestDestroy,
      on: mockRequestOn,
    };
  }),
}));

import { ThreatCloudClient } from '../src/threat-cloud/index.js';

function makeThreatData(overrides: Partial<AnonymizedThreatData> = {}): AnonymizedThreatData {
  return {
    attackSourceIP: '203.0.0.0',
    attackType: 'brute_force',
    mitreTechnique: 'T1110',
    sigmaRuleMatched: 'rule-1',
    timestamp: new Date().toISOString(),
    region: 'US',
    ...overrides,
  };
}

describe('ThreatCloudClient', () => {
  let tempDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), 'threat-cloud-test-'));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  describe('constructor', () => {
    it('should start in offline mode when no endpoint is provided', () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      expect(client.getStatus()).toBe('offline');
      client.stopFlushTimer();
    });

    it('should start in disconnected mode when endpoint is provided', () => {
      const client = new ThreatCloudClient('https://cloud.example.com', tempDir);
      expect(client.getStatus()).toBe('disconnected');
      client.stopFlushTimer();
    });

    it('should load existing cache from disk', () => {
      const cacheData = {
        rules: [{ ruleId: 'r1', ruleContent: 'test', publishedAt: '2024-01-01', source: 'community' }],
        lastSync: '2024-01-01T00:00:00Z',
        stats: { totalUploaded: 10, totalRulesReceived: 5 },
      };
      writeFileSync(join(tempDir, 'threat-cloud-cache.json'), JSON.stringify(cacheData), 'utf-8');

      const client = new ThreatCloudClient(undefined, tempDir);
      const cached = client.getCachedRules();
      expect(cached.length).toBe(1);
      expect(cached[0].ruleId).toBe('r1');
      client.stopFlushTimer();
    });

    it('should load existing upload queue from disk', () => {
      const queue = [makeThreatData(), makeThreatData()];
      writeFileSync(join(tempDir, 'threat-cloud-queue.json'), JSON.stringify(queue), 'utf-8');

      const client = new ThreatCloudClient(undefined, tempDir);
      expect(client.getQueueSize()).toBe(2);
      client.stopFlushTimer();
    });

    it('should handle corrupted cache file gracefully', () => {
      writeFileSync(join(tempDir, 'threat-cloud-cache.json'), 'not valid json', 'utf-8');

      const client = new ThreatCloudClient(undefined, tempDir);
      expect(client.getCachedRules()).toEqual([]);
      client.stopFlushTimer();
    });

    it('should handle corrupted queue file gracefully', () => {
      writeFileSync(join(tempDir, 'threat-cloud-queue.json'), '{broken', 'utf-8');

      const client = new ThreatCloudClient(undefined, tempDir);
      expect(client.getQueueSize()).toBe(0);
      client.stopFlushTimer();
    });
  });

  describe('upload()', () => {
    it('should queue data when in offline mode', async () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      const data = makeThreatData();

      const result = await client.upload(data);

      expect(result).toBe(false);
      expect(client.getQueueSize()).toBe(1);
      client.stopFlushTimer();
    });

    it('should persist queue to disk in offline mode', async () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      await client.upload(makeThreatData());

      const queuePath = join(tempDir, 'threat-cloud-queue.json');
      expect(existsSync(queuePath)).toBe(true);

      const savedQueue = JSON.parse(readFileSync(queuePath, 'utf-8'));
      expect(savedQueue.length).toBe(1);
      client.stopFlushTimer();
    });

    it('should buffer data when endpoint is available and batch not full', async () => {
      const client = new ThreatCloudClient('https://cloud.example.com', tempDir);
      const data = makeThreatData();

      const result = await client.upload(data);

      // Buffer not full (< 50), should return true without flushing
      expect(result).toBe(true);
      client.stopFlushTimer();
    });
  });

  describe('fetchRules()', () => {
    it('should return cached rules in offline mode', async () => {
      const cacheData = {
        rules: [
          { ruleId: 'cached-rule', ruleContent: 'content', publishedAt: '2024-01-01', source: 'cache' },
        ],
        lastSync: '2024-01-01T00:00:00Z',
        stats: { totalUploaded: 0, totalRulesReceived: 1 },
      };
      writeFileSync(join(tempDir, 'threat-cloud-cache.json'), JSON.stringify(cacheData), 'utf-8');

      const client = new ThreatCloudClient(undefined, tempDir);
      const rules = await client.fetchRules();

      expect(rules.length).toBe(1);
      expect(rules[0].ruleId).toBe('cached-rule');
      client.stopFlushTimer();
    });

    it('should return empty array when no cache and offline', async () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      const rules = await client.fetchRules();
      expect(rules).toEqual([]);
      client.stopFlushTimer();
    });
  });

  describe('fetchBlocklist()', () => {
    it('should return empty array in offline mode', async () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      const ips = await client.fetchBlocklist();
      expect(ips).toEqual([]);
      client.stopFlushTimer();
    });
  });

  describe('flushQueue()', () => {
    it('should return 0 when queue is empty', async () => {
      const client = new ThreatCloudClient('https://cloud.example.com', tempDir);
      const uploaded = await client.flushQueue();
      expect(uploaded).toBe(0);
      client.stopFlushTimer();
    });

    it('should return 0 when offline with non-empty queue', async () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      await client.upload(makeThreatData());
      await client.upload(makeThreatData());

      const uploaded = await client.flushQueue();
      expect(uploaded).toBe(0);
      client.stopFlushTimer();
    });
  });

  describe('getStats()', () => {
    it('should return correct initial stats', () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      const stats = client.getStats();

      expect(stats.totalUploaded).toBe(0);
      expect(stats.totalRulesReceived).toBe(0);
      expect(stats.queueSize).toBe(0);
      client.stopFlushTimer();
    });

    it('should reflect queue size after uploads in offline mode', async () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      await client.upload(makeThreatData());
      await client.upload(makeThreatData());
      await client.upload(makeThreatData());

      const stats = client.getStats();
      expect(stats.queueSize).toBe(3);
      client.stopFlushTimer();
    });

    it('should load stats from cache on disk', () => {
      const cacheData = {
        rules: [],
        lastSync: '2024-01-01T00:00:00Z',
        stats: { totalUploaded: 42, totalRulesReceived: 17 },
      };
      writeFileSync(join(tempDir, 'threat-cloud-cache.json'), JSON.stringify(cacheData), 'utf-8');

      const client = new ThreatCloudClient(undefined, tempDir);
      const stats = client.getStats();

      expect(stats.totalUploaded).toBe(42);
      expect(stats.totalRulesReceived).toBe(17);
      client.stopFlushTimer();
    });
  });

  describe('getCachedRules()', () => {
    it('should return a copy of cached rules', () => {
      const cacheData = {
        rules: [
          { ruleId: 'r1', ruleContent: 'content', publishedAt: '2024-01-01', source: 'community' },
        ],
        lastSync: '2024-01-01T00:00:00Z',
        stats: { totalUploaded: 0, totalRulesReceived: 0 },
      };
      writeFileSync(join(tempDir, 'threat-cloud-cache.json'), JSON.stringify(cacheData), 'utf-8');

      const client = new ThreatCloudClient(undefined, tempDir);
      const rules1 = client.getCachedRules();
      const rules2 = client.getCachedRules();

      // Should be a copy, not the same reference
      expect(rules1).not.toBe(rules2);
      expect(rules1).toEqual(rules2);
      client.stopFlushTimer();
    });
  });

  describe('stopFlushTimer()', () => {
    it('should not throw when called on offline client', () => {
      const client = new ThreatCloudClient(undefined, tempDir);
      expect(() => client.stopFlushTimer()).not.toThrow();
    });

    it('should not throw when called on online client', () => {
      const client = new ThreatCloudClient('https://cloud.example.com', tempDir);
      expect(() => client.stopFlushTimer()).not.toThrow();
    });

    it('should not throw when called multiple times', () => {
      const client = new ThreatCloudClient('https://cloud.example.com', tempDir);
      client.stopFlushTimer();
      client.stopFlushTimer();
      // No error
    });
  });
});
