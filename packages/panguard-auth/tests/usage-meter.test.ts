import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuthDB } from '../src/database.js';
import {
  checkQuota,
  recordUsage,
  setUsage,
  getUsageSummary,
  getQuotaLimits,
  currentPeriod,
} from '../src/usage-meter.js';

describe('Usage Meter', () => {
  let db: AuthDB;

  beforeEach(() => {
    db = new AuthDB(':memory:');
    // Create a test user (RegisterInput + passwordHash as separate args)
    db.createUser({ email: 'test@example.com', name: 'Test', password: 'unused' }, 'hash:salt');
  });

  afterEach(() => {
    db.close();
  });

  describe('currentPeriod', () => {
    it('should return YYYY-MM format', () => {
      const period = currentPeriod();
      expect(period).toMatch(/^\d{4}-\d{2}$/);
    });

    it('should match current year and month', () => {
      const now = new Date();
      const expected = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
      expect(currentPeriod()).toBe(expected);
    });
  });

  describe('checkQuota', () => {
    it('should allow usage under limit', () => {
      // Community tier: scan is unlimited (-1), use api_calls (1000) for limit test
      const result = checkQuota(db, 1, 'community', 'api_calls');
      expect(result.allowed).toBe(true);
      expect(result.current).toBe(0);
      expect(result.limit).toBe(1000);
      expect(result.remaining).toBe(1000);
      expect(result.resource).toBe('api_calls');
    });

    it('should report unlimited for -1 limits', () => {
      const result = checkQuota(db, 1, 'solo', 'scan');
      expect(result.allowed).toBe(true);
      expect(result.limit).toBe(-1);
      expect(result.remaining).toBe(-1);
    });

    it('should deny when at limit', () => {
      // Community tier has 1000 api_calls/month
      for (let i = 0; i < 1000; i++) {
        recordUsage(db, 1, 'api_calls', 1);
      }
      const result = checkQuota(db, 1, 'community', 'api_calls');
      expect(result.allowed).toBe(false);
      expect(result.current).toBe(1000);
      expect(result.remaining).toBe(0);
    });

    it('should use community tier quotas for unknown tiers', () => {
      const result = checkQuota(db, 1, 'unknown_tier', 'api_calls');
      expect(result.limit).toBe(1000); // community tier limit
    });

    it('should track guard_endpoints as lifetime resource', () => {
      setUsage(db, 1, 'guard_endpoints', 1);
      const result = checkQuota(db, 1, 'community', 'guard_endpoints');
      expect(result.current).toBe(1);
      expect(result.limit).toBe(1);
      expect(result.remaining).toBe(0);
      expect(result.allowed).toBe(false);
    });
  });

  describe('recordUsage', () => {
    it('should increment usage count', () => {
      recordUsage(db, 1, 'scan', 1);
      recordUsage(db, 1, 'scan', 1);
      const result = checkQuota(db, 1, 'community', 'scan');
      expect(result.current).toBe(2);
    });

    it('should support bulk recording', () => {
      recordUsage(db, 1, 'api_calls', 50);
      const result = checkQuota(db, 1, 'community', 'api_calls');
      expect(result.current).toBe(50);
    });

    it('should default count to 1', () => {
      recordUsage(db, 1, 'scan');
      const result = checkQuota(db, 1, 'community', 'scan');
      expect(result.current).toBe(1);
    });
  });

  describe('setUsage', () => {
    it('should set absolute usage', () => {
      setUsage(db, 1, 'guard_endpoints', 3);
      const result = checkQuota(db, 1, 'solo', 'guard_endpoints');
      expect(result.current).toBe(3);
    });

    it('should overwrite previous value', () => {
      setUsage(db, 1, 'guard_endpoints', 5);
      setUsage(db, 1, 'guard_endpoints', 2);
      const result = checkQuota(db, 1, 'solo', 'guard_endpoints');
      expect(result.current).toBe(2);
    });
  });

  describe('getUsageSummary', () => {
    it('should return summaries for all resources', () => {
      const summary = getUsageSummary(db, 1, 'community');
      expect(summary.length).toBe(6); // 6 meterable resources
      const resources = summary.map((s) => s.resource);
      expect(resources).toContain('scan');
      expect(resources).toContain('guard_endpoints');
      expect(resources).toContain('reports');
      expect(resources).toContain('api_calls');
      expect(resources).toContain('notifications');
      expect(resources).toContain('trap_instances');
    });

    it('should compute percentage correctly', () => {
      recordUsage(db, 1, 'api_calls', 500);
      const summary = getUsageSummary(db, 1, 'community');
      const apiCalls = summary.find((s) => s.resource === 'api_calls')!;
      expect(apiCalls.current).toBe(500);
      expect(apiCalls.limit).toBe(1000);
      expect(apiCalls.percentage).toBe(50);
    });

    it('should cap percentage at 100', () => {
      recordUsage(db, 1, 'api_calls', 1500);
      const summary = getUsageSummary(db, 1, 'community');
      const apiCalls = summary.find((s) => s.resource === 'api_calls')!;
      expect(apiCalls.percentage).toBe(100);
    });

    it('should show 0% for unlimited resources', () => {
      recordUsage(db, 1, 'scan', 50);
      const summary = getUsageSummary(db, 1, 'solo');
      const scan = summary.find((s) => s.resource === 'scan')!;
      expect(scan.percentage).toBe(0); // unlimited
    });

    it('should show 100% when usage > 0 and limit is 0', () => {
      // Free tier has reports = 0
      recordUsage(db, 1, 'reports', 1);
      const summary = getUsageSummary(db, 1, 'community');
      const reports = summary.find((s) => s.resource === 'reports')!;
      expect(reports.percentage).toBe(100);
    });
  });

  describe('getQuotaLimits', () => {
    it('should return limits for known tiers', () => {
      const community = getQuotaLimits('community');
      expect(community.scan).toBe(-1); // unlimited
      expect(community.guard_endpoints).toBe(1);
      expect(community.api_calls).toBe(1000);

      const business = getQuotaLimits('business');
      expect(business.scan).toBe(-1);
      expect(business.api_calls).toBe(-1);
    });

    it('should return community limits for unknown tier', () => {
      const limits = getQuotaLimits('nonexistent');
      expect(limits.scan).toBe(-1); // community = unlimited scan
      expect(limits.api_calls).toBe(1000);
    });

    it('should return a copy (not mutable reference)', () => {
      const a = getQuotaLimits('community');
      const b = getQuotaLimits('community');
      a.api_calls = 999;
      expect(b.api_calls).toBe(1000);
    });
  });

  describe('tier quota definitions', () => {
    it('should have increasing limits per tier', () => {
      const tiers = ['community', 'solo', 'pro', 'business', 'enterprise'];
      for (let i = 1; i < tiers.length; i++) {
        const prev = getQuotaLimits(tiers[i - 1]!);
        const curr = getQuotaLimits(tiers[i]!);
        // guard_endpoints should be >= previous (or unlimited)
        const prevEndpoints = prev.guard_endpoints === -1 ? Infinity : prev.guard_endpoints;
        const currEndpoints = curr.guard_endpoints === -1 ? Infinity : curr.guard_endpoints;
        expect(currEndpoints).toBeGreaterThanOrEqual(prevEndpoints);
      }
    });

    it('enterprise should be all unlimited', () => {
      const limits = getQuotaLimits('enterprise');
      for (const value of Object.values(limits)) {
        expect(value).toBe(-1);
      }
    });
  });
});
