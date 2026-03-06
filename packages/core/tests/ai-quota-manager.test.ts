import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { AIQuotaManager } from '../src/ai/quota-manager.js';
import type { QuotaTier } from '../src/ai/quota-manager.js';

// Suppress logger stderr output during tests
let stderrSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  stderrSpy.mockRestore();
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeManager(tier: QuotaTier, overrides?: Parameters<typeof AIQuotaManager>[1]) {
  return new AIQuotaManager(tier, overrides);
}

// Build a minimal AnalysisResult-shaped object (not used directly here but
// kept for completeness if helpers are shared later)
const NOW = new Date('2026-03-06T12:00:00Z').getTime();

// ---------------------------------------------------------------------------
// Free tier
// ---------------------------------------------------------------------------

describe('Free tier', () => {
  it('blocks all AI calls', () => {
    const mgr = makeManager('free');
    const result = mgr.checkQuota();

    expect(result.allowed).toBe(false);
    expect(result.remainingCalls).toBe(0);
    expect(result.remainingBudgetUSD).toBe(0);
    expect(result.reason).toContain('free tier');
  });

  it('still blocks after recordCall is invoked (no state change unlocks free)', () => {
    const mgr = makeManager('free');
    mgr.recordCall(0);
    const result = mgr.checkQuota();
    expect(result.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Pro tier – hourly quota
// ---------------------------------------------------------------------------

describe('Pro tier – hourly quota', () => {
  it('allows calls within the 200/hr quota', () => {
    const mgr = makeManager('pro');
    const result = mgr.checkQuota();

    expect(result.allowed).toBe(true);
    expect(result.remainingCalls).toBe(200);
  });

  it('tracks remaining calls correctly after multiple recordCall invocations', () => {
    const mgr = makeManager('pro');

    mgr.recordCall(0.001);
    mgr.recordCall(0.001);
    mgr.recordCall(0.001);

    const result = mgr.checkQuota();
    expect(result.allowed).toBe(true);
    expect(result.remainingCalls).toBe(197);
  });

  it('blocks when hourly quota of 200 calls is exhausted', () => {
    const mgr = makeManager('pro');

    // Record 200 calls
    for (let i = 0; i < 200; i++) {
      mgr.recordCall(0);
    }

    const result = mgr.checkQuota();
    expect(result.allowed).toBe(false);
    expect(result.remainingCalls).toBe(0);
    expect(result.reason).toContain('Hourly AI quota exceeded');
    expect(result.reason).toContain('200/200');
  });

  it('blocks when monthly budget of $10 is exhausted', () => {
    const mgr = makeManager('pro');

    // Spend the whole $10 budget in one call (simulate)
    mgr.recordCall(10);

    const result = mgr.checkQuota();
    expect(result.allowed).toBe(false);
    expect(result.remainingBudgetUSD).toBe(0);
    expect(result.reason).toContain('Monthly AI budget exceeded');
  });

  it('partial budget spend still allows calls when under $10 limit', () => {
    const mgr = makeManager('pro');
    mgr.recordCall(5);

    const result = mgr.checkQuota();
    expect(result.allowed).toBe(true);
    expect(result.remainingBudgetUSD).toBeCloseTo(5, 5);
  });
});

// ---------------------------------------------------------------------------
// Enterprise / BYOK tier
// ---------------------------------------------------------------------------

describe('Enterprise (BYOK) tier', () => {
  it('allows unlimited calls regardless of call count', () => {
    const mgr = makeManager('enterprise');

    // Record thousands of calls – should never block
    for (let i = 0; i < 1000; i++) {
      mgr.recordCall(0.05);
    }

    const result = mgr.checkQuota();
    expect(result.allowed).toBe(true);
    expect(result.remainingCalls).toBe(Infinity);
    expect(result.remainingBudgetUSD).toBe(Infinity);
  });

  it('does not accumulate monetary cost for BYOK (they pay their own API)', () => {
    const mgr = makeManager('enterprise');
    mgr.recordCall(99.99);

    const usage = mgr.getUsage();
    // BYOK cost tracking is skipped in recordCall – cost stays 0
    expect(usage.costThisMonth).toBe(0);
  });

  it('reports isBYOK as true in usage snapshot', () => {
    const mgr = makeManager('enterprise');
    expect(mgr.getUsage().isBYOK).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Sliding window – timestamp pruning
// ---------------------------------------------------------------------------

describe('Sliding window (hourly timestamp pruning)', () => {
  it('prunes timestamps older than 1 hour so old calls do not count', () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);

    const mgr = makeManager('pro');

    // Record 199 calls at T=0
    for (let i = 0; i < 199; i++) {
      mgr.recordCall(0);
    }

    // Advance clock by exactly 1 hour + 1 ms so those timestamps expire
    vi.setSystemTime(NOW + 3_600_001);

    // After pruning the old 199 calls should disappear
    const result = mgr.checkQuota();
    expect(result.allowed).toBe(true);
    expect(result.remainingCalls).toBe(200);
  });

  it('only prunes timestamps older than exactly 1 hour – recent ones survive', () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);

    const mgr = makeManager('pro');

    // Record 100 calls
    for (let i = 0; i < 100; i++) {
      mgr.recordCall(0);
    }

    // Advance only 30 minutes – calls should still be counted
    vi.setSystemTime(NOW + 1_800_000);

    const result = mgr.checkQuota();
    expect(result.remainingCalls).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Monthly cost reset
// ---------------------------------------------------------------------------

describe('Monthly cost reset', () => {
  it('resets accumulated cost when the month changes', () => {
    vi.useFakeTimers();

    // Start in March 2026
    vi.setSystemTime(new Date('2026-03-31T23:59:59Z').getTime());
    const mgr = makeManager('pro');

    // Spend $9 – almost at limit
    mgr.recordCall(9);
    expect(mgr.getUsage().costThisMonth).toBeCloseTo(9, 5);

    // Cross into April
    vi.setSystemTime(new Date('2026-04-01T00:00:00Z').getTime());

    // Any call into getUsage / checkQuota should trigger the reset
    const usage = mgr.getUsage();
    expect(usage.costThisMonth).toBe(0);

    const check = mgr.checkQuota();
    expect(check.allowed).toBe(true);
  });

  it('does not reset when the month has not changed', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-03-06T10:00:00Z').getTime());

    const mgr = makeManager('pro');
    mgr.recordCall(3);

    // Still the same month
    vi.setSystemTime(new Date('2026-03-06T22:00:00Z').getTime());

    expect(mgr.getUsage().costThisMonth).toBeCloseTo(3, 5);
  });
});

// ---------------------------------------------------------------------------
// recordCall() cost tracking
// ---------------------------------------------------------------------------

describe('recordCall() cost tracking', () => {
  it('accumulates cost across multiple calls', () => {
    const mgr = makeManager('pro');

    mgr.recordCall(0.001);
    mgr.recordCall(0.002);
    mgr.recordCall(0.0054);

    const usage = mgr.getUsage();
    expect(usage.costThisMonth).toBeCloseTo(0.0084, 5);
  });

  it('rounds cost to 6 decimal places in usage snapshot', () => {
    const mgr = makeManager('pro');
    mgr.recordCall(0.000_000_1); // Sub-precision value

    const usage = mgr.getUsage();
    // Result is rounded to 6 decimal places
    expect(usage.costThisMonth).toBe(Math.round(0.000_000_1 * 1_000_000) / 1_000_000);
  });

  it('increments callsThisHour by one per recordCall', () => {
    const mgr = makeManager('pro');

    expect(mgr.getUsage().callsThisHour).toBe(0);
    mgr.recordCall(0.001);
    expect(mgr.getUsage().callsThisHour).toBe(1);
    mgr.recordCall(0.001);
    expect(mgr.getUsage().callsThisHour).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// getUsage() snapshot
// ---------------------------------------------------------------------------

describe('getUsage() snapshot', () => {
  it('returns correct snapshot for pro tier with no calls', () => {
    const mgr = makeManager('pro');
    const usage = mgr.getUsage();

    expect(usage.tier).toBe('pro');
    expect(usage.callsThisHour).toBe(0);
    expect(usage.maxCallsPerHour).toBe(200);
    expect(usage.costThisMonth).toBe(0);
    expect(usage.maxMonthlyBudgetUSD).toBe(10);
    expect(usage.isBYOK).toBe(false);
  });

  it('returns correct snapshot for enterprise tier', () => {
    const mgr = makeManager('enterprise');
    const usage = mgr.getUsage();

    expect(usage.tier).toBe('enterprise');
    expect(usage.maxCallsPerHour).toBe(-1);
    expect(usage.maxMonthlyBudgetUSD).toBe(-1);
    expect(usage.isBYOK).toBe(true);
  });

  it('reflects config override when passed to constructor', () => {
    const mgr = makeManager('pro', { maxCallsPerHour: 50 });
    const usage = mgr.getUsage();
    expect(usage.maxCallsPerHour).toBe(50);
  });

  it('getMonthKey returns a YYYY-MM formatted string', () => {
    const key = AIQuotaManager.getMonthKey();
    expect(key).toMatch(/^\d{4}-\d{2}$/);
  });
});
