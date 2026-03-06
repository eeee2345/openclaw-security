import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { SmartRouter } from '../src/ai/smart-router.js';
import type { SmartRouterConfig } from '../src/ai/smart-router.js';
import type { LLMProvider, AnalysisResult, ThreatClassification, TokenUsage } from '../src/ai/types.js';
import type { SecurityEvent } from '../src/types.js';

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
// Mock LLM provider factory
// ---------------------------------------------------------------------------

function makeAnalysisResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    summary: 'SSH brute force detected',
    severity: 'high',
    confidence: 0.85,
    recommendations: ['Block source IP', 'Enable fail2ban'],
    ...overrides,
  };
}

function makeMockProvider(result: AnalysisResult = makeAnalysisResult()): LLMProvider {
  return {
    providerType: 'ollama',
    model: 'llama3',
    analyze: vi.fn().mockResolvedValue(result),
    classify: vi.fn().mockResolvedValue({} as ThreatClassification),
    summarize: vi.fn().mockResolvedValue('summary'),
    isAvailable: vi.fn().mockResolvedValue(true),
    getTokenUsage: vi.fn().mockReturnValue({
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      estimatedCost: 0,
    } as TokenUsage),
  };
}

/** Build a SmartRouter pre-configured with mocked providers */
function makeRouter(options: {
  tier?: SmartRouterConfig['tier'];
  localProvider?: LLMProvider | null;
  cloudProvider?: LLMProvider | null;
  skipAIThreshold?: number;
  preferLocalThreshold?: number;
  quotaOverride?: SmartRouterConfig['quotaOverride'];
} = {}): SmartRouter {
  const config: SmartRouterConfig = {
    tier: options.tier ?? 'pro',
    localProvider: options.localProvider ?? makeMockProvider(),
    cloudProvider: options.cloudProvider ?? null,
    skipAIThreshold: options.skipAIThreshold ?? 80,
    preferLocalThreshold: options.preferLocalThreshold ?? 60,
    quotaOverride: options.quotaOverride,
  };
  return new SmartRouter(config);
}

// ---------------------------------------------------------------------------
// assessComplexity()
// ---------------------------------------------------------------------------

describe('assessComplexity()', () => {
  it("returns 'skip' when rule confidence >= 80% and no attack chain", () => {
    const router = makeRouter();

    expect(router.assessComplexity(80, false)).toBe('skip');
    expect(router.assessComplexity(95, false)).toBe('skip');
    expect(router.assessComplexity(100, false)).toBe('skip');
  });

  it("returns 'simple' when rule confidence is 60-79%", () => {
    const router = makeRouter();

    expect(router.assessComplexity(60, false)).toBe('simple');
    expect(router.assessComplexity(70, false)).toBe('simple');
    expect(router.assessComplexity(79, false)).toBe('simple');
  });

  it("returns 'complex' when rule confidence is below 60%", () => {
    const router = makeRouter();

    expect(router.assessComplexity(0, false)).toBe('complex');
    expect(router.assessComplexity(30, false)).toBe('complex');
    expect(router.assessComplexity(59, false)).toBe('complex');
  });

  it("returns 'simple' (not 'skip') when attack chain is present even with confidence >= 80%", () => {
    const router = makeRouter();

    // Attack chains force at least 'simple' analysis even if confidence is high
    expect(router.assessComplexity(80, true)).toBe('simple');
    expect(router.assessComplexity(95, true)).toBe('simple');
    expect(router.assessComplexity(100, true)).toBe('simple');
  });

  it("returns 'complex' when attack chain is present and confidence < 60%", () => {
    const router = makeRouter();

    expect(router.assessComplexity(30, true)).toBe('complex');
  });

  it('respects custom skipAIThreshold override', () => {
    const router = makeRouter({ skipAIThreshold: 90 });

    // 85% is below the custom 90% threshold – should NOT skip
    expect(router.assessComplexity(85, false)).toBe('simple');
    // 90% meets the threshold
    expect(router.assessComplexity(90, false)).toBe('skip');
  });

  it('respects custom preferLocalThreshold override', () => {
    const router = makeRouter({ preferLocalThreshold: 70 });

    // 65% is below the custom 70% threshold
    expect(router.assessComplexity(65, false)).toBe('complex');
    // 70% meets the threshold
    expect(router.assessComplexity(70, false)).toBe('simple');
  });
});

// ---------------------------------------------------------------------------
// analyze() – skip AI for high-confidence rules
// ---------------------------------------------------------------------------

describe('analyze() – skip AI for high-confidence rules', () => {
  it('returns null result and rules-only decision for confidence >= 80%', async () => {
    const localProvider = makeMockProvider();
    const router = makeRouter({ localProvider });

    const { result, decision } = await router.analyze('test prompt', 85, false);

    expect(result).toBeNull();
    expect(decision.complexity).toBe('skip');
    expect(decision.provider).toBe('rules-only');
    expect(decision.quotaAllowed).toBe(true);

    // Provider should never have been called
    expect(localProvider.analyze).not.toHaveBeenCalled();
  });

  it('increments skippedByRules stat counter when AI is skipped', async () => {
    const router = makeRouter();

    await router.analyze('p1', 80, false);
    await router.analyze('p2', 90, false);

    const stats = router.getStats();
    expect(stats.totalRequests).toBe(2);
    expect(stats.skippedByRules).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// analyze() – knowledge cache
// ---------------------------------------------------------------------------

describe('analyze() – knowledge cache', () => {
  it('serves cached result for a previously analyzed pattern hash', async () => {
    const localProvider = makeMockProvider();
    const router = makeRouter({ localProvider });

    const patternHash = 'pattern-abc-123';

    // First call: below skip threshold, no cache hit -> should call provider
    const first = await router.analyze('prompt', 65, false, patternHash);
    expect(localProvider.analyze).toHaveBeenCalledTimes(1);
    expect(first.result).not.toBeNull();

    // Second call with the same patternHash: should come from cache
    const second = await router.analyze('prompt', 65, false, patternHash);
    // Provider must NOT have been called again
    expect(localProvider.analyze).toHaveBeenCalledTimes(1);
    expect(second.decision.reason).toContain('cache');
    expect(second.result).toEqual(first.result);
  });

  it('increments servedFromCache stat on a cache hit', async () => {
    const router = makeRouter();

    await router.analyze('p', 65, false, 'hash-xyz');
    await router.analyze('p', 65, false, 'hash-xyz');

    expect(router.getStats().servedFromCache).toBe(1);
  });

  it('recordDistilledPattern pre-populates the cache so next analyze hits cache', async () => {
    const localProvider = makeMockProvider();
    const router = makeRouter({ localProvider });

    const storedResult = makeAnalysisResult({ summary: 'pre-cached' });
    router.recordDistilledPattern('pre-hash', storedResult);

    const { result, decision } = await router.analyze('p', 65, false, 'pre-hash');

    expect(result?.summary).toBe('pre-cached');
    expect(decision.reason).toContain('cache');
    expect(localProvider.analyze).not.toHaveBeenCalled();
  });

  it('does not use cache when no patternHash is provided', async () => {
    const localProvider = makeMockProvider();
    const router = makeRouter({ localProvider });

    // Call twice without patternHash
    await router.analyze('p', 65, false);
    await router.analyze('p', 65, false);

    // Both calls should reach the provider
    expect(localProvider.analyze).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// analyze() – quota enforcement
// ---------------------------------------------------------------------------

describe('analyze() – quota enforcement', () => {
  it('blocks analysis and returns quota-blocked decision when quota exceeded', async () => {
    // Use free tier which always blocks
    const router = makeRouter({ tier: 'free' });

    const { result, decision } = await router.analyze('prompt', 50, false);

    expect(result).toBeNull();
    expect(decision.provider).toBe('quota-blocked');
    expect(decision.quotaAllowed).toBe(false);
  });

  it('increments blockedByQuota stat when quota is exceeded', async () => {
    const router = makeRouter({ tier: 'free' });

    await router.analyze('p', 50, false);
    await router.analyze('p', 50, false);

    expect(router.getStats().blockedByQuota).toBe(2);
  });

  it('enterprise BYOK tier is never blocked by quota', async () => {
    const localProvider = makeMockProvider();
    const router = makeRouter({ tier: 'enterprise', localProvider });

    // Simulate many calls – should never be blocked
    for (let i = 0; i < 10; i++) {
      const { decision } = await router.analyze(`prompt-${i}`, 50, false);
      expect(decision.provider).not.toBe('quota-blocked');
    }
  });
});

// ---------------------------------------------------------------------------
// Stats tracking
// ---------------------------------------------------------------------------

describe('getStats() – stats tracking', () => {
  it('starts with all-zero stats', () => {
    const router = makeRouter();
    const stats = router.getStats();

    expect(stats.totalRequests).toBe(0);
    expect(stats.skippedByRules).toBe(0);
    expect(stats.routedToLocal).toBe(0);
    expect(stats.routedToCloud).toBe(0);
    expect(stats.servedFromCache).toBe(0);
    expect(stats.blockedByQuota).toBe(0);
  });

  it('correctly tracks a mix of skip, cache hit and local routes', async () => {
    const localProvider = makeMockProvider();
    const router = makeRouter({ localProvider });

    // 1. High confidence – skip
    await router.analyze('p1', 85, false);

    // 2. Below skip threshold, new pattern – goes to local
    await router.analyze('p2', 65, false, 'hash-1');

    // 3. Same pattern – served from cache
    await router.analyze('p3', 65, false, 'hash-1');

    const stats = router.getStats();
    expect(stats.totalRequests).toBe(3);
    expect(stats.skippedByRules).toBe(1);
    expect(stats.servedFromCache).toBe(1);
    expect(stats.routedToLocal).toBe(1);
  });

  it('getStats returns a copy (mutating it does not affect internal state)', () => {
    const router = makeRouter();
    const stats = router.getStats();
    stats.totalRequests = 9999;

    // Internal state should be unchanged
    expect(router.getStats().totalRequests).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// getQuotaUsage() delegation
// ---------------------------------------------------------------------------

describe('getQuotaUsage()', () => {
  it('returns quota usage with correct tier', () => {
    const router = makeRouter({ tier: 'pro' });
    const usage = router.getQuotaUsage();
    expect(usage.tier).toBe('pro');
  });
});
