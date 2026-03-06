/**
 * RespondAgent rate limiter tests
 * Tests the ActionRateLimiter integration: per-action rate limits,
 * circuit breaker on consecutive failures, and rate limit status reporting.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ThreatVerdict } from '../src/types.js';
import { DEFAULT_ACTION_POLICY } from '../src/types.js';

// Mock child_process.execFile to avoid actual firewall commands
vi.mock('node:child_process', () => ({
  execFile: vi.fn(
    (
      _cmd: string,
      _args: string[],
      _opts: unknown,
      cb: (err: Error | null, stdout: string) => void
    ) => {
      cb(null, '');
    }
  ),
}));

// Mock createLogger
vi.mock('@panguard-ai/core', async () => {
  const actual =
    await vi.importActual<Record<string, unknown>>('@panguard-ai/core');
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

import { RespondAgent } from '../src/agent/respond-agent.js';
import { execFile } from 'node:child_process';

function makeVerdict(
  confidence: number,
  action: string = 'block_ip',
  ip: string = '10.0.0.1'
): ThreatVerdict {
  return {
    conclusion: 'malicious',
    confidence,
    reasoning: 'Test threat detected',
    recommendedAction: action as ThreatVerdict['recommendedAction'],
    evidence: [
      {
        source: 'threat_intel',
        description: 'Test threat intel match',
        confidence: 85,
        data: { ip, remoteAddress: ip },
      },
    ],
    mitreTechnique: 'T1110',
  } as ThreatVerdict;
}

describe('RespondAgent rate limiting', () => {
  let agent: RespondAgent;
  let tempDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), 'respond-ratelimit-test-'));
    agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection', [], tempDir);
  });

  afterEach(() => {
    agent.destroy();
    try {
      rmSync(tempDir, { recursive: true });
    } catch {
      // cleanup best-effort
    }
  });

  it('should allow actions under the rate limit', async () => {
    const verdict = makeVerdict(90, 'block_ip', '10.0.0.1');
    const result = await agent.respond(verdict);
    expect(result.success).toBe(true);
    expect(result.action).toBe('block_ip');
  });

  it('should rate-limit block_ip after 10 calls in 60 seconds', async () => {
    // Execute 10 block_ip actions (limit)
    for (let i = 0; i < 10; i++) {
      const verdict = makeVerdict(90, 'block_ip', `10.0.0.${i + 1}`);
      const result = await agent.respond(verdict);
      expect(result.action).toBe('block_ip');
    }

    // 11th should be rate-limited
    const verdict11 = makeVerdict(90, 'block_ip', '10.0.0.99');
    const result = await agent.respond(verdict11);
    expect(result.success).toBe(false);
    expect(result.details).toContain('Rate-limited');
  });

  it('should rate-limit disable_account after 2 calls', async () => {
    for (let i = 0; i < 2; i++) {
      const verdict = makeVerdict(90, 'disable_account');
      verdict.evidence = [
        { source: 'rule', description: 'test', confidence: 90, data: { userName: `user${i}` } },
      ];
      await agent.respond(verdict);
    }

    // 3rd should be rate-limited
    const verdict3 = makeVerdict(90, 'disable_account');
    verdict3.evidence = [
      { source: 'rule', description: 'test', confidence: 90, data: { userName: 'user99' } },
    ];
    const result = await agent.respond(verdict3);
    expect(result.success).toBe(false);
    expect(result.details).toContain('Rate-limited');
  });

  it('should expose rate limiter status', async () => {
    const verdict = makeVerdict(90, 'block_ip', '10.0.0.1');
    await agent.respond(verdict);

    const status = agent.getRateLimiterStatus();
    expect(status.circuitBroken).toBe(false);
    expect(status.consecutiveFailures).toBe(0);
    expect(status.windowCounts.block_ip).toBe(1);
  });

  it('should trip circuit breaker after 5 consecutive failures', async () => {
    // Mock execFile to simulate failures
    const mockedExecFile = vi.mocked(execFile);
    mockedExecFile.mockImplementation(
      ((_cmd: string, _args: string[], _opts: unknown, cb: (err: Error | null) => void) => {
        cb(new Error('firewall command failed'));
      }) as typeof execFile
    );

    // Execute 5 failing actions
    for (let i = 0; i < 5; i++) {
      const verdict = makeVerdict(90, 'block_ip', `10.0.0.${i + 1}`);
      const result = await agent.respond(verdict);
      expect(result.success).toBe(false);
    }

    // 6th should be circuit-broken
    const verdict6 = makeVerdict(90, 'block_ip', '10.0.0.99');
    const result = await agent.respond(verdict6);
    expect(result.success).toBe(false);
    expect(result.details).toContain('Circuit breaker');

    const status = agent.getRateLimiterStatus();
    expect(status.circuitBroken).toBe(true);
  });

  it('should not rate-limit log_only actions', async () => {
    // Log-only actions should never be rate-limited
    for (let i = 0; i < 50; i++) {
      const verdict = makeVerdict(30); // Low confidence = log only
      const result = await agent.respond(verdict);
      expect(result.action).toBe('log_only');
      expect(result.success).toBe(true);
    }
  });

  it('should not rate-limit in learning mode', async () => {
    const learningAgent = new RespondAgent(
      DEFAULT_ACTION_POLICY,
      'learning',
      [],
      tempDir
    );

    for (let i = 0; i < 20; i++) {
      const verdict = makeVerdict(90, 'block_ip', `10.0.0.${i + 1}`);
      const result = await learningAgent.respond(verdict);
      expect(result.action).toBe('log_only');
      expect(result.success).toBe(true);
    }

    learningAgent.destroy();
  });
});
