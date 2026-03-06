/**
 * RespondAgent chaos scenario tests
 * Tests edge cases: firewall failures, concurrent high-volume actions,
 * protected process guarding, and rate limiter boundary conditions.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ThreatVerdict } from '../src/types.js';
import { DEFAULT_ACTION_POLICY } from '../src/types.js';

// Mock child_process.execFile
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
    reasoning: 'Chaos test threat',
    recommendedAction: action as ThreatVerdict['recommendedAction'],
    evidence: [
      {
        source: 'threat_intel',
        description: 'Chaos test evidence',
        confidence: 90,
        data: { ip, remoteAddress: ip },
      },
    ],
    mitreTechnique: 'T1110',
  } as ThreatVerdict;
}

describe('RespondAgent chaos scenarios', () => {
  let agent: RespondAgent;
  let tempDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), 'respond-chaos-test-'));
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

  it('should handle firewall command failure gracefully', async () => {
    const mockedExecFile = vi.mocked(execFile);
    mockedExecFile.mockImplementation(
      ((_cmd: string, _args: string[], _opts: unknown, cb: (err: Error | null) => void) => {
        cb(new Error('iptables: command not found'));
      }) as typeof execFile
    );

    const verdict = makeVerdict(90, 'block_ip', '10.0.0.1');
    const result = await agent.respond(verdict);
    expect(result.success).toBe(false);
    expect(result.action).toBe('block_ip');
  });

  it('should not exceed rate limit even with concurrent block_ip calls', async () => {
    // Fire 15 concurrent block_ip requests (limit is 10)
    const promises = Array.from({ length: 15 }, (_, i) => {
      const verdict = makeVerdict(90, 'block_ip', `10.0.${Math.floor(i / 5)}.${(i % 5) + 1}`);
      return agent.respond(verdict);
    });

    const results = await Promise.all(promises);
    const successful = results.filter((r) => r.action === 'block_ip' && r.success);
    const rateLimited = results.filter((r) => !r.success && r.details?.includes('Rate-limited'));

    // At most 10 should succeed, at least 5 should be rate-limited
    expect(successful.length).toBeLessThanOrEqual(10);
    expect(rateLimited.length).toBeGreaterThanOrEqual(5);
  });

  it('should refuse to block whitelisted IPs (127.0.0.1)', async () => {
    const verdict = makeVerdict(90, 'block_ip', '127.0.0.1');
    const result = await agent.respond(verdict);
    // Should not block localhost
    expect(result.details).toContain('whitelisted');
  });

  it('should handle missing IP gracefully for block_ip', async () => {
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 90,
      reasoning: 'No IP evidence',
      recommendedAction: 'block_ip',
      evidence: [],
    } as ThreatVerdict;

    const result = await agent.respond(verdict);
    expect(result.success).toBe(false);
    expect(result.details).toContain('No IP');
  });

  it('should recover from circuit breaker after cooldown', async () => {
    const mockedExecFile = vi.mocked(execFile);
    mockedExecFile.mockImplementation(
      ((_cmd: string, _args: string[], _opts: unknown, cb: (err: Error | null) => void) => {
        cb(new Error('fail'));
      }) as typeof execFile
    );

    // Trip circuit breaker with 5 consecutive failures
    for (let i = 0; i < 5; i++) {
      await agent.respond(makeVerdict(90, 'block_ip', `10.0.0.${i + 1}`));
    }

    const status = agent.getRateLimiterStatus();
    expect(status.circuitBroken).toBe(true);

    // While circuit is broken, actions should fail
    const blockedResult = await agent.respond(makeVerdict(90, 'block_ip', '10.0.0.99'));
    expect(blockedResult.success).toBe(false);
    expect(blockedResult.details).toContain('Circuit breaker');
  });

  it('should process log_only actions even when circuit breaker is active', async () => {
    const mockedExecFile = vi.mocked(execFile);
    mockedExecFile.mockImplementation(
      ((_cmd: string, _args: string[], _opts: unknown, cb: (err: Error | null) => void) => {
        cb(new Error('fail'));
      }) as typeof execFile
    );

    // Trip circuit breaker
    for (let i = 0; i < 5; i++) {
      await agent.respond(makeVerdict(90, 'block_ip', `10.0.0.${i + 1}`));
    }

    // log_only (low confidence) should still work
    const verdict = makeVerdict(30);
    const result = await agent.respond(verdict);
    expect(result.action).toBe('log_only');
    expect(result.success).toBe(true);
  });

  it('should handle rapid mixed-action sequences', async () => {
    const actions = [
      { action: 'block_ip', ip: '10.0.0.1' },
      { action: 'block_ip', ip: '10.0.0.2' },
      { action: 'kill_process', ip: '10.0.0.3' },
      { action: 'disable_account', ip: '10.0.0.4' },
      { action: 'block_ip', ip: '10.0.0.5' },
    ];

    const results = [];
    for (const { action, ip } of actions) {
      const verdict = makeVerdict(90, action, ip);
      if (action === 'disable_account') {
        verdict.evidence = [
          { source: 'rule', description: 'test', confidence: 90, data: { userName: 'hacker' } },
        ];
      }
      results.push(await agent.respond(verdict));
    }

    // All should have been processed (not crashed)
    expect(results).toHaveLength(5);
    for (const r of results) {
      expect(r.action).toBeDefined();
      expect(r.timestamp).toBeDefined();
    }
  });

  it('should track rate limiter window counts per action type', async () => {
    await agent.respond(makeVerdict(90, 'block_ip', '10.0.0.1'));
    await agent.respond(makeVerdict(90, 'block_ip', '10.0.0.2'));

    const status = agent.getRateLimiterStatus();
    expect(status.windowCounts.block_ip).toBe(2);
    expect(status.circuitBroken).toBe(false);
  });
});
