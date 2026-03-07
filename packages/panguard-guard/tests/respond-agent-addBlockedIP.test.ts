/**
 * RespondAgent addBlockedIP() tests
 * Tests the public addBlockedIP() method including whitelisted IP rejection,
 * invalid IP format rejection, manifest recording, and escalation tracking.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ThreatVerdict } from '../src/types.js';
import { DEFAULT_ACTION_POLICY } from '../src/types.js';

// Mock child_process.execFile to avoid actual firewall commands
vi.mock('node:child_process', () => ({
  execFile: vi.fn((_cmd: string, _args: string[], _opts: unknown, cb: (err: Error | null, stdout: string) => void) => {
    // Simulate successful firewall command
    cb(null, '');
  }),
}));

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

import { RespondAgent } from '../src/agent/respond-agent.js';
import { execFile } from 'node:child_process';

describe('RespondAgent.addBlockedIP()', () => {
  let agent: RespondAgent;
  let tempDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), 'respond-agent-test-'));
    agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection', [], tempDir);
  });

  afterEach(() => {
    agent.destroy();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('should reject whitelisted IP 127.0.0.1', async () => {
    const result = await agent.addBlockedIP('127.0.0.1');
    expect(result.success).toBe(false);
    expect(result.details).toContain('whitelisted');
    expect(result.target).toBe('127.0.0.1');
    expect(result.action).toBe('block_ip');
  });

  it('should reject whitelisted IP ::1 (IPv6 loopback)', async () => {
    const result = await agent.addBlockedIP('::1');
    expect(result.success).toBe(false);
    expect(result.details).toContain('whitelisted');
    expect(result.target).toBe('::1');
  });

  it('should reject whitelisted IP localhost', async () => {
    const result = await agent.addBlockedIP('localhost');
    expect(result.success).toBe(false);
    expect(result.details).toContain('whitelisted');
  });

  it('should reject whitelisted IP 0.0.0.0', async () => {
    const result = await agent.addBlockedIP('0.0.0.0');
    expect(result.success).toBe(false);
    expect(result.details).toContain('whitelisted');
  });

  it('should reject user-configured whitelisted IPs', async () => {
    const customAgent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection', ['192.168.1.100'], tempDir);
    const result = await customAgent.addBlockedIP('192.168.1.100');
    expect(result.success).toBe(false);
    expect(result.details).toContain('whitelisted');
    customAgent.destroy();
  });

  it('should reject invalid IP format (random string)', async () => {
    const result = await agent.addBlockedIP('not-an-ip!@#');
    expect(result.success).toBe(false);
    expect(result.details).toContain('Invalid IP format');
    expect(result.target).toBe('not-an-ip!@#');
  });

  it('should reject IP with mixed invalid characters', async () => {
    const result = await agent.addBlockedIP('abc.xyz.123');
    expect(result.success).toBe(false);
    expect(result.details).toContain('Invalid IP format');
  });

  it('should accept valid IPv4 address', async () => {
    const result = await agent.addBlockedIP('203.0.113.50');
    expect(result.success).toBe(true);
    expect(result.action).toBe('block_ip');
    expect(result.target).toBe('203.0.113.50');
    expect(result.details).toContain('blocked');
    expect(result.details).toContain('policy');
  });

  it('should accept valid IPv6 address', async () => {
    const result = await agent.addBlockedIP('2001:db8::1');
    expect(result.success).toBe(true);
    expect(result.action).toBe('block_ip');
    expect(result.target).toBe('2001:db8::1');
  });

  it('should record manifest entry for successful blocks', async () => {
    await agent.addBlockedIP('10.20.30.40');

    const activeActions = agent.getActiveActions();
    expect(activeActions.length).toBe(1);
    expect(activeActions[0].action).toBe('block_ip');
    expect(activeActions[0].target).toBe('10.20.30.40');
    expect(activeActions[0].rolledBack).toBe(false);
    expect(activeActions[0].verdict.conclusion).toBe('policy_block');
    expect(activeActions[0].verdict.confidence).toBe(100);
  });

  it('should persist manifest entry to disk', async () => {
    await agent.addBlockedIP('10.20.30.40');

    const manifestPath = join(tempDir, 'action-manifest.jsonl');
    expect(existsSync(manifestPath)).toBe(true);

    const content = readFileSync(manifestPath, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(1);

    const entry = JSON.parse(lines[lines.length - 1]);
    expect(entry.action).toBe('block_ip');
    expect(entry.target).toBe('10.20.30.40');
    expect(entry.verdict.conclusion).toBe('policy_block');
  });

  it('should set expiresAt on the manifest entry', async () => {
    const before = Date.now();
    await agent.addBlockedIP('10.20.30.40');
    const after = Date.now();

    const activeActions = agent.getActiveActions();
    expect(activeActions[0].expiresAt).toBeDefined();

    const expiresTime = new Date(activeActions[0].expiresAt!).getTime();
    // Default block duration is 1 hour (3600000ms)
    expect(expiresTime).toBeGreaterThanOrEqual(before + 3_600_000 - 1000);
    expect(expiresTime).toBeLessThanOrEqual(after + 3_600_000 + 1000);
  });

  it('should increment action count for successful blocks', async () => {
    expect(agent.getActionCount()).toBe(0);

    await agent.addBlockedIP('10.20.30.40');
    expect(agent.getActionCount()).toBe(1);

    await agent.addBlockedIP('10.20.30.41');
    expect(agent.getActionCount()).toBe(2);
  });

  it('should NOT increment action count for rejected IPs', async () => {
    await agent.addBlockedIP('127.0.0.1');
    await agent.addBlockedIP('not-valid!');
    expect(agent.getActionCount()).toBe(0);
  });

  it('should call firewall command for valid IP', async () => {
    await agent.addBlockedIP('10.20.30.40');
    expect(execFile).toHaveBeenCalled();
  });

  it('should NOT call firewall for rejected IPs', async () => {
    vi.mocked(execFile).mockClear();
    await agent.addBlockedIP('127.0.0.1');
    expect(execFile).not.toHaveBeenCalled();
  });

  it('should handle firewall command failure gracefully', async () => {
    vi.mocked(execFile).mockImplementation(
      (_cmd: unknown, _args: unknown, _opts: unknown, cb: unknown) => {
        (cb as (err: Error | null, stdout: string) => void)(new Error('Permission denied'), '');
        return undefined as never;
      }
    );

    const result = await agent.addBlockedIP('10.20.30.40');
    expect(result.success).toBe(false);
    expect(result.details).toContain('Failed to block');
  });

  it('should include auto-unblock time in success details', async () => {
    // Reset mock to success after potential failure mock in previous test
    vi.mocked(execFile).mockImplementation(
      (_cmd: unknown, _args: unknown, _opts: unknown, cb: unknown) => {
        (cb as (err: Error | null, stdout: string) => void)(null, '');
        return undefined as never;
      }
    );

    const result = await agent.addBlockedIP('10.20.30.40');
    expect(result.success).toBe(true);
    expect(result.details).toContain('Auto-unblock');
  });

  it('should handle blocking multiple IPs sequentially', async () => {
    // Reset mock to success
    vi.mocked(execFile).mockImplementation(
      (_cmd: unknown, _args: unknown, _opts: unknown, cb: unknown) => {
        (cb as (err: Error | null, stdout: string) => void)(null, '');
        return undefined as never;
      }
    );

    const result1 = await agent.addBlockedIP('10.0.0.1');
    const result2 = await agent.addBlockedIP('10.0.0.2');
    const result3 = await agent.addBlockedIP('10.0.0.3');

    expect(result1.success).toBe(true);
    expect(result2.success).toBe(true);
    expect(result3.success).toBe(true);
    expect(agent.getActiveActions().length).toBe(3);
  });
});

describe('RespondAgent.respond() - escalation tracking', () => {
  let agent: RespondAgent;
  let tempDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), 'respond-escalation-test-'));
    agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection', [], tempDir);
  });

  afterEach(() => {
    agent.destroy();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('should track escalation for auto-respond actions', async () => {
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 95,
      reasoning: 'Test',
      evidence: [
        { source: 'rule_match', description: 'test', confidence: 95, data: { ip: '10.0.0.1' } },
      ],
      recommendedAction: 'notify',
    };

    await agent.respond(verdict);
    await agent.respond(verdict);

    const records = agent.getEscalationRecords();
    expect(records.has('10.0.0.1')).toBe(true);
    expect(records.get('10.0.0.1')!.violationCount).toBe(2);
  });

  it('should track escalation for notify-level actions too', async () => {
    const verdict: ThreatVerdict = {
      conclusion: 'suspicious',
      confidence: 75,
      reasoning: 'Test',
      evidence: [
        { source: 'rule_match', description: 'test', confidence: 75, data: { ip: '10.0.0.2' } },
      ],
      recommendedAction: 'block_ip',
    };

    await agent.respond(verdict);
    await agent.respond(verdict);

    const records = agent.getEscalationRecords();
    expect(records.has('10.0.0.2')).toBe(true);
    expect(records.get('10.0.0.2')!.violationCount).toBe(2);
  });

  it('should not track escalation for log_only actions', async () => {
    const verdict: ThreatVerdict = {
      conclusion: 'benign',
      confidence: 30,
      reasoning: 'Safe',
      evidence: [
        { source: 'rule_match', description: 'test', confidence: 30, data: { ip: '10.0.0.3' } },
      ],
      recommendedAction: 'log_only',
    };

    await agent.respond(verdict);

    const records = agent.getEscalationRecords();
    expect(records.has('10.0.0.3')).toBe(false);
  });
});

describe('RespondAgent.updateActionPolicy()', () => {
  let agent: RespondAgent;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'respond-policy-test-'));
    agent = new RespondAgent(
      { autoRespond: 90, notifyAndWait: 70, logOnly: 0 },
      'protection',
      [],
      tempDir
    );
  });

  afterEach(() => {
    agent.destroy();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('should update autoRespond threshold', async () => {
    agent.updateActionPolicy({ autoRespond: 80 });

    // Verify by testing that a verdict with confidence 85 now triggers auto-respond
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 85,
      reasoning: 'Test',
      evidence: [],
      recommendedAction: 'notify',
    };

    const result = await agent.respond(verdict);
    // With threshold at 80, confidence 85 should trigger auto-respond
    expect(result.action).toBe('notify'); // The recommended action
  });

  it('should update notifyAndWait threshold', async () => {
    agent.updateActionPolicy({ notifyAndWait: 50 });

    // A verdict with confidence 55 should now trigger notify (was 70 threshold)
    const verdict: ThreatVerdict = {
      conclusion: 'suspicious',
      confidence: 55,
      reasoning: 'Test',
      evidence: [],
      recommendedAction: 'block_ip',
    };

    const result = await agent.respond(verdict);
    expect(result.action).toBe('notify');
  });
});
