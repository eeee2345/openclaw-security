/**
 * Multi-Agent pipeline tests
 * 多代理管線測試
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { SecurityEvent } from '@panguard-ai/core';
import { RuleEngine } from '@panguard-ai/core';
import type { EnvironmentBaseline, ThreatVerdict, DetectionResult } from '../src/types.js';
import { DEFAULT_ACTION_POLICY } from '../src/types.js';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { DetectAgent } from '../src/agent/detect-agent.js';
import { AnalyzeAgent } from '../src/agent/analyze-agent.js';
import { RespondAgent } from '../src/agent/respond-agent.js';
import { ReportAgent } from '../src/agent/report-agent.js';
import { createEmptyBaseline } from '../src/memory/baseline.js';

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: 'evt-test-001',
    timestamp: new Date(),
    source: 'network',
    severity: 'high',
    category: 'brute_force',
    description: 'SSH brute force attempt',
    host: 'test-host',
    metadata: {
      sourceIP: '103.0.0.1',
      remoteAddress: '103.0.0.1',
    },
    ...overrides,
  };
}

describe('DetectAgent', () => {
  it('should return null when no rules match', () => {
    const ruleEngine = new RuleEngine();
    const agent = new DetectAgent(ruleEngine);
    const event = makeEvent();

    const result = agent.detect(event);
    expect(result).toBeNull();
  });

  it('should return detection result when rules match', () => {
    const ruleEngine = new RuleEngine({
      customRules: [
        {
          id: 'test-rule-1',
          title: 'Test SSH Brute Force',
          status: 'stable' as const,
          description: 'Detects SSH brute force',
          level: 'high' as const,
          logsource: { category: 'brute_force' },
          detection: {
            selection: { category: 'brute_force' },
            condition: 'selection',
          },
        },
      ],
    });

    const agent = new DetectAgent(ruleEngine);
    const event = makeEvent({ category: 'brute_force' });

    const result = agent.detect(event);
    expect(result).not.toBeNull();
    expect(result!.ruleMatches.length).toBeGreaterThan(0);
    expect(result!.event.id).toBe('evt-test-001');
  });

  it('should track detection count', () => {
    const ruleEngine = new RuleEngine({
      customRules: [
        {
          id: 'test-count-rule',
          title: 'Test Rule',
          status: 'stable' as const,
          description: 'Test',
          level: 'medium' as const,
          logsource: { category: 'test' },
          detection: {
            selection: { category: 'test' },
            condition: 'selection',
          },
        },
      ],
    });

    const agent = new DetectAgent(ruleEngine);
    agent.detect(makeEvent({ category: 'test' }));
    agent.detect(makeEvent({ category: 'test' }));
    expect(agent.getDetectionCount()).toBe(2);
  });
});

describe('AnalyzeAgent', () => {
  let baseline: EnvironmentBaseline;

  beforeEach(() => {
    baseline = createEmptyBaseline();
  });

  it('should analyze a detection result without AI', async () => {
    const agent = new AnalyzeAgent(null);
    const detection: DetectionResult = {
      event: makeEvent(),
      ruleMatches: [{ ruleId: 'rule-1', ruleName: 'SSH Brute Force', severity: 'high' }],
      timestamp: new Date().toISOString(),
    };

    const verdict = await agent.analyze(detection, baseline);
    expect(verdict.conclusion).toBeDefined();
    expect(verdict.confidence).toBeGreaterThanOrEqual(0);
    expect(verdict.confidence).toBeLessThanOrEqual(100);
    expect(verdict.evidence.length).toBeGreaterThan(0);
    expect(verdict.recommendedAction).toBeDefined();
  });

  it('should give higher confidence for critical severity', async () => {
    const agent = new AnalyzeAgent(null);

    const highDetection: DetectionResult = {
      event: makeEvent(),
      ruleMatches: [{ ruleId: 'rule-1', ruleName: 'Test', severity: 'high' }],
      timestamp: new Date().toISOString(),
    };

    const criticalDetection: DetectionResult = {
      event: makeEvent(),
      ruleMatches: [{ ruleId: 'rule-2', ruleName: 'Critical Test', severity: 'critical' }],
      timestamp: new Date().toISOString(),
    };

    const highVerdict = await agent.analyze(highDetection, baseline);
    const criticalVerdict = await agent.analyze(criticalDetection, baseline);

    expect(criticalVerdict.confidence).toBeGreaterThan(highVerdict.confidence);
  });

  it('should include threat intel evidence', async () => {
    const agent = new AnalyzeAgent(null);
    const detection: DetectionResult = {
      event: makeEvent(),
      ruleMatches: [],
      threatIntelMatch: { ip: '103.0.0.1', threat: 'Known scanner' },
      timestamp: new Date().toISOString(),
    };

    const verdict = await agent.analyze(detection, baseline);
    const threatIntelEvidence = verdict.evidence.find((e) => e.source === 'threat_intel');
    expect(threatIntelEvidence).toBeDefined();
  });

  it('should track analysis count', async () => {
    const agent = new AnalyzeAgent(null);
    const detection: DetectionResult = {
      event: makeEvent(),
      ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'low' }],
      timestamp: new Date().toISOString(),
    };

    await agent.analyze(detection, baseline);
    await agent.analyze(detection, baseline);
    expect(agent.getAnalysisCount()).toBe(2);
  });
});

describe('RespondAgent', () => {
  it('should log only in learning mode', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'learning');
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 95,
      reasoning: 'Test',
      evidence: [],
      recommendedAction: 'block_ip',
    };

    const result = await agent.respond(verdict);
    expect(result.action).toBe('log_only');
    expect(result.success).toBe(true);
  });

  it('should auto-respond when confidence >= threshold', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection');
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 95,
      reasoning: 'Test',
      evidence: [{ source: 'rule_match', description: 'test', confidence: 95 }],
      recommendedAction: 'notify',
    };

    const result = await agent.respond(verdict);
    expect(result.action).toBe('notify');
  });

  it('should notify when confidence is in notify range', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection');
    const verdict: ThreatVerdict = {
      conclusion: 'suspicious',
      confidence: 60,
      reasoning: 'Test',
      evidence: [],
      recommendedAction: 'block_ip',
    };

    const result = await agent.respond(verdict);
    expect(result.action).toBe('notify');
  });

  it('should log only when confidence is low', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection');
    const verdict: ThreatVerdict = {
      conclusion: 'benign',
      confidence: 30,
      reasoning: 'Likely safe',
      evidence: [],
      recommendedAction: 'log_only',
    };

    const result = await agent.respond(verdict);
    expect(result.action).toBe('log_only');
  });

  it('should change mode', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'learning');
    agent.setMode('protection');

    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 95,
      reasoning: 'Test',
      evidence: [],
      recommendedAction: 'notify',
    };

    const result = await agent.respond(verdict);
    // Now in protection mode, should auto-respond
    expect(result.action).toBe('notify');
  });

  it('should refuse to block whitelisted IP (127.0.0.1)', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection');
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 95,
      reasoning: 'Test',
      evidence: [
        { source: 'rule_match', description: 'test', confidence: 95, data: { ip: '127.0.0.1' } },
      ],
      recommendedAction: 'block_ip',
    };

    const result = await agent.respond(verdict);
    expect(result.success).toBe(false);
    expect(result.details).toContain('whitelisted');
  });

  it('should refuse to block user-configured whitelisted IP', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection', ['10.0.0.1']);
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 95,
      reasoning: 'Test',
      evidence: [
        { source: 'rule_match', description: 'test', confidence: 95, data: { ip: '10.0.0.1' } },
      ],
      recommendedAction: 'block_ip',
    };

    const result = await agent.respond(verdict);
    expect(result.success).toBe(false);
    expect(result.details).toContain('whitelisted');
  });

  it('should refuse to kill protected process', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection');
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 95,
      reasoning: 'Test',
      evidence: [
        {
          source: 'rule_match',
          description: 'test',
          confidence: 95,
          data: { pid: 123, processName: 'sshd' },
        },
      ],
      recommendedAction: 'kill_process',
    };

    const result = await agent.respond(verdict);
    expect(result.success).toBe(false);
    expect(result.details).toContain('protected');
  });

  it('should refuse to disable protected account (root)', async () => {
    const agent = new RespondAgent(DEFAULT_ACTION_POLICY, 'protection');
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 95,
      reasoning: 'Test',
      evidence: [
        { source: 'rule_match', description: 'test', confidence: 95, data: { username: 'root' } },
      ],
      recommendedAction: 'disable_account',
    };

    const result = await agent.respond(verdict);
    expect(result.success).toBe(false);
    expect(result.details).toContain('protected');
  });
});

describe('ReportAgent', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'panguard-guard-test-'));
  });

  it('should log events and return updated baseline', () => {
    const logPath = join(tmpDir, 'events.jsonl');
    const agent = new ReportAgent(logPath, 'learning');
    const event = makeEvent();
    const verdict: ThreatVerdict = {
      conclusion: 'suspicious',
      confidence: 60,
      reasoning: 'Test',
      evidence: [{ source: 'rule_match', description: 'test', confidence: 60 }],
      recommendedAction: 'notify',
    };
    const response = {
      action: 'notify' as const,
      success: true,
      details: 'test',
      timestamp: new Date().toISOString(),
    };
    const baseline = createEmptyBaseline();

    const result = agent.report(event, verdict, response, baseline);
    expect(result.updatedBaseline.eventCount).toBeGreaterThanOrEqual(0);
    expect(result.anonymizedData).toBeDefined();
    expect(agent.getReportCount()).toBe(1);
  });

  it('should generate anonymized data with country code', () => {
    const logPath = join(tmpDir, 'events.jsonl');
    const agent = new ReportAgent(logPath, 'protection');
    const event = makeEvent({ metadata: { sourceIP: '203.0.113.42' } });
    const verdict: ThreatVerdict = {
      conclusion: 'malicious',
      confidence: 90,
      reasoning: 'Test',
      evidence: [],
      recommendedAction: 'block_ip',
    };
    const response = {
      action: 'block_ip' as const,
      success: true,
      details: 'test',
      timestamp: new Date().toISOString(),
    };
    const baseline = createEmptyBaseline();

    const result = agent.report(event, verdict, response, baseline);
    expect(result.anonymizedData).toBeDefined();
    // Anonymized IP should have last octet zeroed
    expect(result.anonymizedData!.attackSourceIP).toBe('203.0.113.0');
    // Region should be a country code, not a timezone
    expect(result.anonymizedData!.region).not.toContain('/');
  });

  it('should generate empty daily summary when no events', () => {
    const logPath = join(tmpDir, 'events.jsonl');
    const agent = new ReportAgent(logPath, 'protection');

    const summary = agent.generateDailySummary();
    expect(summary.totalEvents).toBe(0);
    expect(summary.threatsBlocked).toBe(0);
    expect(summary.topAttackSources).toEqual([]);
  });

  it('should generate daily summary from logged events', () => {
    const logPath = join(tmpDir, 'events.jsonl');
    const agent = new ReportAgent(logPath, 'protection');
    const baseline = createEmptyBaseline();

    // Log some events
    for (let i = 0; i < 3; i++) {
      const event = makeEvent({ metadata: { sourceIP: '10.0.0.1' } });
      const verdict: ThreatVerdict = {
        conclusion: i < 2 ? 'suspicious' : 'malicious',
        confidence: 70 + i * 10,
        reasoning: 'Test',
        evidence: [],
        recommendedAction: 'notify',
      };
      const response = {
        action: 'notify' as const,
        success: true,
        details: 'test',
        timestamp: new Date().toISOString(),
      };
      agent.report(event, verdict, response, baseline);
    }

    const summary = agent.generateDailySummary();
    expect(summary.totalEvents).toBe(3);
    expect(summary.verdictBreakdown.suspicious).toBe(2);
    expect(summary.verdictBreakdown.malicious).toBe(1);
    expect(summary.topAttackSources.length).toBeGreaterThan(0);
  });

  // Cleanup temp dirs after tests (not strictly needed, OS cleans up)
});
