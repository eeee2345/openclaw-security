import { describe, it, expect, vi, afterEach } from 'vitest';

import {
  createLLM,
  OllamaProvider,
  ClaudeProvider,
  getEventClassifierPrompt,
  getThreatAnalysisPrompt,
  getReportPrompt,
  parseAnalysisResponse,
  parseClassificationResponse,
  TokenTracker,
} from '@panguard-ai/core/ai/index.js';

import type { SecurityEvent } from '@panguard-ai/core/types.js';

// Suppress stderr output from logger during tests
const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

afterEach(() => {
  stderrSpy.mockClear();
});

/**
 * Helper to create a minimal SecurityEvent for testing prompts
 */
function createTestEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: 'test-event-001',
    timestamp: new Date('2025-03-15T10:00:00Z'),
    source: 'syslog',
    severity: 'high',
    category: 'Initial Access',
    description: 'SSH brute force attempt detected from 185.220.101.42',
    raw: { message: 'Failed password for root from 185.220.101.42 port 22' },
    host: 'test-server',
    metadata: {
      logSource: '/var/log/auth.log',
      remoteAddr: '185.220.101.42',
    },
    ...overrides,
  };
}

describe('createLLM factory', () => {
  it('should return OllamaProvider for ollama', () => {
    const provider = createLLM({
      provider: 'ollama',
      model: 'llama3',
      lang: 'en',
    });

    expect(provider).toBeInstanceOf(OllamaProvider);
    expect(provider.providerType).toBe('ollama');
    expect(provider.model).toBe('llama3');
  });

  it('should return ClaudeProvider for claude', () => {
    const provider = createLLM({
      provider: 'claude',
      model: 'claude-sonnet-4-20250514',
      apiKey: 'test-key',
      lang: 'en',
    });

    expect(provider).toBeInstanceOf(ClaudeProvider);
    expect(provider.providerType).toBe('claude');
    expect(provider.model).toBe('claude-sonnet-4-20250514');
  });

  it('should throw on unknown provider', () => {
    expect(() =>
      createLLM({
        provider: 'unknown-provider' as 'ollama',
        model: 'test',
        lang: 'en',
      })
    ).toThrow('Unknown LLM provider');
  });
});

describe('Event Classifier Prompt', () => {
  it('should include MITRE ATT&CK references in both languages', () => {
    const event = createTestEvent();

    const enPrompt = getEventClassifierPrompt(event, 'en');
    expect(enPrompt).toContain('MITRE ATT&CK');
    expect(enPrompt).toContain('Reconnaissance');
    expect(enPrompt).toContain('Initial Access');
    expect(enPrompt).toContain('Execution');
    expect(enPrompt).toContain('test-event-001');

    const zhPrompt = getEventClassifierPrompt(event, 'zh-TW');
    expect(zhPrompt).toContain('MITRE ATT&CK');
    expect(zhPrompt).toContain('Reconnaissance');
    expect(zhPrompt).toContain('test-event-001');
  });
});

describe('Threat Analyzer Prompt', () => {
  it('should include severity criteria', () => {
    const prompt = getThreatAnalysisPrompt('Analyze suspicious SSH activity', undefined, 'en');

    expect(prompt).toContain('info');
    expect(prompt).toContain('low');
    expect(prompt).toContain('medium');
    expect(prompt).toContain('high');
    expect(prompt).toContain('critical');
    expect(prompt).toContain('Analyze suspicious SSH activity');
    expect(prompt).toContain('Assessment Criteria');
  });
});

describe('Report Generator Prompt', () => {
  it('should include event data', () => {
    const events = [
      createTestEvent({ severity: 'critical', description: 'Critical: system compromised' }),
      createTestEvent({ severity: 'high', description: 'High: brute force detected' }),
      createTestEvent({ severity: 'info', description: 'Info: routine login' }),
    ];

    const prompt = getReportPrompt(events, 'en');

    expect(prompt).toContain('Total events: 3');
    expect(prompt).toContain('critical: 1');
    expect(prompt).toContain('high: 1');
    expect(prompt).toContain('info: 1');
    expect(prompt).toContain('Critical: system compromised');
    expect(prompt).toContain('Executive Summary');
  });
});

describe('Response Parser', () => {
  it('should parse valid JSON analysis response', () => {
    const rawJson = JSON.stringify({
      summary: 'SSH brute force attack detected',
      severity: 'high',
      confidence: 0.92,
      recommendations: ['Block the source IP', 'Enable fail2ban', 'Review auth logs'],
    });

    const result = parseAnalysisResponse(rawJson);

    expect(result.summary).toBe('SSH brute force attack detected');
    expect(result.severity).toBe('high');
    expect(result.confidence).toBe(0.92);
    expect(result.recommendations).toHaveLength(3);
    expect(result.recommendations[0]).toBe('Block the source IP');
    expect(result.rawResponse).toBe(rawJson);
  });

  it('should parse valid JSON classification response', () => {
    const rawJson = JSON.stringify({
      category: 'Initial Access',
      technique: 'T1110',
      severity: 'high',
      confidence: 0.88,
      description: 'Brute force credential attack via SSH',
    });

    const result = parseClassificationResponse(rawJson);

    expect(result.category).toBe('Initial Access');
    expect(result.technique).toBe('T1110');
    expect(result.severity).toBe('high');
    expect(result.confidence).toBe(0.88);
    expect(result.description).toBe('Brute force credential attack via SSH');
  });
});

describe('Token Tracker', () => {
  it('should track usage correctly', () => {
    const tracker = new TokenTracker('ollama', 'llama3');

    // Initial state should be zero
    let usage = tracker.getUsage();
    expect(usage.promptTokens).toBe(0);
    expect(usage.completionTokens).toBe(0);
    expect(usage.totalTokens).toBe(0);
    expect(usage.estimatedCost).toBe(0);

    // Track a request
    tracker.track(100, 50);
    usage = tracker.getUsage();
    expect(usage.promptTokens).toBe(100);
    expect(usage.completionTokens).toBe(50);
    expect(usage.totalTokens).toBe(150);

    // Track another request (cumulative)
    tracker.track(200, 100);
    usage = tracker.getUsage();
    expect(usage.promptTokens).toBe(300);
    expect(usage.completionTokens).toBe(150);
    expect(usage.totalTokens).toBe(450);

    // Ollama is free, so cost should remain 0
    expect(usage.estimatedCost).toBe(0);
  });
});
