import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { KnowledgeDistiller } from '../src/ai/knowledge-distiller.js';
import type { DistillationInput, DistilledRule } from '../src/ai/knowledge-distiller.js';
import type { AnalysisResult } from '../src/ai/types.js';

// Suppress logger stderr output during tests
let stderrSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  stderrSpy.mockRestore();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAnalysisResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    summary: 'SSH brute force attack detected from external IP',
    severity: 'high',
    confidence: 0.85,
    recommendations: ['Block source IP', 'Enable fail2ban', 'Review auth logs'],
    ...overrides,
  };
}

function makeInput(overrides: Partial<DistillationInput> = {}): DistillationInput {
  return {
    eventCategory: 'brute_force',
    eventSource: 'auth',
    eventSeverity: 'high',
    mitreTechnique: 'T1110',
    indicators: {
      remoteAddr: '185.220.101.42',
      targetUser: 'root',
    },
    aiResult: makeAnalysisResult(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Happy path – distilling a valid rule
// ---------------------------------------------------------------------------

describe('distill() – valid high-confidence result', () => {
  it('returns a DistilledRule for an input with confidence >= 0.7', () => {
    const distiller = new KnowledgeDistiller();
    const rule = distiller.distill(makeInput());

    expect(rule).not.toBeNull();
    expect(rule!.source).toBe('ai-distilled');
    expect(rule!.aiConfidence).toBe(0.85);
    expect(rule!.ruleId).toMatch(/^ai-distilled-/);
    expect(rule!.patternHash).toBeTruthy();
    expect(rule!.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('generated YAML contains the rule title with event category and MITRE technique', () => {
    const distiller = new KnowledgeDistiller();
    const rule = distiller.distill(makeInput())!;

    expect(rule.sigmaYaml).toContain('brute_force');
    expect(rule.sigmaYaml).toContain('T1110');
    expect(rule.sigmaYaml).toContain('title:');
  });

  it('generated YAML contains a valid id field matching the ruleId', () => {
    const distiller = new KnowledgeDistiller();
    const rule = distiller.distill(makeInput())!;

    expect(rule.sigmaYaml).toContain(`id: ${rule.ruleId}`);
  });

  it('generated YAML contains the detection section with condition: selection', () => {
    const distiller = new KnowledgeDistiller();
    const rule = distiller.distill(makeInput())!;

    expect(rule.sigmaYaml).toContain('detection:');
    expect(rule.sigmaYaml).toContain('selection:');
    expect(rule.sigmaYaml).toContain('condition: selection');
  });

  it('generated YAML includes category and source in detection selection', () => {
    const distiller = new KnowledgeDistiller();
    const rule = distiller.distill(makeInput())!;

    expect(rule.sigmaYaml).toContain('category: brute_force');
    expect(rule.sigmaYaml).toContain('source: auth');
  });

  it('generated YAML includes MITRE tags for known techniques', () => {
    const distiller = new KnowledgeDistiller();
    const rule = distiller.distill(makeInput({ mitreTechnique: 'T1110' }))!;

    expect(rule.sigmaYaml).toContain('tags:');
    expect(rule.sigmaYaml).toContain('attack.t1110');
  });

  it('generated YAML includes AI confidence in description', () => {
    const distiller = new KnowledgeDistiller();
    const rule = distiller.distill(makeInput())!;

    // 0.85 -> 85%
    expect(rule.sigmaYaml).toContain('85%');
  });

  it('maps AI severity to correct Sigma level', () => {
    const distiller = new KnowledgeDistiller();
    const rule = distiller.distill(makeInput())!;
    expect(rule.sigmaYaml).toContain('level: high');
  });

  it('maps critical severity to Sigma critical level', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ aiResult: makeAnalysisResult({ severity: 'critical' }) });
    const rule = distiller.distill(input)!;
    expect(rule.sigmaYaml).toContain('level: critical');
  });

  it('maps info severity to Sigma informational level', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ aiResult: makeAnalysisResult({ severity: 'info' }) });
    const rule = distiller.distill(input)!;
    expect(rule.sigmaYaml).toContain('level: informational');
  });
});

// ---------------------------------------------------------------------------
// Low-confidence skip
// ---------------------------------------------------------------------------

describe('distill() – low confidence skip', () => {
  it('returns null when AI confidence is below the default threshold of 0.7', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ aiResult: makeAnalysisResult({ confidence: 0.69 }) });

    expect(distiller.distill(input)).toBeNull();
  });

  it('returns null when confidence is exactly 0 (no signal)', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ aiResult: makeAnalysisResult({ confidence: 0 }) });

    expect(distiller.distill(input)).toBeNull();
  });

  it('succeeds at exactly the default threshold (0.7)', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ aiResult: makeAnalysisResult({ confidence: 0.7 }) });

    expect(distiller.distill(input)).not.toBeNull();
  });

  it('respects a custom minConfidence option', () => {
    const distiller = new KnowledgeDistiller({ minConfidence: 0.9 });

    // 0.85 is below the custom 0.9 threshold
    const low = makeInput({ aiResult: makeAnalysisResult({ confidence: 0.85 }) });
    expect(distiller.distill(low)).toBeNull();

    // 0.9 meets the threshold exactly
    const exact = makeInput({ aiResult: makeAnalysisResult({ confidence: 0.9 }) });
    expect(distiller.distill(exact)).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('distill() – deduplication', () => {
  it('returns null for the second call with the same pattern', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput();

    const first = distiller.distill(input);
    const second = distiller.distill(input);

    expect(first).not.toBeNull();
    expect(second).toBeNull();
  });

  it('treats different categories as distinct patterns', () => {
    const distiller = new KnowledgeDistiller();

    const brute = makeInput({ eventCategory: 'brute_force' });
    const scan = makeInput({ eventCategory: 'port_scan' });

    expect(distiller.distill(brute)).not.toBeNull();
    expect(distiller.distill(scan)).not.toBeNull();
  });

  it('treats different MITRE techniques as distinct patterns', () => {
    const distiller = new KnowledgeDistiller();

    const t1110 = makeInput({ mitreTechnique: 'T1110' });
    const t1046 = makeInput({ mitreTechnique: 'T1046' });

    expect(distiller.distill(t1110)).not.toBeNull();
    expect(distiller.distill(t1046)).not.toBeNull();
  });

  it('treats different indicator keys as distinct patterns (sorted key list matters)', () => {
    const distiller = new KnowledgeDistiller();

    const withPort = makeInput({ indicators: { remoteAddr: '1.2.3.4', port: '22' } });
    const withoutPort = makeInput({ indicators: { remoteAddr: '1.2.3.4' } });

    expect(distiller.distill(withPort)).not.toBeNull();
    expect(distiller.distill(withoutPort)).not.toBeNull();
  });

  it('dedup is insensitive to indicator values (same keys, different IPs)', () => {
    const distiller = new KnowledgeDistiller();

    const ip1 = makeInput({ indicators: { remoteAddr: '1.1.1.1' } });
    const ip2 = makeInput({ indicators: { remoteAddr: '9.9.9.9' } });

    // Pattern hash is computed from keys only – both should map to the same hash
    expect(distiller.distill(ip1)).not.toBeNull();
    expect(distiller.distill(ip2)).toBeNull(); // same indicator keys -> dup
  });
});

// ---------------------------------------------------------------------------
// isDistilled()
// ---------------------------------------------------------------------------

describe('isDistilled()', () => {
  it('returns false before the pattern has been distilled', () => {
    const distiller = new KnowledgeDistiller();
    expect(distiller.isDistilled(makeInput())).toBe(false);
  });

  it('returns true after the pattern has been distilled', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput();

    distiller.distill(input);

    expect(distiller.isDistilled(input)).toBe(true);
  });

  it('returns false for a different pattern even after one is distilled', () => {
    const distiller = new KnowledgeDistiller();

    distiller.distill(makeInput({ eventCategory: 'brute_force' }));

    const other = makeInput({ eventCategory: 'port_scan' });
    expect(distiller.isDistilled(other)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// onRuleDistilled callback
// ---------------------------------------------------------------------------

describe('onRuleDistilled callback', () => {
  it('fires with the distilled rule when a new rule is created', () => {
    const callback = vi.fn();
    const distiller = new KnowledgeDistiller({ onRuleDistilled: callback });

    distiller.distill(makeInput());

    expect(callback).toHaveBeenCalledTimes(1);
    const fired: DistilledRule = callback.mock.calls[0][0];
    expect(fired.source).toBe('ai-distilled');
    expect(fired.ruleId).toMatch(/^ai-distilled-/);
  });

  it('does not fire for low-confidence results', () => {
    const callback = vi.fn();
    const distiller = new KnowledgeDistiller({ onRuleDistilled: callback });

    distiller.distill(makeInput({ aiResult: makeAnalysisResult({ confidence: 0.5 }) }));

    expect(callback).not.toHaveBeenCalled();
  });

  it('does not fire on duplicate patterns (second distill call)', () => {
    const callback = vi.fn();
    const distiller = new KnowledgeDistiller({ onRuleDistilled: callback });

    const input = makeInput();
    distiller.distill(input);
    distiller.distill(input);

    expect(callback).toHaveBeenCalledTimes(1);
  });

  it('fires once per unique pattern', () => {
    const callback = vi.fn();
    const distiller = new KnowledgeDistiller({ onRuleDistilled: callback });

    distiller.distill(makeInput({ eventCategory: 'brute_force' }));
    distiller.distill(makeInput({ eventCategory: 'port_scan' }));
    distiller.distill(makeInput({ eventCategory: 'lateral_movement' }));

    expect(callback).toHaveBeenCalledTimes(3);
  });
});

// ---------------------------------------------------------------------------
// getDistilledCount()
// ---------------------------------------------------------------------------

describe('getDistilledCount()', () => {
  it('returns 0 initially', () => {
    const distiller = new KnowledgeDistiller();
    expect(distiller.getDistilledCount()).toBe(0);
  });

  it('increments by 1 for each unique pattern distilled', () => {
    const distiller = new KnowledgeDistiller();

    distiller.distill(makeInput({ eventCategory: 'brute_force' }));
    expect(distiller.getDistilledCount()).toBe(1);

    distiller.distill(makeInput({ eventCategory: 'port_scan' }));
    expect(distiller.getDistilledCount()).toBe(2);
  });

  it('does not increment for duplicate patterns', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput();

    distiller.distill(input);
    distiller.distill(input);
    distiller.distill(input);

    expect(distiller.getDistilledCount()).toBe(1);
  });

  it('does not increment for low-confidence skips', () => {
    const distiller = new KnowledgeDistiller();
    distiller.distill(makeInput({ aiResult: makeAnalysisResult({ confidence: 0.3 }) }));
    expect(distiller.getDistilledCount()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// getDistilledPatterns()
// ---------------------------------------------------------------------------

describe('getDistilledPatterns()', () => {
  it('returns an empty array initially', () => {
    const distiller = new KnowledgeDistiller();
    expect(distiller.getDistilledPatterns()).toEqual([]);
  });

  it('returns the hashes of all distilled patterns', () => {
    const distiller = new KnowledgeDistiller();

    distiller.distill(makeInput({ eventCategory: 'brute_force' }));
    distiller.distill(makeInput({ eventCategory: 'port_scan' }));

    const patterns = distiller.getDistilledPatterns();
    expect(patterns).toHaveLength(2);
    // Each hash is a 12-char hex string
    for (const hash of patterns) {
      expect(hash).toMatch(/^[0-9a-f]{12}$/);
    }
  });

  it('returns a copy (mutating the array does not affect internal state)', () => {
    const distiller = new KnowledgeDistiller();
    distiller.distill(makeInput());

    const patterns = distiller.getDistilledPatterns();
    patterns.push('tampered');

    expect(distiller.getDistilledPatterns()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('Edge cases', () => {
  it('handles input with no MITRE technique (falls back to panguard logsource)', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ mitreTechnique: undefined });
    const rule = distiller.distill(input)!;

    expect(rule).not.toBeNull();
    expect(rule.sigmaYaml).toContain('product: panguard');
    expect(rule.sigmaYaml).toContain('service: guard');
  });

  it('handles input with empty indicators gracefully', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ indicators: {} });
    const rule = distiller.distill(input);

    expect(rule).not.toBeNull();
    expect(rule!.sigmaYaml).toContain('detection:');
  });

  it('sanitizes indicator values containing single quotes from the YAML output', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ indicators: { cmdLine: "bash -c 'echo pwned'" } });
    const rule = distiller.distill(input)!;

    // The generated YAML value should not contain raw single quotes
    expect(rule.sigmaYaml).not.toContain("'echo pwned'");
  });

  it('handles empty recommendations array without crashing', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({ aiResult: makeAnalysisResult({ recommendations: [] }) });
    const rule = distiller.distill(input);
    expect(rule).not.toBeNull();
  });

  it('includes up to 3 recommendations in the YAML description block', () => {
    const distiller = new KnowledgeDistiller();
    const input = makeInput({
      aiResult: makeAnalysisResult({
        recommendations: ['Action A', 'Action B', 'Action C', 'Action D', 'Action E'],
      }),
    });
    const rule = distiller.distill(input)!;

    // Only first 3 should appear
    expect(rule.sigmaYaml).toContain('Action A');
    expect(rule.sigmaYaml).toContain('Action B');
    expect(rule.sigmaYaml).toContain('Action C');
    expect(rule.sigmaYaml).not.toContain('Action D');
  });
});
