/**
 * ATRDrafter unit tests
 * Tests extractYaml() and validateATRYaml() methods.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AnalyzeLLM } from '../src/types.js';
import type { ThreatCloudClient } from '../src/threat-cloud/index.js';

// Mock logger
vi.mock('@panguard-ai/core', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

// Dynamic import to ensure mocks are in place
const { ATRDrafter } = await import('../src/engines/atr-drafter.js');

function createMockLLM(): AnalyzeLLM {
  return {
    analyze: vi.fn().mockResolvedValue({
      summary: '',
      severity: 'low',
      confidence: 0,
      recommendations: [],
    }),
    classify: vi.fn().mockResolvedValue({
      conclusion: 'benign',
      confidence: 0,
      category: 'test',
    }),
    isAvailable: vi.fn().mockResolvedValue(true),
  };
}

function createMockThreatCloud(): ThreatCloudClient {
  return {
    submitATRProposal: vi.fn().mockResolvedValue(true),
  } as unknown as ThreatCloudClient;
}

describe('ATRDrafter', () => {
  let drafter: InstanceType<typeof ATRDrafter>;
  let mockLLM: AnalyzeLLM;
  let mockCloud: ThreatCloudClient;

  beforeEach(() => {
    mockLLM = createMockLLM();
    mockCloud = createMockThreatCloud();
    drafter = new ATRDrafter(mockLLM, mockCloud);
  });

  // -----------------------------------------------------------------------
  // extractYaml() with valid markdown code block
  // -----------------------------------------------------------------------
  describe('extractYaml', () => {
    it('should extract YAML from a ```yaml code block', () => {
      const text = `Here is the rule:

\`\`\`yaml
title: Test Rule
id: ATR-TEST-001
severity: high
detection:
  conditions:
    - pattern: "test"
\`\`\`

That's it.`;

      const result = drafter.extractYaml(text);
      expect(result).toContain('title: Test Rule');
      expect(result).toContain('id: ATR-TEST-001');
      expect(result).toContain('severity: high');
    });

    it('should extract YAML from a ```yml code block', () => {
      const text = `\`\`\`yml
title: Yml Rule
id: ATR-YML-001
severity: medium
detection:
  conditions: []
\`\`\``;

      const result = drafter.extractYaml(text);
      expect(result).toContain('title: Yml Rule');
    });

    it('should extract YAML from a generic ``` code block if content looks like YAML', () => {
      const text = `\`\`\`
title: Generic Block
id: ATR-GEN-001
severity: low
detection:
  conditions: []
\`\`\``;

      const result = drafter.extractYaml(text);
      expect(result).toContain('title: Generic Block');
    });

    it('should fall back to finding YAML keys in plain text', () => {
      const text = `Some explanation text here.

title: Fallback Rule
id: ATR-FALL-001
severity: high
detection:
  conditions:
    - pattern: "test"`;

      const result = drafter.extractYaml(text);
      expect(result).toContain('title: Fallback Rule');
      expect(result).toContain('id: ATR-FALL-001');
    });

    // -------------------------------------------------------------------
    // extractYaml() with malformed input
    // -------------------------------------------------------------------
    it('should return empty string for completely non-YAML text', () => {
      const text = 'This is just a plain text response with no YAML content at all.';
      const result = drafter.extractYaml(text);
      expect(result).toBe('');
    });

    it('should return empty string for empty input', () => {
      expect(drafter.extractYaml('')).toBe('');
    });

    it('should return empty string for an empty code block', () => {
      const text = '```yaml\n```';
      const result = drafter.extractYaml(text);
      expect(result).toBe('');
    });
  });

  // -----------------------------------------------------------------------
  // Schema validation rejects invalid rule
  // -----------------------------------------------------------------------
  describe('validateATRYaml', () => {
    it('should reject invalid YAML syntax', () => {
      const badYaml = 'title: Test\n  broken: [unclosed';
      const result = drafter.validateATRYaml(badYaml);
      expect(result).not.toBeNull();
      expect(result).toContain('Invalid YAML');
    });

    it('should reject YAML missing required fields', () => {
      const missingFields = `title: Test Rule
severity: high`;
      const result = drafter.validateATRYaml(missingFields);
      expect(result).not.toBeNull();
      expect(result).toContain('Missing required fields');
      expect(result).toContain('id');
      expect(result).toContain('detection');
    });

    it('should reject YAML with invalid severity', () => {
      const badSeverity = `title: Test Rule
id: ATR-TEST-001
severity: extreme
detection:
  conditions: []`;
      const result = drafter.validateATRYaml(badSeverity);
      expect(result).not.toBeNull();
      expect(result).toContain('Invalid severity');
    });

    it('should reject YAML where detection is not an object', () => {
      const badDetection = `title: Test Rule
id: ATR-TEST-001
severity: high
detection: "just a string"`;
      const result = drafter.validateATRYaml(badDetection);
      expect(result).not.toBeNull();
      expect(result).toContain('detection must be an object');
    });

    it('should reject YAML that is an array at root', () => {
      const arrayYaml = '- item1\n- item2';
      const result = drafter.validateATRYaml(arrayYaml);
      expect(result).not.toBeNull();
      expect(result).toContain('root must be an object');
    });

    // -------------------------------------------------------------------
    // Schema validation accepts valid rule
    // -------------------------------------------------------------------
    it('should accept a valid ATR rule', () => {
      const validRule = `title: Prompt Injection Detection
id: ATR-AUTO-PROMPT-INJECTION
severity: high
status: draft
detection:
  conditions:
    - field: content
      operator: contains
      value: "ignore previous instructions"
response:
  actions:
    - alert
false_positives:
  - Legitimate discussion about prompt injection`;
      const result = drafter.validateATRYaml(validRule);
      expect(result).toBeNull();
    });

    it('should accept all valid severity levels', () => {
      for (const severity of ['critical', 'high', 'medium', 'low', 'informational']) {
        const rule = `title: Test
id: ATR-TEST
severity: ${severity}
detection:
  conditions: []`;
        const result = drafter.validateATRYaml(rule);
        expect(result).toBeNull();
      }
    });
  });
});
