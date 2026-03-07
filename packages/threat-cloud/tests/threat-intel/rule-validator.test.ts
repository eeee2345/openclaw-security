/**
 * Rule Validator & Deduplicator Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RuleValidator } from '../../src/threat-intel/rule-validator.js';
import type { GeneratedRule } from '../../src/threat-intel/types.js';

const VALID_YAML = `title: Potential SSRF via Internal Network Access
id: 550e8400-e29b-41d4-a716-446655440000
status: experimental
description: |
  Detects potential SSRF attempts.
  Auto-generated from HackerOne report analysis.
references:
  - https://hackerone.com/reports/12345
author: Panguard Threat Intel (auto-generated)
date: 2026/03/07
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '127.0.0.1'
      - 'localhost'
  condition: selection
falsepositives:
  - Legitimate internal API calls
level: high`;

function makeRule(overrides: Partial<GeneratedRule> = {}): GeneratedRule {
  return {
    id: '550e8400-e29b-41d4-a716-446655440000',
    yamlContent: VALID_YAML,
    sourceReportId: '12345',
    sourceReportUrl: 'https://hackerone.com/reports/12345',
    attackType: 'SSRF',
    confidence: 85,
    status: 'experimental',
    generatedAt: '2026-03-07T00:00:00Z',
    reviewed: false,
    reviewDecision: 'pending',
    ...overrides,
  };
}

describe('RuleValidator', () => {
  let validator: RuleValidator;

  beforeEach(() => {
    validator = new RuleValidator();
  });

  it('validates a correct rule', () => {
    const result = validator.validate(makeRule());

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.isDuplicate).toBe(false);
  });

  it('detects missing title', () => {
    const yaml = VALID_YAML.replace(/^title:.*$/m, '');
    const result = validator.validate(makeRule({ yamlContent: yaml }));

    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Missing required field: title');
  });

  it('detects missing id', () => {
    const yaml = VALID_YAML.replace(/^id:.*$/m, '');
    const result = validator.validate(makeRule({ yamlContent: yaml }));

    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Missing required field: id');
  });

  it('detects missing detection block', () => {
    const yaml = VALID_YAML.replace(/^detection:[\s\S]*?(?=^falsepositives:)/m, '');
    const result = validator.validate(makeRule({ yamlContent: yaml }));

    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Missing required field: detection');
  });

  it('detects missing condition in detection', () => {
    const yaml = VALID_YAML.replace(/condition: selection/m, '');
    const result = validator.validate(makeRule({ yamlContent: yaml }));

    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Detection block missing condition');
  });

  it('detects missing level', () => {
    const yaml = VALID_YAML.replace(/^level:.*$/m, '');
    const result = validator.validate(makeRule({ yamlContent: yaml }));

    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Missing required field: level');
  });

  it('warns on invalid level value', () => {
    const yaml = VALID_YAML.replace('level: high', 'level: extreme');
    const result = validator.validate(makeRule({ yamlContent: yaml }));

    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Invalid level: extreme');
  });

  it('warns on low confidence', () => {
    const result = validator.validate(makeRule({ confidence: 40 }));

    expect(result.warnings.some((w) => w.includes('Low confidence'))).toBe(true);
  });

  it('detects duplicate rules', () => {
    const rule1 = makeRule({ id: 'rule-1' });
    const rule2 = makeRule({ id: 'rule-2' });

    // First validation registers the fingerprint
    validator.validate(rule1);

    // Second validation detects duplicate
    const result = validator.validate(rule2);
    expect(result.isDuplicate).toBe(true);
    expect(result.duplicateOf).toBe('rule-1');
  });

  it('does not flag same rule as duplicate of itself', () => {
    const rule = makeRule();
    validator.validate(rule);
    const result = validator.validate(rule);

    expect(result.isDuplicate).toBe(false);
  });

  it('detects different rules as non-duplicate', () => {
    const rule1 = makeRule({ id: 'rule-1' });
    const rule2 = makeRule({
      id: 'rule-2',
      yamlContent: VALID_YAML.replace("'127.0.0.1'", "'10.10.10.10'").replace("'localhost'", "'evil.com'"),
    });

    validator.validate(rule1);
    const result = validator.validate(rule2);

    expect(result.isDuplicate).toBe(false);
  });

  it('supports registering existing rules for dedup', () => {
    validator.registerExistingRules([
      { id: 'existing-rule', yamlContent: VALID_YAML },
    ]);

    const result = validator.validate(makeRule({ id: 'new-rule' }));
    expect(result.isDuplicate).toBe(true);
    expect(result.duplicateOf).toBe('existing-rule');
  });

  it('warns on missing logsource category', () => {
    const yaml = VALID_YAML.replace('category: webserver', '');
    const result = validator.validate(makeRule({ yamlContent: yaml }));

    expect(result.warnings.some((w) => w.includes('Logsource missing category'))).toBe(true);
  });

  it('validates detection has selection', () => {
    const yaml = VALID_YAML
      .replace(/selection:[\s\S]*?condition/m, 'condition')
      .replace('condition: selection', 'condition: 1 of them');
    const result = validator.validate(makeRule({ yamlContent: yaml }));

    expect(result.errors).toContain('Detection block missing selection');
  });
});
