import { describe, it, expect } from 'vitest';
import { matchEvent, matchEventAgainstRules } from '../src/rules/sigma-matcher.js';
import type { SigmaRule } from '../src/rules/types.js';
import type { SecurityEvent } from '../src/types.js';

function makeEvent(overrides: Partial<SecurityEvent> & { metadata?: Record<string, unknown> }): SecurityEvent {
  return {
    id: 'test-001',
    timestamp: new Date(),
    source: 'test',
    severity: 'medium',
    category: 'process',
    description: 'Test event',
    host: 'localhost',
    metadata: {},
    ...overrides,
  };
}

function makeRule(overrides: Partial<SigmaRule>): SigmaRule {
  return {
    id: 'rule-001',
    title: 'Test Rule',
    status: 'test',
    description: 'Test rule',
    logsource: { category: 'process_creation', product: 'any' },
    detection: {
      selection: { description: 'Test event' },
      condition: 'selection',
    },
    level: 'medium',
    ...overrides,
  };
}

describe('Enhanced Sigma Matcher - Aggregation Expressions', () => {
  it('should match "1 of them" condition', () => {
    const rule = makeRule({
      detection: {
        sel1: { description: 'no match here' },
        sel2: { description: 'Test event' },
        condition: '1 of them',
      },
    });

    const event = makeEvent({});
    const result = matchEvent(event, rule);
    expect(result).not.toBeNull();
  });

  it('should fail "1 of them" when no selections match', () => {
    const rule = makeRule({
      detection: {
        sel1: { description: 'nope' },
        sel2: { description: 'also nope' },
        condition: '1 of them',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).toBeNull();
  });

  it('should match "all of them" when all selections match', () => {
    const rule = makeRule({
      detection: {
        sel1: { description: 'Test event' },
        sel2: { host: 'localhost' },
        condition: 'all of them',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });

  it('should fail "all of them" when not all match', () => {
    const rule = makeRule({
      detection: {
        sel1: { description: 'Test event' },
        sel2: { host: 'other-host' },
        condition: 'all of them',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).toBeNull();
  });

  it('should match "1 of sel*" with prefix pattern', () => {
    const rule = makeRule({
      detection: {
        sel_cmd: { description: 'no match' },
        sel_host: { host: 'localhost' },
        filter: { severity: 'critical' },
        condition: '1 of sel*',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });

  it('should match "all of sel*" requiring all sel_ prefixed', () => {
    const rule = makeRule({
      detection: {
        sel_a: { description: 'Test event' },
        sel_b: { host: 'localhost' },
        condition: 'all of sel*',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });

  it('should combine aggregation with NOT', () => {
    const rule = makeRule({
      detection: {
        selection: { description: 'Test event' },
        filter: { host: 'other-host' },
        condition: 'selection AND NOT filter',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });
});

describe('Enhanced Sigma Matcher - Additional Modifiers', () => {
  it('should match |contains modifier', () => {
    const rule = makeRule({
      detection: {
        selection: { 'description|contains': 'event' },
        condition: 'selection',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });

  it('should match |startswith modifier', () => {
    const rule = makeRule({
      detection: {
        selection: { 'description|startswith': 'Test' },
        condition: 'selection',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });

  it('should match |endswith modifier', () => {
    const rule = makeRule({
      detection: {
        selection: { 'description|endswith': 'event' },
        condition: 'selection',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });

  it('should match |re modifier', () => {
    const rule = makeRule({
      detection: {
        selection: { 'description|re': 'Test.*event' },
        condition: 'selection',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });

  it('should match |gt numeric modifier', () => {
    const rule = makeRule({
      detection: {
        selection: { 'port|gt': '80' },
        condition: 'selection',
      },
    });

    const event = makeEvent({ metadata: { port: '443' } });
    const result = matchEvent(event, rule);
    expect(result).not.toBeNull();
  });

  it('should match |lt numeric modifier', () => {
    const rule = makeRule({
      detection: {
        selection: { 'port|lt': '1024' },
        condition: 'selection',
      },
    });

    const event = makeEvent({ metadata: { port: '80' } });
    const result = matchEvent(event, rule);
    expect(result).not.toBeNull();
  });

  it('should match |cidr modifier for IP ranges', () => {
    const rule = makeRule({
      detection: {
        selection: { 'src_ip|cidr': '192.168.1.0/24' },
        condition: 'selection',
      },
    });

    const event = makeEvent({ metadata: { src_ip: '192.168.1.50' } });
    const result = matchEvent(event, rule);
    expect(result).not.toBeNull();
  });

  it('should not match |cidr for IP outside range', () => {
    const rule = makeRule({
      detection: {
        selection: { 'src_ip|cidr': '192.168.1.0/24' },
        condition: 'selection',
      },
    });

    const event = makeEvent({ metadata: { src_ip: '10.0.0.1' } });
    const result = matchEvent(event, rule);
    expect(result).toBeNull();
  });

  it('should match wildcard patterns', () => {
    const rule = makeRule({
      detection: {
        selection: { description: 'Test*' },
        condition: 'selection',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });
});

describe('Enhanced Sigma Matcher - Complex Conditions', () => {
  it('should handle parenthesized conditions', () => {
    const rule = makeRule({
      detection: {
        sel_a: { description: 'Test event' },
        sel_b: { host: 'localhost' },
        filter: { severity: 'critical' },
        condition: '(sel_a OR sel_b) AND NOT filter',
      },
    });

    const result = matchEvent(makeEvent({}), rule);
    expect(result).not.toBeNull();
  });

  it('should match multiple rules against same event', () => {
    const rules = [
      makeRule({ id: 'r1', detection: { sel: { description: 'Test event' }, condition: 'sel' } }),
      makeRule({ id: 'r2', detection: { sel: { host: 'localhost' }, condition: 'sel' } }),
      makeRule({ id: 'r3', detection: { sel: { host: 'no-match' }, condition: 'sel' } }),
    ];

    const matches = matchEventAgainstRules(makeEvent({}), rules);
    expect(matches.length).toBe(2);
    expect(matches.map(m => m.rule.id)).toEqual(['r1', 'r2']);
  });
});
