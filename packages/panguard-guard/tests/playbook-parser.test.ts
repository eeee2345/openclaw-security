/**
 * Playbook Parser Tests
 * 劇本解析器測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parsePlaybook, validatePlaybook, loadPlaybooksFromDir } from '../src/playbook/parser.js';
import type { Playbook } from '../src/playbook/schema.js';

/** Valid playbook YAML for testing / 用於測試的有效劇本 YAML */
const VALID_YAML = `
name: test-playbook
description: "Test playbook"
descriptionZh: "測試劇本"
priority: 100
trigger:
  pattern: brute_force
  minConfidence: 75
actions:
  - type: block_ip
    params:
      duration: "1h"
  - type: notify
    params:
      severity: high
escalation:
  after: 3
  within: "24h"
  actions:
    - type: block_ip
      params:
        duration: "7d"
    - type: notify
      params:
        severity: critical
`;

/** Minimal valid playbook YAML / 最小有效劇本 YAML */
const MINIMAL_YAML = `
name: minimal
trigger:
  pattern: port_scan
actions:
  - type: notify
`;

describe('parsePlaybook', () => {
  it('should parse valid YAML into a correct Playbook object', () => {
    const playbook = parsePlaybook(VALID_YAML);

    expect(playbook.name).toBe('test-playbook');
    expect(playbook.description).toBe('Test playbook');
    expect(playbook.descriptionZh).toBe('測試劇本');
    expect(playbook.priority).toBe(100);
    expect(playbook.trigger.pattern).toBe('brute_force');
    expect(playbook.trigger.minConfidence).toBe(75);
    expect(playbook.actions).toHaveLength(2);
    expect(playbook.actions[0].type).toBe('block_ip');
    expect(playbook.actions[0].params).toEqual({ duration: '1h' });
    expect(playbook.actions[1].type).toBe('notify');
    expect(playbook.escalation).toBeDefined();
    expect(playbook.escalation!.after).toBe(3);
    expect(playbook.escalation!.within).toBe('24h');
    expect(playbook.escalation!.actions).toHaveLength(2);
  });

  it('should parse minimal valid YAML', () => {
    const playbook = parsePlaybook(MINIMAL_YAML);

    expect(playbook.name).toBe('minimal');
    expect(playbook.trigger.pattern).toBe('port_scan');
    expect(playbook.actions).toHaveLength(1);
    expect(playbook.actions[0].type).toBe('notify');
  });

  it('should throw on invalid YAML syntax', () => {
    expect(() => parsePlaybook('{{invalid yaml')).toThrow();
  });

  it('should throw on empty YAML', () => {
    expect(() => parsePlaybook('')).toThrow('Invalid YAML');
  });

  it('should throw on null YAML content', () => {
    expect(() => parsePlaybook('null')).toThrow('Invalid YAML');
  });

  it('should throw on scalar YAML content', () => {
    expect(() => parsePlaybook('just a string')).toThrow('Invalid YAML');
  });
});

describe('validatePlaybook', () => {
  it('should validate a valid playbook as valid: true', () => {
    const playbook = parsePlaybook(VALID_YAML);
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should report error for missing name', () => {
    const playbook: Playbook = {
      name: '',
      trigger: { pattern: 'brute_force' },
      actions: [{ type: 'notify' }],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('name'))).toBe(true);
  });

  it('should report error for empty actions array', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { pattern: 'brute_force' },
      actions: [],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('actions'))).toBe(true);
  });

  it('should report error for invalid action type', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { pattern: 'brute_force' },
      actions: [{ type: 'invalid_action' as unknown as 'notify' }],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('invalid_action'))).toBe(true);
  });

  it('should report error for trigger with no conditions', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: {},
      actions: [{ type: 'notify' }],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('trigger must have at least one condition'))).toBe(true);
  });

  it('should report error for invalid pattern type', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { pattern: 'unknown_pattern' as unknown as 'brute_force' },
      actions: [{ type: 'notify' }],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('correlation pattern'))).toBe(true);
  });

  it('should report error for invalid minSeverity', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { minSeverity: 'extreme' as unknown as 'low' },
      actions: [{ type: 'notify' }],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('severity'))).toBe(true);
  });

  it('should report error for invalid minConfidence', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { pattern: 'brute_force', minConfidence: 150 },
      actions: [{ type: 'notify' }],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('minConfidence'))).toBe(true);
  });

  it('should validate escalation.after as positive integer', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { pattern: 'brute_force' },
      actions: [{ type: 'notify' }],
      escalation: { after: 0, actions: [{ type: 'block_ip' }] },
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('escalation.after'))).toBe(true);
  });

  it('should validate escalation.within as valid duration', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { pattern: 'brute_force' },
      actions: [{ type: 'notify' }],
      escalation: { after: 3, within: 'invalid', actions: [{ type: 'block_ip' }] },
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('escalation.within'))).toBe(true);
  });

  it('should accept valid escalation.within durations', () => {
    const durations = ['1h', '24h', '30m', '7d', '60s'];
    for (const within of durations) {
      const playbook: Playbook = {
        name: 'test',
        trigger: { pattern: 'brute_force' },
        actions: [{ type: 'notify' }],
        escalation: { after: 3, within, actions: [{ type: 'block_ip' }] },
      };
      const result = validatePlaybook(playbook);
      expect(result.errors.filter((e) => e.includes('within'))).toHaveLength(0);
    }
  });

  it('should validate with category trigger only', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { category: 'malware' },
      actions: [{ type: 'notify' }],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(true);
  });

  it('should validate with mitreTechnique trigger only', () => {
    const playbook: Playbook = {
      name: 'test',
      trigger: { mitreTechnique: 'T1110' },
      actions: [{ type: 'notify' }],
    };
    const result = validatePlaybook(playbook);

    expect(result.valid).toBe(true);
  });
});

describe('loadPlaybooksFromDir', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'playbook-test-'));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it('should load all valid .yaml files from directory', () => {
    writeFileSync(
      join(tempDir, 'brute-force.yaml'),
      VALID_YAML,
      'utf-8'
    );
    writeFileSync(
      join(tempDir, 'minimal.yaml'),
      MINIMAL_YAML,
      'utf-8'
    );

    const playbooks = loadPlaybooksFromDir(tempDir);

    expect(playbooks).toHaveLength(2);
    expect(playbooks.map((p) => p.name)).toContain('test-playbook');
    expect(playbooks.map((p) => p.name)).toContain('minimal');
  });

  it('should load .yml files as well', () => {
    writeFileSync(
      join(tempDir, 'test.yml'),
      MINIMAL_YAML,
      'utf-8'
    );

    const playbooks = loadPlaybooksFromDir(tempDir);
    expect(playbooks).toHaveLength(1);
  });

  it('should skip invalid files with warning (not throw)', () => {
    writeFileSync(
      join(tempDir, 'valid.yaml'),
      VALID_YAML,
      'utf-8'
    );
    writeFileSync(
      join(tempDir, 'invalid.yaml'),
      'name: ""\ntrigger: {}\nactions: []',
      'utf-8'
    );

    const playbooks = loadPlaybooksFromDir(tempDir);

    // Only the valid playbook should be loaded
    expect(playbooks).toHaveLength(1);
    expect(playbooks[0].name).toBe('test-playbook');
  });

  it('should skip files with YAML parse errors', () => {
    writeFileSync(
      join(tempDir, 'broken.yaml'),
      '{{{{invalid yaml',
      'utf-8'
    );

    const playbooks = loadPlaybooksFromDir(tempDir);
    expect(playbooks).toHaveLength(0);
  });

  it('should ignore non-yaml files', () => {
    writeFileSync(
      join(tempDir, 'readme.md'),
      '# Not a playbook',
      'utf-8'
    );
    writeFileSync(
      join(tempDir, 'config.json'),
      '{}',
      'utf-8'
    );
    writeFileSync(
      join(tempDir, 'valid.yaml'),
      VALID_YAML,
      'utf-8'
    );

    const playbooks = loadPlaybooksFromDir(tempDir);
    expect(playbooks).toHaveLength(1);
  });

  it('should return empty array for non-existent directory', () => {
    const playbooks = loadPlaybooksFromDir('/tmp/nonexistent-playbook-dir-12345');
    expect(playbooks).toEqual([]);
  });

  it('should return empty array for empty directory', () => {
    const playbooks = loadPlaybooksFromDir(tempDir);
    expect(playbooks).toEqual([]);
  });
});
