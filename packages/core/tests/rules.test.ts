import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdirSync, writeFileSync, rmSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

// Test sigma parser
import { parseSigmaYaml } from '../src/rules/sigma-parser.js';
// Test sigma matcher
import { matchEvent } from '../src/rules/sigma-matcher.js';
// Test rule loader
import { loadRulesFromDirectory, loadRulesRecursive } from '../src/rules/rule-loader.js';
// Test RuleEngine
import { RuleEngine } from '../src/rules/index.js';

// Import types for test data
import type { SecurityEvent } from '../src/types.js';

// Suppress log output during tests
beforeEach(() => {
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

// Helper: create a SecurityEvent for testing
function createTestEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: 'test-001',
    timestamp: new Date(),
    source: 'syslog',
    severity: 'medium',
    category: 'authentication',
    description: 'Failed login attempt for user admin',
    raw: {},
    host: 'test-host',
    metadata: { user: 'admin', action: 'login' },
    ...overrides,
  };
}

// Helper: create a minimal valid Sigma YAML string
function createBruteForceYaml(): string {
  return `
title: Brute Force Login Attempt
id: test-brute-force-001
status: stable
description: Detects failed login attempts
author: Test Author
date: 2026/02/25
logsource:
  category: authentication
  product: any
detection:
  selection:
    category: 'authentication'
    description|contains:
      - 'failed login'
      - 'authentication failure'
  condition: selection
level: high
tags:
  - attack.credential_access
falsepositives:
  - Legitimate user forgot password
`.trim();
}

// Helper: create a suspicious process Sigma YAML string
function createSuspiciousProcessYaml(): string {
  return `
title: Suspicious Process Execution
id: test-suspicious-proc-001
status: stable
description: Detects suspicious process execution
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    category: 'process_creation'
    description|contains:
      - 'powershell'
      - 'EncodedCommand'
  selection_certutil:
    category: 'process_creation'
    description|contains:
      - 'certutil'
      - 'urlcache'
  condition: selection_powershell OR selection_certutil
level: high
`.trim();
}

describe('Sigma Parser', () => {
  it('should parse valid Sigma YAML', () => {
    const rule = parseSigmaYaml(createBruteForceYaml());
    expect(rule).not.toBeNull();
    expect(rule!.title).toBe('Brute Force Login Attempt');
    expect(rule!.id).toBe('test-brute-force-001');
    expect(rule!.status).toBe('stable');
    expect(rule!.level).toBe('high');
    expect(rule!.detection).toBeDefined();
    expect(rule!.detection.condition).toBe('selection');
    expect(rule!.logsource.category).toBe('authentication');
    expect(rule!.tags).toContain('attack.credential_access');
  });

  it('should return null for invalid YAML', () => {
    // Missing required field: title
    const noTitle = `
detection:
  selection:
    category: 'test'
  condition: selection
level: high
`.trim();
    expect(parseSigmaYaml(noTitle)).toBeNull();

    // Missing required field: detection
    const noDetection = `
title: Test Rule
level: high
`.trim();
    expect(parseSigmaYaml(noDetection)).toBeNull();

    // Missing required field: level
    const noLevel = `
title: Test Rule
detection:
  selection:
    category: 'test'
  condition: selection
`.trim();
    expect(parseSigmaYaml(noLevel)).toBeNull();

    // Completely invalid YAML
    expect(parseSigmaYaml('{{{{not yaml at all')).toBeNull();
  });
});

describe('Sigma Matcher', () => {
  it('should match brute force events', () => {
    const rule = parseSigmaYaml(createBruteForceYaml())!;
    expect(rule).not.toBeNull();

    const event = createTestEvent({
      category: 'authentication',
      description: 'Failed login attempt for user admin',
    });

    const result = matchEvent(event, rule);
    expect(result).not.toBeNull();
    expect(result!.rule.id).toBe('test-brute-force-001');
    expect(result!.matchedFields).toContain('category');
    expect(result!.matchedFields).toContain('description');
  });

  it('should match suspicious process events', () => {
    const rule = parseSigmaYaml(createSuspiciousProcessYaml())!;
    expect(rule).not.toBeNull();

    const event = createTestEvent({
      category: 'process_creation',
      description: 'powershell.exe executed with EncodedCommand parameter',
    });

    const result = matchEvent(event, rule);
    expect(result).not.toBeNull();
    expect(result!.rule.id).toBe('test-suspicious-proc-001');
  });

  it('should not match unrelated events', () => {
    const rule = parseSigmaYaml(createBruteForceYaml())!;
    expect(rule).not.toBeNull();

    const event = createTestEvent({
      category: 'network',
      description: 'Normal HTTP GET request to example.com',
    });

    const result = matchEvent(event, rule);
    expect(result).toBeNull();
  });

  it('should support wildcard matching', () => {
    const wildcardYaml = `
title: Wildcard Test
id: test-wildcard-001
status: experimental
description: Tests wildcard matching
detection:
  selection:
    description: '*failed*login*'
  condition: selection
level: medium
`.trim();

    const rule = parseSigmaYaml(wildcardYaml)!;
    expect(rule).not.toBeNull();

    const matchingEvent = createTestEvent({
      description: 'User failed to login with valid credentials',
    });

    const result = matchEvent(matchingEvent, rule);
    expect(result).not.toBeNull();

    const nonMatchingEvent = createTestEvent({
      description: 'Successful authentication completed',
    });

    const noResult = matchEvent(nonMatchingEvent, rule);
    expect(noResult).toBeNull();
  });

  it('should support AND/OR conditions', () => {
    const andOrYaml = `
title: AND OR Test
id: test-andor-001
status: experimental
description: Tests AND/OR condition logic
detection:
  sel_category:
    category: 'authentication'
  sel_failed:
    description|contains: 'failed'
  sel_network:
    category: 'network'
  condition: (sel_category AND sel_failed) OR sel_network
level: medium
`.trim();

    const rule = parseSigmaYaml(andOrYaml)!;
    expect(rule).not.toBeNull();

    // Should match via the AND branch (category=authentication AND description contains 'failed')
    const authEvent = createTestEvent({
      category: 'authentication',
      description: 'User failed login',
    });
    expect(matchEvent(authEvent, rule)).not.toBeNull();

    // Should match via the OR branch (category=network)
    const networkEvent = createTestEvent({
      category: 'network',
      description: 'Normal traffic',
    });
    expect(matchEvent(networkEvent, rule)).not.toBeNull();

    // Should NOT match (category=process and no 'failed')
    const processEvent = createTestEvent({
      category: 'process',
      description: 'Normal process started',
    });
    expect(matchEvent(processEvent, rule)).toBeNull();
  });
});

describe('Rule Loader', () => {
  it('should load rules from directory', () => {
    const rulesDir = join(process.cwd(), 'config', 'sigma-rules', 'custom');

    // The config/sigma-rules/custom directory should exist in the project
    if (existsSync(rulesDir)) {
      const rules = loadRulesFromDirectory(rulesDir);
      expect(Array.isArray(rules)).toBe(true);
      expect(rules.length).toBeGreaterThan(0);

      // Each loaded rule should have required fields
      for (const rule of rules) {
        expect(rule.id).toBeTruthy();
        expect(rule.title).toBeTruthy();
        expect(rule.detection).toBeDefined();
        expect(rule.level).toBeTruthy();
      }
    }
  });

  it('should handle non-existent directory', () => {
    const rules = loadRulesFromDirectory('/tmp/panguard-nonexistent-rules-dir-12345');
    expect(Array.isArray(rules)).toBe(true);
    expect(rules.length).toBe(0);
  });
});

describe('Recursive Rule Loader', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'sigma-recursive-'));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  function writeRuleFile(dir: string, filename: string, id: string, title: string): void {
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, filename),
      `
title: ${title}
id: ${id}
status: stable
description: Test rule
logsource:
  category: authentication
  product: any
detection:
  selection:
    category: 'authentication'
  condition: selection
level: medium
`.trim()
    );
  }

  it('should load rules recursively from nested directories', () => {
    writeRuleFile(join(tempDir, 'linux', 'auth'), 'brute.yml', 'rec-001', 'Linux Brute Force');
    writeRuleFile(join(tempDir, 'windows', 'process'), 'proc.yml', 'rec-002', 'Windows Process');
    writeRuleFile(tempDir, 'root.yml', 'rec-003', 'Root Level Rule');

    const rules = loadRulesRecursive(tempDir);
    expect(rules.length).toBe(3);
  });

  it('should tag rules with custom source', () => {
    writeRuleFile(tempDir, 'rule.yml', 'src-001', 'Custom Rule');

    const rules = loadRulesRecursive(tempDir, 'custom');
    expect(rules.length).toBe(1);
    expect(rules[0]!.source).toBe('custom');
  });

  it('should tag rules with community source', () => {
    writeRuleFile(tempDir, 'rule.yml', 'comm-001', 'Community Rule');

    const rules = loadRulesRecursive(tempDir, 'community');
    expect(rules.length).toBe(1);
    expect(rules[0]!.source).toBe('community');
  });

  it('should return empty array for non-existent directory', () => {
    const rules = loadRulesRecursive(join(tempDir, 'nonexistent'));
    expect(Array.isArray(rules)).toBe(true);
    expect(rules.length).toBe(0);
  });

  it('should skip non-yaml files', () => {
    writeRuleFile(tempDir, 'rule.yml', 'skip-001', 'Valid Rule');
    writeFileSync(join(tempDir, 'readme.md'), '# Not a rule');
    writeFileSync(join(tempDir, 'data.json'), '{}');

    const rules = loadRulesRecursive(tempDir);
    expect(rules.length).toBe(1);
  });
});

describe('Rule Engine', () => {
  it('should add and match custom rules', () => {
    const rule = parseSigmaYaml(createBruteForceYaml())!;
    expect(rule).not.toBeNull();

    const engine = new RuleEngine();
    engine.addRule(rule);

    const rules = engine.getRules();
    expect(rules.length).toBe(1);
    expect(rules[0]!.id).toBe('test-brute-force-001');

    // Match a relevant event
    const matchingEvent = createTestEvent({
      category: 'authentication',
      description: 'Failed login from 192.168.1.1',
    });
    const matches = engine.match(matchingEvent);
    expect(matches.length).toBe(1);
    expect(matches[0]!.rule.title).toBe('Brute Force Login Attempt');

    // Non-matching event
    const normalEvent = createTestEvent({
      category: 'network',
      description: 'DNS query for example.com',
    });
    const noMatches = engine.match(normalEvent);
    expect(noMatches.length).toBe(0);

    // Cleanup
    engine.destroy();
    expect(engine.getRules().length).toBe(0);
  });

  it('should load from both rulesDir and communityRulesDir', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'engine-dual-'));
    const customDir = join(tempDir, 'custom');
    const communityDir = join(tempDir, 'community');

    mkdirSync(customDir, { recursive: true });
    mkdirSync(communityDir, { recursive: true });

    writeFileSync(
      join(customDir, 'custom-rule.yml'),
      `
title: Custom Rule
id: engine-custom-001
status: stable
description: A custom detection rule
logsource:
  category: authentication
  product: any
detection:
  selection:
    category: 'authentication'
  condition: selection
level: high
`.trim()
    );

    writeFileSync(
      join(communityDir, 'community-rule.yml'),
      `
title: Community Rule
id: engine-community-001
status: stable
description: A community detection rule
logsource:
  category: process_creation
  product: any
detection:
  selection:
    category: 'process_creation'
  condition: selection
level: medium
`.trim()
    );

    const engine = new RuleEngine({
      rulesDir: customDir,
      communityRulesDir: communityDir,
    });
    await engine.loadRules();

    const rules = engine.getRules();
    expect(rules.length).toBe(2);
    expect(rules.find((r) => r.id === 'engine-custom-001')?.source).toBe('custom');
    expect(rules.find((r) => r.id === 'engine-community-001')?.source).toBe('community');

    engine.destroy();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it('should gracefully handle missing communityRulesDir', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'engine-nocomm-'));
    const customDir = join(tempDir, 'custom');
    mkdirSync(customDir, { recursive: true });

    writeFileSync(
      join(customDir, 'rule.yml'),
      `
title: Solo Custom Rule
id: solo-001
status: stable
description: Only custom
logsource:
  category: authentication
  product: any
detection:
  selection:
    category: 'authentication'
  condition: selection
level: low
`.trim()
    );

    const engine = new RuleEngine({
      rulesDir: customDir,
      communityRulesDir: join(tempDir, 'nonexistent-community'),
    });

    // Should not throw
    await engine.loadRules();
    expect(engine.getRules().length).toBe(1);

    engine.destroy();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });
});
