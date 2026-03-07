/**
 * Playbook Engine Tests
 * 劇本引擎測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PlaybookEngine, parseDuration } from '../src/playbook/engine.js';
import type { PlaybookCorrelationMatch } from '../src/playbook/engine.js';
import type { Playbook } from '../src/playbook/schema.js';
import type { ThreatVerdict } from '../src/types.js';

// ---------------------------------------------------------------------------
// Test fixtures / 測試資料
// ---------------------------------------------------------------------------

function makeBruteForcePlaybook(): Playbook {
  return {
    name: 'brute-force-response',
    priority: 100,
    trigger: {
      pattern: 'brute_force',
      minConfidence: 75,
    },
    actions: [
      { type: 'block_ip', params: { duration: '1h' } },
      { type: 'notify', params: { severity: 'high' } },
    ],
    escalation: {
      after: 3,
      within: '24h',
      actions: [
        { type: 'block_ip', params: { duration: '7d' } },
        { type: 'notify', params: { severity: 'critical' } },
      ],
    },
  };
}

function makePortScanPlaybook(): Playbook {
  return {
    name: 'port-scan-response',
    priority: 80,
    trigger: {
      pattern: 'port_scan',
      minConfidence: 70,
    },
    actions: [
      { type: 'block_ip', params: { duration: '30m' } },
      { type: 'notify', params: { severity: 'medium' } },
    ],
    escalation: {
      after: 5,
      within: '1h',
      actions: [
        { type: 'block_ip', params: { duration: '24h' } },
        { type: 'notify', params: { severity: 'high' } },
      ],
    },
  };
}

function makeDataExfilPlaybook(): Playbook {
  return {
    name: 'data-exfiltration-response',
    priority: 120,
    trigger: {
      pattern: 'data_exfiltration',
      minConfidence: 80,
      minSeverity: 'high',
    },
    actions: [
      { type: 'block_ip', params: { duration: '24h' } },
      { type: 'isolate_file' },
      { type: 'notify', params: { severity: 'critical' } },
    ],
  };
}

function makeVerdict(overrides: Partial<ThreatVerdict> = {}): ThreatVerdict {
  return {
    conclusion: 'malicious',
    confidence: 85,
    reasoning: 'Test verdict',
    evidence: [
      {
        source: 'rule_match',
        description: 'Test evidence',
        confidence: 85,
        data: { sourceIP: '10.0.0.1' },
      },
    ],
    recommendedAction: 'block_ip',
    ...overrides,
  };
}

function makeBruteForcePatterns(confidence = 80): PlaybookCorrelationMatch[] {
  return [
    {
      type: 'brute_force',
      confidence,
      sourceIP: '10.0.0.1',
      category: 'credential_access',
    },
  ];
}

function makePortScanPatterns(confidence = 75): PlaybookCorrelationMatch[] {
  return [
    {
      type: 'port_scan',
      confidence,
      sourceIP: '10.0.0.2',
      category: 'reconnaissance',
    },
  ];
}

function makeDataExfilPatterns(confidence = 90): PlaybookCorrelationMatch[] {
  return [
    {
      type: 'data_exfiltration',
      confidence,
      sourceIP: '10.0.0.3',
      category: 'data_exfiltration',
    },
  ];
}

// ---------------------------------------------------------------------------
// Tests / 測試
// ---------------------------------------------------------------------------

describe('parseDuration', () => {
  it('should parse seconds', () => {
    expect(parseDuration('60s')).toBe(60_000);
  });

  it('should parse minutes', () => {
    expect(parseDuration('30m')).toBe(30 * 60 * 1000);
  });

  it('should parse hours', () => {
    expect(parseDuration('24h')).toBe(24 * 60 * 60 * 1000);
  });

  it('should parse days', () => {
    expect(parseDuration('7d')).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it('should throw on invalid duration', () => {
    expect(() => parseDuration('invalid')).toThrow('Invalid duration');
    expect(() => parseDuration('10x')).toThrow('Invalid duration');
    expect(() => parseDuration('')).toThrow('Invalid duration');
  });
});

describe('PlaybookEngine', () => {
  let engine: PlaybookEngine;

  beforeEach(() => {
    engine = new PlaybookEngine([
      makeBruteForcePlaybook(),
      makePortScanPlaybook(),
      makeDataExfilPlaybook(),
    ]);
  });

  afterEach(() => {
    engine.destroy();
  });

  describe('constructor and count', () => {
    it('should initialize with provided playbooks', () => {
      expect(engine.count).toBe(3);
    });

    it('should initialize empty when no playbooks provided', () => {
      const empty = new PlaybookEngine();
      expect(empty.count).toBe(0);
      empty.destroy();
    });
  });

  describe('addPlaybook', () => {
    it('should add a valid playbook', () => {
      const newEngine = new PlaybookEngine();
      newEngine.addPlaybook(makeBruteForcePlaybook());
      expect(newEngine.count).toBe(1);
      newEngine.destroy();
    });

    it('should throw for invalid playbook', () => {
      const newEngine = new PlaybookEngine();
      expect(() => {
        newEngine.addPlaybook({
          name: '',
          trigger: {},
          actions: [],
        });
      }).toThrow('Invalid playbook');
      newEngine.destroy();
    });
  });

  describe('match', () => {
    it('should match brute_force pattern to brute-force playbook', () => {
      const verdict = makeVerdict();
      const patterns = makeBruteForcePatterns();

      const matched = engine.match(verdict, patterns);

      expect(matched).not.toBeNull();
      expect(matched!.name).toBe('brute-force-response');
    });

    it('should match port_scan pattern to port-scan playbook', () => {
      const verdict = makeVerdict({ confidence: 75 });
      const patterns = makePortScanPatterns();

      const matched = engine.match(verdict, patterns);

      expect(matched).not.toBeNull();
      expect(matched!.name).toBe('port-scan-response');
    });

    it('should return null when no matching pattern', () => {
      const verdict = makeVerdict();
      const patterns: PlaybookCorrelationMatch[] = [
        { type: 'lateral_movement', confidence: 90 },
      ];

      const matched = engine.match(verdict, patterns);

      expect(matched).toBeNull();
    });

    it('should return null when no patterns provided and all playbooks require pattern', () => {
      const verdict = makeVerdict();
      const matched = engine.match(verdict);

      expect(matched).toBeNull();
    });

    it('should not match when confidence is below threshold', () => {
      const verdict = makeVerdict({ confidence: 50 });
      const patterns = makeBruteForcePatterns(50);

      const matched = engine.match(verdict, patterns);

      // minConfidence is 75, pattern confidence is 50, verdict confidence is 50
      expect(matched).toBeNull();
    });

    it('should match when pattern confidence meets threshold even if verdict confidence is low', () => {
      const verdict = makeVerdict({ confidence: 50 });
      const patterns = makeBruteForcePatterns(80); // Pattern confidence >= 75

      const matched = engine.match(verdict, patterns);

      expect(matched).not.toBeNull();
      expect(matched!.name).toBe('brute-force-response');
    });

    it('should respect priority ordering (higher priority first)', () => {
      // data-exfiltration has highest priority (120)
      // Create patterns that match both brute_force and data_exfiltration
      const verdict = makeVerdict({ confidence: 90 });
      const patterns: PlaybookCorrelationMatch[] = [
        { type: 'brute_force', confidence: 90 },
        { type: 'data_exfiltration', confidence: 90 },
      ];

      const matched = engine.match(verdict, patterns);

      // data-exfiltration has priority 120 > brute_force priority 100
      expect(matched).not.toBeNull();
      expect(matched!.name).toBe('data-exfiltration-response');
    });

    it('should skip disabled playbooks', () => {
      const disabledPlaybook: Playbook = {
        ...makeBruteForcePlaybook(),
        name: 'disabled-playbook',
        enabled: false,
        priority: 200, // Higher priority but disabled
      };

      const engineWithDisabled = new PlaybookEngine([
        disabledPlaybook,
        makeBruteForcePlaybook(),
      ]);

      const verdict = makeVerdict();
      const patterns = makeBruteForcePatterns();
      const matched = engineWithDisabled.match(verdict, patterns);

      expect(matched).not.toBeNull();
      expect(matched!.name).toBe('brute-force-response'); // Not the disabled one
      engineWithDisabled.destroy();
    });

    it('should check minSeverity condition', () => {
      // data-exfiltration requires minSeverity: high (confidence >= 70)
      const lowConfidenceVerdict = makeVerdict({ confidence: 30 }); // low severity
      const patterns = makeDataExfilPatterns(90);

      const matched = engine.match(lowConfidenceVerdict, patterns);

      // Severity is inferred from confidence: 30 -> 'low', but minSeverity requires 'high'
      expect(matched).toBeNull();
    });

    it('should match when severity meets requirement', () => {
      const highConfidenceVerdict = makeVerdict({ confidence: 85 }); // high severity
      const patterns = makeDataExfilPatterns(90);

      const matched = engine.match(highConfidenceVerdict, patterns);

      expect(matched).not.toBeNull();
      expect(matched!.name).toBe('data-exfiltration-response');
    });

    it('should match MITRE ATT&CK technique', () => {
      const mitrePlaybook: Playbook = {
        name: 'mitre-t1110',
        priority: 150,
        trigger: { mitreTechnique: 'T1110' },
        actions: [{ type: 'block_ip' }],
      };
      const mitreEngine = new PlaybookEngine([mitrePlaybook]);
      const verdict = makeVerdict({ mitreTechnique: 'T1110' });

      const matched = mitreEngine.match(verdict);
      expect(matched).not.toBeNull();
      expect(matched!.name).toBe('mitre-t1110');
      mitreEngine.destroy();
    });

    it('should not match wrong MITRE ATT&CK technique', () => {
      const mitrePlaybook: Playbook = {
        name: 'mitre-t1110',
        priority: 150,
        trigger: { mitreTechnique: 'T1110' },
        actions: [{ type: 'block_ip' }],
      };
      const mitreEngine = new PlaybookEngine([mitrePlaybook]);
      const verdict = makeVerdict({ mitreTechnique: 'T1059' });

      const matched = mitreEngine.match(verdict);
      expect(matched).toBeNull();
      mitreEngine.destroy();
    });
  });

  describe('getActions', () => {
    it('should return normal actions when no escalation occurred', () => {
      const playbook = makeBruteForcePlaybook();
      const actions = engine.getActions(playbook, '10.0.0.1');

      expect(actions).toHaveLength(2);
      expect(actions[0].type).toBe('block_ip');
      expect(actions[0].params).toEqual({ duration: '1h' });
    });

    it('should return escalated actions after threshold is met', () => {
      const playbook = makeBruteForcePlaybook();
      const sourceKey = '10.0.0.1';
      const compositeKey = `${playbook.name}:${sourceKey}`;

      // Record 3 occurrences (threshold = 3)
      engine.recordOccurrence(compositeKey);
      engine.recordOccurrence(compositeKey);
      engine.recordOccurrence(compositeKey);

      const actions = engine.getActions(playbook, sourceKey);

      expect(actions).toHaveLength(2);
      expect(actions[0].type).toBe('block_ip');
      expect(actions[0].params).toEqual({ duration: '7d' }); // Escalated duration
      expect(actions[1].params).toEqual({ severity: 'critical' }); // Escalated severity
    });

    it('should return normal actions when below escalation threshold', () => {
      const playbook = makeBruteForcePlaybook();
      const sourceKey = '10.0.0.1';
      const compositeKey = `${playbook.name}:${sourceKey}`;

      // Record only 2 occurrences (threshold = 3)
      engine.recordOccurrence(compositeKey);
      engine.recordOccurrence(compositeKey);

      const actions = engine.getActions(playbook, sourceKey);

      expect(actions).toHaveLength(2);
      expect(actions[0].params).toEqual({ duration: '1h' }); // Normal duration
    });

    it('should return normal actions when escalation time window expired', () => {
      const playbook: Playbook = {
        name: 'short-window',
        priority: 50,
        trigger: { pattern: 'brute_force' },
        actions: [{ type: 'notify' }],
        escalation: {
          after: 2,
          within: '1s', // 1 second window
          actions: [{ type: 'block_ip' }],
        },
      };

      const sourceKey = '10.0.0.1';
      const compositeKey = `${playbook.name}:${sourceKey}`;

      // Manually set an expired entry by manipulating the Map
      // We need access to the internal map, so we use recordOccurrence + time manipulation
      const testEngine = new PlaybookEngine([playbook]);

      // Record occurrences that will expire
      testEngine.recordOccurrence(compositeKey);
      testEngine.recordOccurrence(compositeKey);
      testEngine.recordOccurrence(compositeKey);

      // Hack: override the firstSeen to be in the past
      const internalMap = (testEngine as Record<string, unknown>).occurrenceCounts as Map<
        string,
        { count: number; firstSeen: number }
      >;
      const entry = internalMap.get(compositeKey)!;
      internalMap.set(compositeKey, { ...entry, firstSeen: Date.now() - 5000 }); // 5 seconds ago

      const actions = testEngine.getActions(playbook, sourceKey);

      // Window expired (1s), so should return normal actions
      expect(actions).toHaveLength(1);
      expect(actions[0].type).toBe('notify'); // Normal action, not escalated
      testEngine.destroy();
    });

    it('should return normal actions when no escalation config exists', () => {
      const playbook: Playbook = {
        name: 'no-escalation',
        priority: 50,
        trigger: { pattern: 'brute_force' },
        actions: [{ type: 'notify' }],
      };

      const actions = engine.getActions(playbook, '10.0.0.1');
      expect(actions).toEqual([{ type: 'notify' }]);
    });
  });

  describe('recordOccurrence', () => {
    it('should increment count for repeated keys', () => {
      const key = 'test-key';

      engine.recordOccurrence(key);
      engine.recordOccurrence(key);
      engine.recordOccurrence(key);

      const internalMap = (engine as Record<string, unknown>).occurrenceCounts as Map<
        string,
        { count: number; firstSeen: number }
      >;
      const entry = internalMap.get(key);

      expect(entry).toBeDefined();
      expect(entry!.count).toBe(3);
    });

    it('should create new entry for new key', () => {
      const key = 'new-key';

      engine.recordOccurrence(key);

      const internalMap = (engine as Record<string, unknown>).occurrenceCounts as Map<
        string,
        { count: number; firstSeen: number }
      >;
      const entry = internalMap.get(key);

      expect(entry).toBeDefined();
      expect(entry!.count).toBe(1);
      expect(entry!.firstSeen).toBeGreaterThan(0);
    });

    it('should preserve firstSeen on subsequent occurrences', () => {
      const key = 'preserve-key';

      engine.recordOccurrence(key);

      const internalMap = (engine as Record<string, unknown>).occurrenceCounts as Map<
        string,
        { count: number; firstSeen: number }
      >;
      const firstEntry = internalMap.get(key)!;
      const originalFirstSeen = firstEntry.firstSeen;

      engine.recordOccurrence(key);

      const updatedEntry = internalMap.get(key)!;
      expect(updatedEntry.firstSeen).toBe(originalFirstSeen);
      expect(updatedEntry.count).toBe(2);
    });
  });

  describe('loadFromDir', () => {
    let tempDir: string;

    beforeEach(() => {
      tempDir = mkdtempSync(join(tmpdir(), 'engine-test-'));
    });

    afterEach(() => {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    });

    it('should load playbooks from directory and add to existing', () => {
      writeFileSync(
        join(tempDir, 'test.yaml'),
        `
name: loaded-from-dir
priority: 50
trigger:
  pattern: malware
actions:
  - type: notify
`,
        'utf-8'
      );

      const loadEngine = new PlaybookEngine([makeBruteForcePlaybook()]);
      expect(loadEngine.count).toBe(1);

      loadEngine.loadFromDir(tempDir);
      expect(loadEngine.count).toBe(2);

      const playbooks = loadEngine.getPlaybooks();
      expect(playbooks.map((p) => p.name)).toContain('loaded-from-dir');
      loadEngine.destroy();
    });
  });

  describe('Full integration: load from dir + match + getActions', () => {
    let tempDir: string;

    beforeEach(() => {
      tempDir = mkdtempSync(join(tmpdir(), 'integration-test-'));
    });

    afterEach(() => {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    });

    it('should load playbooks from directory, match verdict, and return actions', () => {
      // Write a playbook YAML to temp dir
      writeFileSync(
        join(tempDir, 'recon.yaml'),
        `
name: reconnaissance-response
priority: 90
trigger:
  pattern: reconnaissance
  minConfidence: 60
actions:
  - type: block_ip
    params:
      duration: "2h"
  - type: notify
    params:
      severity: medium
escalation:
  after: 2
  within: "1h"
  actions:
    - type: block_ip
      params:
        duration: "48h"
    - type: disable_account
`,
        'utf-8'
      );

      // Create engine and load from dir
      const intEngine = new PlaybookEngine();
      intEngine.loadFromDir(tempDir);
      expect(intEngine.count).toBe(1);

      // Create verdict and patterns
      const verdict = makeVerdict({ confidence: 70 });
      const patterns: PlaybookCorrelationMatch[] = [
        { type: 'reconnaissance', confidence: 70 },
      ];

      // Match
      const matched = intEngine.match(verdict, patterns);
      expect(matched).not.toBeNull();
      expect(matched!.name).toBe('reconnaissance-response');

      // Get normal actions
      const normalActions = intEngine.getActions(matched!, '10.0.0.5');
      expect(normalActions).toHaveLength(2);
      expect(normalActions[0].type).toBe('block_ip');
      expect(normalActions[0].params).toEqual({ duration: '2h' });

      // Record occurrences to trigger escalation
      const compositeKey = `${matched!.name}:10.0.0.5`;
      intEngine.recordOccurrence(compositeKey);
      intEngine.recordOccurrence(compositeKey);

      // Get escalated actions
      const escalatedActions = intEngine.getActions(matched!, '10.0.0.5');
      expect(escalatedActions).toHaveLength(2);
      expect(escalatedActions[0].type).toBe('block_ip');
      expect(escalatedActions[0].params).toEqual({ duration: '48h' });
      expect(escalatedActions[1].type).toBe('disable_account');

      intEngine.destroy();
    });
  });

  describe('getPlaybooks', () => {
    it('should return a read-only copy of playbooks', () => {
      const playbooks = engine.getPlaybooks();
      expect(playbooks).toHaveLength(3);

      // Verify it is a copy (modifying returned array does not affect engine)
      const mutable = playbooks as Playbook[];
      mutable.length = 0;
      expect(engine.count).toBe(3); // Still 3
    });
  });
});
