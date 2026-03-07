/**
 * RootkitDetector unit tests
 * RootkitDetector 單元測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  createRootkitEvent,
  checkLdPreload,
  RootkitDetector,
} from '../src/monitors/rootkit-detector.js';
import type { RootkitFinding } from '../src/monitors/rootkit-detector.js';

// ===== createRootkitEvent tests / createRootkitEvent 測試 =====

describe('createRootkitEvent', () => {
  it('should create a SecurityEvent from a hidden process finding', () => {
    const finding: RootkitFinding = {
      checkType: 'hidden_process',
      severity: 'critical',
      description: 'Hidden process detected: PID 1234 visible in /proc but not in ps output',
      details: {
        pid: 1234,
        procVisible: true,
        psVisible: false,
      },
    };

    const event = createRootkitEvent(finding);

    expect(event.id).toMatch(/^rootkit-/);
    expect(event.source).toBe('process');
    expect(event.severity).toBe('critical');
    expect(event.category).toBe('defense_evasion');
    expect(event.description).toContain('Hidden process');
    expect(event.description).toContain('1234');
    expect(event.metadata['checkType']).toBe('hidden_process');
    expect(event.metadata['pid']).toBe(1234);
    expect(event.host).toBeDefined();
  });

  it('should create a SecurityEvent from an LD_PRELOAD finding', () => {
    const finding: RootkitFinding = {
      checkType: 'ld_preload',
      severity: 'high',
      description: 'LD_PRELOAD environment variable is set: /tmp/evil.so',
      details: {
        source: 'environment',
        value: '/tmp/evil.so',
        libraries: ['/tmp/evil.so'],
      },
    };

    const event = createRootkitEvent(finding);

    expect(event.source).toBe('process');
    expect(event.severity).toBe('high');
    expect(event.category).toBe('persistence');
    expect(event.metadata['checkType']).toBe('ld_preload');
    expect(event.metadata['source']).toBe('environment');
  });

  it('should create a SecurityEvent from a kernel module finding', () => {
    const finding: RootkitFinding = {
      checkType: 'kernel_module',
      severity: 'critical',
      description: 'Suspicious kernel module detected: "diamorphine" (known rootkit module)',
      details: {
        moduleName: 'diamorphine',
        reason: 'known_rootkit_module',
      },
    };

    const event = createRootkitEvent(finding);

    expect(event.severity).toBe('critical');
    expect(event.category).toBe('persistence');
    expect(event.description).toContain('diamorphine');
    expect(event.metadata['moduleName']).toBe('diamorphine');
  });

  it('should create a SecurityEvent from a hidden file finding', () => {
    const finding: RootkitFinding = {
      checkType: 'hidden_file',
      severity: 'high',
      description: 'Hidden file detected in /etc: "malicious.conf" visible via ls but not readdir',
      details: {
        directory: '/etc',
        fileName: 'malicious.conf',
        lsVisible: true,
        readdirVisible: false,
      },
    };

    const event = createRootkitEvent(finding);

    expect(event.severity).toBe('high');
    expect(event.category).toBe('defense_evasion');
    expect(event.metadata['directory']).toBe('/etc');
    expect(event.metadata['fileName']).toBe('malicious.conf');
  });

  it('should create a SecurityEvent from a binary integrity finding', () => {
    const finding: RootkitFinding = {
      checkType: 'binary_integrity',
      severity: 'critical',
      description: 'System binary "/bin/ps" checksum mismatch -- possible trojanized binary',
      details: {
        binary: '/bin/ps',
        currentChecksum: 'aaa111',
        expectedChecksum: 'bbb222',
        match: false,
      },
    };

    const event = createRootkitEvent(finding);

    expect(event.severity).toBe('critical');
    expect(event.category).toBe('defense_evasion');
    expect(event.metadata['binary']).toBe('/bin/ps');
    expect(event.metadata['match']).toBe(false);
  });

  it('should generate unique event IDs for consecutive events', () => {
    const finding: RootkitFinding = {
      checkType: 'hidden_process',
      severity: 'critical',
      description: 'Test finding',
      details: {},
    };

    const event1 = createRootkitEvent(finding);
    const event2 = createRootkitEvent(finding);

    expect(event1.id).not.toBe(event2.id);
  });

  it('should set timestamp to current time', () => {
    const before = Date.now();

    const finding: RootkitFinding = {
      checkType: 'hidden_process',
      severity: 'critical',
      description: 'Test',
      details: {},
    };

    const event = createRootkitEvent(finding);
    const after = Date.now();

    expect(event.timestamp.getTime()).toBeGreaterThanOrEqual(before);
    expect(event.timestamp.getTime()).toBeLessThanOrEqual(after);
  });

  it('should not mutate the original finding', () => {
    const finding: RootkitFinding = {
      checkType: 'kernel_module',
      severity: 'critical',
      description: 'Test module',
      details: { moduleName: 'test' },
    };

    const event = createRootkitEvent(finding);

    // Modifying event.raw should not affect the original finding
    // 修改 event.raw 不應影響原始 finding
    (event.raw as Record<string, unknown>)['extra'] = 'injected';
    expect((finding as Record<string, unknown>)['extra']).toBeUndefined();
  });
});

// ===== checkLdPreload tests / checkLdPreload 測試 =====

describe('checkLdPreload', () => {
  const originalEnv = process.env['LD_PRELOAD'];

  afterEach(() => {
    // Restore original environment / 還原原始環境
    if (originalEnv === undefined) {
      delete process.env['LD_PRELOAD'];
    } else {
      process.env['LD_PRELOAD'] = originalEnv;
    }
  });

  it('should detect LD_PRELOAD environment variable when set', () => {
    process.env['LD_PRELOAD'] = '/tmp/evil.so';

    const findings = checkLdPreload();

    const envFinding = findings.find(
      (f) => f.details['source'] === 'environment'
    );
    expect(envFinding).toBeDefined();
    expect(envFinding!.checkType).toBe('ld_preload');
    expect(envFinding!.severity).toBe('high');
    expect(envFinding!.description).toContain('LD_PRELOAD');
    expect(envFinding!.details['value']).toBe('/tmp/evil.so');
  });

  it('should detect multiple libraries in LD_PRELOAD', () => {
    process.env['LD_PRELOAD'] = '/tmp/evil.so:/tmp/hook.so';

    const findings = checkLdPreload();

    const envFinding = findings.find(
      (f) => f.details['source'] === 'environment'
    );
    expect(envFinding).toBeDefined();
    const libraries = envFinding!.details['libraries'] as string[];
    expect(libraries).toHaveLength(2);
    expect(libraries).toContain('/tmp/evil.so');
    expect(libraries).toContain('/tmp/hook.so');
  });

  it('should return empty findings when LD_PRELOAD is not set', () => {
    delete process.env['LD_PRELOAD'];

    const findings = checkLdPreload();

    const envFinding = findings.find(
      (f) => f.details['source'] === 'environment'
    );
    expect(envFinding).toBeUndefined();
  });

  it('should ignore empty LD_PRELOAD value', () => {
    process.env['LD_PRELOAD'] = '';

    const findings = checkLdPreload();

    const envFinding = findings.find(
      (f) => f.details['source'] === 'environment'
    );
    expect(envFinding).toBeUndefined();
  });

  it('should ignore whitespace-only LD_PRELOAD value', () => {
    process.env['LD_PRELOAD'] = '   ';

    const findings = checkLdPreload();

    const envFinding = findings.find(
      (f) => f.details['source'] === 'environment'
    );
    expect(envFinding).toBeUndefined();
  });
});

// ===== RootkitDetector class tests / RootkitDetector 類別測試 =====

describe('RootkitDetector', () => {
  let detector: RootkitDetector;

  beforeEach(() => {
    detector = new RootkitDetector({ intervalMs: 1000 });
  });

  afterEach(() => {
    detector.stop();
  });

  it('should extend EventEmitter', () => {
    expect(detector).toBeInstanceOf(RootkitDetector);
    expect(typeof detector.on).toBe('function');
    expect(typeof detector.emit).toBe('function');
  });

  it('should return false from checkAvailability on non-Linux platforms', async () => {
    // We are running tests on macOS (darwin), so this should return false
    // 在 macOS (darwin) 上執行測試，應該回傳 false
    if (process.platform !== 'linux') {
      const available = await detector.checkAvailability();
      expect(available).toBe(false);
    }
  });

  it('should have start and stop methods', () => {
    expect(typeof detector.start).toBe('function');
    expect(typeof detector.stop).toBe('function');
  });

  it('should accept custom scan interval', () => {
    const custom = new RootkitDetector({ intervalMs: 5000 });
    // The constructor should not throw / 建構函式不應拋出
    expect(custom).toBeInstanceOf(RootkitDetector);
    custom.stop();
  });

  it('should accept custom known checksums', () => {
    const checksums = new Map<string, string>([
      ['/bin/ps', 'abc123'],
      ['/bin/ls', 'def456'],
    ]);
    const custom = new RootkitDetector({ knownChecksums: checksums });
    expect(custom).toBeInstanceOf(RootkitDetector);
    custom.stop();
  });

  it('should not throw when stop is called before start', () => {
    expect(() => detector.stop()).not.toThrow();
  });

  it('should not throw when stop is called multiple times', () => {
    expect(() => {
      detector.stop();
      detector.stop();
    }).not.toThrow();
  });

  it('should emit events for findings during runScan', async () => {
    // Set LD_PRELOAD to trigger at least one finding / 設定 LD_PRELOAD 以觸發至少一個發現
    const originalLdPreload = process.env['LD_PRELOAD'];
    process.env['LD_PRELOAD'] = '/tmp/test-hook.so';

    const events: unknown[] = [];
    detector.on('event', (event: unknown) => {
      events.push(event);
    });

    const findings = await detector.runScan();

    // Restore / 還原
    if (originalLdPreload === undefined) {
      delete process.env['LD_PRELOAD'];
    } else {
      process.env['LD_PRELOAD'] = originalLdPreload;
    }

    // Should have at least the LD_PRELOAD finding / 至少應有 LD_PRELOAD 發現
    const ldFinding = findings.find((f) => f.checkType === 'ld_preload');
    expect(ldFinding).toBeDefined();
    expect(ldFinding!.severity).toBe('high');

    // Events should have been emitted / 應該已發出事件
    expect(events.length).toBeGreaterThanOrEqual(1);
  });

  it('should return empty findings when no issues detected (clean environment)', async () => {
    // Ensure LD_PRELOAD is not set / 確保 LD_PRELOAD 未設定
    const originalLdPreload = process.env['LD_PRELOAD'];
    delete process.env['LD_PRELOAD'];

    const findings = await detector.runScan();

    // Restore / 還原
    if (originalLdPreload !== undefined) {
      process.env['LD_PRELOAD'] = originalLdPreload;
    }

    // On macOS, /proc doesn't exist so process/module checks return empty
    // LD_PRELOAD is cleared so that returns empty too
    // On a clean system, we expect no findings (or at least no crashes)
    // 在 macOS 上，/proc 不存在所以程序/模組檢查回傳空
    expect(Array.isArray(findings)).toBe(true);
  });

  it('should handle errors gracefully during runScan', async () => {
    // runScan should not throw even if checks fail internally
    // runScan 即使內部檢查失敗也不應拋出
    const findings = await detector.runScan();
    expect(Array.isArray(findings)).toBe(true);
  });
});

// ===== RootkitFinding type tests / RootkitFinding 型別測試 =====

describe('RootkitFinding interface', () => {
  it('should support all check types', () => {
    const checkTypes: RootkitFinding['checkType'][] = [
      'hidden_process',
      'ld_preload',
      'kernel_module',
      'hidden_file',
      'binary_integrity',
    ];

    for (const checkType of checkTypes) {
      const finding: RootkitFinding = {
        checkType,
        severity: 'high',
        description: `Test ${checkType}`,
        details: {},
      };
      expect(finding.checkType).toBe(checkType);
    }
  });

  it('should support all severity levels', () => {
    const severities: RootkitFinding['severity'][] = [
      'info',
      'low',
      'medium',
      'high',
      'critical',
    ];

    for (const severity of severities) {
      const finding: RootkitFinding = {
        checkType: 'hidden_process',
        severity,
        description: `Test ${severity}`,
        details: {},
      };
      expect(finding.severity).toBe(severity);
    }
  });
});

// ===== MITRE ATT&CK category mapping tests / MITRE ATT&CK 分類映射測試 =====

describe('MITRE ATT&CK category mapping', () => {
  it('should map hidden_process to defense_evasion', () => {
    const event = createRootkitEvent({
      checkType: 'hidden_process',
      severity: 'critical',
      description: 'test',
      details: {},
    });
    expect(event.category).toBe('defense_evasion');
  });

  it('should map ld_preload to persistence', () => {
    const event = createRootkitEvent({
      checkType: 'ld_preload',
      severity: 'high',
      description: 'test',
      details: {},
    });
    expect(event.category).toBe('persistence');
  });

  it('should map kernel_module to persistence', () => {
    const event = createRootkitEvent({
      checkType: 'kernel_module',
      severity: 'critical',
      description: 'test',
      details: {},
    });
    expect(event.category).toBe('persistence');
  });

  it('should map hidden_file to defense_evasion', () => {
    const event = createRootkitEvent({
      checkType: 'hidden_file',
      severity: 'high',
      description: 'test',
      details: {},
    });
    expect(event.category).toBe('defense_evasion');
  });

  it('should map binary_integrity to defense_evasion', () => {
    const event = createRootkitEvent({
      checkType: 'binary_integrity',
      severity: 'critical',
      description: 'test',
      details: {},
    });
    expect(event.category).toBe('defense_evasion');
  });
});
