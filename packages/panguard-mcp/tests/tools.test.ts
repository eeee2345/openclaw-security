/**
 * Panguard MCP - Tool Handler Tests
 * Panguard MCP - 工具處理程序測試
 *
 * Tests for each tool handler: input validation, mock-based correctness,
 * error handling, and response structure.
 *
 * @module @panguard-ai/panguard-mcp/tests/tools
 */

import { describe, it, expect, vi, beforeEach, afterAll, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// ─── Mock Setup ─────────────────────────────────────────────────────────────

// vi.hoisted ensures these are available when vi.mock factories execute (hoisted above imports)
const { mockRunScan, mockGeneratePdfReport, mockAuditSkill } = vi.hoisted(() => ({
  mockRunScan: vi.fn(),
  mockGeneratePdfReport: vi.fn(),
  mockAuditSkill: vi.fn(),
}));

// Mock @panguard-ai/panguard-scan
vi.mock('@panguard-ai/panguard-scan', () => ({
  runScan: mockRunScan,
  generatePdfReport: mockGeneratePdfReport,
  checkSourceCode: vi.fn(),
  checkHardcodedSecrets: vi.fn(),
}));

// Mock @panguard-ai/core
vi.mock('@panguard-ai/core', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

// Mock @panguard-ai/panguard-skill-auditor
vi.mock('@panguard-ai/panguard-skill-auditor', () => ({
  auditSkill: mockAuditSkill,
}));

// Import after mocks are set up
import { dispatchTool } from '../src/server.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Parse the JSON text from a tool result's first content block. */
function parseResult(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

/** Create a fake ScanResult for mocking. */
function fakeScanResult(overrides: Record<string, unknown> = {}) {
  return {
    riskScore: 25,
    riskLevel: 'low',
    findings: [
      {
        id: 'FIND-001',
        severity: 'medium',
        title: 'Test finding',
        category: 'test',
        description: 'A test finding',
        remediation: 'Fix it',
      },
    ],
    scanDuration: 1234,
    scannedAt: '2026-01-01T00:00:00.000Z',
    discovery: {},
    config: { depth: 'quick', lang: 'en' },
    ...overrides,
  };
}

/** Create a unique temp directory path for test isolation. */
function tmpDir(label: string): string {
  return path.join(os.tmpdir(), `panguard-mcp-test-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
}

// ─── Cleanup tracker ────────────────────────────────────────────────────────

const dirsToClean: string[] = [];

afterAll(async () => {
  for (const dir of dirsToClean) {
    await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_scan
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_scan', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls runScan with default depth and lang when no args provided', async () => {
    mockRunScan.mockResolvedValueOnce(fakeScanResult());

    await dispatchTool('panguard_scan', {});

    expect(mockRunScan).toHaveBeenCalledWith({ depth: 'quick', lang: 'en' });
  });

  it('passes custom depth and lang to runScan', async () => {
    mockRunScan.mockResolvedValueOnce(fakeScanResult());

    await dispatchTool('panguard_scan', { depth: 'full', lang: 'zh-TW' });

    expect(mockRunScan).toHaveBeenCalledWith({ depth: 'full', lang: 'zh-TW' });
  });

  it('returns risk_score, grade, and findings in content', async () => {
    mockRunScan.mockResolvedValueOnce(fakeScanResult({ riskScore: 25 }));

    const result = await dispatchTool('panguard_scan', {});
    const parsed = parseResult(result);

    expect(parsed['risk_score']).toBe(25);
    expect(parsed['grade']).toBe('B'); // safety=75, >= 75 -> B
    expect(parsed['findings_count']).toBe(1);
    expect(parsed['summary']).toContain('25/100');
  });

  it('returns correct grades for different risk scores', async () => {
    const testCases = [
      { riskScore: 5, expectedGrade: 'A' },    // safety=95 >= 90
      { riskScore: 20, expectedGrade: 'B' },   // safety=80 >= 75
      { riskScore: 35, expectedGrade: 'C' },   // safety=65 >= 60
      { riskScore: 55, expectedGrade: 'D' },   // safety=45 >= 40
      { riskScore: 80, expectedGrade: 'F' },   // safety=20 < 40
    ];

    for (const { riskScore, expectedGrade } of testCases) {
      mockRunScan.mockResolvedValueOnce(fakeScanResult({ riskScore }));
      const result = await dispatchTool('panguard_scan', {});
      const parsed = parseResult(result);
      expect(parsed['grade']).toBe(expectedGrade);
    }
  });

  it('limits findings to at most 20 in output', async () => {
    const manyFindings = Array.from({ length: 30 }, (_, i) => ({
      id: `FIND-${i}`,
      severity: 'low',
      title: `Finding ${i}`,
      category: 'test',
      description: 'desc',
      remediation: 'fix',
    }));
    mockRunScan.mockResolvedValueOnce(fakeScanResult({ findings: manyFindings }));

    const result = await dispatchTool('panguard_scan', {});
    const parsed = parseResult(result);

    expect(parsed['findings_count']).toBe(30);
    expect((parsed['findings'] as unknown[]).length).toBe(20);
  });

  it('returns isError and error message when runScan throws', async () => {
    mockRunScan.mockRejectedValueOnce(new Error('Scan engine failed'));

    const result = await dispatchTool('panguard_scan', {});
    const parsed = parseResult(result);

    expect(result.isError).toBe(true);
    expect(parsed['error']).toBe('Scan engine failed');
  });

  it('handles non-Error throws gracefully', async () => {
    mockRunScan.mockRejectedValueOnce('string error');

    const result = await dispatchTool('panguard_scan', {});
    const parsed = parseResult(result);

    expect(result.isError).toBe(true);
    expect(parsed['error']).toBe('string error');
  });

  it('returns content with type "text"', async () => {
    mockRunScan.mockResolvedValueOnce(fakeScanResult());

    const result = await dispatchTool('panguard_scan', {});

    expect(result.content[0]).toHaveProperty('type', 'text');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_block_ip
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_block_ip', () => {
  it('returns error when ip is not provided', async () => {
    const result = await dispatchTool('panguard_block_ip', {});
    const parsed = parseResult(result);

    expect(result.isError).toBe(true);
    expect(parsed['error']).toContain('required');
  });

  it('returns error for invalid IP format', async () => {
    const result = await dispatchTool('panguard_block_ip', { ip: 'not-an-ip' });
    const parsed = parseResult(result);

    expect(result.isError).toBe(true);
    expect(parsed['error']).toContain('Invalid IP');
  });

  it('returns error for empty string IP', async () => {
    const result = await dispatchTool('panguard_block_ip', { ip: '' });
    const parsed = parseResult(result);

    expect(result.isError).toBe(true);
  });

  it('blocks valid IPv4 address successfully', async () => {
    const result = await dispatchTool('panguard_block_ip', { ip: '192.168.1.1' });
    const parsed = parseResult(result);

    expect(result.isError).toBeFalsy();
    expect(parsed['status']).toBe('blocked');
    expect(parsed['ip']).toBe('192.168.1.1');
    expect(parsed['duration']).toBe('1h'); // default
  });

  it('blocks valid IPv6 address successfully', async () => {
    const result = await dispatchTool('panguard_block_ip', { ip: '::1' });
    const parsed = parseResult(result);

    expect(result.isError).toBeFalsy();
    expect(parsed['status']).toBe('blocked');
    expect(parsed['ip']).toBe('::1');
  });

  it('blocks full IPv6 address', async () => {
    const result = await dispatchTool('panguard_block_ip', {
      ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    });
    const parsed = parseResult(result);

    expect(result.isError).toBeFalsy();
    expect(parsed['status']).toBe('blocked');
  });

  it('includes custom duration in response', async () => {
    const result = await dispatchTool('panguard_block_ip', {
      ip: '10.0.0.1',
      duration: '24h',
    });
    const parsed = parseResult(result);

    expect(parsed['duration']).toBe('24h');
  });

  it('includes custom reason in response', async () => {
    const result = await dispatchTool('panguard_block_ip', {
      ip: '10.0.0.1',
      reason: 'Port scanning detected',
    });
    const parsed = parseResult(result);

    expect(parsed['reason']).toBe('Port scanning detected');
  });

  it('uses default reason when none provided', async () => {
    const result = await dispatchTool('panguard_block_ip', { ip: '10.0.0.1' });
    const parsed = parseResult(result);

    expect(parsed['reason']).toContain('Manually blocked');
  });

  it('includes a timestamp in the response', async () => {
    const result = await dispatchTool('panguard_block_ip', { ip: '10.0.0.1' });
    const parsed = parseResult(result);

    expect(parsed['timestamp']).toBeDefined();
    // Validate ISO 8601 format
    expect(() => new Date(parsed['timestamp'] as string)).not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_init
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_init', () => {
  it('creates data directory and config.json', async () => {
    const dataDir = tmpDir('init');
    dirsToClean.push(dataDir);

    const result = await dispatchTool('panguard_init', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['status']).toBe('initialized');
    expect(parsed['dataDir']).toBe(dataDir);

    const configPath = path.join(dataDir, 'config.json');
    const exists = await fs.access(configPath).then(() => true).catch(() => false);
    expect(exists).toBe(true);
  });

  it('writes valid JSON config with correct defaults', async () => {
    const dataDir = tmpDir('init-defaults');
    dirsToClean.push(dataDir);

    await dispatchTool('panguard_init', { dataDir });

    const configPath = path.join(dataDir, 'config.json');
    const content = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(content) as Record<string, unknown>;

    expect(config['mode']).toBe('learning');
    expect(config['lang']).toBe('en');
    expect(config['dataDir']).toBe(dataDir);
    expect(config['learningDays']).toBe(14);
    expect(config['dashboardEnabled']).toBe(false);
    expect(config['watchdogEnabled']).toBe(true);
  });

  it('respects custom mode and lang arguments', async () => {
    const dataDir = tmpDir('init-custom');
    dirsToClean.push(dataDir);

    await dispatchTool('panguard_init', {
      dataDir,
      mode: 'protection',
      lang: 'zh-TW',
    });

    const configPath = path.join(dataDir, 'config.json');
    const content = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(content) as Record<string, unknown>;

    expect(config['mode']).toBe('protection');
    expect(config['lang']).toBe('zh-TW');
  });

  it('includes monitor configuration in written config', async () => {
    const dataDir = tmpDir('init-monitors');
    dirsToClean.push(dataDir);

    await dispatchTool('panguard_init', { dataDir });

    const configPath = path.join(dataDir, 'config.json');
    const content = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(content) as Record<string, unknown>;
    const monitors = config['monitors'] as Record<string, unknown>;

    expect(monitors['logMonitor']).toBe(true);
    expect(monitors['networkMonitor']).toBe(true);
    expect(monitors['processMonitor']).toBe(true);
    expect(monitors['fileMonitor']).toBe(false);
  });

  it('returns configPath in the response', async () => {
    const dataDir = tmpDir('init-configpath');
    dirsToClean.push(dataDir);

    const result = await dispatchTool('panguard_init', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['configPath']).toBe(path.join(dataDir, 'config.json'));
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_guard_start
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_guard_start', () => {
  it('returns status "ready" with command to run', async () => {
    const dataDir = tmpDir('guard-start');
    dirsToClean.push(dataDir);

    const result = await dispatchTool('panguard_guard_start', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['status']).toBe('ready');
    expect(typeof parsed['command']).toBe('string');
    expect((parsed['command'] as string)).toContain('panguard-guard start');
  });

  it('includes the specified mode in the command', async () => {
    const dataDir = tmpDir('guard-start-mode');
    dirsToClean.push(dataDir);

    const result = await dispatchTool('panguard_guard_start', {
      dataDir,
      mode: 'protection',
    });
    const parsed = parseResult(result);

    expect((parsed['command'] as string)).toContain('--mode protection');
    expect(parsed['mode']).toBe('protection');
  });

  it('defaults mode to learning', async () => {
    const dataDir = tmpDir('guard-start-default');
    dirsToClean.push(dataDir);

    const result = await dispatchTool('panguard_guard_start', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['mode']).toBe('learning');
    expect((parsed['command'] as string)).toContain('--mode learning');
  });

  it('creates the data directory if it does not exist', async () => {
    const dataDir = tmpDir('guard-start-mkdir');
    dirsToClean.push(dataDir);

    await dispatchTool('panguard_guard_start', { dataDir });

    const exists = await fs.access(dataDir).then(() => true).catch(() => false);
    expect(exists).toBe(true);
  });

  it('includes dataDir in response', async () => {
    const dataDir = tmpDir('guard-start-dir');
    dirsToClean.push(dataDir);

    const result = await dispatchTool('panguard_guard_start', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['dataDir']).toBe(dataDir);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_guard_stop
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_guard_stop', () => {
  it('returns "not_running" when no PID file exists', async () => {
    const dataDir = tmpDir('guard-stop-nopid');

    const result = await dispatchTool('panguard_guard_stop', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['status']).toBe('not_running');
  });

  it('returns "not_running" when PID file has invalid content', async () => {
    const dataDir = tmpDir('guard-stop-badpid');
    dirsToClean.push(dataDir);

    await fs.mkdir(dataDir, { recursive: true });
    await fs.writeFile(path.join(dataDir, 'guard.pid'), 'not-a-number');

    const result = await dispatchTool('panguard_guard_stop', { dataDir });
    const parsed = parseResult(result);

    // NaN pid won't match a process, so it should be not_running
    expect(parsed['status']).toBe('not_running');
  });

  it('returns "not_running" when PID points to a non-existent process', async () => {
    const dataDir = tmpDir('guard-stop-stale');
    dirsToClean.push(dataDir);

    await fs.mkdir(dataDir, { recursive: true });
    // Use a very high PID that almost certainly doesn't exist
    await fs.writeFile(path.join(dataDir, 'guard.pid'), '9999999');

    const result = await dispatchTool('panguard_guard_stop', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['status']).toBe('not_running');
  });

  it('cleans up stale PID file after failed stop', async () => {
    const dataDir = tmpDir('guard-stop-cleanup');
    dirsToClean.push(dataDir);

    const pidFile = path.join(dataDir, 'guard.pid');
    await fs.mkdir(dataDir, { recursive: true });
    await fs.writeFile(pidFile, '9999999');

    await dispatchTool('panguard_guard_stop', { dataDir });

    const pidExists = await fs.access(pidFile).then(() => true).catch(() => false);
    expect(pidExists).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_status
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_status', () => {
  it('returns guard not running for nonexistent data dir', async () => {
    const dataDir = tmpDir('status-nodir');

    const result = await dispatchTool('panguard_status', { dataDir });
    const parsed = parseResult(result);

    expect(parsed).toHaveProperty('guard');
    expect(parsed).toHaveProperty('summary');

    const guard = parsed['guard'] as Record<string, unknown>;
    expect(guard['running']).toBe(false);
  });

  it('returns event count from events.jsonl', async () => {
    const dataDir = tmpDir('status-events');
    dirsToClean.push(dataDir);

    await fs.mkdir(dataDir, { recursive: true });
    const events = [
      JSON.stringify({ type: 'threat', severity: 'high' }),
      JSON.stringify({ type: 'info', severity: 'low' }),
      JSON.stringify({ type: 'threat', severity: 'critical' }),
    ].join('\n');
    await fs.writeFile(path.join(dataDir, 'events.jsonl'), events);

    const result = await dispatchTool('panguard_status', { dataDir });
    const parsed = parseResult(result);

    const eventsData = parsed['events'] as Record<string, unknown>;
    expect(eventsData['total_logged']).toBe(3);
  });

  it('reads mode and lang from config.json', async () => {
    const dataDir = tmpDir('status-config');
    dirsToClean.push(dataDir);

    await fs.mkdir(dataDir, { recursive: true });
    await fs.writeFile(
      path.join(dataDir, 'config.json'),
      JSON.stringify({ mode: 'protection', lang: 'zh-TW' }),
    );

    const result = await dispatchTool('panguard_status', { dataDir });
    const parsed = parseResult(result);

    const guard = parsed['guard'] as Record<string, unknown>;
    expect(guard['mode']).toBe('protection');
    expect(guard['lang']).toBe('zh-TW');
  });

  it('returns "unknown" mode when no config exists', async () => {
    const dataDir = tmpDir('status-noconfig');

    const result = await dispatchTool('panguard_status', { dataDir });
    const parsed = parseResult(result);

    const guard = parsed['guard'] as Record<string, unknown>;
    expect(guard['mode']).toBe('unknown');
  });

  it('summary suggests starting guard when not running', async () => {
    const dataDir = tmpDir('status-summary');

    const result = await dispatchTool('panguard_status', { dataDir });
    const parsed = parseResult(result);

    expect((parsed['summary'] as string)).toContain('NOT running');
  });

  it('returns zero events when no events file exists', async () => {
    const dataDir = tmpDir('status-noevents');

    const result = await dispatchTool('panguard_status', { dataDir });
    const parsed = parseResult(result);

    const eventsData = parsed['events'] as Record<string, unknown>;
    expect(eventsData['total_logged']).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_alerts
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_alerts', () => {
  it('returns empty alerts array when no events file exists', async () => {
    const dataDir = tmpDir('alerts-nofile');

    const result = await dispatchTool('panguard_alerts', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['total_alerts']).toBe(0);
    expect(Array.isArray(parsed['alerts'])).toBe(true);
    expect((parsed['alerts'] as unknown[]).length).toBe(0);
  });

  it('returns all alerts when severity is "all"', async () => {
    const dataDir = tmpDir('alerts-all');
    dirsToClean.push(dataDir);

    await fs.mkdir(dataDir, { recursive: true });
    const events = [
      JSON.stringify({ severity: 'critical', message: 'Intrusion detected' }),
      JSON.stringify({ severity: 'low', message: 'Login attempt' }),
      JSON.stringify({ severity: 'medium', message: 'Port scan' }),
    ].join('\n');
    await fs.writeFile(path.join(dataDir, 'events.jsonl'), events);

    const result = await dispatchTool('panguard_alerts', { dataDir, severity: 'all' });
    const parsed = parseResult(result);

    expect(parsed['total_alerts']).toBe(3);
  });

  it('filters by severity when specified', async () => {
    const dataDir = tmpDir('alerts-filter');
    dirsToClean.push(dataDir);

    await fs.mkdir(dataDir, { recursive: true });
    const events = [
      JSON.stringify({ severity: 'critical', message: 'Intrusion' }),
      JSON.stringify({ severity: 'low', message: 'Info' }),
      JSON.stringify({ severity: 'critical', message: 'Malware' }),
    ].join('\n');
    await fs.writeFile(path.join(dataDir, 'events.jsonl'), events);

    const result = await dispatchTool('panguard_alerts', { dataDir, severity: 'critical' });
    const parsed = parseResult(result);

    expect(parsed['total_alerts']).toBe(2);
    const alerts = parsed['alerts'] as Array<Record<string, unknown>>;
    for (const alert of alerts) {
      expect(alert['severity']).toBe('critical');
    }
  });

  it('respects the limit parameter', async () => {
    const dataDir = tmpDir('alerts-limit');
    dirsToClean.push(dataDir);

    await fs.mkdir(dataDir, { recursive: true });
    const events = Array.from({ length: 10 }, (_, i) =>
      JSON.stringify({ severity: 'medium', message: `Alert ${i}` }),
    ).join('\n');
    await fs.writeFile(path.join(dataDir, 'events.jsonl'), events);

    const result = await dispatchTool('panguard_alerts', { dataDir, limit: 3 });
    const parsed = parseResult(result);

    expect(parsed['total_alerts']).toBeLessThanOrEqual(3);
  });

  it('returns filter metadata in response', async () => {
    const dataDir = tmpDir('alerts-meta');

    const result = await dispatchTool('panguard_alerts', {
      dataDir,
      severity: 'high',
      limit: 5,
    });
    const parsed = parseResult(result);

    const filter = parsed['filter'] as Record<string, unknown>;
    expect(filter['severity']).toBe('high');
    expect(filter['limit']).toBe(5);
  });

  it('skips malformed JSONL lines gracefully', async () => {
    const dataDir = tmpDir('alerts-malformed');
    dirsToClean.push(dataDir);

    await fs.mkdir(dataDir, { recursive: true });
    const events = [
      JSON.stringify({ severity: 'high', message: 'Valid' }),
      'not-valid-json{{{',
      JSON.stringify({ severity: 'low', message: 'Also valid' }),
    ].join('\n');
    await fs.writeFile(path.join(dataDir, 'events.jsonl'), events);

    const result = await dispatchTool('panguard_alerts', { dataDir });
    const parsed = parseResult(result);

    // Should only have the 2 valid entries
    expect(parsed['total_alerts']).toBe(2);
  });

  it('summary says clean when no alerts', async () => {
    const dataDir = tmpDir('alerts-clean');

    const result = await dispatchTool('panguard_alerts', { dataDir });
    const parsed = parseResult(result);

    expect((parsed['summary'] as string)).toContain('clean');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_generate_report
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_generate_report', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls runScan with correct depth and lang', async () => {
    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockResolvedValueOnce(undefined);

    await dispatchTool('panguard_generate_report', {
      depth: 'quick',
      lang: 'zh-TW',
    });

    expect(mockRunScan).toHaveBeenCalledWith({ depth: 'quick', lang: 'zh-TW' });
  });

  it('calls generatePdfReport with scan result, output path, and lang', async () => {
    const scan = fakeScanResult();
    mockRunScan.mockResolvedValueOnce(scan);
    mockGeneratePdfReport.mockResolvedValueOnce(undefined);

    await dispatchTool('panguard_generate_report', {
      output: '/tmp/test-report.pdf',
      lang: 'en',
    });

    expect(mockGeneratePdfReport).toHaveBeenCalledWith(scan, '/tmp/test-report.pdf', 'en');
  });

  it('returns generated status with report path', async () => {
    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockResolvedValueOnce(undefined);

    const result = await dispatchTool('panguard_generate_report', {
      output: '/tmp/test-report.pdf',
    });
    const parsed = parseResult(result);

    expect(parsed['status']).toBe('generated');
    expect(parsed['output']).toBe(path.resolve('/tmp/test-report.pdf'));
    expect(parsed['risk_score']).toBeDefined();
    expect(parsed['grade']).toBeDefined();
  });

  it('uses defaults when no args provided', async () => {
    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockResolvedValueOnce(undefined);

    await dispatchTool('panguard_generate_report', {});

    expect(mockRunScan).toHaveBeenCalledWith({ depth: 'full', lang: 'en' });
    expect(mockGeneratePdfReport).toHaveBeenCalledWith(
      expect.anything(),
      './panguard-report.pdf',
      'en',
    );
  });

  it('returns isError when runScan throws', async () => {
    mockRunScan.mockRejectedValueOnce(new Error('Scan unavailable'));

    const result = await dispatchTool('panguard_generate_report', {});
    const parsed = parseResult(result);

    expect(result.isError).toBe(true);
    expect(parsed['error']).toBe('Scan unavailable');
  });

  it('returns isError when generatePdfReport throws', async () => {
    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockRejectedValueOnce(new Error('PDF write failed'));

    const result = await dispatchTool('panguard_generate_report', {});
    const parsed = parseResult(result);

    expect(result.isError).toBe(true);
    expect(parsed['error']).toBe('PDF write failed');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_deploy
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_deploy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('creates config and runs scan on deploy', async () => {
    const dataDir = tmpDir('deploy');
    dirsToClean.push(dataDir);

    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockResolvedValueOnce(undefined);

    const result = await dispatchTool('panguard_deploy', { dataDir });
    const parsed = parseResult(result);

    expect(parsed['status']).toBe('deployed');

    // Verify config was written
    const configPath = path.join(dataDir, 'config.json');
    const exists = await fs.access(configPath).then(() => true).catch(() => false);
    expect(exists).toBe(true);
  });

  it('returns step statuses in order', async () => {
    const dataDir = tmpDir('deploy-steps');
    dirsToClean.push(dataDir);

    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockResolvedValueOnce(undefined);

    const result = await dispatchTool('panguard_deploy', { dataDir });
    const parsed = parseResult(result);

    const steps = parsed['steps'] as Array<Record<string, unknown>>;
    expect(steps).toHaveLength(4);
    expect(steps[0]!['step']).toBe('init');
    expect(steps[1]!['step']).toBe('scan');
    expect(steps[2]!['step']).toBe('report');
    expect(steps[3]!['step']).toBe('guard');
  });

  it('handles scan failure gracefully during deploy', async () => {
    const dataDir = tmpDir('deploy-scanfail');
    dirsToClean.push(dataDir);

    mockRunScan.mockRejectedValueOnce(new Error('Scan crashed'));

    const result = await dispatchTool('panguard_deploy', { dataDir });
    const parsed = parseResult(result);

    // Deploy should still succeed partially
    expect(parsed['status']).toBe('deployed');

    const steps = parsed['steps'] as Array<Record<string, unknown>>;
    const scanStep = steps.find((s) => s['step'] === 'scan');
    expect(scanStep!['status']).toBe('failed');
  });

  it('handles report generation failure gracefully', async () => {
    const dataDir = tmpDir('deploy-reportfail');
    dirsToClean.push(dataDir);

    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockRejectedValueOnce(new Error('PDF failed'));

    const result = await dispatchTool('panguard_deploy', { dataDir });
    const parsed = parseResult(result);

    const steps = parsed['steps'] as Array<Record<string, unknown>>;
    const reportStep = steps.find((s) => s['step'] === 'report');
    expect(reportStep!['status']).toBe('failed');
  });

  it('skips report when generateReport is false', async () => {
    const dataDir = tmpDir('deploy-noreport');
    dirsToClean.push(dataDir);

    mockRunScan.mockResolvedValueOnce(fakeScanResult());

    const result = await dispatchTool('panguard_deploy', {
      dataDir,
      generateReport: false,
    });
    const parsed = parseResult(result);

    expect(mockGeneratePdfReport).not.toHaveBeenCalled();

    const steps = parsed['steps'] as Array<Record<string, unknown>>;
    const reportStep = steps.find((s) => s['step'] === 'report');
    expect(reportStep!['status']).toBe('skipped');
  });

  it('includes next_steps in response', async () => {
    const dataDir = tmpDir('deploy-nextsteps');
    dirsToClean.push(dataDir);

    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockResolvedValueOnce(undefined);

    const result = await dispatchTool('panguard_deploy', { dataDir });
    const parsed = parseResult(result);

    expect(Array.isArray(parsed['next_steps'])).toBe(true);
    const nextSteps = parsed['next_steps'] as string[];
    expect(nextSteps.length).toBeGreaterThan(0);
    expect(nextSteps[0]).toContain('panguard_guard_start');
  });

  it('uses custom mode and lang', async () => {
    const dataDir = tmpDir('deploy-custom');
    dirsToClean.push(dataDir);

    mockRunScan.mockResolvedValueOnce(fakeScanResult());
    mockGeneratePdfReport.mockResolvedValueOnce(undefined);

    await dispatchTool('panguard_deploy', {
      dataDir,
      mode: 'protection',
      lang: 'zh-TW',
    });

    // Verify config was written with custom values
    const configContent = await fs.readFile(path.join(dataDir, 'config.json'), 'utf-8');
    const config = JSON.parse(configContent) as Record<string, unknown>;
    expect(config['mode']).toBe('protection');
    expect(config['lang']).toBe('zh-TW');

    // Verify scan was called with custom lang
    expect(mockRunScan).toHaveBeenCalledWith({ depth: 'quick', lang: 'zh-TW' });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_audit_skill
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_audit_skill', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls auditSkill with the provided path', async () => {
    mockAuditSkill.mockResolvedValueOnce({
      riskScore: 30,
      findings: [],
      summary: 'Low risk',
    });

    await dispatchTool('panguard_audit_skill', { path: '/some/skill/dir' });

    expect(mockAuditSkill).toHaveBeenCalledWith('/some/skill/dir');
  });

  it('defaults path to "." when not provided', async () => {
    mockAuditSkill.mockResolvedValueOnce({
      riskScore: 0,
      findings: [],
      summary: 'Clean',
    });

    await dispatchTool('panguard_audit_skill', {});

    expect(mockAuditSkill).toHaveBeenCalledWith('.');
  });

  it('returns the audit report as JSON text', async () => {
    const fakeReport = {
      riskScore: 45,
      findings: [{ id: 'SKILL-001', title: 'Prompt injection risk' }],
      summary: 'Medium risk',
    };
    mockAuditSkill.mockResolvedValueOnce(fakeReport);

    const result = await dispatchTool('panguard_audit_skill', { path: '/skill' });
    const parsed = parseResult(result);

    expect(parsed['riskScore']).toBe(45);
    expect((parsed['findings'] as unknown[]).length).toBe(1);
  });

  it('content block has type "text"', async () => {
    mockAuditSkill.mockResolvedValueOnce({ riskScore: 0, findings: [] });

    const result = await dispatchTool('panguard_audit_skill', { path: '/skill' });

    expect(result.content[0]).toHaveProperty('type', 'text');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// panguard_scan_code (SAST)
// ═══════════════════════════════════════════════════════════════════════════

describe('panguard_scan_code', () => {
  // Note: SAST functions are loaded at module level via top-level await import.
  // With mocks, checkSourceCode and checkHardcodedSecrets are vi.fn() stubs
  // that return undefined by default. The module detects them as functions,
  // so it takes the "available" branch. We configure the stubs to return
  // proper Finding arrays via the mock module.

  // We need to access the mock functions from the mocked module to configure them
  let mockCheckSourceCode: ReturnType<typeof vi.fn>;
  let mockCheckHardcodedSecrets: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Get references to the mock functions from the mocked module
    const scanMod = await import('@panguard-ai/panguard-scan');
    mockCheckSourceCode = (scanMod as Record<string, unknown>)['checkSourceCode'] as ReturnType<typeof vi.fn>;
    mockCheckHardcodedSecrets = (scanMod as Record<string, unknown>)['checkHardcodedSecrets'] as ReturnType<typeof vi.fn>;
  });

  it('returns content array with scan_type "sast"', async () => {
    mockCheckSourceCode.mockResolvedValueOnce([]);
    mockCheckHardcodedSecrets.mockResolvedValueOnce([]);

    const result = await dispatchTool('panguard_scan_code', { dir: '/some/code' });
    const parsed = parseResult(result);

    expect(parsed['scan_type']).toBe('sast');
    expect(parsed['target']).toBe('/some/code');
  });

  it('uses default dir "." when not provided', async () => {
    mockCheckSourceCode.mockResolvedValueOnce([]);
    mockCheckHardcodedSecrets.mockResolvedValueOnce([]);

    const result = await dispatchTool('panguard_scan_code', {});
    const parsed = parseResult(result);

    expect(parsed['target']).toBe('.');
  });

  it('includes the target directory in response', async () => {
    mockCheckSourceCode.mockResolvedValueOnce([]);
    mockCheckHardcodedSecrets.mockResolvedValueOnce([]);

    const result = await dispatchTool('panguard_scan_code', { dir: '/my/project' });
    const parsed = parseResult(result);

    expect(parsed['target']).toBe('/my/project');
  });

  it('aggregates findings from both source code and secrets checks', async () => {
    mockCheckSourceCode.mockResolvedValueOnce([
      { id: 'SAST-001', severity: 'high', title: 'SQL Injection', category: 'injection', description: 'desc', remediation: 'fix' },
    ]);
    mockCheckHardcodedSecrets.mockResolvedValueOnce([
      { id: 'SECRET-001', severity: 'critical', title: 'Hardcoded API key', category: 'secrets', description: 'desc', remediation: 'fix' },
    ]);

    const result = await dispatchTool('panguard_scan_code', { dir: '/code' });
    const parsed = parseResult(result);

    expect(parsed['findings_count']).toBe(2);
    expect(parsed['critical']).toBe(1);
    expect(parsed['high']).toBe(1);
  });

  it('returns zero findings when code is clean', async () => {
    mockCheckSourceCode.mockResolvedValueOnce([]);
    mockCheckHardcodedSecrets.mockResolvedValueOnce([]);

    const result = await dispatchTool('panguard_scan_code', { dir: '/clean-code' });
    const parsed = parseResult(result);

    expect(parsed['findings_count']).toBe(0);
    expect((parsed['summary'] as string)).toContain('No security issues');
  });

  it('returns isError when SAST check throws', async () => {
    mockCheckSourceCode.mockRejectedValueOnce(new Error('Parse error'));
    mockCheckHardcodedSecrets.mockResolvedValueOnce([]);

    const result = await dispatchTool('panguard_scan_code', { dir: '/bad-code' });
    const parsed = parseResult(result);

    expect(result.isError).toBe(true);
    expect(parsed['error']).toBe('Parse error');
  });

  it('counts severity levels correctly', async () => {
    mockCheckSourceCode.mockResolvedValueOnce([
      { id: 'S1', severity: 'medium', title: 't', category: 'c', description: 'd', remediation: 'r' },
      { id: 'S2', severity: 'low', title: 't', category: 'c', description: 'd', remediation: 'r' },
      { id: 'S3', severity: 'medium', title: 't', category: 'c', description: 'd', remediation: 'r' },
    ]);
    mockCheckHardcodedSecrets.mockResolvedValueOnce([
      { id: 'S4', severity: 'low', title: 't', category: 'c', description: 'd', remediation: 'r' },
    ]);

    const result = await dispatchTool('panguard_scan_code', { dir: '/code' });
    const parsed = parseResult(result);

    expect(parsed['medium']).toBe(2);
    expect(parsed['low']).toBe(2);
    expect(parsed['critical']).toBe(0);
    expect(parsed['high']).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Response Structure (cross-cutting)
// ═══════════════════════════════════════════════════════════════════════════

describe('Response structure consistency', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('all successful tool responses have content array', async () => {
    mockRunScan.mockResolvedValue(fakeScanResult());
    mockGeneratePdfReport.mockResolvedValue(undefined);
    mockAuditSkill.mockResolvedValue({ riskScore: 0, findings: [] });

    const dataDir = tmpDir('response-structure');
    dirsToClean.push(dataDir);

    const toolCalls = [
      { name: 'panguard_status', args: { dataDir } },
      { name: 'panguard_alerts', args: { dataDir } },
      { name: 'panguard_guard_start', args: { dataDir } },
      { name: 'panguard_guard_stop', args: { dataDir } },
      { name: 'panguard_block_ip', args: { ip: '1.2.3.4' } },
      { name: 'panguard_init', args: { dataDir: tmpDir('resp-init') } },
    ];

    for (const { name, args } of toolCalls) {
      if (name === 'panguard_init') {
        dirsToClean.push(args['dataDir'] as string);
      }
      const result = await dispatchTool(name, args);
      expect(result.content).toBeInstanceOf(Array);
      expect(result.content.length).toBeGreaterThan(0);
      expect(result.content[0]).toHaveProperty('type', 'text');
      expect(typeof result.content[0]!.text).toBe('string');

      // All text content should be valid JSON
      expect(() => JSON.parse(result.content[0]!.text)).not.toThrow();
    }
  });
});
