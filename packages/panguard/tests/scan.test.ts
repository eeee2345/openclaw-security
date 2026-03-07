/**
 * Tests for `panguard scan` command
 * Tests command structure, option parsing, and scan mode selection
 */

import { describe, it, expect, vi } from 'vitest';
import { scanCommand } from '../src/cli/commands/scan.js';

// Mock external dependencies
vi.mock('@panguard-ai/panguard-scan', () => ({
  runScan: vi.fn().mockResolvedValue({
    riskScore: 25,
    riskLevel: 'low',
    findings: [],
    scannedAt: '2026-01-01T00:00:00.000Z',
    scanDuration: 5000,
    discovery: {
      os: { distro: 'macOS', version: '15.0', arch: 'arm64' },
      openPorts: [],
      services: [],
      security: { firewall: { enabled: true }, existingTools: [] },
    },
  }),
  runRemoteScan: vi.fn().mockResolvedValue({
    riskScore: 10,
    riskLevel: 'low',
    findings: [],
    scannedAt: '2026-01-01T00:00:00.000Z',
    scanDuration: 3000,
    discovery: { openPorts: [] },
  }),
  generatePdfReport: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../src/cli/auth-guard.js', () => ({
  requireAuth: vi.fn().mockReturnValue({
    authenticated: true,
    authorized: true,
    credentials: null,
  }),
  withAuth: vi.fn((_tier: string, handler: (...args: unknown[]) => unknown) => handler),
}));

vi.mock('@panguard-ai/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@panguard-ai/core')>();
  return {
    ...actual,
    c: {
      sage: (s: string) => s,
      bold: (s: string) => s,
      dim: (s: string) => s,
      safe: (s: string) => s,
      caution: (s: string) => s,
      critical: (s: string) => s,
      underline: (s: string) => s,
    },
    banner: () => 'BANNER',
    spinner: () => ({ succeed: vi.fn(), fail: vi.fn() }),
    statusPanel: () => '',
    divider: () => '',
    scoreDisplay: () => '',
    colorSeverity: (s: string) => s,
    table: () => '',
    box: () => '',
    symbols: { scan: '[scan]', pass: '[ok]', fail: '[x]', warn: '[!]' },
    formatDuration: (ms: number) => `${ms}ms`,
    setLogLevel: vi.fn(),
  };
});

vi.mock('../../index.js', () => ({
  PANGUARD_VERSION: '0.0.0-test',
}));

describe('scanCommand', () => {
  it('should create a command named "scan"', () => {
    const cmd = scanCommand();
    expect(cmd.name()).toBe('scan');
  });

  it('should have a description mentioning security scan', () => {
    const cmd = scanCommand();
    const desc = cmd.description();
    expect(desc).toContain('scan');
  });

  describe('options', () => {
    it('should define --quick option with default false', () => {
      const cmd = scanCommand();
      const quickOpt = cmd.options.find((o) => o.long === '--quick');
      expect(quickOpt).toBeDefined();
      expect(quickOpt!.defaultValue).toBe(false);
    });

    it('should define --output option for PDF report path', () => {
      const cmd = scanCommand();
      const outputOpt = cmd.options.find((o) => o.long === '--output');
      expect(outputOpt).toBeDefined();
      expect(outputOpt!.flags).toContain('<path>');
    });

    it('should define --lang option with default "en"', () => {
      const cmd = scanCommand();
      const langOpt = cmd.options.find((o) => o.long === '--lang');
      expect(langOpt).toBeDefined();
      expect(langOpt!.defaultValue).toBe('en');
    });

    it('should define --verbose option with default false', () => {
      const cmd = scanCommand();
      const verboseOpt = cmd.options.find((o) => o.long === '--verbose');
      expect(verboseOpt).toBeDefined();
      expect(verboseOpt!.defaultValue).toBe(false);
    });

    it('should define --json option with default false', () => {
      const cmd = scanCommand();
      const jsonOpt = cmd.options.find((o) => o.long === '--json');
      expect(jsonOpt).toBeDefined();
      expect(jsonOpt!.defaultValue).toBe(false);
    });

    it('should define --target option for remote scanning', () => {
      const cmd = scanCommand();
      const targetOpt = cmd.options.find((o) => o.long === '--target');
      expect(targetOpt).toBeDefined();
      expect(targetOpt!.flags).toContain('<host>');
    });

    it('should have exactly 7 options', () => {
      const cmd = scanCommand();
      expect(cmd.options).toHaveLength(7);
    });

    it('should define --save option for saving JSON results to file', () => {
      const cmd = scanCommand();
      const saveOpt = cmd.options.find((o) => o.long === '--save');
      expect(saveOpt).toBeDefined();
      expect(saveOpt!.flags).toContain('<path>');
    });
  });

  describe('scan mode logic', () => {
    it('should pass "quick" depth when --quick is set', async () => {
      const { runScan } = await import('@panguard-ai/panguard-scan');
      const mockedRunScan = vi.mocked(runScan);
      mockedRunScan.mockClear();

      const cmd = scanCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['--quick'], { from: 'user' });
      consoleSpy.mockRestore();

      expect(mockedRunScan).toHaveBeenCalledWith(
        expect.objectContaining({ depth: 'quick' })
      );
    });

    it('should pass "full" depth by default', async () => {
      const { runScan } = await import('@panguard-ai/panguard-scan');
      const mockedRunScan = vi.mocked(runScan);
      mockedRunScan.mockClear();

      const cmd = scanCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync([], { from: 'user' });
      consoleSpy.mockRestore();

      expect(mockedRunScan).toHaveBeenCalledWith(
        expect.objectContaining({ depth: 'full' })
      );
    });

    it('should use runRemoteScan when --target is set with --json', async () => {
      const { runRemoteScan } = await import('@panguard-ai/panguard-scan');
      const mockedRunRemoteScan = vi.mocked(runRemoteScan);
      mockedRunRemoteScan.mockClear();

      const cmd = scanCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['--target', '192.168.1.1', '--json'], { from: 'user' });
      consoleSpy.mockRestore();

      expect(mockedRunRemoteScan).toHaveBeenCalledWith(
        expect.objectContaining({ target: '192.168.1.1' })
      );
    });

    it('should output JSON to stdout when --json is set', async () => {
      const { runScan } = await import('@panguard-ai/panguard-scan');
      vi.mocked(runScan).mockClear();

      const cmd = scanCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['--json'], { from: 'user' });

      // The last console.log call should be a JSON string
      const calls = consoleSpy.mock.calls;
      const lastCall = calls[calls.length - 1]![0] as string;
      expect(() => JSON.parse(lastCall)).not.toThrow();

      const parsed = JSON.parse(lastCall);
      expect(parsed).toHaveProperty('risk_score');
      expect(parsed).toHaveProperty('grade');
      expect(parsed).toHaveProperty('findings');
      expect(parsed).toHaveProperty('agent_friendly', true);
      expect(parsed).toHaveProperty('powered_by', 'Panguard AI');

      consoleSpy.mockRestore();
    });

    it('should parse zh-TW language option correctly', async () => {
      const { runScan } = await import('@panguard-ai/panguard-scan');
      const mockedRunScan = vi.mocked(runScan);
      mockedRunScan.mockClear();

      const cmd = scanCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['--lang', 'zh-TW'], { from: 'user' });
      consoleSpy.mockRestore();

      expect(mockedRunScan).toHaveBeenCalledWith(
        expect.objectContaining({ lang: 'zh-TW' })
      );
    });
  });

  describe('grade calculation', () => {
    it('should compute grade A for safety score >= 90', async () => {
      const { runScan } = await import('@panguard-ai/panguard-scan');
      vi.mocked(runScan).mockResolvedValueOnce({
        riskScore: 5,
        riskLevel: 'low',
        findings: [],
        scannedAt: '2026-01-01T00:00:00.000Z',
        scanDuration: 1000,
        discovery: {
          os: { distro: 'macOS', version: '15.0', arch: 'arm64' },
          openPorts: [],
          services: [],
          security: { firewall: { enabled: true }, existingTools: [] },
        },
      } as never);

      const cmd = scanCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['--json'], { from: 'user' });
      const lastCall = consoleSpy.mock.calls[consoleSpy.mock.calls.length - 1]![0] as string;
      const parsed = JSON.parse(lastCall);
      // safetyScore = max(0, 100 - 5) = 95 >= 90 -> A
      expect(parsed.grade).toBe('A');
      consoleSpy.mockRestore();
    });

    it('should compute grade F for safety score < 40', async () => {
      const { runScan } = await import('@panguard-ai/panguard-scan');
      vi.mocked(runScan).mockResolvedValueOnce({
        riskScore: 80,
        riskLevel: 'critical',
        findings: [],
        scannedAt: '2026-01-01T00:00:00.000Z',
        scanDuration: 1000,
        discovery: {
          os: { distro: 'Linux', version: '6.1', arch: 'x64' },
          openPorts: [],
          services: [],
          security: { firewall: { enabled: false }, existingTools: [] },
        },
      } as never);

      const cmd = scanCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['--json'], { from: 'user' });
      const lastCall = consoleSpy.mock.calls[consoleSpy.mock.calls.length - 1]![0] as string;
      const parsed = JSON.parse(lastCall);
      // safetyScore = max(0, 100 - 80) = 20 < 40 -> F
      expect(parsed.grade).toBe('F');
      consoleSpy.mockRestore();
    });
  });
});
