/**
 * Tests for `panguard report` command
 * Tests command structure, subcommand registration, and argument forwarding
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { reportCommand } from '../src/cli/commands/report.js';

// Mock the report CLI
vi.mock('@panguard-ai/panguard-report', () => ({
  executeCli: vi.fn().mockResolvedValue(undefined),
}));

// Mock auth-guard to bypass authentication for testing
vi.mock('../src/cli/auth-guard.js', () => ({
  withAuth: vi.fn((_tier: string, handler: (opts: Record<string, string | undefined>) => Promise<void>) => {
    return async (opts: Record<string, string | undefined>) => {
      await handler(opts);
    };
  }),
}));

import { executeCli } from '@panguard-ai/panguard-report';

const mockedExecuteCli = vi.mocked(executeCli);

describe('reportCommand', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create a command named "report"', () => {
    const cmd = reportCommand();
    expect(cmd.name()).toBe('report');
  });

  it('should have a description mentioning compliance', () => {
    const cmd = reportCommand();
    expect(cmd.description()).toContain('Compliance');
  });

  describe('subcommands', () => {
    it('should register expected subcommands', () => {
      const cmd = reportCommand();
      const subcommandNames = cmd.commands.map((c) => c.name());
      expect(subcommandNames).toContain('generate');
      expect(subcommandNames).toContain('summary');
      expect(subcommandNames).toContain('list-frameworks');
      expect(subcommandNames).toContain('validate');
    });

    it('should have 4 subcommands', () => {
      const cmd = reportCommand();
      expect(cmd.commands).toHaveLength(4);
    });
  });

  describe('report generate', () => {
    it('should forward "generate" to executeCli', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['generate'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['generate']);
    });

    it('should forward --framework option', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['generate', '--framework', 'iso27001'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['generate', '--framework', 'iso27001']);
    });

    it('should forward --language option', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['generate', '--language', 'zh-TW'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['generate', '--language', 'zh-TW']);
    });

    it('should forward --format option', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['generate', '--format', 'pdf'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['generate', '--format', 'pdf']);
    });

    it('should forward --output-dir option', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['generate', '--output-dir', '/tmp/reports'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith([
        'generate',
        '--output-dir',
        '/tmp/reports',
      ]);
    });

    it('should forward --org option', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['generate', '--org', 'Acme Corp'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['generate', '--org', 'Acme Corp']);
    });

    it('should forward --input option', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['generate', '--input', './findings.json'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['generate', '--input', './findings.json']);
    });

    it('should forward all generate options combined', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(
        [
          'generate',
          '--framework',
          'soc2',
          '--language',
          'en',
          '--format',
          'json',
          '--output-dir',
          '/out',
          '--org',
          'Test Inc',
          '--input',
          'data.json',
        ],
        { from: 'user' }
      );
      expect(mockedExecuteCli).toHaveBeenCalledWith([
        'generate',
        '--framework',
        'soc2',
        '--language',
        'en',
        '--format',
        'json',
        '--output-dir',
        '/out',
        '--org',
        'Test Inc',
        '--input',
        'data.json',
      ]);
    });

    it('should have generate subcommand with expected options', () => {
      const cmd = reportCommand();
      const genCmd = cmd.commands.find((c) => c.name() === 'generate');
      expect(genCmd).toBeDefined();
      const optionNames = genCmd!.options.map((o) => o.long);
      expect(optionNames).toContain('--framework');
      expect(optionNames).toContain('--language');
      expect(optionNames).toContain('--format');
      expect(optionNames).toContain('--output-dir');
      expect(optionNames).toContain('--org');
      expect(optionNames).toContain('--input');
    });
  });

  describe('report summary', () => {
    it('should forward "summary" to executeCli', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['summary'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['summary']);
    });

    it('should forward --framework and --language options', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(
        ['summary', '--framework', 'tw_cyber_security_act', '--language', 'zh-TW'],
        { from: 'user' }
      );
      expect(mockedExecuteCli).toHaveBeenCalledWith([
        'summary',
        '--framework',
        'tw_cyber_security_act',
        '--language',
        'zh-TW',
      ]);
    });

    it('should forward --input option', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['summary', '--input', 'scan-results.json'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith([
        'summary',
        '--input',
        'scan-results.json',
      ]);
    });
  });

  describe('report list-frameworks', () => {
    it('should forward "list-frameworks" to executeCli', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['list-frameworks'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['list-frameworks']);
    });
  });

  describe('report validate', () => {
    it('should forward "validate" to executeCli', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['validate'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['validate']);
    });

    it('should forward --input option', async () => {
      const cmd = reportCommand();
      await cmd.parseAsync(['validate', '--input', 'findings.json'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['validate', '--input', 'findings.json']);
    });
  });

  describe('auth tier requirements', () => {
    it('should require "pro" tier for generate subcommand', async () => {
      const { withAuth } = vi.mocked(await import('../src/cli/auth-guard.js'));
      reportCommand();
      const proCalls = withAuth.mock.calls.filter((c) => c[0] === 'pro');
      // generate and summary both require 'pro'
      expect(proCalls.length).toBeGreaterThanOrEqual(2);
    });

    it('should not require auth for list-frameworks', async () => {
      // list-frameworks does not use withAuth; it directly calls executeCli
      const cmd = reportCommand();
      await cmd.parseAsync(['list-frameworks'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['list-frameworks']);
    });

    it('should not require auth for validate', async () => {
      // validate also does not use withAuth
      const cmd = reportCommand();
      await cmd.parseAsync(['validate'], { from: 'user' });
      expect(mockedExecuteCli).toHaveBeenCalledWith(['validate']);
    });
  });
});
