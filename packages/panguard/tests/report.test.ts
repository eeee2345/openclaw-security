/**
 * Tests for `panguard report` command
 * Tests command structure and subcommand registration.
 * The report command is a "Coming Soon" stub — subcommands print COMING_SOON_MSG.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { reportCommand } from '../src/cli/commands/report.js';

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
    it('should run "generate" without error', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['generate'], { from: 'user' });
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
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

    it('should accept --framework option', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(['generate', '--framework', 'iso27001'], { from: 'user' })
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });

    it('should accept --language option', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(['generate', '--language', 'zh-TW'], { from: 'user' })
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });

    it('should accept --format option', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(['generate', '--format', 'pdf'], { from: 'user' })
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });

    it('should accept --output-dir option', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(['generate', '--output-dir', '/tmp/reports'], { from: 'user' })
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });

    it('should accept --org option', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(['generate', '--org', 'Acme Corp'], { from: 'user' })
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });

    it('should accept --input option', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(['generate', '--input', './findings.json'], { from: 'user' })
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });

    it('should accept all generate options combined', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(
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
        )
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });
  });

  describe('report summary', () => {
    it('should run "summary" without error', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['summary'], { from: 'user' });
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('should accept --framework and --language options', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(
          ['summary', '--framework', 'tw_cyber_security_act', '--language', 'zh-TW'],
          { from: 'user' }
        )
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });

    it('should accept --input option', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(['summary', '--input', 'scan-results.json'], { from: 'user' })
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });
  });

  describe('report list-frameworks', () => {
    it('should run "list-frameworks" without error', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['list-frameworks'], { from: 'user' });
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe('report validate', () => {
    it('should run "validate" without error', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await cmd.parseAsync(['validate'], { from: 'user' });
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('should accept --input option', async () => {
      const cmd = reportCommand();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await expect(
        cmd.parseAsync(['validate', '--input', 'findings.json'], { from: 'user' })
      ).resolves.not.toThrow();
      consoleSpy.mockRestore();
    });
  });

  describe('coming soon behavior', () => {
    it('should print a coming soon message for all subcommands', async () => {
      const subcommands = ['generate', 'summary', 'list-frameworks', 'validate'];
      for (const sub of subcommands) {
        const cmd = reportCommand();
        const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        await cmd.parseAsync([sub], { from: 'user' });
        expect(consoleSpy).toHaveBeenCalled();
        const output: string = consoleSpy.mock.calls.map((c) => String(c[0])).join('');
        expect(output.toLowerCase()).toMatch(/coming soon|即將推出/i);
        consoleSpy.mockRestore();
      }
    });
  });
});
