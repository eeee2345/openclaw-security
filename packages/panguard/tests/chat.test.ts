/**
 * Tests for `panguard chat` command
 * Tests command structure, subcommand registration, and argument forwarding
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { chatCommand } from '../src/cli/commands/chat.js';

// Mock the chat CLI
vi.mock('@panguard-ai/panguard-chat', () => ({
  runCLI: vi.fn().mockResolvedValue(undefined),
}));

// Mock auth-guard to bypass authentication for testing
vi.mock('../src/cli/auth-guard.js', () => ({
  withAuth: vi.fn((_tier: string, handler: (opts: Record<string, string | undefined>) => Promise<void>) => {
    return async (opts: Record<string, string | undefined>) => {
      await handler(opts);
    };
  }),
}));

import { runCLI } from '@panguard-ai/panguard-chat';

const mockedRunCLI = vi.mocked(runCLI);

describe('chatCommand', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create a command named "chat"', () => {
    const cmd = chatCommand();
    expect(cmd.name()).toBe('chat');
  });

  it('should have a description mentioning notifications', () => {
    const cmd = chatCommand();
    expect(cmd.description()).toContain('Notification');
  });

  describe('subcommands', () => {
    it('should register expected subcommands', () => {
      const cmd = chatCommand();
      const subcommandNames = cmd.commands.map((c) => c.name());
      expect(subcommandNames).toContain('setup');
      expect(subcommandNames).toContain('test');
      expect(subcommandNames).toContain('status');
      expect(subcommandNames).toContain('config');
      expect(subcommandNames).toContain('prefs');
    });

    it('should have 5 subcommands', () => {
      const cmd = chatCommand();
      expect(cmd.commands).toHaveLength(5);
    });
  });

  describe('chat setup', () => {
    it('should forward "setup" to runCLI with defaults', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['setup'], { from: 'user' });
      // --lang defaults to 'zh-TW', so it is always forwarded
      expect(mockedRunCLI).toHaveBeenCalledWith(['setup', '--lang', 'zh-TW']);
    });

    it('should forward --lang option', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['setup', '--lang', 'en'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith(['setup', '--lang', 'en']);
    });

    it('should forward --channel option along with default --lang', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['setup', '--channel', 'telegram'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith([
        'setup',
        '--lang',
        'zh-TW',
        '--channel',
        'telegram',
      ]);
    });

    it('should forward --user-type option along with default --lang', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['setup', '--user-type', 'developer'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith([
        'setup',
        '--lang',
        'zh-TW',
        '--user-type',
        'developer',
      ]);
    });

    it('should forward all setup options combined', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(
        ['setup', '--lang', 'zh-TW', '--channel', 'slack', '--user-type', 'it_admin'],
        { from: 'user' }
      );
      expect(mockedRunCLI).toHaveBeenCalledWith([
        'setup',
        '--lang',
        'zh-TW',
        '--channel',
        'slack',
        '--user-type',
        'it_admin',
      ]);
    });

    it('should have setup --lang default to zh-TW', () => {
      const cmd = chatCommand();
      const setupCmd = cmd.commands.find((c) => c.name() === 'setup');
      const langOpt = setupCmd!.options.find((o) => o.long === '--lang');
      expect(langOpt).toBeDefined();
      expect(langOpt!.defaultValue).toBe('zh-TW');
    });
  });

  describe('chat test', () => {
    it('should forward "test" to runCLI with defaults', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['test'], { from: 'user' });
      // --channel defaults to 'webhook' and --lang defaults to 'zh-TW'
      expect(mockedRunCLI).toHaveBeenCalledWith([
        'test',
        '--channel',
        'webhook',
        '--lang',
        'zh-TW',
      ]);
    });

    it('should forward --channel and --url options with default --lang', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(
        ['test', '--channel', 'webhook', '--url', 'https://hooks.example.com/notify'],
        { from: 'user' }
      );
      expect(mockedRunCLI).toHaveBeenCalledWith([
        'test',
        '--channel',
        'webhook',
        '--url',
        'https://hooks.example.com/notify',
        '--lang',
        'zh-TW',
      ]);
    });

    it('should have test --channel default to webhook', () => {
      const cmd = chatCommand();
      const testCmd = cmd.commands.find((c) => c.name() === 'test');
      const channelOpt = testCmd!.options.find((o) => o.long === '--channel');
      expect(channelOpt!.defaultValue).toBe('webhook');
    });
  });

  describe('chat status', () => {
    it('should forward "status" to runCLI', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['status'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith(['status']);
    });
  });

  describe('chat config', () => {
    it('should forward "config" to runCLI', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['config'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith(['config']);
    });
  });

  describe('chat prefs', () => {
    it('should forward "prefs" to runCLI without options', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['prefs'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith(['prefs']);
    });

    it('should forward --critical option', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['prefs', '--critical', 'on'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith(['prefs', '--critical', 'on']);
    });

    it('should forward --daily option', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['prefs', '--daily', 'off'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith(['prefs', '--daily', 'off']);
    });

    it('should forward --weekly and --peaceful options', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(['prefs', '--weekly', 'on', '--peaceful', 'off'], { from: 'user' });
      expect(mockedRunCLI).toHaveBeenCalledWith([
        'prefs',
        '--weekly',
        'on',
        '--peaceful',
        'off',
      ]);
    });

    it('should forward all preference options combined', async () => {
      const cmd = chatCommand();
      await cmd.parseAsync(
        ['prefs', '--critical', 'on', '--daily', 'on', '--weekly', 'off', '--peaceful', 'on'],
        { from: 'user' }
      );
      expect(mockedRunCLI).toHaveBeenCalledWith([
        'prefs',
        '--critical',
        'on',
        '--daily',
        'on',
        '--weekly',
        'off',
        '--peaceful',
        'on',
      ]);
    });
  });

  describe('auth tier requirements', () => {
    it('should require "solo" tier for setup', async () => {
      const { withAuth } = vi.mocked(await import('../src/cli/auth-guard.js'));
      chatCommand(); // Triggers the withAuth calls during command registration
      // withAuth should have been called with 'solo' for setup
      const calls = withAuth.mock.calls;
      const setupCall = calls.find((c) => c[0] === 'solo');
      expect(setupCall).toBeDefined();
    });
  });
});
