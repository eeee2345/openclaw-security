import { describe, it, expect } from 'vitest';
import { isPathAllowed, createFilesystemGuard } from '../src/sandbox/filesystem-guard.js';
import {
  isCommandAllowed,
  createCommandValidator,
  extractBaseCommand,
  DEFAULT_ALLOWED_COMMANDS,
} from '../src/sandbox/command-whitelist.js';

describe('Filesystem Guard', () => {
  const allowedDirs = ['/home/user/.panguard/workspace', '/tmp/panguard-data'];

  it('should allow paths inside allowed directories', () => {
    expect(isPathAllowed('/home/user/.panguard/workspace/file.txt', allowedDirs)).toBe(true);
    expect(isPathAllowed('/tmp/panguard-data/report.json', allowedDirs)).toBe(true);
  });

  it('should block paths outside allowed directories', () => {
    expect(isPathAllowed('/etc/passwd', allowedDirs)).toBe(false);
    expect(isPathAllowed('/home/user/.ssh/id_rsa', allowedDirs)).toBe(false);
    expect(isPathAllowed('/root/.bashrc', allowedDirs)).toBe(false);
  });

  it('should block directory traversal attempts', () => {
    expect(isPathAllowed('/home/user/.panguard/workspace/../../.ssh/id_rsa', allowedDirs)).toBe(
      false
    );
    expect(isPathAllowed('/tmp/panguard-data/../../../etc/shadow', allowedDirs)).toBe(false);
  });

  it('should block when no allowed directories configured', () => {
    expect(isPathAllowed('/any/path', [])).toBe(false);
  });

  it('should throw via createFilesystemGuard for blocked paths', () => {
    const guard = createFilesystemGuard(allowedDirs);
    expect(() => guard('/etc/passwd')).toThrow('Filesystem access denied');
    expect(() => guard('/home/user/.panguard/workspace/ok.txt')).not.toThrow();
  });
});

describe('Command Whitelist', () => {
  it('should allow whitelisted commands', () => {
    expect(isCommandAllowed('ls')).toBe(true);
    expect(isCommandAllowed('git')).toBe(true);
    expect(isCommandAllowed('cat')).toBe(true);
    expect(isCommandAllowed('grep')).toBe(true);
  });

  it('should block non-whitelisted commands', () => {
    expect(isCommandAllowed('rm')).toBe(false);
    expect(isCommandAllowed('curl')).toBe(false);
    expect(isCommandAllowed('wget')).toBe(false);
    expect(isCommandAllowed('sudo')).toBe(false);
    expect(isCommandAllowed('chmod')).toBe(false);
  });

  it('should extract base command from full paths', () => {
    expect(extractBaseCommand('/usr/bin/ls -la')).toBe('ls');
    expect(extractBaseCommand('/bin/cat /etc/passwd')).toBe('cat');
    expect(extractBaseCommand('git status')).toBe('git');
  });

  it('should handle commands with arguments', () => {
    expect(isCommandAllowed('ls -la /tmp')).toBe(true);
    expect(isCommandAllowed('grep -r "pattern" /src')).toBe(true);
    expect(isCommandAllowed('rm -rf /')).toBe(false);
  });

  it('should support custom whitelists', () => {
    const custom = ['curl', 'jq'];
    expect(isCommandAllowed('curl', custom)).toBe(true);
    expect(isCommandAllowed('jq', custom)).toBe(true);
    expect(isCommandAllowed('ls', custom)).toBe(false);
  });

  it('should throw via createCommandValidator for blocked commands', () => {
    const validate = createCommandValidator();
    expect(() => validate('ls -la')).not.toThrow();
    expect(() => validate('rm -rf /')).toThrow('Command execution denied');
    expect(() => validate('sudo su')).toThrow('Command execution denied');
  });

  it('should have reasonable default commands', () => {
    expect(DEFAULT_ALLOWED_COMMANDS).toContain('ls');
    expect(DEFAULT_ALLOWED_COMMANDS).toContain('cat');
    expect(DEFAULT_ALLOWED_COMMANDS).toContain('git');
    expect(DEFAULT_ALLOWED_COMMANDS).not.toContain('rm');
    expect(DEFAULT_ALLOWED_COMMANDS).not.toContain('sudo');
  });
});
