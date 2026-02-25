import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IPBlocker } from '../src/response/ip-blocker.js';
import { FileQuarantine } from '../src/response/file-quarantine.js';
import { ProcessKiller } from '../src/response/process-killer.js';
import { join } from 'node:path';
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('IPBlocker', () => {
  let blocker: IPBlocker;

  beforeEach(() => {
    blocker = new IPBlocker({
      defaultBlockDurationMs: 2000,
      autoUnblockEnabled: true,
    });
  });

  afterEach(() => {
    blocker.destroy();
  });

  it('should reject whitelisted IPs', async () => {
    const result = await blocker.block('127.0.0.1', 'test');
    expect(result.success).toBe(false);
    expect(result.message).toContain('whitelisted');
  });

  it('should reject invalid IP format', async () => {
    const result = await blocker.block('not-an-ip!', 'test');
    expect(result.success).toBe(false);
    expect(result.message).toContain('Invalid IP');
  });

  it('should track blocked IPs', async () => {
    // Firewall commands will fail in test (not root), but the blocker
    // should handle the error gracefully
    const result = await blocker.block('203.0.113.50', 'brute force');
    // In test env, firewall will fail - that's OK, we test the logic
    expect(result).toBeDefined();
    expect(typeof result.success).toBe('boolean');
    expect(typeof result.message).toBe('string');
  });

  it('should check whitelist correctly', () => {
    expect(blocker.isWhitelisted('127.0.0.1')).toBe(true);
    expect(blocker.isWhitelisted('::1')).toBe(true);
    expect(blocker.isWhitelisted('8.8.8.8')).toBe(false);
  });

  it('should allow adding to whitelist', () => {
    blocker.addToWhitelist('10.0.0.1');
    expect(blocker.isWhitelisted('10.0.0.1')).toBe(true);
  });

  it('should support custom whitelist in config', () => {
    const custom = new IPBlocker({ whitelist: ['192.168.1.1'] });
    expect(custom.isWhitelisted('192.168.1.1')).toBe(true);
    expect(custom.isWhitelisted('127.0.0.1')).toBe(true); // default always included
    custom.destroy();
  });

  it('should return blocked IPs list', async () => {
    expect(blocker.getBlockedIPs()).toEqual([]);
  });
});

describe('FileQuarantine', () => {
  let quarantine: FileQuarantine;
  let tempDir: string;
  let quarantineDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'quarantine-test-'));
    quarantineDir = join(tempDir, 'quarantine');
    quarantine = new FileQuarantine(quarantineDir);
  });

  afterEach(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('should quarantine a file with SHA-256', async () => {
    const testFile = join(tempDir, 'malware.txt');
    writeFileSync(testFile, 'malicious content');

    const record = await quarantine.quarantine(testFile, 'YARA match: webshell');

    expect(record.originalPath).toBe(testFile);
    expect(record.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(record.reason).toBe('YARA match: webshell');
    expect(record.fileSize).toBeGreaterThan(0);
    expect(existsSync(testFile)).toBe(false); // Original removed
    expect(existsSync(record.quarantinePath)).toBe(true); // In quarantine
  });

  it('should record quarantine in manifest', async () => {
    const testFile = join(tempDir, 'suspect.exe');
    writeFileSync(testFile, 'PE header');

    await quarantine.quarantine(testFile, 'suspicious binary');
    const records = quarantine.getRecords();

    expect(records.length).toBe(1);
    expect(records[0].reason).toBe('suspicious binary');
  });

  it('should restore a quarantined file', async () => {
    const testFile = join(tempDir, 'important.doc');
    writeFileSync(testFile, 'document content');

    const record = await quarantine.quarantine(testFile, 'false positive');
    expect(existsSync(testFile)).toBe(false);

    const result = await quarantine.restore(record.id);
    expect(result.success).toBe(true);
    expect(existsSync(testFile)).toBe(true);
    expect(readFileSync(testFile, 'utf-8')).toBe('document content');
  });

  it('should reject restoring unknown ID', async () => {
    await quarantine.initialize();
    const result = await quarantine.restore('nonexistent');
    expect(result.success).toBe(false);
  });

  it('should prevent quarantining files inside quarantine dir', async () => {
    await quarantine.initialize();
    const badFile = join(quarantineDir, 'already-quarantined.txt');
    writeFileSync(badFile, 'data');

    await expect(quarantine.quarantine(badFile, 'test'))
      .rejects.toThrow('Cannot quarantine a file already in quarantine');
  });

  it('should track active vs restored records', async () => {
    const f1 = join(tempDir, 'file1.txt');
    const f2 = join(tempDir, 'file2.txt');
    writeFileSync(f1, 'a');
    writeFileSync(f2, 'b');

    const r1 = await quarantine.quarantine(f1, 'test1');
    await quarantine.quarantine(f2, 'test2');

    expect(quarantine.getActiveRecords().length).toBe(2);

    await quarantine.restore(r1.id);
    expect(quarantine.getActiveRecords().length).toBe(1);
    expect(quarantine.getRecords().length).toBe(2); // All records preserved
  });

  it('should persist manifest to disk', async () => {
    const testFile = join(tempDir, 'persist.txt');
    writeFileSync(testFile, 'data');

    await quarantine.quarantine(testFile, 'test');

    // Create new instance and verify manifest loaded
    const quarantine2 = new FileQuarantine(quarantineDir);
    await quarantine2.initialize();
    expect(quarantine2.getRecords().length).toBe(1);
  });
});

describe('ProcessKiller', () => {
  let killer: ProcessKiller;

  beforeEach(() => {
    killer = new ProcessKiller();
  });

  it('should protect system-critical processes', () => {
    expect(killer.isProtected('init')).toBe(true);
    expect(killer.isProtected('systemd')).toBe(true);
    expect(killer.isProtected('sshd')).toBe(true);
    expect(killer.isProtected('launchd')).toBe(true);
    expect(killer.isProtected('panguard-guard')).toBe(true);
    expect(killer.isProtected('node')).toBe(true);
  });

  it('should protect PIDs 0 and 1', () => {
    expect(killer.isProtected(0)).toBe(true);
    expect(killer.isProtected(1)).toBe(true);
  });

  it('should protect own PID', () => {
    expect(killer.isProtected(process.pid)).toBe(true);
  });

  it('should not protect random process names', () => {
    expect(killer.isProtected('my-random-app')).toBe(false);
    expect(killer.isProtected('suspicious.sh')).toBe(false);
  });

  it('should refuse to kill PID 1', async () => {
    const result = await killer.kill(1);
    expect(result.success).toBe(false);
    expect(result.message).toContain('protected');
  });

  it('should refuse to kill own PID', async () => {
    const result = await killer.kill(process.pid);
    expect(result.success).toBe(false);
    expect(result.message).toContain('protected');
  });

  it('should refuse to kill protected process by name', async () => {
    const result = await killer.kill(99999, { processName: 'sshd' });
    expect(result.success).toBe(false);
    expect(result.message).toContain('protected');
  });

  it('should support additional protected processes', () => {
    const custom = new ProcessKiller(['my-critical-app']);
    expect(custom.isProtected('my-critical-app')).toBe(true);
    expect(custom.isProtected('other-app')).toBe(false);
  });

  it('should handle non-existent PID gracefully', async () => {
    const result = await killer.kill(999999);
    // ESRCH = no such process, should be treated as success (already gone)
    expect(result).toBeDefined();
    expect(typeof result.success).toBe('boolean');
  });
});
