/**
 * SkillWhitelistManager unit tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { SkillWhitelistManager } from '../src/engines/skill-whitelist.js';

// Mock logger
vi.mock('@panguard-ai/core', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

// Mock fs for persistence tests
vi.mock('node:fs', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('node:fs');
  return {
    ...actual,
    existsSync: vi.fn().mockReturnValue(false),
    readFileSync: vi.fn().mockReturnValue('{}'),
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn(),
  };
});

describe('SkillWhitelistManager', () => {
  let manager: SkillWhitelistManager;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -----------------------------------------------------------------------
  // Add a skill to whitelist
  // -----------------------------------------------------------------------
  describe('add', () => {
    it('should add a skill to the whitelist', () => {
      manager = new SkillWhitelistManager();
      const result = manager.add('read-file', 'manual', 'Trusted tool');

      expect(result).toBe(true);
      expect(manager.isWhitelisted('read-file')).toBe(true);
    });

    it('should normalize skill names (case-insensitive, trimmed)', () => {
      manager = new SkillWhitelistManager();
      manager.add('Read-File', 'manual');

      expect(manager.isWhitelisted('read-file')).toBe(true);
      expect(manager.isWhitelisted('READ-FILE')).toBe(true);
      expect(manager.isWhitelisted('  read-file  ')).toBe(true);
    });

    it('should not exceed max whitelist size', () => {
      manager = new SkillWhitelistManager({ maxSize: 2 });
      manager.add('skill-a', 'manual');
      manager.add('skill-b', 'manual');
      const result = manager.add('skill-c', 'manual');

      expect(result).toBe(false);
      expect(manager.isWhitelisted('skill-c')).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Revoke a skill
  // -----------------------------------------------------------------------
  describe('revoke', () => {
    it('should revoke a whitelisted skill', () => {
      manager = new SkillWhitelistManager();
      manager.add('web-search', 'manual');
      expect(manager.isWhitelisted('web-search')).toBe(true);

      const result = manager.revoke('web-search', 'Suspicious behavior');
      expect(result).toBe(true);
      expect(manager.isWhitelisted('web-search')).toBe(false);
    });

    it('should return false when revoking a skill that is not whitelisted', () => {
      manager = new SkillWhitelistManager();
      const result = manager.revoke('nonexistent-skill');
      expect(result).toBe(false);
    });

    it('should allow re-adding a revoked skill', () => {
      manager = new SkillWhitelistManager();
      manager.add('tool-x', 'manual');
      manager.revoke('tool-x');
      expect(manager.isWhitelisted('tool-x')).toBe(false);

      manager.add('tool-x', 'manual', 'Re-trusted');
      expect(manager.isWhitelisted('tool-x')).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Auto-promote after stable fingerprint
  // -----------------------------------------------------------------------
  describe('autoPromote', () => {
    it('should auto-promote a skill with a stable fingerprint', () => {
      manager = new SkillWhitelistManager({ autoPromoteStable: true });

      const result = manager.autoPromote('stable-tool', 'abc123def456');
      expect(result).toBe(true);
      expect(manager.isWhitelisted('stable-tool')).toBe(true);

      const all = manager.getAll();
      const entry = all.find((s) => s.normalizedName === 'stable-tool');
      expect(entry?.source).toBe('fingerprint');
      expect(entry?.fingerprintHash).toBe('abc123def456');
    });

    it('should not auto-promote when autoPromoteStable is disabled', () => {
      manager = new SkillWhitelistManager({ autoPromoteStable: false });

      const result = manager.autoPromote('some-tool', 'hash123');
      expect(result).toBe(false);
      expect(manager.isWhitelisted('some-tool')).toBe(false);
    });

    it('should not overwrite a static/manual whitelisted skill via auto-promote', () => {
      manager = new SkillWhitelistManager({ autoPromoteStable: true });
      manager.add('core-tool', 'static', 'Always trusted');

      const result = manager.autoPromote('core-tool', 'newhash');
      expect(result).toBe(false);

      const all = manager.getAll();
      const entry = all.find((s) => s.normalizedName === 'core-tool');
      expect(entry?.source).toBe('static');
    });
  });

  // -----------------------------------------------------------------------
  // Prevent promotion of revoked skill
  // -----------------------------------------------------------------------
  describe('revoked skill cannot be auto-promoted', () => {
    it('should prevent auto-promotion of a revoked skill', () => {
      manager = new SkillWhitelistManager({ autoPromoteStable: true });
      manager.add('bad-tool', 'fingerprint');
      manager.revoke('bad-tool', 'Drift detected');

      const result = manager.autoPromote('bad-tool', 'newhash');
      expect(result).toBe(false);
      expect(manager.isWhitelisted('bad-tool')).toBe(false);
    });

    it('onFingerprintDrift should revoke fingerprint-sourced entries', () => {
      manager = new SkillWhitelistManager({ autoPromoteStable: true });
      manager.autoPromote('drifty-tool', 'hash1');
      expect(manager.isWhitelisted('drifty-tool')).toBe(true);

      manager.onFingerprintDrift('drifty-tool');
      expect(manager.isWhitelisted('drifty-tool')).toBe(false);
    });

    it('onFingerprintDrift should NOT revoke static/manual entries', () => {
      manager = new SkillWhitelistManager();
      manager.add('static-tool', 'static', 'Core tool');

      manager.onFingerprintDrift('static-tool');
      expect(manager.isWhitelisted('static-tool')).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Persistence (save/load)
  // -----------------------------------------------------------------------
  describe('persistence', () => {
    it('should persist whitelist to disk on add', () => {
      const mockExistsSync = vi.mocked(existsSync);
      const mockWriteFileSync = vi.mocked(writeFileSync);
      mockExistsSync.mockReturnValue(false);

      manager = new SkillWhitelistManager({ persistPath: '/tmp/test-whitelist.json' });
      manager.add('persist-tool', 'manual', 'Test persist');

      expect(mockWriteFileSync).toHaveBeenCalled();
      const [path, content] = mockWriteFileSync.mock.calls.at(-1)!;
      expect(path).toBe('/tmp/test-whitelist.json');

      const data = JSON.parse(content as string) as {
        whitelist: Array<{ name: string }>;
        revoked: string[];
      };
      expect(data.whitelist.some((s) => s.name === 'persist-tool')).toBe(true);
    });

    it('should load whitelist from disk on construction', () => {
      const mockExistsSync = vi.mocked(existsSync);
      const mockReadFileSync = vi.mocked(readFileSync);

      const savedData = {
        whitelist: [
          {
            name: 'loaded-tool',
            normalizedName: 'loaded-tool',
            source: 'manual',
            addedAt: '2025-01-01T00:00:00.000Z',
          },
        ],
        revoked: ['revoked-tool'],
      };

      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(JSON.stringify(savedData));

      manager = new SkillWhitelistManager({ persistPath: '/tmp/test-whitelist.json' });

      expect(manager.isWhitelisted('loaded-tool')).toBe(true);
    });

    it('should persist revoked list on revoke', () => {
      const mockExistsSync = vi.mocked(existsSync);
      const mockWriteFileSync = vi.mocked(writeFileSync);
      mockExistsSync.mockReturnValue(false);

      manager = new SkillWhitelistManager({ persistPath: '/tmp/test-whitelist.json' });
      manager.add('revoke-me', 'manual');
      manager.revoke('revoke-me');

      const lastCall = mockWriteFileSync.mock.calls.at(-1)!;
      const data = JSON.parse(lastCall[1] as string) as {
        whitelist: Array<{ name: string }>;
        revoked: string[];
      };
      expect(data.revoked).toContain('revoke-me');
    });
  });
});
