import { describe, it, expect } from 'vitest';
import {
  loadSecurityPolicy,
  isOperationAllowed,
  DEFAULT_SECURITY_POLICY,
  SecurityPolicySchema,
} from '../src/permissions/security-policy.js';
import type { SecurityPolicy } from '../src/types.js';

// ---------------------------------------------------------------------------
// Security Policy Loading
// ---------------------------------------------------------------------------
describe('Security Policy', () => {
  describe('loadSecurityPolicy', () => {
    it('should load valid security policy from config', () => {
      const policy = loadSecurityPolicy({
        allowShellAccess: true,
        allowedDirectories: ['/tmp'],
        allowedCommands: ['ls', 'cat'],
        requireCsrfToken: true,
        enableAuditLog: true,
      });
      expect(policy.allowShellAccess).toBe(true);
      expect(policy.allowedDirectories).toEqual(['/tmp']);
      expect(policy.allowedCommands).toEqual(['ls', 'cat']);
    });

    it('should fall back to defaults for invalid config (string)', () => {
      const policy = loadSecurityPolicy('invalid config');
      expect(policy).toEqual(DEFAULT_SECURITY_POLICY);
    });

    it('should fall back to defaults for invalid config (number)', () => {
      const policy = loadSecurityPolicy(42);
      expect(policy).toEqual(DEFAULT_SECURITY_POLICY);
    });

    it('should fall back to defaults for invalid config (null)', () => {
      const policy = loadSecurityPolicy(null);
      expect(policy).toEqual(DEFAULT_SECURITY_POLICY);
    });

    it('should fall back to defaults for invalid config (array)', () => {
      const policy = loadSecurityPolicy([1, 2, 3]);
      expect(policy).toEqual(DEFAULT_SECURITY_POLICY);
    });

    it('should fill missing fields with defaults', () => {
      const policy = loadSecurityPolicy({});
      expect(policy.allowShellAccess).toBe(false);
      expect(policy.requireCsrfToken).toBe(true);
      expect(policy.enableAuditLog).toBe(true);
      expect(policy.allowedDirectories).toEqual([]);
      expect(policy.allowedCommands).toEqual([]);
      expect(policy.allowedOrigins).toEqual([
        'http://localhost:18789',
        'http://127.0.0.1:18789',
      ]);
    });

    it('should preserve explicitly provided values', () => {
      const policy = loadSecurityPolicy({
        allowShellAccess: true,
        allowedDirectories: ['/home/user/project'],
        allowedCommands: ['npm', 'node'],
        requireCsrfToken: false,
        allowedOrigins: ['https://custom-origin.com'],
        enableAuditLog: false,
      });
      expect(policy.allowShellAccess).toBe(true);
      expect(policy.allowedDirectories).toEqual(['/home/user/project']);
      expect(policy.allowedCommands).toEqual(['npm', 'node']);
      expect(policy.requireCsrfToken).toBe(false);
      expect(policy.allowedOrigins).toEqual(['https://custom-origin.com']);
      expect(policy.enableAuditLog).toBe(false);
    });

    it('should load policy with optional syslog configuration', () => {
      const policy = loadSecurityPolicy({
        syslogServer: 'syslog.example.com',
        syslogPort: 1514,
      });
      expect(policy.syslogServer).toBe('syslog.example.com');
      expect(policy.syslogPort).toBe(1514);
    });

    it('should reject invalid syslog port (out of range)', () => {
      const policy = loadSecurityPolicy({
        syslogPort: 70000,
      });
      // Invalid port causes validation failure -> defaults
      expect(policy).toEqual(DEFAULT_SECURITY_POLICY);
    });

    it('should reject invalid syslog port (zero)', () => {
      const policy = loadSecurityPolicy({
        syslogPort: 0,
      });
      expect(policy).toEqual(DEFAULT_SECURITY_POLICY);
    });

    it('should reject invalid syslog port (negative)', () => {
      const policy = loadSecurityPolicy({
        syslogPort: -1,
      });
      expect(policy).toEqual(DEFAULT_SECURITY_POLICY);
    });

    it('should reject non-integer syslog port', () => {
      const policy = loadSecurityPolicy({
        syslogPort: 514.5,
      });
      expect(policy).toEqual(DEFAULT_SECURITY_POLICY);
    });

    it('should handle undefined optional fields', () => {
      const policy = loadSecurityPolicy({
        syslogServer: undefined,
        syslogPort: undefined,
      });
      expect(policy.syslogServer).toBeUndefined();
      expect(policy.syslogPort).toBeUndefined();
    });
  });

  describe('DEFAULT_SECURITY_POLICY', () => {
    it('should have secure defaults (restricted mode)', () => {
      expect(DEFAULT_SECURITY_POLICY.allowShellAccess).toBe(false);
      expect(DEFAULT_SECURITY_POLICY.requireCsrfToken).toBe(true);
      expect(DEFAULT_SECURITY_POLICY.enableAuditLog).toBe(true);
      expect(DEFAULT_SECURITY_POLICY.allowedDirectories).toEqual([]);
      expect(DEFAULT_SECURITY_POLICY.allowedCommands).toEqual([]);
    });

    it('should have default localhost origins', () => {
      expect(DEFAULT_SECURITY_POLICY.allowedOrigins).toContain('http://localhost:18789');
      expect(DEFAULT_SECURITY_POLICY.allowedOrigins).toContain('http://127.0.0.1:18789');
      expect(DEFAULT_SECURITY_POLICY.allowedOrigins).toHaveLength(2);
    });

    it('should not have syslog configured by default', () => {
      expect(DEFAULT_SECURITY_POLICY.syslogServer).toBeUndefined();
      expect(DEFAULT_SECURITY_POLICY.syslogPort).toBeUndefined();
    });
  });

  describe('SecurityPolicySchema', () => {
    it('should validate a fully specified policy', () => {
      const result = SecurityPolicySchema.safeParse({
        allowShellAccess: false,
        allowedDirectories: ['/tmp'],
        allowedCommands: ['ls'],
        requireCsrfToken: true,
        allowedOrigins: ['http://localhost:3000'],
        enableAuditLog: true,
        syslogServer: 'syslog.local',
        syslogPort: 514,
      });
      expect(result.success).toBe(true);
    });

    it('should apply defaults for empty object', () => {
      const result = SecurityPolicySchema.safeParse({});
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.allowShellAccess).toBe(false);
        expect(result.data.requireCsrfToken).toBe(true);
        expect(result.data.enableAuditLog).toBe(true);
      }
    });

    it('should reject non-boolean allowShellAccess', () => {
      const result = SecurityPolicySchema.safeParse({
        allowShellAccess: 'yes',
      });
      expect(result.success).toBe(false);
    });

    it('should reject non-array allowedDirectories', () => {
      const result = SecurityPolicySchema.safeParse({
        allowedDirectories: '/tmp',
      });
      expect(result.success).toBe(false);
    });

    it('should accept valid port range boundaries', () => {
      const result1 = SecurityPolicySchema.safeParse({ syslogPort: 1 });
      expect(result1.success).toBe(true);

      const result2 = SecurityPolicySchema.safeParse({ syslogPort: 65535 });
      expect(result2.success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Operation Permission Check
// ---------------------------------------------------------------------------
describe('Operation Permission Check', () => {
  describe('shell operation', () => {
    it('should block shell access in default policy', () => {
      expect(isOperationAllowed('shell', DEFAULT_SECURITY_POLICY)).toBe(false);
    });

    it('should allow shell when policy permits', () => {
      const policy: SecurityPolicy = { ...DEFAULT_SECURITY_POLICY, allowShellAccess: true };
      expect(isOperationAllowed('shell', policy)).toBe(true);
    });
  });

  describe('file operations', () => {
    it('should block file_read when no directories configured', () => {
      expect(isOperationAllowed('file_read', DEFAULT_SECURITY_POLICY)).toBe(false);
    });

    it('should allow file_read when directories configured', () => {
      const policy: SecurityPolicy = {
        ...DEFAULT_SECURITY_POLICY,
        allowedDirectories: ['/tmp'],
      };
      expect(isOperationAllowed('file_read', policy)).toBe(true);
    });

    it('should block file_write when no directories configured', () => {
      expect(isOperationAllowed('file_write', DEFAULT_SECURITY_POLICY)).toBe(false);
    });

    it('should allow file_write when directories configured', () => {
      const policy: SecurityPolicy = {
        ...DEFAULT_SECURITY_POLICY,
        allowedDirectories: ['/tmp'],
      };
      expect(isOperationAllowed('file_write', policy)).toBe(true);
    });
  });

  describe('command operation', () => {
    it('should block commands when no commands configured and shell disabled', () => {
      expect(isOperationAllowed('command', DEFAULT_SECURITY_POLICY)).toBe(false);
    });

    it('should allow commands when commands configured', () => {
      const policy: SecurityPolicy = { ...DEFAULT_SECURITY_POLICY, allowedCommands: ['ls'] };
      expect(isOperationAllowed('command', policy)).toBe(true);
    });

    it('should allow commands when shell access is enabled (even without whitelist)', () => {
      const policy: SecurityPolicy = {
        ...DEFAULT_SECURITY_POLICY,
        allowShellAccess: true,
        allowedCommands: [],
      };
      expect(isOperationAllowed('command', policy)).toBe(true);
    });
  });

  describe('network operation', () => {
    it('should always allow network by default', () => {
      expect(isOperationAllowed('network', DEFAULT_SECURITY_POLICY)).toBe(true);
    });

    it('should allow network even in most restrictive policy', () => {
      const restrictive: SecurityPolicy = {
        allowShellAccess: false,
        allowedDirectories: [],
        allowedCommands: [],
        requireCsrfToken: true,
        allowedOrigins: [],
        enableAuditLog: false,
      };
      expect(isOperationAllowed('network', restrictive)).toBe(true);
    });
  });

  describe('unknown operation', () => {
    it('should block unknown operation types', () => {
      // Cast to bypass TypeScript to test the default case
      expect(isOperationAllowed('unknown_op' as unknown as Parameters<typeof isOperationAllowed>[0], DEFAULT_SECURITY_POLICY)).toBe(false);
    });
  });
});
