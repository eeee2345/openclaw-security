/**
 * Tests for Syscall Monitor
 * Syscall 監控器測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { parseSyscallEvent, SyscallMonitor } from '../src/monitors/syscall-monitor.js';
import type { SyscallEvent } from '../src/monitors/syscall-monitor.js';

describe('parseSyscallEvent', () => {
  it('should parse execve event correctly', () => {
    const raw: SyscallEvent = {
      syscall: 'execve',
      pid: 1234,
      uid: 1000,
      gid: 1000,
      comm: 'curl',
      timestamp: Date.now(),
      args: { parent_comm: 'bash' },
    };

    const event = parseSyscallEvent(raw);
    expect(event.source).toBe('syscall');
    expect(event.category).toBe('process_execution');
    expect(event.severity).toBe('medium');
    expect(event.description).toContain('curl');
    expect(event.description).toContain('PID 1234');
    expect(event.metadata?.['pid']).toBe(1234);
    expect(event.metadata?.['processName']).toBe('curl');
  });

  it('should flag suspicious processes as high severity', () => {
    const raw: SyscallEvent = {
      syscall: 'execve',
      pid: 5678,
      uid: 0,
      gid: 0,
      comm: 'nmap',
      timestamp: Date.now(),
      args: {},
    };

    const event = parseSyscallEvent(raw);
    expect(event.severity).toBe('high');
    expect(event.category).toBe('suspicious_execution');
  });

  it('should flag shell from unusual parent as high severity', () => {
    const raw: SyscallEvent = {
      syscall: 'execve',
      pid: 9000,
      uid: 33, // www-data
      gid: 33,
      comm: 'bash',
      timestamp: Date.now(),
      args: { parent_comm: 'apache2' },
    };

    const event = parseSyscallEvent(raw);
    expect(event.severity).toBe('high');
  });

  it('should not flag shell from normal parent', () => {
    const raw: SyscallEvent = {
      syscall: 'execve',
      pid: 9001,
      uid: 1000,
      gid: 1000,
      comm: 'bash',
      timestamp: Date.now(),
      args: { parent_comm: 'sshd' },
    };

    const event = parseSyscallEvent(raw);
    expect(event.severity).toBe('medium');
  });

  it('should parse setuid event as privilege escalation', () => {
    const raw: SyscallEvent = {
      syscall: 'setuid',
      pid: 2000,
      uid: 0,
      gid: 0,
      comm: 'exploit',
      timestamp: Date.now(),
      args: { target_id: 0, original_uid: 1000 },
    };

    const event = parseSyscallEvent(raw);
    expect(event.category).toBe('privilege_escalation');
    expect(event.severity).toBe('critical');
  });

  it('should parse non-root setuid as high', () => {
    const raw: SyscallEvent = {
      syscall: 'setuid',
      pid: 2001,
      uid: 1000,
      gid: 1000,
      comm: 'su',
      timestamp: Date.now(),
      args: { target_id: 1001 },
    };

    const event = parseSyscallEvent(raw);
    expect(event.severity).toBe('high');
  });

  it('should parse write to sensitive dir', () => {
    const raw: SyscallEvent = {
      syscall: 'write',
      pid: 3000,
      uid: 0,
      gid: 0,
      comm: 'malware',
      timestamp: Date.now(),
      args: { path: '/etc/passwd' },
    };

    const event = parseSyscallEvent(raw);
    expect(event.category).toBe('file_modification');
    expect(event.severity).toBe('high');
    expect(event.description).toContain('/etc/passwd');
  });

  it('should parse connect to suspicious port', () => {
    const raw: SyscallEvent = {
      syscall: 'connect',
      pid: 4000,
      uid: 1000,
      gid: 1000,
      comm: 'backdoor',
      timestamp: Date.now(),
      args: { addr: '10.0.0.1', port: 4444 },
    };

    const event = parseSyscallEvent(raw);
    expect(event.category).toBe('network_activity');
    expect(event.severity).toBe('high');
    expect(event.description).toContain('4444');
  });

  it('should parse ptrace event', () => {
    const raw: SyscallEvent = {
      syscall: 'ptrace',
      pid: 5000,
      uid: 0,
      gid: 0,
      comm: 'injector',
      timestamp: Date.now(),
      args: { target_pid: 1234 },
    };

    const event = parseSyscallEvent(raw);
    expect(event.category).toBe('process_injection');
    expect(event.severity).toBe('high');
    expect(event.description).toContain('ptrace');
  });

  it('should generate unique IDs', () => {
    const raw: SyscallEvent = {
      syscall: 'execve',
      pid: 100,
      uid: 0,
      gid: 0,
      comm: 'test',
      timestamp: Date.now(),
      args: {},
    };

    const e1 = parseSyscallEvent(raw);
    const e2 = parseSyscallEvent(raw);
    expect(e1.id).not.toBe(e2.id);
  });

  it('should generate IDs with syscall- prefix', () => {
    const raw: SyscallEvent = {
      syscall: 'execve',
      pid: 100,
      uid: 0,
      gid: 0,
      comm: 'test',
      timestamp: Date.now(),
      args: {},
    };

    const event = parseSyscallEvent(raw);
    expect(event.id).toMatch(/^syscall-/);
  });
});

describe('SyscallMonitor', () => {
  let monitor: SyscallMonitor;

  beforeEach(() => {
    monitor = new SyscallMonitor(1000);
  });

  afterEach(() => {
    monitor.stop();
  });

  it('should extend EventEmitter', () => {
    expect(typeof monitor.on).toBe('function');
    expect(typeof monitor.emit).toBe('function');
  });

  it('should return false on non-Linux platforms', async () => {
    // On macOS this will return false
    const available = await monitor.checkAvailability();
    if (process.platform !== 'linux') {
      expect(available).toBe(false);
    }
  });

  it('should track running state', () => {
    expect(monitor.isRunning()).toBe(false);
  });

  it('should stop cleanly even if not started', () => {
    expect(() => monitor.stop()).not.toThrow();
    expect(monitor.isRunning()).toBe(false);
  });
});
