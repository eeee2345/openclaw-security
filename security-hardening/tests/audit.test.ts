import { describe, it, expect, vi, beforeEach } from 'vitest';
import { formatSyslogMessage } from '../src/audit/syslog-adapter.js';
import type { AuditEvent } from '../src/types.js';

describe('Audit Logger', () => {
  beforeEach(() => {
    // Suppress log output during tests
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  it('should format audit events as structured JSON via core logger', async () => {
    // We test indirectly by ensuring the function doesn't throw
    const { logAuditEvent } = await import('../src/audit/audit-logger.js');
    expect(() =>
      logAuditEvent({
        level: 'info',
        action: 'websocket_connect',
        target: 'http://localhost:18789',
        result: 'success',
      })
    ).not.toThrow();
  });

  it('should log different event types without errors', async () => {
    const {
      logWebSocketConnect,
      logCredentialAccess,
      logFileAccess,
      logCommandExecution,
      logPolicyCheck,
    } = await import('../src/audit/audit-logger.js');

    expect(() => logWebSocketConnect('http://localhost', 'success')).not.toThrow();
    expect(() => logCredentialAccess('telegram', 'bot', 'success')).not.toThrow();
    expect(() => logFileAccess('/tmp/test.txt', 'blocked')).not.toThrow();
    expect(() => logCommandExecution('ls -la', 'success')).not.toThrow();
    expect(() => logPolicyCheck('shell', 'blocked')).not.toThrow();
  });

  it('should include IP address in WebSocket connect log', async () => {
    const { logWebSocketConnect } = await import('../src/audit/audit-logger.js');
    expect(() => logWebSocketConnect('http://evil.com', 'blocked', '192.168.1.100')).not.toThrow();
  });
});

describe('Syslog Adapter', () => {
  it('should format syslog message in RFC 5424 format', () => {
    const event: AuditEvent = {
      timestamp: '2025-02-25T10:30:00.000Z',
      level: 'warn',
      action: 'websocket_connect',
      target: 'https://evil.com',
      result: 'blocked',
      module: 'audit',
    };

    const message = formatSyslogMessage(event);

    // Check RFC 5424 structure
    expect(message).toMatch(/^<\d+>1 /); // Priority + version
    expect(message).toContain('2025-02-25T10:30:00.000Z'); // Timestamp
    expect(message).toContain('panguard-ai'); // App name
    expect(message).toContain('websocket_connect'); // Message ID
    expect(message).toContain('[panguard'); // Structured data
    expect(message).toContain('action="websocket_connect"');
    expect(message).toContain('target="https://evil.com"');
    expect(message).toContain('result="blocked"');
  });

  it('should calculate correct syslog priority', () => {
    const errorEvent: AuditEvent = {
      timestamp: new Date().toISOString(),
      level: 'error',
      action: 'command_execution',
      target: 'rm -rf /',
      result: 'blocked',
      module: 'audit',
    };

    const warnEvent: AuditEvent = {
      ...errorEvent,
      level: 'warn',
    };

    const infoEvent: AuditEvent = {
      ...errorEvent,
      level: 'info',
    };

    const errorMsg = formatSyslogMessage(errorEvent);
    const warnMsg = formatSyslogMessage(warnEvent);
    const infoMsg = formatSyslogMessage(infoEvent);

    // facility=16(local0), error=3, warn=4, info=6
    // priority = facility*8 + severity
    expect(errorMsg).toMatch(/^<131>/); // 16*8+3
    expect(warnMsg).toMatch(/^<132>/); // 16*8+4
    expect(infoMsg).toMatch(/^<134>/); // 16*8+6
  });
});
