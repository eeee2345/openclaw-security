import { describe, it, expect, vi, afterEach } from 'vitest';

import {
  AdapterRegistry,
  DefenderAdapter,
  WazuhAdapter,
  parseSyslogMessage,
} from '@panguard-ai/core/adapters/index.js';

// Suppress stderr output from logger during tests
const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

afterEach(() => {
  stderrSpy.mockClear();
});

describe('AdapterRegistry', () => {
  it('should create and have initial empty state', () => {
    const registry = new AdapterRegistry();

    expect(registry.size).toBe(0);
    expect(registry.getAvailableAdapters()).toEqual([]);
    expect(registry.getAdapterNames()).toEqual([]);
    expect(registry.getAdapter('nonexistent')).toBeUndefined();
  });

  it('should handle autoDetect gracefully with no tools available', async () => {
    const registry = new AdapterRegistry();

    // autoDetect without discovery result should not throw
    await registry.autoDetect();

    // On macOS, Defender is not available, so no adapters should be registered
    // (Defender checks process.platform !== 'win32' and returns false)
    expect(registry.size).toBe(0);
    expect(registry.getAvailableAdapters()).toEqual([]);
  });
});

describe('DefenderAdapter', () => {
  it('should return isAvailable false on non-Windows (macOS)', async () => {
    const adapter = new DefenderAdapter({ enabled: true });

    const available = await adapter.isAvailable();

    // We are on macOS/Linux, so Defender should not be available
    expect(available).toBe(false);
    expect(adapter.name).toBe('Windows Defender');
    expect(adapter.type).toBe('antivirus');
  });
});

describe('WazuhAdapter', () => {
  it('should return isAvailable false without server', async () => {
    const adapter = new WazuhAdapter({
      enabled: true,
      endpoint: 'https://localhost:55000',
      username: 'test',
      password: 'test',
    });

    const available = await adapter.isAvailable();

    // No Wazuh server running, so should be false
    expect(available).toBe(false);
    expect(adapter.name).toBe('Wazuh');
    expect(adapter.type).toBe('siem');
  });
});

describe('SyslogAdapter', () => {
  it('should parse an RFC 5424 syslog message', () => {
    // RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    // PRI = facility * 8 + severity
    // facility 4 (auth) * 8 + severity 3 (error) = 35
    const rawMessage =
      '<35>1 2025-03-15T10:30:00Z webserver01 sshd 12345 AUTH_FAIL [meta key="value"] Failed password for root from 10.0.0.1';

    const parsed = parseSyslogMessage(rawMessage);

    expect(parsed.facility).toBe(4); // auth (35 / 8 = 4)
    expect(parsed.severityCode).toBe(3); // error (35 % 8 = 3)
    expect(parsed.version).toBe(1);
    expect(parsed.timestamp).toBe('2025-03-15T10:30:00Z');
    expect(parsed.hostname).toBe('webserver01');
    expect(parsed.appName).toBe('sshd');
    expect(parsed.procId).toBe('12345');
    expect(parsed.msgId).toBe('AUTH_FAIL');
    expect(parsed.structuredData).toBe('[meta key="value"]');
    expect(parsed.message).toBe('Failed password for root from 10.0.0.1');
  });
});
