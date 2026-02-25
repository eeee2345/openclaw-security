import { describe, it, expect } from 'vitest';
import { OsqueryProvider } from '../src/discovery/osquery-provider.js';

describe('OsqueryProvider', () => {
  let provider: OsqueryProvider;

  it('should create provider with default path', () => {
    provider = new OsqueryProvider();
    expect(provider).toBeDefined();
  });

  it('should create provider with custom path', () => {
    provider = new OsqueryProvider('/usr/bin/osqueryi');
    expect(provider).toBeDefined();
  });

  it('should detect osquery as unavailable when not installed', async () => {
    // Use a non-existent path to ensure it fails
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    const available = await provider.isAvailable();
    expect(available).toBe(false);
  });

  it('should cache availability result', async () => {
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    await provider.isAvailable();
    // Second call should use cached result
    const available = await provider.isAvailable();
    expect(available).toBe(false);
  });

  it('should throw on query when not available', async () => {
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    await provider.isAvailable();

    await expect(
      provider.query('SELECT 1')
    ).rejects.toThrow('osquery is not available');
  });

  it('should throw on getProcesses when not available', async () => {
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    await provider.isAvailable();

    await expect(
      provider.getProcesses()
    ).rejects.toThrow('osquery is not available');
  });

  it('should throw on getListeningPorts when not available', async () => {
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    await provider.isAvailable();

    await expect(
      provider.getListeningPorts()
    ).rejects.toThrow('osquery is not available');
  });

  it('should throw on getUsers when not available', async () => {
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    await provider.isAvailable();

    await expect(
      provider.getUsers()
    ).rejects.toThrow('osquery is not available');
  });

  it('should throw on getLoggedInUsers when not available', async () => {
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    await provider.isAvailable();

    await expect(
      provider.getLoggedInUsers()
    ).rejects.toThrow('osquery is not available');
  });

  it('should throw on getSystemInfo when not available', async () => {
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    await provider.isAvailable();

    await expect(
      provider.getSystemInfo()
    ).rejects.toThrow('osquery is not available');
  });

  it('should throw on getPortsAsPortInfo when not available', async () => {
    provider = new OsqueryProvider('/nonexistent/osqueryi');
    await provider.isAvailable();

    await expect(
      provider.getPortsAsPortInfo()
    ).rejects.toThrow('osquery is not available');
  });
});
