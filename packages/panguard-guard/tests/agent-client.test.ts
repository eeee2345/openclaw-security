/**
 * PanguardAgentClient unit tests
 * PanguardAgentClient 單元測試
 */

import { describe, it, expect } from 'vitest';
import { PanguardAgentClient } from '../src/agent-client/index.js';

describe('PanguardAgentClient', () => {
  it('should initialize with manager URL', () => {
    const client = new PanguardAgentClient('http://localhost:8443');
    expect(client.isRegistered()).toBe(false);
    expect(client.getAgentId()).toBeNull();
  });

  it('should strip trailing slash from manager URL', () => {
    const client = new PanguardAgentClient('http://localhost:8443///');
    expect(client.isRegistered()).toBe(false);
  });

  it('should throw on heartbeat before registration', async () => {
    const client = new PanguardAgentClient('http://localhost:8443');
    await expect(
      client.heartbeat({
        eventsProcessed: 0,
        threatsDetected: 0,
        actionsExecuted: 0,
        mode: 'learning',
        uptime: 0,
        memoryUsageMB: 0,
      }),
    ).rejects.toThrow('Agent not registered');
  });

  it('should throw on reportEvent before registration', async () => {
    const client = new PanguardAgentClient('http://localhost:8443');
    await expect(
      client.reportEvent({
        event: {
          id: 'test-1',
          timestamp: new Date(),
          source: 'network',
          severity: 'high',
          category: 'test',
          description: 'test event',
          raw: {},
          host: 'localhost',
        },
      }),
    ).rejects.toThrow('Agent not registered');
  });

  it('should throw on pullRules before registration', async () => {
    const client = new PanguardAgentClient('http://localhost:8443');
    await expect(client.pullRules()).rejects.toThrow('Agent not registered');
  });
});
