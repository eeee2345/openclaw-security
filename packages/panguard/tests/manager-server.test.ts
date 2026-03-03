/**
 * ManagerServer integration tests
 * Uses the production @panguard-ai/manager ManagerServer
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ManagerServer, DEFAULT_MANAGER_CONFIG } from '@panguard-ai/manager';
import type { ManagerConfig } from '@panguard-ai/manager';

// Use a random high port to avoid conflicts
const TEST_PORT = 19843;
const TEST_AUTH_TOKEN = 'test-auth-token-12345';
let server: ManagerServer;

const config: ManagerConfig = {
  ...DEFAULT_MANAGER_CONFIG,
  port: TEST_PORT,
  authToken: TEST_AUTH_TOKEN,
};

const authHeaders = {
  'Content-Type': 'application/json',
  Authorization: `Bearer ${TEST_AUTH_TOKEN}`,
};

describe('ManagerServer (production)', () => {
  beforeAll(async () => {
    server = new ManagerServer(config);
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('should start and respond to health check', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/health`);
    expect(res.status).toBe(200);

    const data = (await res.json()) as { ok: boolean; data: { status: string } };
    expect(data.ok).toBe(true);
    expect(data.data.status).toBe('healthy');
  });

  it('should reject unauthenticated requests', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/agents`);
    expect(res.status).toBe(401);
  });

  it('should register an agent', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        hostname: 'test-host',
        endpoint: 'http://localhost:9999',
        os: 'Linux 6.1',
        arch: 'x64',
        version: '1.0.0',
        ip: '192.168.1.100',
      }),
    });

    expect(res.status).toBe(201);
    const data = (await res.json()) as {
      ok: boolean;
      data: { agentId: string; hostname: string };
    };
    expect(data.ok).toBe(true);
    expect(data.data.agentId).toBeDefined();
    expect(data.data.hostname).toBe('test-host');
  });

  it('should list registered agents', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/agents`, {
      headers: { Authorization: `Bearer ${TEST_AUTH_TOKEN}` },
    });
    expect(res.status).toBe(200);

    const data = (await res.json()) as { ok: boolean; data: unknown[] };
    expect(data.ok).toBe(true);
    expect(Array.isArray(data.data)).toBe(true);
  });

  it('should accept heartbeat', async () => {
    // Register first
    const regRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        hostname: 'heartbeat-test',
        endpoint: 'http://localhost:9998',
        os: 'Darwin 24.0',
        arch: 'arm64',
        version: '1.0.0',
      }),
    });
    const regData = (await regRes.json()) as {
      ok: boolean;
      data: { agentId: string };
    };
    const agentId = regData.data.agentId;

    // Send heartbeat
    const hbRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/${agentId}/heartbeat`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        agentId,
        timestamp: new Date().toISOString(),
        cpuUsage: 15.5,
        memUsage: 42.3,
        activeMonitors: 3,
        threatCount: 0,
        eventsProcessed: 42,
        mode: 'protection',
        uptime: 60000,
      }),
    });

    expect(hbRes.status).toBe(200);
    const data = (await hbRes.json()) as { ok: boolean };
    expect(data.ok).toBe(true);
  });

  it('should accept threat reports', async () => {
    // Register first
    const regRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        hostname: 'event-test',
        endpoint: 'http://localhost:9997',
        os: 'Linux',
        arch: 'x64',
        version: '1.0.0',
      }),
    });
    const regData = (await regRes.json()) as {
      ok: boolean;
      data: { agentId: string };
    };
    const agentId = regData.data.agentId;

    // Report threat
    const eventRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/${agentId}/events`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        agentId,
        threats: [
          {
            event: {
              id: 'test-event-1',
              type: 'file_modified',
              source: 'network',
              severity: 'high',
              timestamp: new Date().toISOString(),
              metadata: {},
            },
            verdict: { conclusion: 'malicious', confidence: 92, action: 'block_ip' },
          },
        ],
        reportedAt: new Date().toISOString(),
      }),
    });

    expect(eventRes.status).toBe(200);
    const data = (await eventRes.json()) as { ok: boolean };
    expect(data.ok).toBe(true);
  });

  it('should provide overview data', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/overview`, {
      headers: { Authorization: `Bearer ${TEST_AUTH_TOKEN}` },
    });
    expect(res.status).toBe(200);

    const data = (await res.json()) as {
      ok: boolean;
      data: { totalAgents: number; onlineAgents: number };
    };
    expect(data.ok).toBe(true);
    expect(data.data.totalAgents).toBeGreaterThanOrEqual(1);
  });

  it('should provide threat summary', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/threats/summary`, {
      headers: { Authorization: `Bearer ${TEST_AUTH_TOKEN}` },
    });
    expect(res.status).toBe(200);

    const data = (await res.json()) as {
      ok: boolean;
      data: { totalThreats: number };
    };
    expect(data.ok).toBe(true);
    expect(typeof data.data.totalThreats).toBe('number');
  });

  it('should deregister an agent', async () => {
    // Register
    const regRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        hostname: 'delete-test',
        endpoint: 'http://localhost:9996',
        os: 'Linux',
        arch: 'x64',
        version: '1.0.0',
      }),
    });
    const regData = (await regRes.json()) as {
      ok: boolean;
      data: { agentId: string };
    };
    const agentId = regData.data.agentId;

    // Deregister
    const delRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/${agentId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${TEST_AUTH_TOKEN}` },
    });
    expect(delRes.status).toBe(200);

    const data = (await delRes.json()) as { ok: boolean; data: { removed: boolean } };
    expect(data.ok).toBe(true);
    expect(data.data.removed).toBe(true);
  });

  it('should return 404 for unknown routes', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/nonexistent`, {
      headers: { Authorization: `Bearer ${TEST_AUTH_TOKEN}` },
    });
    expect(res.status).toBe(404);
  });
});
