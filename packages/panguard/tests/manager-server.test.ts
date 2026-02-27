/**
 * ManagerServer unit tests
 * ManagerServer 單元測試
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ManagerServer } from '../src/manager/manager-server.js';

// Use a random high port to avoid conflicts
const TEST_PORT = 19843;
let server: ManagerServer;

describe('ManagerServer', () => {
  beforeAll(async () => {
    server = new ManagerServer(TEST_PORT);
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('should start and listen on the configured port', () => {
    expect(server.getPort()).toBe(TEST_PORT);
  });

  it('should register an agent', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hostname: 'test-host',
        os: 'Linux 6.1',
        arch: 'x64',
        version: '1.0.0',
        ip: '192.168.1.100',
      }),
    });

    expect(res.status).toBe(201);
    const data = (await res.json()) as { agentId: string; token: string };
    expect(data.agentId).toMatch(/^agent-/);
    expect(data.token).toBeDefined();
    expect(typeof data.token).toBe('string');
  });

  it('should list registered agents', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/agents`);
    expect(res.status).toBe(200);

    const data = (await res.json()) as {
      agents: Array<{ id: string; hostname: string }>;
      total: number;
    };
    expect(data.total).toBeGreaterThanOrEqual(1);
    expect(data.agents[0]!.hostname).toBe('test-host');
  });

  it('should accept heartbeat with valid token', async () => {
    // Register first
    const regRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hostname: 'heartbeat-test',
        os: 'Darwin 24.0',
        arch: 'arm64',
        version: '1.0.0',
      }),
    });
    const { agentId, token } = (await regRes.json()) as { agentId: string; token: string };

    // Send heartbeat
    const hbRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/${agentId}/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        eventsProcessed: 42,
        threatsDetected: 3,
        actionsExecuted: 1,
        mode: 'protection',
        uptime: 60000,
        memoryUsageMB: 128.5,
      }),
    });

    expect(hbRes.status).toBe(200);
    const data = (await hbRes.json()) as { ok: boolean };
    expect(data.ok).toBe(true);
  });

  it('should reject heartbeat with invalid token', async () => {
    // Register first
    const regRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hostname: 'auth-test',
        os: 'Linux',
        arch: 'x64',
        version: '1.0.0',
      }),
    });
    const { agentId } = (await regRes.json()) as { agentId: string };

    // Send heartbeat with wrong token
    const hbRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/${agentId}/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer wrong-token',
      },
      body: JSON.stringify({
        eventsProcessed: 0,
        threatsDetected: 0,
        actionsExecuted: 0,
        mode: 'learning',
        uptime: 0,
        memoryUsageMB: 0,
      }),
    });

    expect(hbRes.status).toBe(401);
  });

  it('should accept event reports', async () => {
    // Register first
    const regRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hostname: 'event-test',
        os: 'Linux',
        arch: 'x64',
        version: '1.0.0',
      }),
    });
    const { agentId, token } = (await regRes.json()) as { agentId: string; token: string };

    // Report event
    const eventRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/${agentId}/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        event: { id: 'test-event-1', source: 'network', severity: 'high' },
        verdict: { conclusion: 'malicious', confidence: 92, action: 'block_ip' },
      }),
    });

    expect(eventRes.status).toBe(200);
  });

  it('should list events', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/events`);
    expect(res.status).toBe(200);

    const data = (await res.json()) as { events: unknown[]; total: number };
    expect(data.total).toBeGreaterThanOrEqual(1);
  });

  it('should serve dashboard HTML', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/dashboard`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');

    const html = await res.text();
    expect(html).toContain('Panguard Manager Dashboard');
    expect(html).toContain('Agents');
  });

  it('should return 404 for unknown routes', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/nonexistent`);
    expect(res.status).toBe(404);
  });

  it('should queue scan command for agent', async () => {
    // Register first
    const regRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hostname: 'scan-test',
        os: 'Linux',
        arch: 'x64',
        version: '1.0.0',
      }),
    });
    const { agentId, token } = (await regRes.json()) as { agentId: string; token: string };

    // Queue scan
    const scanRes = await fetch(`http://localhost:${TEST_PORT}/api/agents/${agentId}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
    });

    expect(scanRes.status).toBe(200);
    const data = (await scanRes.json()) as { ok: boolean; message: string };
    expect(data.ok).toBe(true);
    expect(data.message).toContain('Scan queued');
  });

  it('should return rules endpoint', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/api/rules/latest`);
    expect(res.status).toBe(200);

    const data = (await res.json()) as { rules: unknown[] };
    expect(Array.isArray(data.rules)).toBe(true);
  });
});
