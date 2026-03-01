/**
 * AgentRegistry unit tests
 * AgentRegistry 單元測試
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AgentRegistry } from '../src/agent-registry.js';
import type {
  AgentRegistrationRequest,
  AgentHeartbeat,
} from '../src/types.js';

function makeRequest(overrides?: Partial<AgentRegistrationRequest>): AgentRegistrationRequest {
  return {
    hostname: 'test-server-01',
    os: 'Linux 6.1.0',
    arch: 'x64',
    version: '1.0.0',
    ip: '192.168.1.100',
    ...overrides,
  };
}

describe('AgentRegistry', () => {
  let registry: AgentRegistry;

  beforeEach(() => {
    registry = new AgentRegistry(10);
  });

  // ===== Registration =====

  describe('registerAgent', () => {
    it('should register an agent and return a record with generated ID', () => {
      const result = registry.registerAgent(makeRequest());

      expect(result.agentId).toMatch(/^ag-[0-9a-f]{12}$/);
      expect(result.hostname).toBe('test-server-01');
      expect(result.platform.os).toBe('Linux 6.1.0');
      expect(result.platform.arch).toBe('x64');
      expect(result.platform.ip).toBe('192.168.1.100');
      expect(result.version).toBe('1.0.0');
      expect(result.status).toBe('online');
      expect(result.registeredAt).toBeTruthy();
      expect(result.lastHeartbeat).toBeTruthy();
    });

    it('should assign unique IDs to each registration', () => {
      const r1 = registry.registerAgent(makeRequest({ hostname: 'server-1' }));
      const r2 = registry.registerAgent(makeRequest({ hostname: 'server-2' }));

      expect(r1.agentId).not.toBe(r2.agentId);
    });

    it('should increment the registry size on registration', () => {
      expect(registry.size).toBe(0);
      registry.registerAgent(makeRequest());
      expect(registry.size).toBe(1);
      registry.registerAgent(makeRequest({ hostname: 'server-2' }));
      expect(registry.size).toBe(2);
    });

    it('should throw when max agents is reached', () => {
      const smallRegistry = new AgentRegistry(2);
      smallRegistry.registerAgent(makeRequest({ hostname: 's1' }));
      smallRegistry.registerAgent(makeRequest({ hostname: 's2' }));

      expect(() =>
        smallRegistry.registerAgent(makeRequest({ hostname: 's3' }))
      ).toThrow('Maximum agent limit reached');
    });

    it('should return an immutable copy (modifying return does not affect registry)', () => {
      const result = registry.registerAgent(makeRequest());
      const agentId = result.agentId;

      // The returned object is a copy; modifying it should not affect internal state
      (result as Record<string, unknown>)['hostname'] = 'hacked';

      const fetched = registry.getAgent(agentId);
      expect(fetched?.hostname).toBe('test-server-01');
    });
  });

  // ===== Deregistration =====

  describe('deregisterAgent', () => {
    it('should remove a registered agent', () => {
      const reg = registry.registerAgent(makeRequest());
      expect(registry.size).toBe(1);

      const removed = registry.deregisterAgent(reg.agentId);
      expect(removed).toBe(true);
      expect(registry.size).toBe(0);
    });

    it('should return false for unknown agent ID', () => {
      const removed = registry.deregisterAgent('ag-nonexistent');
      expect(removed).toBe(false);
    });

    it('should make agent unfindable after deregistration', () => {
      const reg = registry.registerAgent(makeRequest());
      registry.deregisterAgent(reg.agentId);

      expect(registry.getAgent(reg.agentId)).toBeUndefined();
    });
  });

  // ===== Heartbeat =====

  describe('updateHeartbeat', () => {
    it('should update lastHeartbeat timestamp', () => {
      const reg = registry.registerAgent(makeRequest());
      const newTimestamp = new Date(Date.now() + 30000).toISOString();

      const heartbeat: AgentHeartbeat = {
        agentId: reg.agentId,
        timestamp: newTimestamp,
        cpuUsage: 45,
        memUsage: 1024,
        activeMonitors: 3,
        threatCount: 2,
        eventsProcessed: 150,
        mode: 'protection',
        uptime: 30000,
      };

      const updated = registry.updateHeartbeat(heartbeat);
      expect(updated).toBeDefined();
      expect(updated!.lastHeartbeat).toBe(newTimestamp);
      expect(updated!.status).toBe('online');
    });

    it('should return undefined for unknown agent', () => {
      const heartbeat: AgentHeartbeat = {
        agentId: 'ag-nonexistent',
        timestamp: new Date().toISOString(),
        cpuUsage: 0,
        memUsage: 0,
        activeMonitors: 0,
        threatCount: 0,
        eventsProcessed: 0,
        mode: 'learning',
        uptime: 0,
      };

      expect(registry.updateHeartbeat(heartbeat)).toBeUndefined();
    });

    it('should restore online status from stale after heartbeat', () => {
      const reg = registry.registerAgent(makeRequest());

      // Force stale detection with a very short timeout
      registry.getStaleAgents(0);

      const agent = registry.getAgent(reg.agentId);
      expect(agent!.status).toBe('stale');

      // Send heartbeat to recover
      const heartbeat: AgentHeartbeat = {
        agentId: reg.agentId,
        timestamp: new Date().toISOString(),
        cpuUsage: 10,
        memUsage: 512,
        activeMonitors: 2,
        threatCount: 0,
        eventsProcessed: 50,
        mode: 'learning',
        uptime: 5000,
      };

      const updated = registry.updateHeartbeat(heartbeat);
      expect(updated!.status).toBe('online');
    });
  });

  // ===== Stale Detection =====

  describe('getStaleAgents', () => {
    it('should return agents whose last heartbeat exceeds timeout', () => {
      registry.registerAgent(makeRequest({ hostname: 'server-1' }));
      registry.registerAgent(makeRequest({ hostname: 'server-2' }));

      // With timeout of 0, all agents are immediately stale
      const stale = registry.getStaleAgents(0);
      expect(stale.length).toBe(2);
      expect(stale[0]!.status).toBe('stale');
      expect(stale[1]!.status).toBe('stale');
    });

    it('should not return agents within timeout window', () => {
      registry.registerAgent(makeRequest());

      // With a large timeout, no agents should be stale
      const stale = registry.getStaleAgents(999_999_999);
      expect(stale.length).toBe(0);
    });

    it('should skip agents already marked offline', () => {
      const reg = registry.registerAgent(makeRequest());
      registry.markOffline(reg.agentId);

      const stale = registry.getStaleAgents(0);
      expect(stale.length).toBe(0);
    });
  });

  // ===== Active Agents =====

  describe('getActiveAgents', () => {
    it('should return only online agents', () => {
      const r1 = registry.registerAgent(makeRequest({ hostname: 'online-1' }));
      registry.registerAgent(makeRequest({ hostname: 'online-2' }));
      registry.markOffline(r1.agentId);

      const active = registry.getActiveAgents();
      expect(active.length).toBe(1);
      expect(active[0]!.hostname).toBe('online-2');
    });

    it('should return empty array when no agents registered', () => {
      expect(registry.getActiveAgents()).toEqual([]);
    });
  });

  // ===== Status Counts =====

  describe('getStatusCounts', () => {
    it('should count agents by status', () => {
      const r1 = registry.registerAgent(makeRequest({ hostname: 's1' }));
      registry.registerAgent(makeRequest({ hostname: 's2' }));
      const r3 = registry.registerAgent(makeRequest({ hostname: 's3' }));

      registry.markOffline(r1.agentId);
      // Force stale on s3 by using 0 timeout - but s1 is offline so won't be stale
      // We need s3 specifically stale: first mark r3's heartbeat as old
      // Since getStaleAgents(0) catches all non-offline, it will mark s2 and s3
      // Let's be more precise:
      registry.markOffline(r3.agentId);

      const counts = registry.getStatusCounts();
      expect(counts.online).toBe(1); // s2
      expect(counts.offline).toBe(2); // s1, s3
      expect(counts.stale).toBe(0);
    });
  });

  // ===== Mark Offline =====

  describe('markOffline', () => {
    it('should mark an existing agent as offline', () => {
      const reg = registry.registerAgent(makeRequest());
      const result = registry.markOffline(reg.agentId);

      expect(result).toBe(true);
      const agent = registry.getAgent(reg.agentId);
      expect(agent!.status).toBe('offline');
    });

    it('should return false for unknown agent', () => {
      expect(registry.markOffline('ag-nonexistent')).toBe(false);
    });
  });
});
