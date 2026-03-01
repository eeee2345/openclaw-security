/**
 * Manager integration tests - full lifecycle testing
 * Manager 整合測試 - 完整生命週期測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Manager } from '../src/manager.js';
import type {
  ManagerConfig,
  AgentRegistrationRequest,
  AgentHeartbeat,
  ThreatReport,
  ThreatEvent,
  PolicyRule,
} from '../src/types.js';
import type { SecurityEvent } from '@panguard-ai/core';

const TEST_CONFIG: ManagerConfig = {
  port: 9443,
  authToken: 'test-token',
  heartbeatIntervalMs: 60_000, // Long interval to avoid timer interference in tests
  heartbeatTimeoutMs: 90_000,
  maxAgents: 100,
  correlationWindowMs: 300_000,
  threatRetentionMs: 86_400_000,
};

function makeRegistration(hostname: string): AgentRegistrationRequest {
  return {
    hostname,
    os: 'Linux 6.1.0',
    arch: 'x64',
    version: '1.0.0',
    ip: '192.168.1.100',
  };
}

function makeSecurityEvent(overrides?: Partial<SecurityEvent>): SecurityEvent {
  return {
    id: `evt-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date(),
    source: 'network',
    severity: 'high',
    category: 'lateral_movement',
    description: 'Suspicious network activity',
    raw: {},
    host: 'test-host',
    metadata: {},
    ...overrides,
  };
}

function makeThreatEvent(overrides?: {
  eventOverrides?: Partial<SecurityEvent>;
  conclusion?: 'benign' | 'suspicious' | 'malicious';
}): ThreatEvent {
  return {
    event: makeSecurityEvent(overrides?.eventOverrides),
    verdict: {
      conclusion: overrides?.conclusion ?? 'malicious',
      confidence: 90,
      action: 'block_ip',
    },
  };
}

describe('Manager', () => {
  let manager: Manager;

  beforeEach(() => {
    manager = new Manager(TEST_CONFIG);
  });

  afterEach(() => {
    manager.stop();
  });

  // ===== Lifecycle =====

  describe('lifecycle', () => {
    it('should start and report running state', () => {
      expect(manager.isRunning()).toBe(false);
      manager.start();
      expect(manager.isRunning()).toBe(true);
    });

    it('should stop cleanly', () => {
      manager.start();
      manager.stop();
      expect(manager.isRunning()).toBe(false);
    });

    it('should handle double start gracefully', () => {
      manager.start();
      manager.start(); // Should not throw
      expect(manager.isRunning()).toBe(true);
    });

    it('should handle stop without start', () => {
      manager.stop(); // Should not throw
      expect(manager.isRunning()).toBe(false);
    });
  });

  // ===== Agent Registration =====

  describe('agent registration', () => {
    it('should register a new agent', () => {
      manager.start();
      const reg = manager.handleRegistration(makeRegistration('server-01'));

      expect(reg.agentId).toMatch(/^ag-/);
      expect(reg.hostname).toBe('server-01');
      expect(reg.status).toBe('online');
      expect(manager.getAgentCount()).toBe(1);
    });

    it('should register multiple agents', () => {
      manager.start();
      manager.handleRegistration(makeRegistration('server-01'));
      manager.handleRegistration(makeRegistration('server-02'));
      manager.handleRegistration(makeRegistration('server-03'));

      expect(manager.getAgentCount()).toBe(3);
    });

    it('should deregister an agent', () => {
      manager.start();
      const reg = manager.handleRegistration(makeRegistration('server-01'));
      expect(manager.getAgentCount()).toBe(1);

      const result = manager.handleDeregistration(reg.agentId);
      expect(result).toBe(true);
      expect(manager.getAgentCount()).toBe(0);
    });

    it('should retrieve agent details', () => {
      manager.start();
      const reg = manager.handleRegistration(makeRegistration('server-01'));

      const agent = manager.getAgent(reg.agentId);
      expect(agent).toBeDefined();
      expect(agent!.hostname).toBe('server-01');
      expect(agent!.platform.os).toBe('Linux 6.1.0');
    });
  });

  // ===== Heartbeat =====

  describe('heartbeat handling', () => {
    it('should update agent heartbeat', () => {
      manager.start();
      const reg = manager.handleRegistration(makeRegistration('server-01'));

      const newTimestamp = new Date().toISOString();
      const heartbeat: AgentHeartbeat = {
        agentId: reg.agentId,
        timestamp: newTimestamp,
        cpuUsage: 35,
        memUsage: 2048,
        activeMonitors: 4,
        threatCount: 1,
        eventsProcessed: 500,
        mode: 'protection',
        uptime: 60_000,
      };

      const updated = manager.handleHeartbeat(heartbeat);
      expect(updated).toBeDefined();
      expect(updated!.lastHeartbeat).toBe(newTimestamp);
    });

    it('should return undefined for unknown agent heartbeat', () => {
      manager.start();
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

      expect(manager.handleHeartbeat(heartbeat)).toBeUndefined();
    });
  });

  // ===== Threat Reporting & Correlation =====

  describe('threat reporting', () => {
    it('should ingest a threat report', () => {
      manager.start();
      const reg = manager.handleRegistration(makeRegistration('server-01'));

      const report: ThreatReport = {
        agentId: reg.agentId,
        threats: [makeThreatEvent()],
        reportedAt: new Date().toISOString(),
      };

      const result = manager.handleThreatReport(report);
      expect(result).toHaveLength(1);
      expect(result[0]!.sourceAgentId).toBe(reg.agentId);
      expect(result[0]!.sourceHostname).toBe('server-01');
    });

    it('should detect cross-agent correlation (coordinated attack)', () => {
      manager.start();
      const reg1 = manager.handleRegistration(makeRegistration('server-01'));
      const reg2 = manager.handleRegistration(makeRegistration('server-02'));

      const attackerIP = '10.0.0.42';

      // Agent 1 reports attack
      const report1: ThreatReport = {
        agentId: reg1.agentId,
        threats: [
          makeThreatEvent({
            eventOverrides: {
              metadata: { sourceIP: attackerIP },
              severity: 'critical',
            },
          }),
        ],
        reportedAt: new Date().toISOString(),
      };
      const result1 = manager.handleThreatReport(report1);
      expect(result1[0]!.correlatedWith).toEqual([]);

      // Agent 2 reports same attacker
      const report2: ThreatReport = {
        agentId: reg2.agentId,
        threats: [
          makeThreatEvent({
            eventOverrides: {
              metadata: { sourceIP: attackerIP },
              severity: 'critical',
            },
          }),
        ],
        reportedAt: new Date().toISOString(),
      };
      const result2 = manager.handleThreatReport(report2);

      // Cross-agent correlation detected
      expect(result2[0]!.correlatedWith).toHaveLength(1);
      expect(result2[0]!.correlatedWith[0]).toBe(result1[0]!.id);
    });

    it('should provide per-agent threat breakdown', () => {
      manager.start();
      const reg1 = manager.handleRegistration(makeRegistration('server-01'));
      const reg2 = manager.handleRegistration(makeRegistration('server-02'));

      manager.handleThreatReport({
        agentId: reg1.agentId,
        threats: [makeThreatEvent(), makeThreatEvent()],
        reportedAt: new Date().toISOString(),
      });

      manager.handleThreatReport({
        agentId: reg2.agentId,
        threats: [makeThreatEvent()],
        reportedAt: new Date().toISOString(),
      });

      expect(manager.getThreatsByAgent(reg1.agentId)).toHaveLength(2);
      expect(manager.getThreatsByAgent(reg2.agentId)).toHaveLength(1);
    });

    it('should provide a threat summary', () => {
      manager.start();
      const reg1 = manager.handleRegistration(makeRegistration('server-01'));
      const reg2 = manager.handleRegistration(makeRegistration('server-02'));

      manager.handleThreatReport({
        agentId: reg1.agentId,
        threats: [
          makeThreatEvent({
            eventOverrides: {
              severity: 'critical',
              metadata: { sourceIP: '10.0.0.1' },
            },
          }),
        ],
        reportedAt: new Date().toISOString(),
      });

      manager.handleThreatReport({
        agentId: reg2.agentId,
        threats: [
          makeThreatEvent({
            eventOverrides: {
              severity: 'high',
              metadata: { sourceIP: '10.0.0.2' },
            },
          }),
        ],
        reportedAt: new Date().toISOString(),
      });

      const summary = manager.getThreatSummary();
      expect(summary.totalThreats).toBe(2);
      expect(summary.criticalCount).toBe(1);
      expect(summary.highCount).toBe(1);
      expect(summary.uniqueAttackers).toBe(2);
      expect(summary.affectedAgents).toBe(2);
    });
  });

  // ===== Policy Management =====

  describe('policy management', () => {
    it('should create a policy', () => {
      manager.start();

      const rules: PolicyRule[] = [
        {
          ruleId: 'rule-001',
          type: 'block_ip',
          condition: { repeatCount: 3 },
          action: 'auto_block',
          severity: 'high',
          description: 'Block IP after 3 failed attempts',
        },
      ];

      const policy = manager.createPolicy(rules, false);
      expect(policy.policyId).toMatch(/^pol-/);
      expect(policy.version).toBe(1);
      expect(policy.rules).toHaveLength(1);
    });

    it('should get active policy', () => {
      manager.start();

      expect(manager.getActivePolicy()).toBeNull();

      const rules: PolicyRule[] = [
        {
          ruleId: 'rule-001',
          type: 'alert_threshold',
          condition: { threshold: 50 },
          action: 'notify',
          severity: 'medium',
          description: 'Alert on high threat score',
        },
      ];

      manager.createPolicy(rules, false);
      const active = manager.getActivePolicy();
      expect(active).not.toBeNull();
      expect(active!.version).toBe(1);
    });

    it('should increment version on policy updates', () => {
      manager.start();

      manager.createPolicy(
        [
          {
            ruleId: 'r1',
            type: 'block_ip',
            condition: {},
            action: 'block',
            severity: 'high',
            description: 'V1',
          },
        ],
        false
      );

      const v2 = manager.createPolicy(
        [
          {
            ruleId: 'r2',
            type: 'auto_respond',
            condition: {},
            action: 'respond',
            severity: 'critical',
            description: 'V2',
          },
        ],
        false
      );

      expect(v2.version).toBe(2);
    });

    it('should broadcast policy to active agents', () => {
      manager.start();
      manager.handleRegistration(makeRegistration('server-01'));
      manager.handleRegistration(makeRegistration('server-02'));

      const rules: PolicyRule[] = [
        {
          ruleId: 'r1',
          type: 'block_ip',
          condition: {},
          action: 'block',
          severity: 'high',
          description: 'Block known bad IPs',
        },
      ];

      manager.createPolicy(rules, true);

      const broadcasts = manager.getPendingBroadcasts();
      expect(broadcasts).toHaveLength(1);
      expect(broadcasts[0]!.targetAgents).toHaveLength(2);
    });

    it('should get policy for a specific agent', () => {
      manager.start();

      manager.createPolicy(
        [
          {
            ruleId: 'r1',
            type: 'block_ip',
            condition: {},
            action: 'block',
            severity: 'high',
            description: 'Global policy',
          },
        ],
        false
      );

      const policy = manager.getPolicyForAgent('ag-any');
      expect(policy).not.toBeNull();
      expect(policy!.rules[0]!.description).toBe('Global policy');
    });
  });

  // ===== Dashboard Overview =====

  describe('getOverview', () => {
    it('should provide comprehensive fleet overview', () => {
      manager.start();

      const reg1 = manager.handleRegistration(makeRegistration('server-01'));
      const reg2 = manager.handleRegistration(makeRegistration('server-02'));

      // Report a threat from agent 1
      manager.handleThreatReport({
        agentId: reg1.agentId,
        threats: [
          makeThreatEvent({
            eventOverrides: {
              severity: 'critical',
              metadata: { sourceIP: '10.0.0.1' },
            },
          }),
        ],
        reportedAt: new Date().toISOString(),
      });

      // Create a policy
      manager.createPolicy(
        [
          {
            ruleId: 'r1',
            type: 'block_ip',
            condition: {},
            action: 'block',
            severity: 'high',
            description: 'Test',
          },
        ],
        false
      );

      const overview = manager.getOverview();

      // Agent counts
      expect(overview.totalAgents).toBe(2);
      expect(overview.onlineAgents).toBe(2);
      expect(overview.staleAgents).toBe(0);
      expect(overview.offlineAgents).toBe(0);

      // Agents detail
      expect(overview.agents).toHaveLength(2);
      const agent1Overview = overview.agents.find(
        (a) => a.agentId === reg1.agentId
      );
      expect(agent1Overview).toBeDefined();
      expect(agent1Overview!.threatCount).toBe(1);

      const agent2Overview = overview.agents.find(
        (a) => a.agentId === reg2.agentId
      );
      expect(agent2Overview!.threatCount).toBe(0);

      // Threat summary
      expect(overview.threatSummary.totalThreats).toBe(1);
      expect(overview.threatSummary.criticalCount).toBe(1);

      // Policy version
      expect(overview.activePolicyVersion).toBe(1);

      // Uptime (may be 0 if test runs within same ms tick)
      expect(overview.uptimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should report zero uptime when not running', () => {
      const overview = manager.getOverview();
      expect(overview.uptimeMs).toBe(0);
    });
  });

  // ===== Full Lifecycle Scenario =====

  describe('full lifecycle scenario', () => {
    it('should handle complete agent lifecycle: register, heartbeat, report, deregister', () => {
      manager.start();

      // Step 1: Register agents
      const reg1 = manager.handleRegistration(makeRegistration('prod-web-01'));
      const reg2 = manager.handleRegistration(makeRegistration('prod-db-01'));
      const reg3 = manager.handleRegistration(makeRegistration('prod-api-01'));
      expect(manager.getAgentCount()).toBe(3);

      // Step 2: Heartbeats
      for (const reg of [reg1, reg2, reg3]) {
        manager.handleHeartbeat({
          agentId: reg.agentId,
          timestamp: new Date().toISOString(),
          cpuUsage: 25,
          memUsage: 1024,
          activeMonitors: 3,
          threatCount: 0,
          eventsProcessed: 100,
          mode: 'protection',
          uptime: 60_000,
        });
      }

      // Step 3: Coordinated attack detected
      const attackerIP = '203.0.113.42';

      // Web server gets hit
      manager.handleThreatReport({
        agentId: reg1.agentId,
        threats: [
          makeThreatEvent({
            eventOverrides: {
              severity: 'critical',
              category: 'initial_access',
              description: 'SQL injection attempt',
              metadata: { sourceIP: attackerIP },
            },
          }),
        ],
        reportedAt: new Date().toISOString(),
      });

      // API server gets hit by same attacker
      const apiResult = manager.handleThreatReport({
        agentId: reg3.agentId,
        threats: [
          makeThreatEvent({
            eventOverrides: {
              severity: 'critical',
              category: 'initial_access',
              description: 'API brute force',
              metadata: { sourceIP: attackerIP },
            },
          }),
        ],
        reportedAt: new Date().toISOString(),
      });

      // Correlation should be detected
      expect(apiResult[0]!.correlatedWith.length).toBeGreaterThan(0);

      // Step 4: Create and broadcast blocking policy
      const policy = manager.createPolicy(
        [
          {
            ruleId: 'emergency-001',
            type: 'block_ip',
            condition: { ip: attackerIP },
            action: 'auto_block',
            severity: 'critical',
            description: `Block coordinated attacker ${attackerIP}`,
          },
        ],
        true
      );
      expect(policy.version).toBe(1);

      const broadcasts = manager.getPendingBroadcasts();
      expect(broadcasts[0]!.targetAgents).toHaveLength(3);

      // Step 5: Verify overview
      const overview = manager.getOverview();
      expect(overview.totalAgents).toBe(3);
      expect(overview.onlineAgents).toBe(3);
      expect(overview.threatSummary.totalThreats).toBe(2);
      expect(overview.threatSummary.criticalCount).toBe(2);
      expect(overview.threatSummary.uniqueAttackers).toBe(1); // Same attacker
      expect(overview.threatSummary.affectedAgents).toBe(2); // web + api
      expect(overview.threatSummary.correlatedGroups).toBeGreaterThan(0);

      // Step 6: Deregister retired server
      manager.handleDeregistration(reg2.agentId);
      expect(manager.getAgentCount()).toBe(2);

      // Step 7: Clean stop
      manager.stop();
      expect(manager.isRunning()).toBe(false);
    });
  });
});
