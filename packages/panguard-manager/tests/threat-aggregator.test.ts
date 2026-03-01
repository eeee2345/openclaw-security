/**
 * ThreatAggregator unit tests
 * ThreatAggregator 單元測試
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ThreatAggregator } from '../src/threat-aggregator.js';
import type {
  ThreatReport,
  ThreatEvent,
  SecurityEvent,
} from '../src/types.js';

function makeSecurityEvent(overrides?: Partial<SecurityEvent>): SecurityEvent {
  return {
    id: `evt-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date(),
    source: 'network',
    severity: 'high',
    category: 'lateral_movement',
    description: 'Suspicious network activity detected',
    raw: {},
    host: 'test-host',
    metadata: {},
    ...overrides,
  };
}

function makeThreatEvent(overrides?: {
  eventOverrides?: Partial<SecurityEvent>;
  conclusion?: 'benign' | 'suspicious' | 'malicious';
  confidence?: number;
}): ThreatEvent {
  return {
    event: makeSecurityEvent(overrides?.eventOverrides),
    verdict: {
      conclusion: overrides?.conclusion ?? 'malicious',
      confidence: overrides?.confidence ?? 85,
      action: 'block_ip',
    },
  };
}

function makeReport(
  agentId: string,
  threats: ThreatEvent[]
): ThreatReport {
  return {
    agentId,
    threats,
    reportedAt: new Date().toISOString(),
  };
}

describe('ThreatAggregator', () => {
  let aggregator: ThreatAggregator;

  beforeEach(() => {
    // 5 minute correlation window, 24h retention
    aggregator = new ThreatAggregator(300_000, 86_400_000);
  });

  // ===== Ingestion =====

  describe('ingestReport', () => {
    it('should ingest a single threat and assign an ID', () => {
      const threat = makeThreatEvent();
      const report = makeReport('ag-001', [threat]);

      const result = aggregator.ingestReport(report, 'server-01');

      expect(result).toHaveLength(1);
      expect(result[0]!.id).toMatch(/^th-[0-9a-f]{12}$/);
      expect(result[0]!.sourceAgentId).toBe('ag-001');
      expect(result[0]!.sourceHostname).toBe('server-01');
      expect(result[0]!.correlatedWith).toEqual([]);
    });

    it('should ingest multiple threats in a single report', () => {
      const threats = [
        makeThreatEvent({ eventOverrides: { description: 'Threat 1' } }),
        makeThreatEvent({ eventOverrides: { description: 'Threat 2' } }),
        makeThreatEvent({ eventOverrides: { description: 'Threat 3' } }),
      ];
      const report = makeReport('ag-001', threats);

      const result = aggregator.ingestReport(report, 'server-01');
      expect(result).toHaveLength(3);
      expect(aggregator.size).toBe(3);
    });

    it('should track threats in the size property', () => {
      expect(aggregator.size).toBe(0);

      aggregator.ingestReport(
        makeReport('ag-001', [makeThreatEvent()]),
        'server-01'
      );
      expect(aggregator.size).toBe(1);

      aggregator.ingestReport(
        makeReport('ag-002', [makeThreatEvent(), makeThreatEvent()]),
        'server-02'
      );
      expect(aggregator.size).toBe(3);
    });
  });

  // ===== Cross-Agent IP Correlation =====

  describe('IP correlation', () => {
    it('should correlate threats with same source IP from different agents', () => {
      const attackerIP = '10.0.0.99';

      // Agent 1 reports threat from attacker IP
      const report1 = makeReport('ag-001', [
        makeThreatEvent({
          eventOverrides: {
            metadata: { sourceIP: attackerIP },
          },
        }),
      ]);
      const result1 = aggregator.ingestReport(report1, 'server-01');
      expect(result1[0]!.correlatedWith).toEqual([]);

      // Agent 2 reports threat from same attacker IP
      const report2 = makeReport('ag-002', [
        makeThreatEvent({
          eventOverrides: {
            metadata: { sourceIP: attackerIP },
          },
        }),
      ]);
      const result2 = aggregator.ingestReport(report2, 'server-02');

      // The second threat should be correlated with the first
      expect(result2[0]!.correlatedWith).toHaveLength(1);
      expect(result2[0]!.correlatedWith[0]).toBe(result1[0]!.id);

      // Verify the first threat was updated with back-reference
      const correlations = aggregator.getCorrelations();
      expect(correlations).toHaveLength(1);
      expect(correlations[0]!.correlationType).toBe('same_source_ip');
      expect(correlations[0]!.sharedIndicator).toBe(attackerIP);
    });

    it('should NOT correlate threats from the same agent', () => {
      const attackerIP = '10.0.0.99';

      const report = makeReport('ag-001', [
        makeThreatEvent({
          eventOverrides: { metadata: { sourceIP: attackerIP } },
        }),
      ]);
      aggregator.ingestReport(report, 'server-01');

      // Same agent, same IP - should NOT correlate
      const report2 = makeReport('ag-001', [
        makeThreatEvent({
          eventOverrides: { metadata: { sourceIP: attackerIP } },
        }),
      ]);
      const result2 = aggregator.ingestReport(report2, 'server-01');

      expect(result2[0]!.correlatedWith).toEqual([]);
    });

    it('should correlate using alternative IP field names', () => {
      // Agent 1 uses 'sourceIP'
      const report1 = makeReport('ag-001', [
        makeThreatEvent({
          eventOverrides: { metadata: { sourceIP: '10.0.0.55' } },
        }),
      ]);
      aggregator.ingestReport(report1, 'server-01');

      // Agent 2 uses 'remoteAddress'
      const report2 = makeReport('ag-002', [
        makeThreatEvent({
          eventOverrides: { metadata: { remoteAddress: '10.0.0.55' } },
        }),
      ]);
      const result2 = aggregator.ingestReport(report2, 'server-02');

      expect(result2[0]!.correlatedWith).toHaveLength(1);
    });
  });

  // ===== Cross-Agent Hash Correlation =====

  describe('hash correlation', () => {
    it('should correlate threats with same malware hash from different agents', () => {
      const malwareHash = 'abc123def456789012345678901234567890123456789012345678901234abcd';

      const report1 = makeReport('ag-001', [
        makeThreatEvent({
          eventOverrides: {
            source: 'file',
            metadata: { sha256: malwareHash },
          },
        }),
      ]);
      const result1 = aggregator.ingestReport(report1, 'server-01');

      const report2 = makeReport('ag-002', [
        makeThreatEvent({
          eventOverrides: {
            source: 'file',
            metadata: { sha256: malwareHash },
          },
        }),
      ]);
      const result2 = aggregator.ingestReport(report2, 'server-02');

      expect(result2[0]!.correlatedWith).toHaveLength(1);
      expect(result2[0]!.correlatedWith[0]).toBe(result1[0]!.id);

      const correlations = aggregator.getCorrelations();
      const hashCorrelation = correlations.find(
        (c) => c.correlationType === 'same_malware_hash'
      );
      expect(hashCorrelation).toBeDefined();
      expect(hashCorrelation!.sharedIndicator).toBe(malwareHash);
    });
  });

  // ===== Attack Pattern Correlation =====

  describe('attack pattern correlation', () => {
    it('should correlate same attack category from same IP across agents', () => {
      const attackerIP = '10.0.0.77';
      const category = 'credential_access';

      const report1 = makeReport('ag-001', [
        makeThreatEvent({
          eventOverrides: {
            category,
            metadata: { sourceIP: attackerIP },
          },
        }),
      ]);
      aggregator.ingestReport(report1, 'server-01');

      const report2 = makeReport('ag-002', [
        makeThreatEvent({
          eventOverrides: {
            category,
            metadata: { sourceIP: attackerIP },
          },
        }),
      ]);
      const result2 = aggregator.ingestReport(report2, 'server-02');

      // Should have correlations (IP + pattern)
      expect(result2[0]!.correlatedWith.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ===== Multi-Agent Coordinated Attack =====

  describe('coordinated attack detection', () => {
    it('should detect coordinated attack across 3 agents', () => {
      const attackerIP = '10.0.0.42';

      // Agent 1
      aggregator.ingestReport(
        makeReport('ag-001', [
          makeThreatEvent({
            eventOverrides: {
              metadata: { sourceIP: attackerIP },
              severity: 'critical',
            },
          }),
        ]),
        'server-01'
      );

      // Agent 2
      const result2 = aggregator.ingestReport(
        makeReport('ag-002', [
          makeThreatEvent({
            eventOverrides: {
              metadata: { sourceIP: attackerIP },
              severity: 'critical',
            },
          }),
        ]),
        'server-02'
      );
      expect(result2[0]!.correlatedWith).toHaveLength(1);

      // Agent 3
      const result3 = aggregator.ingestReport(
        makeReport('ag-003', [
          makeThreatEvent({
            eventOverrides: {
              metadata: { sourceIP: attackerIP },
              severity: 'critical',
            },
          }),
        ]),
        'server-03'
      );
      // Should correlate with both previous threats
      expect(result3[0]!.correlatedWith).toHaveLength(2);
    });
  });

  // ===== Querying =====

  describe('getRecentThreats', () => {
    it('should return threats since the given timestamp', () => {
      const before = new Date(Date.now() - 10000);

      aggregator.ingestReport(
        makeReport('ag-001', [makeThreatEvent()]),
        'server-01'
      );

      const recent = aggregator.getRecentThreats(before);
      expect(recent).toHaveLength(1);
    });

    it('should exclude old threats', () => {
      aggregator.ingestReport(
        makeReport('ag-001', [makeThreatEvent()]),
        'server-01'
      );

      const future = new Date(Date.now() + 60000);
      const recent = aggregator.getRecentThreats(future);
      expect(recent).toHaveLength(0);
    });
  });

  describe('getThreatsByAgent', () => {
    it('should return only threats from the specified agent', () => {
      aggregator.ingestReport(
        makeReport('ag-001', [makeThreatEvent(), makeThreatEvent()]),
        'server-01'
      );
      aggregator.ingestReport(
        makeReport('ag-002', [makeThreatEvent()]),
        'server-02'
      );

      const agent1Threats = aggregator.getThreatsByAgent('ag-001');
      expect(agent1Threats).toHaveLength(2);

      const agent2Threats = aggregator.getThreatsByAgent('ag-002');
      expect(agent2Threats).toHaveLength(1);
    });

    it('should return empty for unknown agent', () => {
      expect(aggregator.getThreatsByAgent('ag-unknown')).toEqual([]);
    });
  });

  // ===== Summary =====

  describe('getSummary', () => {
    it('should calculate threat summary correctly', () => {
      // Critical threat from agent 1
      aggregator.ingestReport(
        makeReport('ag-001', [
          makeThreatEvent({
            eventOverrides: {
              severity: 'critical',
              metadata: { sourceIP: '10.0.0.1' },
            },
          }),
        ]),
        'server-01'
      );

      // High threat from agent 2
      aggregator.ingestReport(
        makeReport('ag-002', [
          makeThreatEvent({
            eventOverrides: {
              severity: 'high',
              metadata: { sourceIP: '10.0.0.2' },
            },
          }),
        ]),
        'server-02'
      );

      // Suspicious verdict from agent 1
      aggregator.ingestReport(
        makeReport('ag-001', [
          makeThreatEvent({
            eventOverrides: {
              severity: 'medium',
              metadata: { sourceIP: '10.0.0.1' },
            },
            conclusion: 'suspicious',
          }),
        ]),
        'server-01'
      );

      const summary = aggregator.getSummary();
      expect(summary.totalThreats).toBe(3);
      expect(summary.criticalCount).toBe(1);
      expect(summary.highCount).toBe(1);
      expect(summary.suspiciousCount).toBe(1);
      expect(summary.uniqueAttackers).toBe(2); // 10.0.0.1 and 10.0.0.2
      expect(summary.affectedAgents).toBe(2); // ag-001 and ag-002
    });

    it('should return zero summary when empty', () => {
      const summary = aggregator.getSummary();
      expect(summary.totalThreats).toBe(0);
      expect(summary.criticalCount).toBe(0);
      expect(summary.uniqueAttackers).toBe(0);
      expect(summary.affectedAgents).toBe(0);
    });
  });

  // ===== Purge =====

  describe('purgeExpired', () => {
    it('should purge threats older than retention period', () => {
      // Use zero retention so everything is immediately expired
      const shortRetention = new ThreatAggregator(300_000, 0);

      shortRetention.ingestReport(
        makeReport('ag-001', [makeThreatEvent()]),
        'server-01'
      );

      expect(shortRetention.size).toBe(1);

      const purged = shortRetention.purgeExpired();
      expect(purged).toBe(1);
      expect(shortRetention.size).toBe(0);
    });

    it('should not purge recent threats', () => {
      aggregator.ingestReport(
        makeReport('ag-001', [makeThreatEvent()]),
        'server-01'
      );

      const purged = aggregator.purgeExpired();
      expect(purged).toBe(0);
      expect(aggregator.size).toBe(1);
    });
  });
});
