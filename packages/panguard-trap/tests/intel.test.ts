/**
 * Trap Intelligence tests
 * 蜜罐情報測試
 */

import { describe, it, expect } from 'vitest';
import { buildTrapIntel, buildBatchIntel, generateIntelSummary } from '../src/intel/index.js';
import type { TrapSession, AttackerProfile, TrapIntelligence } from '../src/types.js';

/** Create a test session / 建立測試連線 */
function createTestSession(overrides: Partial<TrapSession> = {}): TrapSession {
  return {
    sessionId: 'test-session-1',
    serviceType: 'ssh',
    sourceIP: '103.45.67.89',
    sourcePort: 12345,
    startTime: new Date('2025-01-15T10:00:00Z'),
    endTime: new Date('2025-01-15T10:05:00Z'),
    durationMs: 300_000,
    events: [
      { timestamp: new Date(), type: 'connection', data: '103.45.67.89:12345' },
      { timestamp: new Date(), type: 'authentication_attempt', data: 'admin:***' },
      { timestamp: new Date(), type: 'disconnection', data: 'duration=300000ms' },
    ],
    credentials: [
      { timestamp: new Date(), username: 'admin', password: '123456', grantedAccess: false },
      { timestamp: new Date(), username: 'root', password: 'toor', grantedAccess: false },
    ],
    commands: ['whoami'],
    mitreTechniques: ['T1110'],
    ...overrides,
  };
}

/** Create a test profile / 建立測試 profile */
function createTestProfile(overrides: Partial<AttackerProfile> = {}): AttackerProfile {
  return {
    profileId: 'atk-test-1',
    sourceIPs: ['103.45.67.89'],
    firstSeen: new Date(),
    lastSeen: new Date(),
    totalSessions: 1,
    skillLevel: 'script_kiddie',
    intent: 'credential_harvesting',
    toolsDetected: [],
    mitreTechniques: ['T1110'],
    credentialPatterns: {
      commonUsernames: ['admin'],
      commonPasswords: ['123456'],
      totalAttempts: 5,
    },
    geoHints: { country: 'CN' },
    riskScore: 15,
    ...overrides,
  };
}

describe('buildTrapIntel', () => {
  it('should build intel from session', () => {
    const session = createTestSession();
    const profile = createTestProfile();
    const intel = buildTrapIntel(session, profile);

    expect(intel).not.toBeNull();
    expect(intel!.sourceIP).toBe('103.45.67.89');
    expect(intel!.serviceType).toBe('ssh');
    expect(intel!.attackType).toBe('brute_force');
    expect(intel!.mitreTechniques).toContain('T1110');
    expect(intel!.skillLevel).toBe('script_kiddie');
    expect(intel!.intent).toBe('credential_harvesting');
    expect(intel!.region).toBe('CN');
  });

  it('should include top credentials', () => {
    const session = createTestSession();
    const intel = buildTrapIntel(session);
    expect(intel).not.toBeNull();
    expect(intel!.topCredentials.length).toBeGreaterThan(0);
    expect(intel!.topCredentials[0]!.username).toBe('admin');
  });

  it('should skip private IPs', () => {
    const privateSession = createTestSession({ sourceIP: '192.168.1.100' });
    expect(buildTrapIntel(privateSession)).toBeNull();
  });

  it('should skip 10.x.x.x IPs', () => {
    const session = createTestSession({ sourceIP: '10.0.0.50' });
    expect(buildTrapIntel(session)).toBeNull();
  });

  it('should skip 172.16-31.x.x IPs', () => {
    const session = createTestSession({ sourceIP: '172.16.0.1' });
    expect(buildTrapIntel(session)).toBeNull();
  });

  it('should skip localhost', () => {
    const session = createTestSession({ sourceIP: '127.0.0.1' });
    expect(buildTrapIntel(session)).toBeNull();
  });

  it('should skip sessions with too few events', () => {
    const session = createTestSession({
      events: [{ timestamp: new Date(), type: 'connection', data: 'test' }],
    });
    expect(buildTrapIntel(session)).toBeNull();
  });

  it('should detect exploit_attempt attack type', () => {
    const session = createTestSession({
      mitreTechniques: ['T1190'],
    });
    const intel = buildTrapIntel(session);
    expect(intel).not.toBeNull();
    expect(intel!.attackType).toBe('exploit_attempt');
  });

  it('should detect cryptomining attack type', () => {
    const session = createTestSession({
      mitreTechniques: ['T1496'],
    });
    const intel = buildTrapIntel(session);
    expect(intel).not.toBeNull();
    expect(intel!.attackType).toBe('cryptomining');
  });

  it('should detect reconnaissance for http', () => {
    const session = createTestSession({
      serviceType: 'http',
      mitreTechniques: [],
      credentials: [],
    });
    const intel = buildTrapIntel(session);
    expect(intel).not.toBeNull();
    expect(intel!.attackType).toBe('web_attack');
  });
});

describe('buildBatchIntel', () => {
  it('should build intel for multiple sessions', () => {
    const sessions = [
      createTestSession({ sourceIP: '1.2.3.4' }),
      createTestSession({ sessionId: 'test-2', sourceIP: '5.6.7.8' }),
      createTestSession({ sessionId: 'test-3', sourceIP: '192.168.1.1' }), // should be skipped
    ];
    const profiles = new Map<string, AttackerProfile>();

    const results = buildBatchIntel(sessions, profiles);
    expect(results).toHaveLength(2); // private IP skipped
  });
});

describe('generateIntelSummary', () => {
  it('should generate summary from reports', () => {
    const reports: TrapIntelligence[] = [
      {
        timestamp: new Date(),
        serviceType: 'ssh',
        sourceIP: '1.2.3.4',
        attackType: 'brute_force',
        mitreTechniques: ['T1110'],
        skillLevel: 'script_kiddie',
        intent: 'credential_harvesting',
        tools: [],
        topCredentials: [{ username: 'admin', count: 10 }],
      },
      {
        timestamp: new Date(),
        serviceType: 'http',
        sourceIP: '5.6.7.8',
        attackType: 'web_attack',
        mitreTechniques: ['T1190'],
        skillLevel: 'intermediate',
        intent: 'reconnaissance',
        tools: ['nikto'],
        topCredentials: [],
      },
      {
        timestamp: new Date(),
        serviceType: 'ssh',
        sourceIP: '1.2.3.4',
        attackType: 'brute_force',
        mitreTechniques: ['T1110'],
        skillLevel: 'script_kiddie',
        intent: 'credential_harvesting',
        tools: [],
        topCredentials: [],
      },
    ];

    const summary = generateIntelSummary(reports);
    expect(summary.totalIntelReports).toBe(3);
    expect(summary.uniqueSourceIPs).toBe(2);
    expect(summary.attackTypeDistribution['brute_force']).toBe(2);
    expect(summary.attackTypeDistribution['web_attack']).toBe(1);
    expect(summary.serviceDistribution['ssh']).toBe(2);
    expect(summary.serviceDistribution['http']).toBe(1);
    expect(summary.topSourceIPs[0]!.ip).toBe('1.2.3.4');
    expect(summary.topSourceIPs[0]!.count).toBe(2);
  });

  it('should handle empty reports', () => {
    const summary = generateIntelSummary([]);
    expect(summary.totalIntelReports).toBe(0);
    expect(summary.uniqueSourceIPs).toBe(0);
    expect(summary.topSourceIPs).toHaveLength(0);
  });
});
