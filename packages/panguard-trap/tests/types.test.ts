/**
 * PanguardTrap type definitions tests
 * PanguardTrap 型別定義測試
 */

import { describe, it, expect } from 'vitest';
import { DEFAULT_SERVICE_CONFIGS, DEFAULT_TRAP_CONFIG } from '../src/types.js';
import type {
  TrapServiceType,
  TrapSession,
  AttackerProfile,
  TrapStatistics,
} from '../src/types.js';

describe('DEFAULT_SERVICE_CONFIGS', () => {
  it('should have configs for all 8 service types', () => {
    const types: TrapServiceType[] = [
      'ssh',
      'http',
      'ftp',
      'smb',
      'mysql',
      'rdp',
      'telnet',
      'redis',
    ];
    for (const type of types) {
      expect(DEFAULT_SERVICE_CONFIGS[type]).toBeDefined();
      expect(DEFAULT_SERVICE_CONFIGS[type].type).toBe(type);
      expect(DEFAULT_SERVICE_CONFIGS[type].port).toBeGreaterThan(0);
    }
  });

  it('should have SSH on port 2222', () => {
    expect(DEFAULT_SERVICE_CONFIGS.ssh.port).toBe(2222);
    expect(DEFAULT_SERVICE_CONFIGS.ssh.banner).toContain('OpenSSH');
  });

  it('should have HTTP on port 8080', () => {
    expect(DEFAULT_SERVICE_CONFIGS.http.port).toBe(8080);
    expect(DEFAULT_SERVICE_CONFIGS.http.banner).toContain('Apache');
  });

  it('should have FTP on port 2121', () => {
    expect(DEFAULT_SERVICE_CONFIGS.ftp.port).toBe(2121);
    expect(DEFAULT_SERVICE_CONFIGS.ftp.banner).toContain('ProFTPD');
  });

  it('should have MySQL on port 3307', () => {
    expect(DEFAULT_SERVICE_CONFIGS.mysql.port).toBe(3307);
  });

  it('should have all configs with maxConnections and sessionTimeout', () => {
    for (const config of Object.values(DEFAULT_SERVICE_CONFIGS)) {
      expect(config.maxConnections).toBeGreaterThan(0);
      expect(config.sessionTimeoutMs).toBeGreaterThan(0);
    }
  });
});

describe('DEFAULT_TRAP_CONFIG', () => {
  it('should have SSH and HTTP enabled by default', () => {
    const enabledServices = DEFAULT_TRAP_CONFIG.services.filter((s) => s.enabled);
    const enabledTypes = enabledServices.map((s) => s.type);
    expect(enabledTypes).toContain('ssh');
    expect(enabledTypes).toContain('http');
  });

  it('should have FTP, SMB, MySQL, RDP disabled by default', () => {
    const disabledServices = DEFAULT_TRAP_CONFIG.services.filter((s) => !s.enabled);
    const disabledTypes = disabledServices.map((s) => s.type);
    expect(disabledTypes).toContain('ftp');
    expect(disabledTypes).toContain('smb');
    expect(disabledTypes).toContain('mysql');
    expect(disabledTypes).toContain('rdp');
  });

  it('should have Threat Cloud enabled by default', () => {
    expect(DEFAULT_TRAP_CONFIG.feedThreatCloud).toBe(true);
  });

  it('should have fake access enabled after 3 attempts', () => {
    expect(DEFAULT_TRAP_CONFIG.grantFakeAccess).toBe(true);
    expect(DEFAULT_TRAP_CONFIG.fakeAccessAfterAttempts).toBe(3);
  });

  it('should retain up to 1000 sessions in memory', () => {
    expect(DEFAULT_TRAP_CONFIG.maxSessionsInMemory).toBe(1000);
  });

  it('should notify on high value catches', () => {
    expect(DEFAULT_TRAP_CONFIG.notifyOnHighValue).toBe(true);
  });
});

describe('Type safety', () => {
  it('should create valid TrapSession', () => {
    const session: TrapSession = {
      sessionId: 'test-1',
      serviceType: 'ssh',
      sourceIP: '1.2.3.4',
      sourcePort: 12345,
      startTime: new Date(),
      events: [],
      credentials: [],
      commands: [],
      mitreTechniques: [],
    };
    expect(session.sessionId).toBe('test-1');
    expect(session.serviceType).toBe('ssh');
  });

  it('should create valid AttackerProfile', () => {
    const profile: AttackerProfile = {
      profileId: 'atk-1',
      sourceIPs: ['1.2.3.4'],
      firstSeen: new Date(),
      lastSeen: new Date(),
      totalSessions: 1,
      skillLevel: 'script_kiddie',
      intent: 'reconnaissance',
      toolsDetected: [],
      mitreTechniques: [],
      credentialPatterns: {
        commonUsernames: ['admin'],
        commonPasswords: ['123456'],
        totalAttempts: 5,
      },
      geoHints: {},
      riskScore: 10,
    };
    expect(profile.skillLevel).toBe('script_kiddie');
    expect(profile.intent).toBe('reconnaissance');
  });

  it('should create valid TrapStatistics', () => {
    const stats: TrapStatistics = {
      totalSessions: 100,
      activeSessions: 5,
      uniqueSourceIPs: 50,
      totalCredentialAttempts: 500,
      totalCommandsCaptured: 200,
      sessionsByService: {
        ssh: 60,
        http: 30,
        ftp: 5,
        smb: 2,
        mysql: 1,
        rdp: 1,
        telnet: 1,
        redis: 0,
      },
      topAttackerIPs: [{ ip: '1.2.3.4', sessions: 10, riskScore: 75 }],
      topUsernames: [{ username: 'admin', count: 100 }],
      topPasswords: [{ password: '123456', count: 80 }],
      skillDistribution: { script_kiddie: 30, intermediate: 15, advanced: 4, apt: 1 },
      intentDistribution: {
        reconnaissance: 10,
        credential_harvesting: 20,
        ransomware_deployment: 2,
        cryptomining: 5,
        data_theft: 3,
        botnet_recruitment: 1,
        lateral_movement: 2,
        unknown: 7,
      },
      uptimeMs: 3_600_000,
    };
    expect(stats.totalSessions).toBe(100);
  });
});
