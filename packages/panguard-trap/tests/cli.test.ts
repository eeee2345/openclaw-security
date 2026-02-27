/**
 * PanguardTrap CLI tests
 * PanguardTrap CLI 測試
 */

import { describe, it, expect } from 'vitest';
import {
  parseCliArgs,
  buildConfigFromOptions,
  formatStatistics,
  getHelpText,
} from '../src/cli/index.js';
import type { TrapStatistics } from '../src/types.js';

describe('parseCliArgs', () => {
  it('should parse help command', () => {
    const options = parseCliArgs(['help']);
    expect(options.command).toBe('help');
  });

  it('should default to help when no args', () => {
    const options = parseCliArgs([]);
    expect(options.command).toBe('help');
  });

  it('should parse start command', () => {
    const options = parseCliArgs(['start']);
    expect(options.command).toBe('start');
  });

  it('should parse --services option', () => {
    const options = parseCliArgs(['start', '--services', 'ssh,http,ftp']);
    expect(options.services).toEqual(['ssh', 'http', 'ftp']);
  });

  it('should parse --port option', () => {
    const options = parseCliArgs(['deploy', '--port', '9999']);
    expect(options.port).toBe(9999);
  });

  it('should parse --data-dir option', () => {
    const options = parseCliArgs(['start', '--data-dir', '/tmp/trap']);
    expect(options.dataDir).toBe('/tmp/trap');
  });

  it('should parse --no-cloud flag', () => {
    const options = parseCliArgs(['start', '--no-cloud']);
    expect(options.noCloud).toBe(true);
  });

  it('should parse --verbose flag', () => {
    const options = parseCliArgs(['start', '--verbose']);
    expect(options.verbose).toBe(true);
  });

  it('should parse -v flag', () => {
    const options = parseCliArgs(['start', '-v']);
    expect(options.verbose).toBe(true);
  });
});

describe('buildConfigFromOptions', () => {
  it('should build default config', () => {
    const options = parseCliArgs(['start']);
    const config = buildConfigFromOptions(options);
    expect(config.feedThreatCloud).toBe(true);
    expect(config.dataDir).toBeTruthy();
  });

  it('should override data dir', () => {
    const options = parseCliArgs(['start', '--data-dir', '/custom/path']);
    const config = buildConfigFromOptions(options);
    expect(config.dataDir).toBe('/custom/path');
  });

  it('should disable threat cloud', () => {
    const options = parseCliArgs(['start', '--no-cloud']);
    const config = buildConfigFromOptions(options);
    expect(config.feedThreatCloud).toBe(false);
  });

  it('should configure specific services', () => {
    const options = parseCliArgs(['start', '--services', 'ssh,ftp']);
    const config = buildConfigFromOptions(options);
    expect(config.services).toHaveLength(2);
    expect(config.services.map((s) => s.type)).toContain('ssh');
    expect(config.services.map((s) => s.type)).toContain('ftp');
    expect(config.services.every((s) => s.enabled)).toBe(true);
  });
});

describe('formatStatistics', () => {
  it('should format statistics for display', () => {
    const stats: TrapStatistics = {
      totalSessions: 42,
      activeSessions: 3,
      uniqueSourceIPs: 15,
      totalCredentialAttempts: 200,
      totalCommandsCaptured: 85,
      sessionsByService: {
        ssh: 25,
        http: 12,
        ftp: 3,
        smb: 1,
        mysql: 1,
        rdp: 0,
        telnet: 0,
        redis: 0,
      },
      topAttackerIPs: [
        { ip: '1.2.3.4', sessions: 10, riskScore: 75 },
        { ip: '5.6.7.8', sessions: 5, riskScore: 30 },
      ],
      topUsernames: [
        { username: 'admin', count: 50 },
        { username: 'root', count: 40 },
      ],
      topPasswords: [{ password: '123456', count: 30 }],
      skillDistribution: { script_kiddie: 10, intermediate: 4, advanced: 1, apt: 0 },
      intentDistribution: {
        reconnaissance: 5,
        credential_harvesting: 8,
        ransomware_deployment: 0,
        cryptomining: 1,
        data_theft: 0,
        botnet_recruitment: 0,
        lateral_movement: 1,
        unknown: 0,
      },
      uptimeMs: 7_200_000, // 2 hours
    };

    const output = formatStatistics(stats);
    expect(output).toContain('42');
    expect(output).toContain('3');
    expect(output).toContain('15');
    expect(output).toContain('200');
    expect(output).toContain('ssh: 25');
    expect(output).toContain('1.2.3.4');
    expect(output).toContain('admin');
    expect(output).toContain('script_kiddie: 10');
    expect(output).toContain('2h 0m');
  });
});

describe('getHelpText', () => {
  it('should contain title and usage', () => {
    const help = getHelpText();
    expect(help).toContain('PanguardTrap');
    expect(help).toContain('Panguard AI');
    expect(help).toContain('panguard-trap <command>');
  });

  it('should list all commands', () => {
    const help = getHelpText();
    expect(help).toContain('start');
    expect(help).toContain('stop');
    expect(help).toContain('status');
    expect(help).toContain('deploy');
    expect(help).toContain('profiles');
    expect(help).toContain('intel');
    expect(help).toContain('config');
    expect(help).toContain('help');
  });

  it('should list options', () => {
    const help = getHelpText();
    expect(help).toContain('--services');
    expect(help).toContain('--port');
    expect(help).toContain('--data-dir');
    expect(help).toContain('--no-cloud');
    expect(help).toContain('--verbose');
  });

  it('should include bilingual text', () => {
    const help = getHelpText();
    expect(help).toContain('Smart Honeypot System');
    expect(help).toContain('智慧蜜罐系統');
  });
});
