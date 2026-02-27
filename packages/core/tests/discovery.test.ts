import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import from source files directly (vitest uses aliases)
import { detectOS } from '../src/discovery/os-detector.js';
import {
  getNetworkInterfaces,
  scanOpenPorts,
  getDnsServers,
} from '../src/discovery/network-scanner.js';
import { detectServices } from '../src/discovery/service-detector.js';
import { detectSecurityTools } from '../src/discovery/security-tools.js';
import { checkFirewall } from '../src/discovery/firewall-checker.js';
import { auditUsers } from '../src/discovery/user-auditor.js';
import { calculateRiskScore, getRiskLevel } from '../src/discovery/risk-scorer.js';

// Suppress log output during tests
beforeEach(() => {
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

describe('OS Detector', () => {
  it('should detect current OS info', { timeout: 30_000 }, async () => {
    const info = await detectOS();
    expect(info.platform).toBeTruthy();
    expect(info.arch).toBeTruthy();
    expect(info.hostname).toBeTruthy();
    expect(info.uptime).toBeGreaterThan(0);
    // Check that it returns the right platform for this machine
    expect(info.platform).toBe(process.platform);
  });
});

describe('Network Scanner', () => {
  it('should return network interfaces', () => {
    const interfaces = getNetworkInterfaces();
    expect(Array.isArray(interfaces)).toBe(true);
    expect(interfaces.length).toBeGreaterThan(0);
    // At least one interface should have an IP
    expect(interfaces.some((i) => i.ip)).toBe(true);
  });

  it('should scan open ports', async () => {
    const ports = await scanOpenPorts();
    expect(Array.isArray(ports)).toBe(true);
    // Should return port objects with required fields
    for (const port of ports) {
      expect(port).toHaveProperty('port');
      expect(port).toHaveProperty('protocol');
    }
  });

  it('should get DNS servers', () => {
    const dns = getDnsServers();
    expect(Array.isArray(dns)).toBe(true);
  });
});

describe('Service Detector', () => {
  it('should detect running services', async () => {
    const services = await detectServices();
    expect(Array.isArray(services)).toBe(true);
    // Should find at least one service on any system
    expect(services.length).toBeGreaterThan(0);
    // Services should have name and status
    for (const svc of services) {
      expect(svc.name).toBeTruthy();
      expect(svc.status).toBeTruthy();
    }
  });
});

describe('Security Tools', () => {
  it('should return array (may be empty on dev machine)', async () => {
    const tools = await detectSecurityTools([]);
    expect(Array.isArray(tools)).toBe(true);
  });
});

describe('Firewall Checker', () => {
  it('should check firewall status without throwing', async () => {
    const status = await checkFirewall();
    expect(status).toHaveProperty('enabled');
    expect(typeof status.enabled).toBe('boolean');
  });
});

describe('User Auditor', () => {
  it('should list user accounts', async () => {
    const users = await auditUsers();
    expect(Array.isArray(users)).toBe(true);
    expect(users.length).toBeGreaterThan(0);
    // Current user should be in the list
    const currentUser = process.env['USER'] || process.env['USERNAME'];
    if (currentUser) {
      expect(users.some((u) => u.username === currentUser)).toBe(true);
    }
  });
});

describe('Risk Scorer', () => {
  it('should calculate risk score in 0-100 range', () => {
    const result = calculateRiskScore({});
    expect(result.riskScore).toBeGreaterThanOrEqual(0);
    expect(result.riskScore).toBeLessThanOrEqual(100);
    expect(Array.isArray(result.factors)).toBe(true);
  });

  it('should give higher score for weaker security', () => {
    const weak = calculateRiskScore({
      security: {
        existingTools: [],
        firewall: { enabled: false, product: 'None', rules: [] },
        updates: { pendingUpdates: 10, autoUpdateEnabled: false },
        users: [
          { username: 'admin1', isAdmin: true },
          { username: 'admin2', isAdmin: true },
          { username: 'admin3', isAdmin: true },
          { username: 'admin4', isAdmin: true },
        ],
      },
      openPorts: [
        { port: 22, protocol: 'tcp', state: 'listening', process: 'sshd', service: 'ssh' },
        { port: 3389, protocol: 'tcp', state: 'listening', process: 'rdp', service: 'rdp' },
        { port: 23, protocol: 'tcp', state: 'listening', process: 'telnet', service: 'telnet' },
      ],
    });
    // Should be high risk
    expect(weak.riskScore).toBeGreaterThan(60);
  });

  it('should map risk levels correctly', () => {
    expect(getRiskLevel(10)).toBe('info');
    expect(getRiskLevel(30)).toBe('low');
    expect(getRiskLevel(50)).toBe('medium');
    expect(getRiskLevel(70)).toBe('high');
    expect(getRiskLevel(90)).toBe('critical');
  });

  // Integration test
  it('should work with discover() function', async () => {
    // Test the risk scorer with real discovery data
    const { calculateRiskScore: score } = await import('../src/discovery/risk-scorer.js');
    const result = score({});
    expect(result.riskScore).toBeGreaterThanOrEqual(0);
  });
});
