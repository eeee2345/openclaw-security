/**
 * SuricataMonitor unit tests
 * SuricataMonitor 單元測試
 */

import { describe, it, expect } from 'vitest';
import { parseSuricataEvent } from '../src/monitors/suricata-monitor.js';
import type { SuricataEveAlert } from '../src/monitors/suricata-monitor.js';

describe('parseSuricataEvent', () => {
  it('should parse a severity 1 (critical) C2 alert', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:00:00.000000+0000',
      event_type: 'alert',
      src_ip: '192.168.1.100',
      src_port: 54321,
      dest_ip: '10.0.0.1',
      dest_port: 443,
      proto: 'TCP',
      alert: {
        action: 'allowed',
        gid: 1,
        signature_id: 2024897,
        rev: 1,
        signature: 'ET TROJAN Win32/Emotet CnC Activity',
        category: 'A Network Trojan was detected',
        severity: 1,
      },
      app_proto: 'tls',
      in_iface: 'eth0',
    };

    const event = parseSuricataEvent(raw);

    expect(event).not.toBeNull();
    expect(event!.source).toBe('suricata');
    expect(event!.severity).toBe('critical');
    // CnC in signature takes priority over trojan in category
    expect(event!.category).toBe('command_and_control');
    expect(event!.description).toContain('Emotet');
    expect(event!.metadata!['sourceIP']).toBe('192.168.1.100');
    expect(event!.metadata!['destIP']).toBe('10.0.0.1');
    expect(event!.metadata!['destPort']).toBe(443);
    expect(event!.metadata!['protocol']).toBe('TCP');
    expect(event!.id).toMatch(/^suricata-/);
  });

  it('should parse a severity 2 (high) web attack alert', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:01:00.000000+0000',
      event_type: 'alert',
      src_ip: '203.0.113.5',
      src_port: 44000,
      dest_ip: '192.168.1.10',
      dest_port: 80,
      proto: 'TCP',
      alert: {
        action: 'allowed',
        signature_id: 2100498,
        signature: 'ET WEB_ATTACK SQL Injection Attempt',
        category: 'Web Application Attack',
        severity: 2,
      },
      app_proto: 'http',
    };

    const event = parseSuricataEvent(raw);

    expect(event).not.toBeNull();
    expect(event!.severity).toBe('high');
    expect(event!.category).toBe('web_attack');
    expect(event!.metadata!['appProto']).toBe('http');
  });

  it('should parse a severity 3 (medium) scan/recon alert', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:02:00.000000+0000',
      event_type: 'alert',
      src_ip: '10.0.0.50',
      dest_ip: '10.0.0.1',
      proto: 'TCP',
      alert: {
        signature_id: 2002910,
        signature: 'ET SCAN Nmap SYN Scan',
        category: 'Attempted Information Leak',
        severity: 3,
      },
    };

    const event = parseSuricataEvent(raw);

    expect(event).not.toBeNull();
    expect(event!.severity).toBe('medium');
    expect(event!.category).toBe('reconnaissance');
  });

  it('should parse severity 4 as low', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:03:00.000000+0000',
      event_type: 'alert',
      src_ip: '10.0.0.1',
      dest_ip: '8.8.8.8',
      proto: 'UDP',
      alert: {
        signature_id: 2027757,
        signature: 'ET POLICY DNS Query to .onion proxy Domain',
        category: 'Potential Corporate Privacy Violation',
        severity: 4,
      },
    };

    const event = parseSuricataEvent(raw);

    expect(event).not.toBeNull();
    expect(event!.severity).toBe('low');
    expect(event!.category).toBe('policy_violation');
  });

  it('should return null for non-alert event types', () => {
    const dnsEvent: SuricataEveAlert = {
      timestamp: '2026-02-28T12:04:00.000000+0000',
      event_type: 'dns',
      src_ip: '10.0.0.1',
      dest_ip: '8.8.8.8',
    };

    expect(parseSuricataEvent(dnsEvent)).toBeNull();
  });

  it('should return null for alert without alert object', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:05:00.000000+0000',
      event_type: 'alert',
      src_ip: '10.0.0.1',
    };

    expect(parseSuricataEvent(raw)).toBeNull();
  });

  it('should parse C2 / command and control category', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:06:00.000000+0000',
      event_type: 'alert',
      src_ip: '192.168.1.50',
      dest_ip: '45.33.32.156',
      dest_port: 8080,
      proto: 'TCP',
      alert: {
        signature_id: 2025000,
        signature: 'ET CNC Cobalt Strike Beacon Activity',
        category: 'A Network Trojan was detected',
        severity: 1,
      },
    };

    const event = parseSuricataEvent(raw);

    expect(event).not.toBeNull();
    // "CNC" in signature maps to command_and_control
    expect(event!.category).toBe('command_and_control');
  });

  it('should parse cryptomining alert', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:07:00.000000+0000',
      event_type: 'alert',
      src_ip: '192.168.1.100',
      dest_ip: '104.28.8.93',
      dest_port: 3333,
      proto: 'TCP',
      alert: {
        signature_id: 2024792,
        signature: 'ET POLICY Cryptocurrency Mining Stratum Protocol',
        category: 'Potential Corporate Privacy Violation',
        severity: 2,
      },
    };

    const event = parseSuricataEvent(raw);

    expect(event).not.toBeNull();
    expect(event!.category).toBe('cryptomining');
  });

  it('should generate unique event IDs', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:08:00.000000+0000',
      event_type: 'alert',
      src_ip: '10.0.0.1',
      alert: {
        signature_id: 1000001,
        signature: 'Test Rule',
        severity: 3,
      },
    };

    const event1 = parseSuricataEvent(raw);
    const event2 = parseSuricataEvent(raw);

    expect(event1).not.toBeNull();
    expect(event2).not.toBeNull();
    expect(event1!.id).not.toBe(event2!.id);
  });

  it('should handle missing optional fields gracefully', () => {
    const raw: SuricataEveAlert = {
      timestamp: '2026-02-28T12:09:00.000000+0000',
      event_type: 'alert',
      alert: {
        signature_id: 9999,
        severity: 1,
      },
    };

    const event = parseSuricataEvent(raw);

    expect(event).not.toBeNull();
    expect(event!.source).toBe('suricata');
    expect(event!.severity).toBe('critical');
    expect(event!.description).toContain('9999');
    expect(event!.metadata!['sourceIP']).toBeUndefined();
    expect(event!.metadata!['protocol']).toBeUndefined();
  });

  it('should use signature as description, fallback to SID', () => {
    const withSig: SuricataEveAlert = {
      timestamp: '2026-02-28T12:10:00.000000+0000',
      event_type: 'alert',
      alert: {
        signature_id: 2000001,
        signature: 'Custom Detection Rule',
        severity: 2,
      },
    };

    const withoutSig: SuricataEveAlert = {
      timestamp: '2026-02-28T12:11:00.000000+0000',
      event_type: 'alert',
      alert: {
        signature_id: 2000002,
        severity: 3,
      },
    };

    const event1 = parseSuricataEvent(withSig);
    const event2 = parseSuricataEvent(withoutSig);

    expect(event1!.description).toBe('Custom Detection Rule');
    expect(event2!.description).toContain('2000002');
  });
});
