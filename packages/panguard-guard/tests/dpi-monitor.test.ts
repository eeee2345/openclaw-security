/**
 * Tests for DPI Monitor
 * DPI 監控器測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { DpiMonitor } from '../src/monitors/dpi-monitor.js';
import type { SecurityEvent } from '@panguard-ai/core';

describe('DpiMonitor', () => {
  let monitor: DpiMonitor;

  beforeEach(() => {
    monitor = new DpiMonitor(5000);
  });

  afterEach(() => {
    monitor.stop();
  });

  it('should extend EventEmitter', () => {
    expect(typeof monitor.on).toBe('function');
    expect(typeof monitor.emit).toBe('function');
  });

  it('should return false on non-Linux platforms', async () => {
    if (process.platform !== 'linux') {
      const available = await monitor.checkAvailability();
      expect(available).toBe(false);
    }
  });

  it('should track running state', () => {
    expect(monitor.isRunning()).toBe(false);
  });

  it('should stop cleanly even if not started', () => {
    expect(() => monitor.stop()).not.toThrow();
    expect(monitor.isRunning()).toBe(false);
  });

  it('should return empty beacon summary when not tracking', () => {
    const summary = monitor.getBeaconSummary();
    expect(summary).toEqual([]);
  });
});

describe('DPI DNS tunneling detection', () => {
  let monitor: DpiMonitor;
  let events: SecurityEvent[];

  beforeEach(() => {
    monitor = new DpiMonitor(60000); // Long interval, we test manually
    events = [];
    monitor.on('event', (event: SecurityEvent) => {
      events.push(event);
    });
  });

  afterEach(() => {
    monitor.stop();
  });

  it('should detect known DNS tunnel tool domains', () => {
    monitor.submitDnsQuery('test.dnscat2.example.com', 'A');
    expect(events).toHaveLength(1);
    expect(events[0]!.category).toBe('dns_tunneling');
    expect(events[0]!.severity).toBe('critical');
    expect(events[0]!.description).toContain('Known DNS tunnel tool');
  });

  it('should detect iodine DNS tunnel', () => {
    monitor.submitDnsQuery('data.iodine.tunneldomain.net', 'A');
    expect(events).toHaveLength(1);
    expect(events[0]!.severity).toBe('critical');
  });

  it('should detect high-entropy subdomain labels', () => {
    // Base64-like encoded data in subdomain
    monitor.submitDnsQuery('aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.example.com', 'A');
    expect(events).toHaveLength(1);
    expect(events[0]!.category).toBe('dns_tunneling');
    expect(events[0]!.severity).toBe('high');
    expect(events[0]!.description).toContain('High-entropy');
  });

  it('should detect suspicious TXT queries with long domains', () => {
    const longDomain = 'a'.repeat(50) + '.b'.repeat(30) + '.example.com';
    monitor.submitDnsQuery(longDomain, 'TXT');
    expect(events).toHaveLength(1);
    expect(events[0]!.description).toContain('TXT query');
  });

  it('should not flag normal domains', () => {
    monitor.submitDnsQuery('www.google.com', 'A');
    expect(events).toHaveLength(0);
  });

  it('should not flag short subdomains', () => {
    monitor.submitDnsQuery('api.example.com', 'A');
    expect(events).toHaveLength(0);
  });

  it('should include MITRE technique in DNS tunnel events', () => {
    monitor.submitDnsQuery('payload.dnscat2.evil.com', 'A');
    expect(events[0]!.metadata?.['mitreTechnique']).toBe('T1071.004');
  });
});

describe('DPI event structure', () => {
  it('should emit events with correct source field', () => {
    const monitor = new DpiMonitor();
    const events: SecurityEvent[] = [];
    monitor.on('event', (e: SecurityEvent) => events.push(e));

    monitor.submitDnsQuery('test.dnscat2.example.com', 'A');
    expect(events[0]!.source).toBe('dpi');
    expect(events[0]!.id).toMatch(/^dpi-dns-/);
    expect(events[0]!.host).toBe('localhost');

    monitor.stop();
  });

  it('should generate unique IDs per event', () => {
    const monitor = new DpiMonitor();
    const events: SecurityEvent[] = [];
    monitor.on('event', (e: SecurityEvent) => events.push(e));

    monitor.submitDnsQuery('a.dnscat2.evil.com', 'A');
    monitor.submitDnsQuery('b.dnscat2.evil.com', 'A');

    expect(events).toHaveLength(2);
    expect(events[0]!.id).not.toBe(events[1]!.id);

    monitor.stop();
  });
});
