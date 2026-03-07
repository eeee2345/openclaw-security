/**
 * Continuous Baseline Learning tests
 * 持續基線學習測試
 *
 * Tests continuousBaselineUpdate and pruneStalePatterns functions.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { SecurityEvent } from '@panguard-ai/core';
import type { EnvironmentBaseline } from '../src/types.js';
import {
  createEmptyBaseline,
  continuousBaselineUpdate,
  pruneStalePatterns,
} from '../src/memory/baseline.js';

// ---------------------------------------------------------------------------
// Helper: create a SecurityEvent with sensible defaults
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: 'evt-001',
    timestamp: new Date(),
    source: 'process',
    severity: 'medium',
    category: 'process_execution',
    description: 'Test event',
    host: 'test-host',
    metadata: {},
    ...overrides,
  };
}

/** Create a baseline with some pre-existing patterns for testing */
function makePopulatedBaseline(): EnvironmentBaseline {
  const now = new Date().toISOString();
  return {
    normalProcesses: [
      { name: 'nginx', path: '/usr/sbin/nginx', frequency: 10, firstSeen: now, lastSeen: now },
      { name: 'node', path: '/usr/bin/node', frequency: 5, firstSeen: now, lastSeen: now },
    ],
    normalConnections: [
      {
        remoteAddress: '8.8.8.8',
        remotePort: 53,
        protocol: 'udp',
        frequency: 20,
        firstSeen: now,
        lastSeen: now,
      },
    ],
    normalLoginPatterns: [
      {
        username: 'admin',
        sourceIP: '10.0.0.1',
        hourOfDay: 9,
        dayOfWeek: 1,
        frequency: 15,
        firstSeen: now,
        lastSeen: now,
      },
    ],
    normalServicePorts: [
      { port: 443, service: 'https', firstSeen: now, lastSeen: now },
    ],
    learningStarted: now,
    learningComplete: true,
    confidenceLevel: 0.6,
    lastUpdated: now,
    eventCount: 500,
  };
}

// ---------------------------------------------------------------------------
// continuousBaselineUpdate
// ---------------------------------------------------------------------------

describe('continuousBaselineUpdate', () => {
  let baseline: EnvironmentBaseline;

  beforeEach(() => {
    baseline = makePopulatedBaseline();
  });

  it('should update baseline for benign events', () => {
    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'nginx' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    expect(updated.eventCount).toBe(baseline.eventCount + 1);
    expect(updated).not.toBe(baseline); // immutable: new object
  });

  it('should NOT update baseline for suspicious events', () => {
    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'suspicious-tool' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'suspicious');

    // Baseline should be returned unchanged (same reference)
    expect(updated).toBe(baseline);
    expect(updated.eventCount).toBe(baseline.eventCount);
  });

  it('should NOT update baseline for malicious events', () => {
    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'malware' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'malicious');

    expect(updated).toBe(baseline);
    expect(updated.eventCount).toBe(baseline.eventCount);
  });

  it('should add new process patterns with 0.25 initial frequency', () => {
    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'postgres', processPath: '/usr/bin/postgres' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    const newProcess = updated.normalProcesses.find((p) => p.name === 'postgres');
    expect(newProcess).toBeDefined();
    expect(newProcess!.frequency).toBe(0.25);
    expect(newProcess!.path).toBe('/usr/bin/postgres');
  });

  it('should increment existing process pattern frequency by 0.25', () => {
    const originalFrequency = baseline.normalProcesses.find(
      (p) => p.name === 'nginx'
    )!.frequency;

    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'nginx' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    const nginxPattern = updated.normalProcesses.find((p) => p.name === 'nginx');
    expect(nginxPattern).toBeDefined();
    expect(nginxPattern!.frequency).toBe(originalFrequency + 0.25);
  });

  it('should add new connection patterns with 0.25 initial frequency', () => {
    const event = makeEvent({
      source: 'network',
      metadata: { remoteAddress: '1.1.1.1', remotePort: 443, protocol: 'tcp' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    const newConn = updated.normalConnections.find(
      (c) => c.remoteAddress === '1.1.1.1' && c.remotePort === 443
    );
    expect(newConn).toBeDefined();
    expect(newConn!.frequency).toBe(0.25);
  });

  it('should increment existing connection frequency by 0.25', () => {
    const originalFreq = baseline.normalConnections.find(
      (c) => c.remoteAddress === '8.8.8.8'
    )!.frequency;

    const event = makeEvent({
      source: 'network',
      metadata: { remoteAddress: '8.8.8.8', remotePort: 53, protocol: 'udp' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    const conn = updated.normalConnections.find(
      (c) => c.remoteAddress === '8.8.8.8' && c.remotePort === 53
    );
    expect(conn!.frequency).toBe(originalFreq + 0.25);
  });

  it('should add new login patterns with 0.25 initial frequency', () => {
    const event = makeEvent({
      source: 'process',
      metadata: { user: 'deploy-bot' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    const newLogin = updated.normalLoginPatterns.find(
      (l) => l.username === 'deploy-bot'
    );
    expect(newLogin).toBeDefined();
    expect(newLogin!.frequency).toBe(0.25);
  });

  it('should increment existing login pattern frequency by 0.25', () => {
    const originalFreq = baseline.normalLoginPatterns.find(
      (l) => l.username === 'admin'
    )!.frequency;

    const event = makeEvent({
      source: 'process',
      metadata: { user: 'admin' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    const login = updated.normalLoginPatterns.find((l) => l.username === 'admin');
    expect(login!.frequency).toBe(originalFreq + 0.25);
  });

  it('should set lastContinuousUpdate timestamp', () => {
    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'nginx' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    expect(updated.lastContinuousUpdate).toBeDefined();
    expect(typeof updated.lastContinuousUpdate).toBe('string');
    // Should be a valid ISO date
    const parsed = new Date(updated.lastContinuousUpdate!);
    expect(parsed.getTime()).not.toBeNaN();
  });

  it('should recalculate confidence level', () => {
    // Start with a baseline that has low event count
    const lowBaseline = createEmptyBaseline();
    lowBaseline.eventCount = 50;
    lowBaseline.confidenceLevel = 0.15;

    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'test-proc' },
    });

    const updated = continuousBaselineUpdate(lowBaseline, event, 'benign');

    // After update, eventCount = 51, confidence should be recalculated
    // For 51 events (< 100 minimum), confidence = (51/100) * 0.3 = 0.153
    expect(updated.confidenceLevel).toBeGreaterThan(0);
    expect(typeof updated.confidenceLevel).toBe('number');
  });

  it('should not mutate the original baseline', () => {
    const originalProcessCount = baseline.normalProcesses.length;
    const originalEventCount = baseline.eventCount;

    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'new-process' },
    });

    continuousBaselineUpdate(baseline, event, 'benign');

    // Original should be untouched
    expect(baseline.normalProcesses.length).toBe(originalProcessCount);
    expect(baseline.eventCount).toBe(originalEventCount);
  });
});

// ---------------------------------------------------------------------------
// pruneStalePatterns
// ---------------------------------------------------------------------------

describe('pruneStalePatterns', () => {
  it('should prune process patterns older than retention window', () => {
    const now = new Date();
    const staleDate = new Date(now.getTime() - 45 * 24 * 60 * 60 * 1000).toISOString(); // 45 days ago
    const recentDate = now.toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [
        { name: 'old-proc', frequency: 5, firstSeen: staleDate, lastSeen: staleDate },
        { name: 'new-proc', frequency: 10, firstSeen: recentDate, lastSeen: recentDate },
      ],
      normalConnections: [],
      normalLoginPatterns: [],
      normalServicePorts: [],
      learningStarted: staleDate,
      learningComplete: true,
      confidenceLevel: 0.5,
      lastUpdated: recentDate,
      eventCount: 100,
    };

    const pruned = pruneStalePatterns(baseline, 30);

    expect(pruned.normalProcesses.length).toBe(1);
    expect(pruned.normalProcesses[0]!.name).toBe('new-proc');
  });

  it('should prune connection patterns older than retention window', () => {
    const staleDate = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
    const recentDate = new Date().toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [],
      normalConnections: [
        {
          remoteAddress: '1.2.3.4',
          remotePort: 80,
          protocol: 'tcp',
          frequency: 3,
          firstSeen: staleDate,
          lastSeen: staleDate,
        },
        {
          remoteAddress: '5.6.7.8',
          remotePort: 443,
          protocol: 'tcp',
          frequency: 10,
          firstSeen: recentDate,
          lastSeen: recentDate,
        },
      ],
      normalLoginPatterns: [],
      normalServicePorts: [],
      learningStarted: staleDate,
      learningComplete: true,
      confidenceLevel: 0.5,
      lastUpdated: recentDate,
      eventCount: 100,
    };

    const pruned = pruneStalePatterns(baseline, 30);

    expect(pruned.normalConnections.length).toBe(1);
    expect(pruned.normalConnections[0]!.remoteAddress).toBe('5.6.7.8');
  });

  it('should prune login patterns older than retention window', () => {
    const staleDate = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
    const recentDate = new Date().toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [],
      normalConnections: [],
      normalLoginPatterns: [
        {
          username: 'old-user',
          hourOfDay: 9,
          dayOfWeek: 1,
          frequency: 2,
          firstSeen: staleDate,
          lastSeen: staleDate,
        },
        {
          username: 'active-user',
          hourOfDay: 14,
          dayOfWeek: 3,
          frequency: 50,
          firstSeen: staleDate,
          lastSeen: recentDate,
        },
      ],
      normalServicePorts: [],
      learningStarted: staleDate,
      learningComplete: true,
      confidenceLevel: 0.5,
      lastUpdated: recentDate,
      eventCount: 100,
    };

    const pruned = pruneStalePatterns(baseline, 30);

    expect(pruned.normalLoginPatterns.length).toBe(1);
    expect(pruned.normalLoginPatterns[0]!.username).toBe('active-user');
  });

  it('should prune service port patterns older than retention window', () => {
    const staleDate = new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString();
    const recentDate = new Date().toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [],
      normalConnections: [],
      normalLoginPatterns: [],
      normalServicePorts: [
        { port: 8080, service: 'old-svc', firstSeen: staleDate, lastSeen: staleDate },
        { port: 443, service: 'https', firstSeen: recentDate, lastSeen: recentDate },
      ],
      learningStarted: staleDate,
      learningComplete: true,
      confidenceLevel: 0.5,
      lastUpdated: recentDate,
      eventCount: 100,
    };

    const pruned = pruneStalePatterns(baseline, 30);

    expect(pruned.normalServicePorts.length).toBe(1);
    expect(pruned.normalServicePorts[0]!.port).toBe(443);
  });

  it('should keep patterns with recent lastSeen', () => {
    const recentDate = new Date().toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [
        { name: 'active', frequency: 100, firstSeen: recentDate, lastSeen: recentDate },
      ],
      normalConnections: [
        {
          remoteAddress: '10.0.0.1',
          remotePort: 22,
          protocol: 'tcp',
          frequency: 50,
          firstSeen: recentDate,
          lastSeen: recentDate,
        },
      ],
      normalLoginPatterns: [
        {
          username: 'root',
          hourOfDay: 10,
          dayOfWeek: 2,
          frequency: 30,
          firstSeen: recentDate,
          lastSeen: recentDate,
        },
      ],
      normalServicePorts: [
        { port: 22, service: 'ssh', firstSeen: recentDate, lastSeen: recentDate },
      ],
      learningStarted: recentDate,
      learningComplete: true,
      confidenceLevel: 0.8,
      lastUpdated: recentDate,
      eventCount: 1000,
    };

    const pruned = pruneStalePatterns(baseline, 30);

    expect(pruned.normalProcesses.length).toBe(1);
    expect(pruned.normalConnections.length).toBe(1);
    expect(pruned.normalLoginPatterns.length).toBe(1);
    expect(pruned.normalServicePorts.length).toBe(1);
  });

  it('should return empty arrays after pruning empty baseline', () => {
    const baseline = createEmptyBaseline();
    const pruned = pruneStalePatterns(baseline, 30);

    expect(pruned.normalProcesses).toEqual([]);
    expect(pruned.normalConnections).toEqual([]);
    expect(pruned.normalLoginPatterns).toEqual([]);
    expect(pruned.normalServicePorts).toEqual([]);
  });

  it('should use default retention of 30 days when not specified', () => {
    const thirtyOneDaysAgo = new Date(
      Date.now() - 31 * 24 * 60 * 60 * 1000
    ).toISOString();
    const recentDate = new Date().toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [
        { name: 'stale', frequency: 1, firstSeen: thirtyOneDaysAgo, lastSeen: thirtyOneDaysAgo },
        { name: 'fresh', frequency: 1, firstSeen: recentDate, lastSeen: recentDate },
      ],
      normalConnections: [],
      normalLoginPatterns: [],
      normalServicePorts: [],
      learningStarted: thirtyOneDaysAgo,
      learningComplete: true,
      confidenceLevel: 0.5,
      lastUpdated: recentDate,
      eventCount: 100,
    };

    // Call without retentionDays parameter (defaults to 30)
    const pruned = pruneStalePatterns(baseline);

    expect(pruned.normalProcesses.length).toBe(1);
    expect(pruned.normalProcesses[0]!.name).toBe('fresh');
  });

  it('should not mutate the original baseline', () => {
    const staleDate = new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString();
    const recentDate = new Date().toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [
        { name: 'stale', frequency: 1, firstSeen: staleDate, lastSeen: staleDate },
        { name: 'fresh', frequency: 1, firstSeen: recentDate, lastSeen: recentDate },
      ],
      normalConnections: [],
      normalLoginPatterns: [],
      normalServicePorts: [],
      learningStarted: staleDate,
      learningComplete: true,
      confidenceLevel: 0.5,
      lastUpdated: recentDate,
      eventCount: 100,
    };

    const originalLength = baseline.normalProcesses.length;
    pruneStalePatterns(baseline, 30);

    expect(baseline.normalProcesses.length).toBe(originalLength);
  });

  it('should handle custom retention window', () => {
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    const recentDate = new Date().toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [
        { name: 'old', frequency: 1, firstSeen: eightDaysAgo, lastSeen: eightDaysAgo },
        { name: 'current', frequency: 1, firstSeen: recentDate, lastSeen: recentDate },
      ],
      normalConnections: [],
      normalLoginPatterns: [],
      normalServicePorts: [],
      learningStarted: eightDaysAgo,
      learningComplete: true,
      confidenceLevel: 0.5,
      lastUpdated: recentDate,
      eventCount: 100,
    };

    // 7 day retention should prune 8-day-old pattern
    const pruned = pruneStalePatterns(baseline, 7);
    expect(pruned.normalProcesses.length).toBe(1);
    expect(pruned.normalProcesses[0]!.name).toBe('current');

    // 10 day retention should keep both
    const pruned2 = pruneStalePatterns(baseline, 10);
    expect(pruned2.normalProcesses.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Integration: continuousBaselineUpdate calls pruneStalePatterns internally
// ---------------------------------------------------------------------------

describe('continuousBaselineUpdate - integration with pruning', () => {
  it('should prune stale patterns during continuous update', () => {
    const staleDate = new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString();
    const recentDate = new Date().toISOString();

    const baseline: EnvironmentBaseline = {
      normalProcesses: [
        { name: 'stale-proc', frequency: 5, firstSeen: staleDate, lastSeen: staleDate },
        { name: 'active-proc', frequency: 10, firstSeen: recentDate, lastSeen: recentDate },
      ],
      normalConnections: [],
      normalLoginPatterns: [],
      normalServicePorts: [],
      learningStarted: staleDate,
      learningComplete: true,
      confidenceLevel: 0.5,
      lastUpdated: recentDate,
      eventCount: 200,
    };

    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'active-proc' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign', 30);

    // stale-proc should have been pruned
    expect(updated.normalProcesses.find((p) => p.name === 'stale-proc')).toBeUndefined();
    // active-proc should remain with incremented frequency
    const activeProc = updated.normalProcesses.find((p) => p.name === 'active-proc');
    expect(activeProc).toBeDefined();
    expect(activeProc!.frequency).toBe(10.25);
  });

  it('should handle network event continuous update end-to-end', () => {
    const baseline = makePopulatedBaseline();

    const event = makeEvent({
      source: 'network',
      metadata: {
        remoteAddress: '93.184.216.34',
        remotePort: 80,
        protocol: 'tcp',
      },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    // New connection should be added
    const newConn = updated.normalConnections.find(
      (c) => c.remoteAddress === '93.184.216.34'
    );
    expect(newConn).toBeDefined();
    expect(newConn!.frequency).toBe(0.25);
    expect(newConn!.remotePort).toBe(80);
    expect(newConn!.protocol).toBe('tcp');
  });

  it('should handle event with username for login pattern continuous update', () => {
    const baseline = makePopulatedBaseline();

    const event = makeEvent({
      source: 'process',
      metadata: { user: 'new-user', processName: 'bash' },
    });

    const updated = continuousBaselineUpdate(baseline, event, 'benign');

    const newLogin = updated.normalLoginPatterns.find(
      (l) => l.username === 'new-user'
    );
    expect(newLogin).toBeDefined();
    expect(newLogin!.frequency).toBe(0.25);
  });
});
