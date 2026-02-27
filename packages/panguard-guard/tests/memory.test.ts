/**
 * Context Memory tests
 * Context Memory 測試
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { SecurityEvent } from '@panguard-ai/core';
import type { EnvironmentBaseline } from '../src/types.js';
import { createEmptyBaseline, checkDeviation, updateBaseline } from '../src/memory/baseline.js';
import {
  isLearningComplete,
  getLearningProgress,
  getRemainingDays,
  switchToProtectionMode,
  getBaselineSummary,
} from '../src/memory/learning.js';

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

describe('baseline', () => {
  let baseline: EnvironmentBaseline;

  beforeEach(() => {
    baseline = createEmptyBaseline();
  });

  it('should create empty baseline with correct defaults', () => {
    expect(baseline.normalProcesses).toEqual([]);
    expect(baseline.normalConnections).toEqual([]);
    expect(baseline.normalLoginPatterns).toEqual([]);
    expect(baseline.normalServicePorts).toEqual([]);
    expect(baseline.learningComplete).toBe(false);
    expect(baseline.confidenceLevel).toBe(0);
    expect(baseline.eventCount).toBe(0);
  });

  it('should detect no deviation for empty baseline', () => {
    const event = makeEvent();
    const result = checkDeviation(baseline, event);
    // Empty baseline: no known processes, so a process event without processName won't flag
    expect(result.isDeviation).toBe(false);
  });

  it('should detect new process deviation', () => {
    // Add a known process
    baseline.normalProcesses = [
      { name: 'nginx', frequency: 10, firstSeen: '2024-01-01', lastSeen: '2024-01-02' },
    ];

    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'suspicious-tool' },
    });

    const result = checkDeviation(baseline, event);
    expect(result.isDeviation).toBe(true);
    expect(result.deviationType).toBe('new_process');
    expect(result.confidence).toBe(70);
  });

  it('should not flag known process', () => {
    baseline.normalProcesses = [
      { name: 'nginx', frequency: 10, firstSeen: '2024-01-01', lastSeen: '2024-01-02' },
    ];

    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'nginx' },
    });

    const result = checkDeviation(baseline, event);
    expect(result.isDeviation).toBe(false);
  });

  it('should detect new network destination', () => {
    baseline.normalConnections = [
      {
        remoteAddress: '1.1.1.1',
        remotePort: 443,
        protocol: 'tcp',
        frequency: 5,
        firstSeen: '2024-01-01',
        lastSeen: '2024-01-02',
      },
    ];

    const event = makeEvent({
      source: 'network',
      metadata: { remoteAddress: '10.0.0.99' },
    });

    const result = checkDeviation(baseline, event);
    expect(result.isDeviation).toBe(true);
    expect(result.deviationType).toBe('new_network_dest');
  });

  it('should update baseline with process event', () => {
    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'node', processPath: '/usr/bin/node' },
    });

    const updated = updateBaseline(baseline, event);
    expect(updated.eventCount).toBe(1);
    expect(updated.normalProcesses.length).toBe(1);
    expect(updated.normalProcesses[0]!.name).toBe('node');
  });

  it('should increment frequency for known process', () => {
    const event = makeEvent({
      source: 'process',
      metadata: { processName: 'node' },
    });

    let updated = updateBaseline(baseline, event);
    updated = updateBaseline(updated, event);
    expect(updated.eventCount).toBe(2);
    expect(updated.normalProcesses.length).toBe(1);
    expect(updated.normalProcesses[0]!.frequency).toBe(2);
  });

  it('should update baseline with network event', () => {
    const event = makeEvent({
      source: 'network',
      metadata: { remoteAddress: '8.8.8.8', remotePort: 53, protocol: 'udp' },
    });

    const updated = updateBaseline(baseline, event);
    expect(updated.normalConnections.length).toBe(1);
    expect(updated.normalConnections[0]!.remoteAddress).toBe('8.8.8.8');
  });
});

describe('learning', () => {
  let baseline: EnvironmentBaseline;

  beforeEach(() => {
    baseline = createEmptyBaseline();
  });

  it('should report learning not complete at start', () => {
    expect(isLearningComplete(baseline, 7)).toBe(false);
  });

  it('should report learning complete when flag is set', () => {
    baseline.learningComplete = true;
    expect(isLearningComplete(baseline, 7)).toBe(true);
  });

  it('should report learning complete after enough days', () => {
    baseline.learningStarted = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    expect(isLearningComplete(baseline, 7)).toBe(true);
  });

  it('should get learning progress at 0%', () => {
    expect(getLearningProgress(baseline, 7)).toBe(0);
  });

  it('should get learning progress at 100% when complete', () => {
    baseline.learningComplete = true;
    expect(getLearningProgress(baseline, 7)).toBe(100);
  });

  it('should get remaining days', () => {
    const remaining = getRemainingDays(baseline, 7);
    expect(remaining).toBe(7);
  });

  it('should get 0 remaining days when complete', () => {
    baseline.learningComplete = true;
    expect(getRemainingDays(baseline, 7)).toBe(0);
  });

  it('should switch to protection mode', () => {
    baseline.normalProcesses = [
      { name: 'test', frequency: 1, firstSeen: '2024-01-01', lastSeen: '2024-01-02' },
    ];
    const result = switchToProtectionMode(baseline);
    expect(result.learningComplete).toBe(true);
  });

  it('should get baseline summary', () => {
    baseline.normalProcesses = [
      { name: 'a', frequency: 1, firstSeen: '2024-01-01', lastSeen: '2024-01-02' },
    ];
    baseline.eventCount = 42;
    baseline.confidenceLevel = 0.5;

    const summary = getBaselineSummary(baseline);
    expect(summary.processCount).toBe(1);
    expect(summary.eventCount).toBe(42);
    expect(summary.confidenceLevel).toBe(0.5);
    expect(summary.learningComplete).toBe(false);
  });
});
