/**
 * Baseline Operations Benchmark
 *
 * Measures performance of continuousBaselineUpdate and pruneStalePatterns
 * with varying baseline sizes.
 */

import { bench, describe } from 'vitest';
import type { SecurityEvent } from '@panguard-ai/core';
import { setLogLevel } from '@panguard-ai/core';
import type {
  EnvironmentBaseline,
  ProcessPattern,
  ConnectionPattern,
  LoginPattern,
  PortPattern,
} from '../src/types.js';
import {
  continuousBaselineUpdate,
  pruneStalePatterns,
  updateBaseline,
} from '../src/memory/baseline.js';

// Suppress all logging during benchmarks to avoid OOM from stderr writes
setLogLevel('silent');

// ---------------------------------------------------------------------------
// Synthetic data factories
// ---------------------------------------------------------------------------

function makeProcessPattern(index: number, stale: boolean): ProcessPattern {
  const lastSeen = stale
    ? new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString() // 60 days ago
    : new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(); // 2 days ago

  return {
    name: `process-${index}`,
    path: `/usr/bin/process-${index}`,
    frequency: Math.floor(Math.random() * 100) + 1,
    firstSeen: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeen,
  };
}

function makeConnectionPattern(index: number, stale: boolean): ConnectionPattern {
  const lastSeen = stale
    ? new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString()
    : new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();

  return {
    remoteAddress: `10.0.${Math.floor(index / 256)}.${index % 256}`,
    remotePort: 1024 + (index % 60000),
    protocol: index % 3 === 0 ? 'udp' : 'tcp',
    frequency: Math.floor(Math.random() * 50) + 1,
    firstSeen: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeen,
  };
}

function makeLoginPattern(index: number, stale: boolean): LoginPattern {
  const lastSeen = stale
    ? new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString()
    : new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();

  return {
    username: `user-${index}`,
    sourceIP: `192.168.1.${index % 256}`,
    hourOfDay: index % 24,
    dayOfWeek: index % 7,
    frequency: Math.floor(Math.random() * 30) + 1,
    firstSeen: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeen,
  };
}

function makePortPattern(index: number, stale: boolean): PortPattern {
  const lastSeen = stale
    ? new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString()
    : new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();

  return {
    port: 1024 + index,
    service: `svc-${index}`,
    firstSeen: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeen,
  };
}

function buildBaseline(
  processCount: number,
  connectionCount: number,
  loginCount: number,
  portCount: number,
  staleRatio: number = 0.2,
): EnvironmentBaseline {
  const processes: ProcessPattern[] = [];
  for (let i = 0; i < processCount; i++) {
    processes.push(makeProcessPattern(i, i < processCount * staleRatio));
  }

  const connections: ConnectionPattern[] = [];
  for (let i = 0; i < connectionCount; i++) {
    connections.push(makeConnectionPattern(i, i < connectionCount * staleRatio));
  }

  const logins: LoginPattern[] = [];
  for (let i = 0; i < loginCount; i++) {
    logins.push(makeLoginPattern(i, i < loginCount * staleRatio));
  }

  const ports: PortPattern[] = [];
  for (let i = 0; i < portCount; i++) {
    ports.push(makePortPattern(i, i < portCount * staleRatio));
  }

  return {
    normalProcesses: processes,
    normalConnections: connections,
    normalLoginPatterns: logins,
    normalServicePorts: ports,
    learningStarted: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    learningComplete: true,
    confidenceLevel: 0.85,
    lastUpdated: new Date().toISOString(),
    eventCount: processCount + connectionCount + loginCount,
  };
}

function makeProcessEvent(index: number): SecurityEvent {
  return {
    id: `base-evt-proc-${index}`,
    timestamp: new Date(),
    source: 'process',
    severity: 'info',
    category: 'process_creation',
    description: `Process event ${index}`,
    raw: {},
    host: 'bench-host',
    metadata: {
      processName: `new-proc-${index}`,
      processPath: `/usr/local/bin/new-proc-${index}`,
      user: `user-${index % 20}`,
    },
  };
}

function makeNetworkEvent(index: number): SecurityEvent {
  return {
    id: `base-evt-net-${index}`,
    timestamp: new Date(),
    source: 'network',
    severity: 'info',
    category: 'connection',
    description: `Network event ${index}`,
    raw: {},
    host: 'bench-host',
    metadata: {
      remoteAddress: `10.1.${Math.floor(index / 256)}.${index % 256}`,
      remotePort: 8000 + (index % 1000),
      protocol: 'tcp',
      user: `user-${index % 20}`,
    },
  };
}

// ---------------------------------------------------------------------------
// Pre-generate baselines and events
// ---------------------------------------------------------------------------

const SMALL_BASELINE = buildBaseline(50, 50, 20, 10);
const MEDIUM_BASELINE = buildBaseline(200, 200, 100, 50);
const LARGE_BASELINE = buildBaseline(1000, 1000, 500, 200);

const PROCESS_EVENTS: SecurityEvent[] = [];
for (let i = 0; i < 100; i++) {
  PROCESS_EVENTS.push(makeProcessEvent(i));
}

const NETWORK_EVENTS: SecurityEvent[] = [];
for (let i = 0; i < 100; i++) {
  NETWORK_EVENTS.push(makeNetworkEvent(i));
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

describe('Baseline Operations', () => {
  describe('updateBaseline (learning mode)', () => {
    bench('update small baseline (130 patterns) with process event', () => {
      updateBaseline(SMALL_BASELINE, PROCESS_EVENTS[0]!);
    });

    bench('update medium baseline (550 patterns) with process event', () => {
      updateBaseline(MEDIUM_BASELINE, PROCESS_EVENTS[0]!);
    });

    bench('update large baseline (2700 patterns) with process event', () => {
      updateBaseline(LARGE_BASELINE, PROCESS_EVENTS[0]!);
    });

    bench('update large baseline (2700 patterns) with network event', () => {
      updateBaseline(LARGE_BASELINE, NETWORK_EVENTS[0]!);
    });
  });

  describe('continuousBaselineUpdate (protection mode)', () => {
    bench('continuous update small baseline with benign event', () => {
      continuousBaselineUpdate(SMALL_BASELINE, PROCESS_EVENTS[0]!, 'benign');
    });

    bench('continuous update medium baseline with benign event', () => {
      continuousBaselineUpdate(MEDIUM_BASELINE, PROCESS_EVENTS[0]!, 'benign');
    });

    bench('continuous update large baseline with benign event', () => {
      continuousBaselineUpdate(LARGE_BASELINE, PROCESS_EVENTS[0]!, 'benign');
    });

    bench('continuous update - suspicious event (should skip)', () => {
      continuousBaselineUpdate(LARGE_BASELINE, PROCESS_EVENTS[0]!, 'suspicious');
    });

    bench('continuous update - malicious event (should skip)', () => {
      continuousBaselineUpdate(LARGE_BASELINE, PROCESS_EVENTS[0]!, 'malicious');
    });
  });

  describe('pruneStalePatterns', () => {
    bench('prune small baseline (130 patterns, 20% stale)', () => {
      pruneStalePatterns(SMALL_BASELINE, 30);
    });

    bench('prune medium baseline (550 patterns, 20% stale)', () => {
      pruneStalePatterns(MEDIUM_BASELINE, 30);
    });

    bench('prune large baseline (2700 patterns, 20% stale)', () => {
      pruneStalePatterns(LARGE_BASELINE, 30);
    });

    bench('prune large baseline with short retention (7 days)', () => {
      pruneStalePatterns(LARGE_BASELINE, 7);
    });

    bench('prune large baseline with long retention (90 days, no prune)', () => {
      pruneStalePatterns(LARGE_BASELINE, 90);
    });
  });

  describe('Batch continuous updates', () => {
    bench('10 continuous updates on large baseline', () => {
      let baseline = LARGE_BASELINE;
      for (let i = 0; i < 10; i++) {
        baseline = continuousBaselineUpdate(
          baseline,
          PROCESS_EVENTS[i % PROCESS_EVENTS.length]!,
          'benign',
        );
      }
    });

    bench('50 continuous updates on large baseline', () => {
      let baseline = LARGE_BASELINE;
      for (let i = 0; i < 50; i++) {
        const event = i % 2 === 0
          ? PROCESS_EVENTS[i % PROCESS_EVENTS.length]!
          : NETWORK_EVENTS[i % NETWORK_EVENTS.length]!;
        baseline = continuousBaselineUpdate(baseline, event, 'benign');
      }
    });
  });
});
