/**
 * Memory Footprint Benchmark
 *
 * Tracks heap usage under various loads:
 * - Idle memory
 * - Memory after loading rules
 * - Memory under event processing
 */

import { bench, describe } from 'vitest';
import { RuleEngine, setLogLevel } from '@panguard-ai/core';
import type { SecurityEvent, SigmaRule } from '@panguard-ai/core';
import { DetectAgent } from '../src/agent/detect-agent.js';
import { EventCorrelator } from '../src/correlation/event-correlator.js';
import {
  createEmptyBaseline,
  updateBaseline,
  continuousBaselineUpdate,
} from '../src/memory/baseline.js';

// Suppress all logging during benchmarks to avoid OOM from stderr writes
setLogLevel('silent');

// ---------------------------------------------------------------------------
// Synthetic data factories
// ---------------------------------------------------------------------------

const CATEGORIES = [
  'brute_force',
  'port_scan',
  'lateral_movement',
  'process_creation',
  'file_write',
  'authentication',
];

const SOURCES: SecurityEvent['source'][] = [
  'network',
  'process',
  'file',
  'syslog',
  'suricata',
];

const SEVERITIES: SecurityEvent['severity'][] = [
  'info',
  'low',
  'medium',
  'high',
  'critical',
];

function makeEvent(index: number): SecurityEvent {
  return {
    id: `mem-evt-${index}`,
    timestamp: new Date(),
    source: SOURCES[index % SOURCES.length]!,
    severity: SEVERITIES[index % SEVERITIES.length]!,
    category: CATEGORIES[index % CATEGORIES.length]!,
    description: `Memory benchmark event ${index}`,
    raw: { index, data: `payload-${index}` },
    host: `mem-host-${index % 10}`,
    metadata: {
      sourceIP: `10.0.${Math.floor(index / 256) % 256}.${index % 256}`,
      remoteAddress: `10.0.${Math.floor(index / 256) % 256}.${index % 256}`,
      processName: `memproc-${index % 50}`,
      user: `user-${index % 20}`,
      destinationPort: 1024 + (index % 60000),
      destinationIP: `192.168.1.${index % 256}`,
    },
  };
}

function makeRule(index: number): SigmaRule {
  const category = CATEGORIES[index % CATEGORIES.length]!;
  return {
    id: `mem-rule-${index}`,
    title: `Memory Benchmark Rule ${index}`,
    status: 'stable' as const,
    description: `Synthetic rule ${index} for memory benchmarking`,
    level: SEVERITIES[index % SEVERITIES.length]!,
    logsource: { category },
    detection: {
      selection: { category },
      condition: 'selection',
    },
  };
}

function generateRules(count: number): SigmaRule[] {
  return Array.from({ length: count }, (_, i) => makeRule(i));
}

function generateEvents(count: number): SecurityEvent[] {
  return Array.from({ length: count }, (_, i) => makeEvent(i));
}

// ---------------------------------------------------------------------------
// Utility: snapshot heap usage
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Pre-generate data
// ---------------------------------------------------------------------------

const RULES_3000 = generateRules(3000);
const EVENTS_1000 = generateEvents(1000);
const EVENTS_100 = generateEvents(100);

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

describe('Memory Footprint', () => {
  describe('RuleEngine memory allocation', () => {
    bench('create RuleEngine with 100 rules', () => {
      const rules = RULES_3000.slice(0, 100);
      const engine = new RuleEngine({ customRules: rules });
      engine.getRules(); // access to prevent dead-code elimination
    });

    bench('create RuleEngine with 1000 rules', () => {
      const rules = RULES_3000.slice(0, 1000);
      const engine = new RuleEngine({ customRules: rules });
      engine.getRules();
    });

    bench('create RuleEngine with 3000 rules', () => {
      const engine = new RuleEngine({ customRules: RULES_3000 });
      engine.getRules();
    });
  });

  describe('DetectAgent under load', () => {
    bench('detect 100 events (3000 rules) - memory pressure', () => {
      const engine = new RuleEngine({ customRules: RULES_3000 });
      const agent = new DetectAgent(engine);
      for (let i = 0; i < 100; i++) {
        agent.detect({
          ...EVENTS_100[i % EVENTS_100.length]!,
          id: `mem-da-${Date.now()}-${i}`,
        });
      }
    });

    bench('detect 500 events (3000 rules) - sustained load', () => {
      const engine = new RuleEngine({ customRules: RULES_3000 });
      const agent = new DetectAgent(engine);
      for (let i = 0; i < 500; i++) {
        agent.detect({
          ...EVENTS_1000[i % EVENTS_1000.length]!,
          id: `mem-da2-${Date.now()}-${i}`,
        });
      }
    });
  });

  describe('EventCorrelator buffer growth', () => {
    bench('correlator with 500 events in buffer', () => {
      const correlator = new EventCorrelator(5 * 60 * 1000, 10000);
      const now = Date.now();
      for (let i = 0; i < 500; i++) {
        correlator.addEvent({
          id: `mem-corr-${now}-${i}`,
          timestamp: now + i,
          sourceIP: `10.0.${Math.floor(i / 256)}.${i % 256}`,
          source: SOURCES[i % SOURCES.length]!,
          category: CATEGORIES[i % CATEGORIES.length]!,
          severity: SEVERITIES[i % SEVERITIES.length]!,
          ruleIds: [`rule-${i % 100}`],
          metadata: { destinationPort: 1024 + i },
        });
      }
    });

    bench('correlator with 2000 events in buffer', () => {
      const correlator = new EventCorrelator(5 * 60 * 1000, 10000);
      const now = Date.now();
      for (let i = 0; i < 2000; i++) {
        correlator.addEvent({
          id: `mem-corr2-${now}-${i}`,
          timestamp: now + i,
          sourceIP: `10.0.${Math.floor(i / 256)}.${i % 256}`,
          source: SOURCES[i % SOURCES.length]!,
          category: CATEGORIES[i % CATEGORIES.length]!,
          severity: SEVERITIES[i % SEVERITIES.length]!,
          ruleIds: [`rule-${i % 100}`],
          metadata: { destinationPort: 1024 + i },
        });
      }
    });

    bench('correlator with 5000 events (near max buffer)', () => {
      const correlator = new EventCorrelator(5 * 60 * 1000, 5000);
      const now = Date.now();
      for (let i = 0; i < 5000; i++) {
        correlator.addEvent({
          id: `mem-corr5-${now}-${i}`,
          timestamp: now + i,
          sourceIP: `10.0.${Math.floor(i / 256)}.${i % 256}`,
          source: SOURCES[i % SOURCES.length]!,
          category: CATEGORIES[i % CATEGORIES.length]!,
          severity: SEVERITIES[i % SEVERITIES.length]!,
          ruleIds: [`rule-${i % 100}`],
          metadata: { destinationPort: 1024 + i },
        });
      }
    });
  });

  describe('Baseline memory with increasing patterns', () => {
    bench('build baseline from 100 events', () => {
      let baseline = createEmptyBaseline();
      for (let i = 0; i < 100; i++) {
        baseline = updateBaseline(baseline, EVENTS_100[i % EVENTS_100.length]!);
      }
    });

    bench('build baseline from 500 events', () => {
      let baseline = createEmptyBaseline();
      for (let i = 0; i < 500; i++) {
        baseline = updateBaseline(baseline, EVENTS_1000[i % EVENTS_1000.length]!);
      }
    });

    bench('continuous update baseline with 200 benign events', () => {
      let baseline = createEmptyBaseline();
      // Build initial baseline
      for (let i = 0; i < 100; i++) {
        baseline = updateBaseline(baseline, EVENTS_100[i % EVENTS_100.length]!);
      }
      // Then continuous updates
      for (let i = 0; i < 200; i++) {
        baseline = continuousBaselineUpdate(
          baseline,
          EVENTS_1000[i % EVENTS_1000.length]!,
          'benign',
        );
      }
    });
  });

  describe('Combined system memory pressure', () => {
    bench('full pipeline: RuleEngine + DetectAgent + Correlator + Baseline (100 events)', () => {
      const engine = new RuleEngine({ customRules: RULES_3000 });
      const agent = new DetectAgent(engine);
      const correlator = new EventCorrelator(5 * 60 * 1000, 5000);
      let baseline = createEmptyBaseline();

      for (let i = 0; i < 100; i++) {
        const event = {
          ...EVENTS_100[i % EVENTS_100.length]!,
          id: `full-${Date.now()}-${i}`,
        };
        agent.detect(event);
        correlator.addEvent({
          id: event.id,
          timestamp: Date.now(),
          sourceIP: event.metadata['sourceIP'] as string,
          source: event.source,
          category: event.category,
          severity: event.severity,
          ruleIds: [],
          metadata: event.metadata,
        });
        baseline = updateBaseline(baseline, event);
      }
    });
  });
});
