/**
 * Event Correlator tests
 * 事件關聯器測試
 *
 * Tests all 7 detection patterns plus buffer management.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { CorrelationEvent } from '../src/types.js';
import { EventCorrelator } from '../src/correlation/event-correlator.js';

// ---------------------------------------------------------------------------
// Helper: create a CorrelationEvent with sensible defaults
// ---------------------------------------------------------------------------

let nextId = 1;

function makeCorrelationEvent(
  overrides: Partial<CorrelationEvent> = {}
): CorrelationEvent {
  return {
    id: `evt-${String(nextId++).padStart(4, '0')}`,
    timestamp: Date.now(),
    source: 'network',
    category: 'general',
    severity: 'medium',
    ruleIds: [],
    metadata: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Brute Force (T1110)
// ---------------------------------------------------------------------------

describe('EventCorrelator - Brute Force (T1110)', () => {
  let correlator: EventCorrelator;

  beforeEach(() => {
    nextId = 1;
    correlator = new EventCorrelator();
  });

  it('should detect brute force with 5+ auth failures from same IP within 60s', () => {
    const now = Date.now();
    const ip = '203.0.113.42';

    // Add 5 auth failure events from same IP within 60s
    for (let i = 0; i < 4; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          sourceIP: ip,
          source: 'auth',
          category: 'authentication',
          metadata: { result: 'failure' },
        })
      );
    }

    // 5th event should trigger detection
    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 4000,
        sourceIP: ip,
        source: 'auth',
        category: 'authentication',
        metadata: { result: 'failure' },
      })
    );

    expect(result.matched).toBe(true);
    const bruteForce = result.patterns.find((p) => p.type === 'brute_force');
    expect(bruteForce).toBeDefined();
    expect(bruteForce!.mitreTechnique).toBe('T1110');
    expect(bruteForce!.eventCount).toBeGreaterThanOrEqual(5);
    expect(bruteForce!.sourceIP).toBe(ip);
    expect(bruteForce!.suggestedSeverity).toBe('high');
  });

  it('should NOT detect brute force with only 4 failures (below threshold)', () => {
    const now = Date.now();
    const ip = '203.0.113.42';

    let lastResult;
    for (let i = 0; i < 4; i++) {
      lastResult = correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          sourceIP: ip,
          source: 'auth',
          category: 'authentication',
          metadata: { result: 'failure' },
        })
      );
    }

    const bruteForce = lastResult!.patterns.find((p) => p.type === 'brute_force');
    expect(bruteForce).toBeUndefined();
  });

  it('should NOT detect brute force when failures come from different IPs', () => {
    const now = Date.now();

    let lastResult;
    for (let i = 0; i < 6; i++) {
      lastResult = correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          sourceIP: `10.0.0.${i + 1}`,
          source: 'auth',
          category: 'authentication',
          metadata: { result: 'failure' },
        })
      );
    }

    const bruteForce = lastResult!.patterns.find((p) => p.type === 'brute_force');
    expect(bruteForce).toBeUndefined();
  });

  it('should NOT detect brute force when events spread over >60s', () => {
    const now = Date.now();
    const ip = '203.0.113.42';

    // Spread 5 events over 70 seconds (each 15s apart)
    for (let i = 0; i < 5; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 15000,
          sourceIP: ip,
          source: 'auth',
          category: 'authentication',
          metadata: { result: 'failure' },
        })
      );
    }

    // Last event is at now + 60000, first at now. The brute force window is 60s.
    // Events at: 0, 15, 30, 45, 60 -- the first event is exactly at the boundary.
    // The filter uses cutoff = now - 60000 and checks e.timestamp < cutoff.
    // With timestamp exactly 60s back, it depends on the implementation.
    // Let's spread further to ensure they fall outside.
    nextId = 1;
    const correlator2 = new EventCorrelator();
    let result2;
    for (let i = 0; i < 5; i++) {
      result2 = correlator2.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 20000, // 0, 20s, 40s, 60s, 80s
          sourceIP: ip,
          source: 'auth',
          category: 'authentication',
          metadata: { result: 'failure' },
        })
      );
    }

    // At the 5th event (80s), looking back 60s means cutoff = 80s - 60s = 20s.
    // Events at 0s and possibly 20s are at/before cutoff.
    // Only events at 40s, 60s, 80s qualify = 3 events < 5 threshold
    const bruteForce2 = result2!.patterns.find((p) => p.type === 'brute_force');
    expect(bruteForce2).toBeUndefined();
  });

  it('should detect brute force via rule ID containing "brute"', () => {
    const now = Date.now();
    const ip = '198.51.100.10';

    for (let i = 0; i < 4; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          sourceIP: ip,
          source: 'auth',
          category: 'authentication',
          ruleIds: ['sigma-brute-force-001'],
          metadata: {},
        })
      );
    }

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 4000,
        sourceIP: ip,
        source: 'auth',
        category: 'authentication',
        ruleIds: ['sigma-brute-force-001'],
        metadata: {},
      })
    );

    expect(result.matched).toBe(true);
    expect(result.patterns.some((p) => p.type === 'brute_force')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Port Scan (T1046)
// ---------------------------------------------------------------------------

describe('EventCorrelator - Port Scan (T1046)', () => {
  let correlator: EventCorrelator;

  beforeEach(() => {
    nextId = 1;
    correlator = new EventCorrelator();
  });

  it('should detect port scan with 10+ distinct ports from same IP within 60s', () => {
    const now = Date.now();
    const ip = '192.0.2.50';

    for (let i = 0; i < 9; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 100,
          sourceIP: ip,
          source: 'network',
          category: 'connection',
          metadata: { destinationPort: 1000 + i },
        })
      );
    }

    // 10th distinct port triggers detection
    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 900,
        sourceIP: ip,
        source: 'network',
        category: 'connection',
        metadata: { destinationPort: 1009 },
      })
    );

    expect(result.matched).toBe(true);
    const portScan = result.patterns.find((p) => p.type === 'port_scan');
    expect(portScan).toBeDefined();
    expect(portScan!.mitreTechnique).toBe('T1046');
    expect(portScan!.sourceIP).toBe(ip);
    expect(portScan!.suggestedSeverity).toBe('medium');
  });

  it('should NOT detect port scan when same port is repeated 10 times (not distinct)', () => {
    const now = Date.now();
    const ip = '192.0.2.50';

    let lastResult;
    for (let i = 0; i < 10; i++) {
      lastResult = correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 100,
          sourceIP: ip,
          source: 'network',
          category: 'connection',
          metadata: { destinationPort: 80 }, // same port every time
        })
      );
    }

    const portScan = lastResult!.patterns.find((p) => p.type === 'port_scan');
    expect(portScan).toBeUndefined();
  });

  it('should NOT detect port scan with only 9 distinct ports', () => {
    const now = Date.now();
    const ip = '192.0.2.50';

    let lastResult;
    for (let i = 0; i < 9; i++) {
      lastResult = correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 100,
          sourceIP: ip,
          source: 'network',
          category: 'connection',
          metadata: { destinationPort: 2000 + i },
        })
      );
    }

    const portScan = lastResult!.patterns.find((p) => p.type === 'port_scan');
    expect(portScan).toBeUndefined();
  });

  it('should detect port scan using suricata source', () => {
    const now = Date.now();
    const ip = '192.0.2.50';

    for (let i = 0; i < 10; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 100,
          sourceIP: ip,
          source: 'suricata',
          category: 'connection',
          metadata: { dst_port: 3000 + i },
        })
      );
    }

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        sourceIP: ip,
        source: 'suricata',
        category: 'connection',
        metadata: { dst_port: 3010 },
      })
    );

    const portScan = result.patterns.find((p) => p.type === 'port_scan');
    expect(portScan).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Lateral Movement (T1021)
// ---------------------------------------------------------------------------

describe('EventCorrelator - Lateral Movement (T1021)', () => {
  let correlator: EventCorrelator;

  beforeEach(() => {
    nextId = 1;
    correlator = new EventCorrelator();
  });

  it('should detect lateral movement with 3+ internal IPs from same source', () => {
    const now = Date.now();
    const ip = '10.0.0.1';

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '192.168.1.10' },
      })
    );

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '192.168.1.20' },
      })
    );

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 2000,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '10.0.0.50' },
      })
    );

    expect(result.matched).toBe(true);
    const lateral = result.patterns.find((p) => p.type === 'lateral_movement');
    expect(lateral).toBeDefined();
    expect(lateral!.mitreTechnique).toBe('T1021');
    expect(lateral!.sourceIP).toBe(ip);
    expect(lateral!.suggestedSeverity).toBe('high');
  });

  it('should NOT detect lateral movement with only 2 internal IPs', () => {
    const now = Date.now();
    const ip = '10.0.0.1';

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '192.168.1.10' },
      })
    );

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '192.168.1.20' },
      })
    );

    const lateral = result.patterns.find((p) => p.type === 'lateral_movement');
    expect(lateral).toBeUndefined();
  });

  it('should NOT detect lateral movement when destinations are external IPs', () => {
    const now = Date.now();
    const ip = '10.0.0.1';

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '8.8.8.8' },
      })
    );

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '1.1.1.1' },
      })
    );

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 2000,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '9.9.9.9' },
      })
    );

    const lateral = result.patterns.find((p) => p.type === 'lateral_movement');
    expect(lateral).toBeUndefined();
  });

  it('should escalate to critical severity with 5+ internal IPs', () => {
    const now = Date.now();
    const ip = '10.0.0.1';

    for (let i = 0; i < 4; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          sourceIP: ip,
          source: 'network',
          metadata: { destinationIP: `192.168.1.${10 + i}` },
        })
      );
    }

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 4000,
        sourceIP: ip,
        source: 'network',
        metadata: { destinationIP: '192.168.1.99' },
      })
    );

    const lateral = result.patterns.find((p) => p.type === 'lateral_movement');
    expect(lateral).toBeDefined();
    expect(lateral!.suggestedSeverity).toBe('critical');
  });
});

// ---------------------------------------------------------------------------
// Data Exfiltration (T1041)
// ---------------------------------------------------------------------------

describe('EventCorrelator - Data Exfiltration (T1041)', () => {
  let correlator: EventCorrelator;

  beforeEach(() => {
    nextId = 1;
    correlator = new EventCorrelator();
  });

  it('should detect data exfiltration with 10MB+ outbound to external IP', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'network',
        sourceIP: '10.0.0.5',
        metadata: {
          destinationIP: '203.0.113.99',
          bytesOut: 15 * 1024 * 1024, // 15MB
        },
      })
    );

    expect(result.matched).toBe(true);
    const exfil = result.patterns.find((p) => p.type === 'data_exfiltration');
    expect(exfil).toBeDefined();
    expect(exfil!.mitreTechnique).toBe('T1041');
    expect(exfil!.suggestedSeverity).toBe('high');
  });

  it('should NOT detect exfiltration with small transfer (<10MB)', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'network',
        sourceIP: '10.0.0.5',
        metadata: {
          destinationIP: '203.0.113.99',
          bytesOut: 5 * 1024 * 1024, // 5MB
        },
      })
    );

    const exfil = result.patterns.find((p) => p.type === 'data_exfiltration');
    expect(exfil).toBeUndefined();
  });

  it('should NOT detect exfiltration to internal IP', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'network',
        sourceIP: '10.0.0.5',
        metadata: {
          destinationIP: '192.168.1.100', // internal
          bytesOut: 50 * 1024 * 1024, // 50MB
        },
      })
    );

    const exfil = result.patterns.find((p) => p.type === 'data_exfiltration');
    expect(exfil).toBeUndefined();
  });

  it('should escalate to critical with 50MB+ transfer', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'network',
        sourceIP: '10.0.0.5',
        metadata: {
          destinationIP: '203.0.113.99',
          bytesOut: 55 * 1024 * 1024, // 55MB (>= 5x threshold)
        },
      })
    );

    const exfil = result.patterns.find((p) => p.type === 'data_exfiltration');
    expect(exfil).toBeDefined();
    expect(exfil!.suggestedSeverity).toBe('critical');
  });

  it('should accept alternate metadata field names (bytes_sent)', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'network',
        metadata: {
          destinationIP: '8.8.4.4',
          bytes_sent: 12 * 1024 * 1024,
        },
      })
    );

    const exfil = result.patterns.find((p) => p.type === 'data_exfiltration');
    expect(exfil).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Backdoor Installation (T1059)
// ---------------------------------------------------------------------------

describe('EventCorrelator - Backdoor Installation (T1059)', () => {
  let correlator: EventCorrelator;

  beforeEach(() => {
    nextId = 1;
    // Use a short window so tests are deterministic
    correlator = new EventCorrelator(60_000);
  });

  it('should detect backdoor when file write + process creation + network connection are present', () => {
    const now = Date.now();
    const ip = '10.0.0.5';

    // Step 1: file write
    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        sourceIP: ip,
        source: 'file',
        category: 'file_write',
        metadata: { action: 'write', path: '/tmp/backdoor.sh' },
      })
    );

    // Step 2: process creation
    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        sourceIP: ip,
        source: 'process',
        category: 'process_creation',
        metadata: { action: 'exec', processName: 'backdoor.sh' },
      })
    );

    // Step 3: network connection (triggers backdoor check)
    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 2000,
        sourceIP: ip,
        source: 'network',
        category: 'connection',
        metadata: { destinationIP: '203.0.113.99' },
      })
    );

    expect(result.matched).toBe(true);
    const backdoor = result.patterns.find((p) => p.type === 'backdoor_install');
    expect(backdoor).toBeDefined();
    expect(backdoor!.mitreTechnique).toBe('T1059');
    expect(backdoor!.suggestedSeverity).toBe('critical');
    expect(backdoor!.eventCount).toBe(3);
  });

  it('should NOT detect backdoor with only file write + network (missing process)', () => {
    const now = Date.now();
    const ip = '10.0.0.5';

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        sourceIP: ip,
        source: 'file',
        category: 'file_write',
        metadata: {},
      })
    );

    // Network connection without process creation in between
    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        sourceIP: ip,
        source: 'network',
        category: 'connection',
        metadata: {},
      })
    );

    const backdoor = result.patterns.find((p) => p.type === 'backdoor_install');
    expect(backdoor).toBeUndefined();
  });

  it('should NOT detect backdoor with only process + network (missing file write)', () => {
    const now = Date.now();
    const ip = '10.0.0.5';

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        sourceIP: ip,
        source: 'process',
        category: 'process_creation',
        metadata: {},
      })
    );

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        sourceIP: ip,
        source: 'network',
        category: 'connection',
        metadata: {},
      })
    );

    const backdoor = result.patterns.find((p) => p.type === 'backdoor_install');
    expect(backdoor).toBeUndefined();
  });

  it('should detect backdoor via metadata action fields', () => {
    const now = Date.now();

    // file_creation via metadata action
    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        source: 'file',
        category: 'general',
        metadata: { action: 'create' },
      })
    );

    // process via metadata action
    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 500,
        source: 'process',
        category: 'general',
        metadata: { action: 'execve' },
      })
    );

    // network event triggers the check
    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        source: 'network',
        category: 'connection',
        metadata: {},
      })
    );

    const backdoor = result.patterns.find((p) => p.type === 'backdoor_install');
    expect(backdoor).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Privilege Escalation (T1548)
// ---------------------------------------------------------------------------

describe('EventCorrelator - Privilege Escalation (T1548)', () => {
  let correlator: EventCorrelator;

  beforeEach(() => {
    nextId = 1;
    correlator = new EventCorrelator();
  });

  it('should detect privilege escalation for setuid category', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'process',
        category: 'setuid',
        sourceIP: '10.0.0.1',
        metadata: {},
      })
    );

    expect(result.matched).toBe(true);
    const privEsc = result.patterns.find((p) => p.type === 'privilege_escalation');
    expect(privEsc).toBeDefined();
    expect(privEsc!.mitreTechnique).toBe('T1548');
    expect(privEsc!.suggestedSeverity).toBe('high');
  });

  it('should detect privilege escalation for sudo process', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'process',
        category: 'process_execution',
        metadata: { processName: 'sudo' },
      })
    );

    const privEsc = result.patterns.find((p) => p.type === 'privilege_escalation');
    expect(privEsc).toBeDefined();
  });

  it('should detect privilege escalation for setuid action in metadata', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'process',
        category: 'syscall',
        metadata: { action: 'setuid' },
      })
    );

    const privEsc = result.patterns.find((p) => p.type === 'privilege_escalation');
    expect(privEsc).toBeDefined();
  });

  it('should detect privilege escalation for chmod +s command', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'process',
        category: 'command_exec',
        metadata: { command: 'chmod +s /usr/local/bin/myapp' },
      })
    );

    const privEsc = result.patterns.find((p) => p.type === 'privilege_escalation');
    expect(privEsc).toBeDefined();
  });

  it('should detect privilege escalation via rule ID containing "privilege"', () => {
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'process',
        category: 'general',
        ruleIds: ['sigma-privilege-escalation-001'],
        metadata: {},
      })
    );

    const privEsc = result.patterns.find((p) => p.type === 'privilege_escalation');
    expect(privEsc).toBeDefined();
  });

  it('should escalate to critical with 3+ priv-esc events', () => {
    const now = Date.now();
    const ip = '10.0.0.1';

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        sourceIP: ip,
        source: 'process',
        category: 'setuid',
        metadata: {},
      })
    );

    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 1000,
        sourceIP: ip,
        source: 'process',
        category: 'setgid',
        metadata: {},
      })
    );

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 2000,
        sourceIP: ip,
        source: 'process',
        category: 'privilege_escalation',
        metadata: {},
      })
    );

    const privEsc = result.patterns.find((p) => p.type === 'privilege_escalation');
    expect(privEsc).toBeDefined();
    expect(privEsc!.suggestedSeverity).toBe('critical');
  });
});

// ---------------------------------------------------------------------------
// Severity Escalation
// ---------------------------------------------------------------------------

describe('EventCorrelator - Severity Escalation', () => {
  let correlator: EventCorrelator;

  beforeEach(() => {
    nextId = 1;
    correlator = new EventCorrelator();
  });

  it('should escalate 3+ low severity events from same IP to medium', () => {
    const now = Date.now();
    const ip = '10.0.0.5';

    for (let i = 0; i < 2; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          sourceIP: ip,
          source: 'file',
          severity: 'low',
          metadata: {},
        })
      );
    }

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 2000,
        sourceIP: ip,
        source: 'file',
        severity: 'low',
        metadata: {},
      })
    );

    expect(result.matched).toBe(true);
    const escalation = result.patterns.find(
      (p) => p.type === 'attack_chain' && p.suggestedSeverity === 'medium'
    );
    expect(escalation).toBeDefined();
    expect(escalation!.eventCount).toBe(3);
  });

  it('should escalate 3+ medium severity events from same IP to high', () => {
    const now = Date.now();
    const ip = '10.0.0.5';

    for (let i = 0; i < 2; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          sourceIP: ip,
          source: 'file',
          severity: 'medium',
          metadata: {},
        })
      );
    }

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 2000,
        sourceIP: ip,
        source: 'file',
        severity: 'medium',
        metadata: {},
      })
    );

    expect(result.matched).toBe(true);
    const escalation = result.patterns.find(
      (p) => p.type === 'attack_chain' && p.suggestedSeverity === 'high'
    );
    expect(escalation).toBeDefined();
    expect(escalation!.eventCount).toBe(3);
  });

  it('should NOT escalate mixed severities from different IPs', () => {
    const now = Date.now();

    // Low severity events from different IPs
    for (let i = 0; i < 3; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          sourceIP: `10.0.0.${i + 1}`,
          source: 'file',
          severity: 'low',
          metadata: {},
        })
      );
    }

    const result = correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 3000,
        sourceIP: '10.0.0.99',
        source: 'file',
        severity: 'low',
        metadata: {},
      })
    );

    // Each IP only has 1 event, so no escalation
    const escalation = result.patterns.find((p) => p.type === 'attack_chain');
    expect(escalation).toBeUndefined();
  });

  it('should NOT escalate when source IP is missing', () => {
    const now = Date.now();

    let lastResult;
    for (let i = 0; i < 5; i++) {
      lastResult = correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 1000,
          // no sourceIP
          source: 'file',
          severity: 'low',
          metadata: {},
        })
      );
    }

    const escalation = lastResult!.patterns.find((p) => p.type === 'attack_chain');
    expect(escalation).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Buffer Management
// ---------------------------------------------------------------------------

describe('EventCorrelator - Buffer Management', () => {
  it('should evict events outside the time window', () => {
    const correlator = new EventCorrelator(5000); // 5s window
    const now = Date.now();

    // Add event at t=0
    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now,
        metadata: {},
      })
    );

    expect(correlator.getBufferSize()).toBe(1);

    // Add event at t=6s (beyond 5s window), old event should be evicted
    correlator.addEvent(
      makeCorrelationEvent({
        timestamp: now + 6000,
        metadata: {},
      })
    );

    expect(correlator.getBufferSize()).toBe(1);
  });

  it('should not exceed max buffer size', () => {
    const correlator = new EventCorrelator(60_000, 5); // max 5 events
    const now = Date.now();

    for (let i = 0; i < 10; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 100, // all within window
          metadata: {},
        })
      );
    }

    expect(correlator.getBufferSize()).toBeLessThanOrEqual(5);
  });

  it('should clear buffer on reset()', () => {
    const correlator = new EventCorrelator();
    const now = Date.now();

    for (let i = 0; i < 5; i++) {
      correlator.addEvent(
        makeCorrelationEvent({
          timestamp: now + i * 100,
          metadata: {},
        })
      );
    }

    expect(correlator.getBufferSize()).toBe(5);

    correlator.reset();
    expect(correlator.getBufferSize()).toBe(0);
  });

  it('should return correct buffer size via getBufferSize()', () => {
    const correlator = new EventCorrelator();
    expect(correlator.getBufferSize()).toBe(0);

    const now = Date.now();
    correlator.addEvent(
      makeCorrelationEvent({ timestamp: now, metadata: {} })
    );
    expect(correlator.getBufferSize()).toBe(1);

    correlator.addEvent(
      makeCorrelationEvent({ timestamp: now + 100, metadata: {} })
    );
    expect(correlator.getBufferSize()).toBe(2);
  });

  it('should return CorrelationResult with matched=false when no patterns match', () => {
    const correlator = new EventCorrelator();
    const result = correlator.addEvent(
      makeCorrelationEvent({
        source: 'file',
        category: 'file_read',
        metadata: {},
      })
    );

    expect(result.matched).toBe(false);
    expect(result.patterns).toEqual([]);
  });
});
