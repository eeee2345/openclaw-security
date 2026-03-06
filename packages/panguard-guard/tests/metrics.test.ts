import { describe, it, expect } from 'vitest';
import { MetricsCollector } from '../src/metrics.js';
import type { GuardStatus } from '../src/types.js';

function makeStatus(overrides: Partial<GuardStatus> = {}): GuardStatus {
  return {
    running: true,
    mode: 'protection',
    uptime: 60000,
    eventsProcessed: 100,
    threatsDetected: 5,
    actionsExecuted: 3,
    learningProgress: 1.0,
    baselineConfidence: 0.85,
    memoryUsageMB: 120,
    licenseTier: 'free',
    ...overrides,
  };
}

describe('MetricsCollector', () => {
  it('should generate valid Prometheus text format', () => {
    const collector = new MetricsCollector();
    const output = collector.toPrometheus(makeStatus());

    expect(output).toContain('# HELP panguard_events_processed_total');
    expect(output).toContain('# TYPE panguard_events_processed_total counter');
    expect(output).toContain('panguard_events_processed_total 100');
    expect(output).toContain('panguard_threats_detected_total 5');
    expect(output).toContain('panguard_actions_executed_total 3');
    expect(output).toContain('panguard_running 1');
    expect(output).toContain('panguard_baseline_confidence 0.85');
  });

  it('should report running=0 when guard is stopped', () => {
    const collector = new MetricsCollector();
    const output = collector.toPrometheus(makeStatus({ running: false }));
    expect(output).toContain('panguard_running 0');
  });

  it('should track AI request count', () => {
    const collector = new MetricsCollector();
    collector.recordAILatency(500);
    collector.recordAILatency(1200);
    collector.recordAILatency(200);

    const output = collector.toPrometheus(makeStatus());
    expect(output).toContain('panguard_ai_requests_total 3');
  });

  it('should generate AI latency histogram buckets', () => {
    const collector = new MetricsCollector();
    collector.recordAILatency(100);   // 0.1s
    collector.recordAILatency(500);   // 0.5s
    collector.recordAILatency(2000);  // 2.0s
    collector.recordAILatency(15000); // 15.0s

    const output = collector.toPrometheus(makeStatus());
    expect(output).toContain('# TYPE panguard_ai_latency_seconds histogram');
    expect(output).toContain('panguard_ai_latency_seconds_bucket{le="0.1"} 1');
    expect(output).toContain('panguard_ai_latency_seconds_bucket{le="0.5"} 2');
    expect(output).toContain('panguard_ai_latency_seconds_bucket{le="2"} 3');
    expect(output).toContain('panguard_ai_latency_seconds_bucket{le="+Inf"} 4');
    expect(output).toContain('panguard_ai_latency_seconds_count 4');
  });

  it('should handle empty latency history', () => {
    const collector = new MetricsCollector();
    const output = collector.toPrometheus(makeStatus());
    expect(output).toContain('panguard_ai_latency_seconds_count 0');
    expect(output).toContain('panguard_ai_latency_seconds_sum 0');
  });

  it('should include CPU and memory metrics', () => {
    const collector = new MetricsCollector();
    const output = collector.toPrometheus(makeStatus());
    expect(output).toContain('panguard_cpu_usage_percent');
    expect(output).toContain('panguard_memory_usage_bytes');
  });

  it('should convert uptime from ms to seconds', () => {
    const collector = new MetricsCollector();
    const output = collector.toPrometheus(makeStatus({ uptime: 120000 }));
    expect(output).toContain('panguard_uptime_seconds 120');
  });
});
