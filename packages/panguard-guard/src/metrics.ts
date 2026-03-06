/**
 * Prometheus-compatible metrics collector
 * Prometheus 相容指標收集器
 *
 * Collects and exposes guard engine metrics in Prometheus text format.
 * Provides counters, gauges, and histograms for observability.
 *
 * @module @panguard-ai/panguard-guard/metrics
 */

import type { GuardStatus } from './types.js';

/** Metric type / 指標類型 */
type MetricType = 'counter' | 'gauge' | 'histogram';

interface MetricDef {
  name: string;
  help: string;
  type: MetricType;
}

const METRIC_DEFS: MetricDef[] = [
  { name: 'panguard_events_processed_total', help: 'Total security events processed', type: 'counter' },
  { name: 'panguard_threats_detected_total', help: 'Total threats detected', type: 'counter' },
  { name: 'panguard_actions_executed_total', help: 'Total response actions executed', type: 'counter' },
  { name: 'panguard_uptime_seconds', help: 'Guard engine uptime in seconds', type: 'gauge' },
  { name: 'panguard_memory_usage_bytes', help: 'Heap memory usage in bytes', type: 'gauge' },
  { name: 'panguard_cpu_usage_percent', help: 'Process CPU usage percentage', type: 'gauge' },
  { name: 'panguard_baseline_confidence', help: 'Environment baseline confidence (0-1)', type: 'gauge' },
  { name: 'panguard_learning_progress', help: 'Learning mode progress (0-1)', type: 'gauge' },
  { name: 'panguard_running', help: 'Whether the guard engine is running (0 or 1)', type: 'gauge' },
  { name: 'panguard_ai_requests_total', help: 'Total AI API requests made', type: 'counter' },
  { name: 'panguard_ai_latency_seconds', help: 'AI API request latency', type: 'histogram' },
];

/**
 * Metrics collector for the guard engine
 * Guard 引擎的指標收集器
 */
export class MetricsCollector {
  private aiRequestCount = 0;
  private aiLatencies: number[] = [];
  private prevCpuUsage: NodeJS.CpuUsage | null = null;
  private prevCpuTime = 0;

  /**
   * Record an AI API request latency
   * 記錄 AI API 請求延遲
   */
  recordAILatency(durationMs: number): void {
    this.aiRequestCount++;
    this.aiLatencies.push(durationMs / 1000);
    // Keep only recent 1000 samples
    if (this.aiLatencies.length > 1000) {
      this.aiLatencies = this.aiLatencies.slice(-1000);
    }
  }

  /**
   * Get current CPU usage percentage
   * 取得當前 CPU 使用百分比
   */
  private getCpuPercent(): number {
    const now = Date.now();
    const cpuUsage = process.cpuUsage(this.prevCpuUsage ?? undefined);
    const elapsed = now - (this.prevCpuTime || now);

    this.prevCpuUsage = process.cpuUsage();
    this.prevCpuTime = now;

    if (elapsed <= 0) return 0;

    const totalCpuMs = (cpuUsage.user + cpuUsage.system) / 1000;
    return Math.min(100, Math.round((totalCpuMs / elapsed) * 100 * 10) / 10);
  }

  /**
   * Generate Prometheus-format metrics text
   * 產生 Prometheus 格式的指標文字
   */
  toPrometheus(status: GuardStatus): string {
    const memUsage = process.memoryUsage();
    const cpuPercent = this.getCpuPercent();

    const values: Record<string, number> = {
      panguard_events_processed_total: status.eventsProcessed,
      panguard_threats_detected_total: status.threatsDetected,
      panguard_actions_executed_total: status.actionsExecuted,
      panguard_uptime_seconds: Math.round(status.uptime / 1000),
      panguard_memory_usage_bytes: memUsage.heapUsed,
      panguard_cpu_usage_percent: cpuPercent,
      panguard_baseline_confidence: status.baselineConfidence,
      panguard_learning_progress: status.learningProgress,
      panguard_running: status.running ? 1 : 0,
      panguard_ai_requests_total: this.aiRequestCount,
    };

    const lines: string[] = [];

    for (const def of METRIC_DEFS) {
      if (def.type === 'histogram') continue; // Handle separately
      lines.push(`# HELP ${def.name} ${def.help}`);
      lines.push(`# TYPE ${def.name} ${def.type}`);
      lines.push(`${def.name} ${values[def.name] ?? 0}`);
      lines.push('');
    }

    // AI latency histogram
    const histDef = METRIC_DEFS.find((d) => d.name === 'panguard_ai_latency_seconds')!;
    lines.push(`# HELP ${histDef.name} ${histDef.help}`);
    lines.push(`# TYPE ${histDef.name} histogram`);

    const buckets = [0.1, 0.5, 1, 2, 5, 10, 30];
    const sorted = [...this.aiLatencies].sort((a, b) => a - b);
    let sum = 0;
    for (const v of sorted) sum += v;

    for (const b of buckets) {
      const count = sorted.filter((v) => v <= b).length;
      lines.push(`panguard_ai_latency_seconds_bucket{le="${b}"} ${count}`);
    }
    lines.push(`panguard_ai_latency_seconds_bucket{le="+Inf"} ${sorted.length}`);
    lines.push(`panguard_ai_latency_seconds_sum ${Math.round(sum * 1000) / 1000}`);
    lines.push(`panguard_ai_latency_seconds_count ${sorted.length}`);
    lines.push('');

    return lines.join('\n');
  }
}
