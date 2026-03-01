/**
 * Report Agent - Event logging with rotation, streaming reads, and retention policy
 * 報告代理 - 事件記錄，支援 log rotation、串流讀取和資料保留策略
 *
 * Fourth stage of the multi-agent pipeline. Logs all events to JSONL with
 * automatic rotation, updates the baseline during learning mode, and
 * generates anonymized threat data for collective intelligence.
 *
 * @module @panguard-ai/panguard-guard/agent/report-agent
 */

import {
  appendFileSync,
  mkdirSync,
  readFileSync,
  statSync,
  renameSync,
  readdirSync,
  unlinkSync,
  createReadStream,
} from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { createInterface } from 'node:readline';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent } from '@panguard-ai/core';
import type {
  ThreatVerdict,
  ResponseResult,
  EnvironmentBaseline,
  AnonymizedThreatData,
  GuardMode,
} from '../types.js';
import { updateBaseline } from '../memory/baseline.js';

const logger = createLogger('panguard-guard:report-agent');

/** Full report record written to JSONL */
export interface ReportRecord {
  event: SecurityEvent;
  verdict: ThreatVerdict;
  response: ResponseResult;
  timestamp: string;
}

/** Daily/weekly summary structure */
export interface ReportSummary {
  period: { start: string; end: string };
  totalEvents: number;
  threatsBlocked: number;
  suspiciousEvents: number;
  benignEvents: number;
  topAttackSources: Array<{ ip: string; count: number }>;
  actionsTaken: Array<{ action: string; count: number }>;
  verdictBreakdown: { benign: number; suspicious: number; malicious: number };
}

/** Log rotation configuration */
interface RotationConfig {
  /** Max log file size before rotation (default 50MB) */
  maxFileSizeBytes: number;
  /** Max number of rotated log files to keep (default 10) */
  maxRotatedFiles: number;
  /** Retention period in days (default 90) */
  retentionDays: number;
}

const DEFAULT_ROTATION: RotationConfig = {
  maxFileSizeBytes: 50 * 1024 * 1024, // 50MB
  maxRotatedFiles: 10,
  retentionDays: 90,
};

/**
 * Report Agent logs events with rotation, updates baselines, and generates anonymized data.
 */
export class ReportAgent {
  private readonly logPath: string;
  private mode: GuardMode;
  private reportCount = 0;
  private readonly rotation: RotationConfig;

  constructor(logPath: string, mode: GuardMode, rotation?: Partial<RotationConfig>) {
    this.logPath = logPath;
    this.mode = mode;
    this.rotation = { ...DEFAULT_ROTATION, ...rotation };

    // Ensure log directory exists
    try {
      mkdirSync(dirname(logPath), { recursive: true });
    } catch {
      // Directory may already exist
    }
  }

  /** Update operating mode */
  setMode(mode: GuardMode): void {
    this.mode = mode;
  }

  /**
   * Process a complete pipeline result: log, update baseline, generate anonymized data.
   * Automatically rotates log file when size limit is reached.
   */
  report(
    event: SecurityEvent,
    verdict: ThreatVerdict,
    response: ResponseResult,
    baseline: EnvironmentBaseline
  ): { updatedBaseline: EnvironmentBaseline; anonymizedData?: AnonymizedThreatData } {
    this.reportCount++;

    // Step 1: Check if rotation needed before writing
    this.rotateIfNeeded();

    // Step 2: Log to JSONL
    const record: ReportRecord = {
      event,
      verdict,
      response,
      timestamp: new Date().toISOString(),
    };
    this.appendLog(record);

    // Step 3: Update baseline (learning mode adds normal patterns)
    let updatedBaseline = baseline;
    if (this.mode === 'learning') {
      updatedBaseline = updateBaseline(baseline, event);
    }

    // Step 4: Generate anonymized data for malicious/suspicious verdicts
    let anonymizedData: AnonymizedThreatData | undefined;
    if (verdict.conclusion !== 'benign') {
      anonymizedData = this.generateAnonymizedData(event, verdict);
    }

    logger.info(
      `Report #${this.reportCount}: ${verdict.conclusion} ` +
        `(action: ${response.action}, success: ${response.success})`
    );

    return { updatedBaseline, anonymizedData };
  }

  // ---------------------------------------------------------------------------
  // Log Rotation
  // ---------------------------------------------------------------------------

  /**
   * Rotate log file if it exceeds the size limit.
   * Naming: events.jsonl -> events.jsonl.1 -> events.jsonl.2 -> ...
   * Oldest files beyond maxRotatedFiles are deleted.
   */
  private rotateIfNeeded(): void {
    try {
      const stats = statSync(this.logPath);
      if (stats.size < this.rotation.maxFileSizeBytes) return;
    } catch {
      return; // File doesn't exist yet, no rotation needed
    }

    logger.info(`Log rotation triggered (file exceeds ${this.rotation.maxFileSizeBytes} bytes)`);

    const dir = dirname(this.logPath);
    const base = basename(this.logPath);

    // Shift existing rotated files: .9 -> .10, .8 -> .9, etc.
    for (let i = this.rotation.maxRotatedFiles; i >= 1; i--) {
      const from = join(dir, `${base}.${i}`);
      const to = join(dir, `${base}.${i + 1}`);
      try {
        renameSync(from, to);
      } catch {
        // File may not exist
      }
    }

    // Rename current log to .1
    try {
      renameSync(this.logPath, join(dir, `${base}.1`));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Log rotation rename failed: ${msg}`);
    }

    // Delete files beyond retention limit
    this.enforceRetention();
  }

  /**
   * Delete rotated log files beyond maxRotatedFiles and older than retentionDays
   */
  private enforceRetention(): void {
    const dir = dirname(this.logPath);
    const base = basename(this.logPath);
    const cutoff = Date.now() - this.rotation.retentionDays * 24 * 60 * 60 * 1000;

    try {
      const files = readdirSync(dir).filter((f) => f.startsWith(base + '.'));

      // Delete files beyond max count
      const numbered = files
        .map((f) => {
          const num = parseInt(f.slice(base.length + 1), 10);
          return { file: f, num };
        })
        .filter((x) => !isNaN(x.num))
        .sort((a, b) => a.num - b.num);

      for (const entry of numbered) {
        if (entry.num > this.rotation.maxRotatedFiles) {
          try {
            unlinkSync(join(dir, entry.file));
            logger.info(`Retention: deleted ${entry.file} (exceeds max rotated files)`);
          } catch {
            // Non-critical
          }
          continue;
        }

        // Also delete if older than retention period
        try {
          const stat = statSync(join(dir, entry.file));
          if (stat.mtimeMs < cutoff) {
            unlinkSync(join(dir, entry.file));
            logger.info(
              `Retention: deleted ${entry.file} (older than ${this.rotation.retentionDays} days)`
            );
          }
        } catch {
          // Non-critical
        }
      }
    } catch {
      // Directory read failure is non-critical
    }
  }

  // ---------------------------------------------------------------------------
  // Log Writing
  // ---------------------------------------------------------------------------

  private appendLog(record: ReportRecord): void {
    try {
      const line = JSON.stringify(record) + '\n';
      appendFileSync(this.logPath, line, 'utf-8');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to write log: ${msg}`);
    }
  }

  // ---------------------------------------------------------------------------
  // Streaming Log Reader (memory-efficient)
  // ---------------------------------------------------------------------------

  /**
   * Read log records from JSONL using streaming (line-by-line).
   * Only loads records after the cutoff date into memory.
   * This replaces the previous readFileSync approach that loaded entire files.
   */
  async readLogRecordsStreaming(after: Date): Promise<ReportRecord[]> {
    const records: ReportRecord[] = [];
    const allFiles = this.getLogFiles();

    for (const filePath of allFiles) {
      try {
        const fileRecords = await this.streamFile(filePath, after);
        records.push(...fileRecords);
      } catch {
        // File may not exist or be corrupted
      }
    }

    return records;
  }

  /**
   * Get all log files (current + rotated) sorted newest first
   */
  private getLogFiles(): string[] {
    const files: string[] = [this.logPath];
    const dir = dirname(this.logPath);
    const base = basename(this.logPath);

    try {
      const rotated = readdirSync(dir)
        .filter((f) => f.startsWith(base + '.'))
        .map((f) => {
          const num = parseInt(f.slice(base.length + 1), 10);
          return { file: join(dir, f), num };
        })
        .filter((x) => !isNaN(x.num))
        .sort((a, b) => a.num - b.num)
        .map((x) => x.file);

      files.push(...rotated);
    } catch {
      // No rotated files
    }

    return files;
  }

  /**
   * Stream a single JSONL file, returning records after the cutoff
   */
  private streamFile(filePath: string, after: Date): Promise<ReportRecord[]> {
    return new Promise((resolve) => {
      const records: ReportRecord[] = [];

      try {
        const stream = createReadStream(filePath, { encoding: 'utf-8' });
        const rl = createInterface({ input: stream, crlfDelay: Infinity });

        rl.on('line', (line) => {
          if (!line.trim()) return;
          try {
            const record = JSON.parse(line) as ReportRecord;
            if (new Date(record.timestamp) >= after) {
              records.push(record);
            }
          } catch {
            // Skip malformed lines
          }
        });

        rl.on('close', () => resolve(records));
        rl.on('error', () => resolve(records));
      } catch {
        resolve(records);
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Summary Generation (now uses streaming)
  // ---------------------------------------------------------------------------

  /**
   * Generate a summary for the given time period.
   * Uses streaming reader for memory efficiency.
   */
  async generateSummary(hoursBack: number): Promise<ReportSummary> {
    const now = new Date();
    const cutoff = new Date(now.getTime() - hoursBack * 60 * 60 * 1000);
    const records = await this.readLogRecordsStreaming(cutoff);

    const ipCounts = new Map<string, number>();
    const actionCounts = new Map<string, number>();
    const verdictBreakdown = { benign: 0, suspicious: 0, malicious: 0 };
    let threatsBlocked = 0;

    for (const r of records) {
      const conclusion = r.verdict.conclusion;
      if (conclusion === 'benign' || conclusion === 'suspicious' || conclusion === 'malicious') {
        verdictBreakdown[conclusion]++;
      }

      if (
        r.response.action !== 'log_only' &&
        r.response.action !== 'notify' &&
        r.response.success
      ) {
        threatsBlocked++;
      }

      const ip =
        (r.event.metadata?.['sourceIP'] as string) ??
        (r.event.metadata?.['remoteAddress'] as string);
      if (ip && conclusion !== 'benign') {
        ipCounts.set(ip, (ipCounts.get(ip) ?? 0) + 1);
      }

      const act = r.response.action;
      actionCounts.set(act, (actionCounts.get(act) ?? 0) + 1);
    }

    const topAttackSources = [...ipCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));

    const actionsTaken = [...actionCounts.entries()].map(([action, count]) => ({ action, count }));

    return {
      period: { start: cutoff.toISOString(), end: now.toISOString() },
      totalEvents: records.length,
      threatsBlocked,
      suspiciousEvents: verdictBreakdown.suspicious,
      benignEvents: verdictBreakdown.benign,
      topAttackSources,
      actionsTaken,
      verdictBreakdown,
    };
  }

  /** Generate daily summary (last 24 hours) */
  async generateDailySummary(): Promise<ReportSummary> {
    return this.generateSummary(24);
  }

  /** Generate weekly summary (last 7 days) */
  async generateWeeklySummary(): Promise<ReportSummary> {
    return this.generateSummary(7 * 24);
  }

  /**
   * Synchronous summary for backwards compatibility (reads current file only).
   * Prefer async generateSummary() for production use.
   */
  generateSummarySync(hoursBack: number): ReportSummary {
    const now = new Date();
    const cutoff = new Date(now.getTime() - hoursBack * 60 * 60 * 1000);
    const records = this.readLogRecordsSync(cutoff);

    const ipCounts = new Map<string, number>();
    const actionCounts = new Map<string, number>();
    const verdictBreakdown = { benign: 0, suspicious: 0, malicious: 0 };
    let threatsBlocked = 0;

    for (const r of records) {
      const conclusion = r.verdict.conclusion;
      if (conclusion === 'benign' || conclusion === 'suspicious' || conclusion === 'malicious') {
        verdictBreakdown[conclusion]++;
      }
      if (
        r.response.action !== 'log_only' &&
        r.response.action !== 'notify' &&
        r.response.success
      ) {
        threatsBlocked++;
      }
      const ip =
        (r.event.metadata?.['sourceIP'] as string) ??
        (r.event.metadata?.['remoteAddress'] as string);
      if (ip && conclusion !== 'benign') {
        ipCounts.set(ip, (ipCounts.get(ip) ?? 0) + 1);
      }
      actionCounts.set(r.response.action, (actionCounts.get(r.response.action) ?? 0) + 1);
    }

    return {
      period: { start: cutoff.toISOString(), end: now.toISOString() },
      totalEvents: records.length,
      threatsBlocked,
      suspiciousEvents: verdictBreakdown.suspicious,
      benignEvents: verdictBreakdown.benign,
      topAttackSources: [...ipCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count })),
      actionsTaken: [...actionCounts.entries()].map(([action, count]) => ({ action, count })),
      verdictBreakdown,
    };
  }

  /** Synchronous read of current log file only */
  private readLogRecordsSync(after: Date): ReportRecord[] {
    const records: ReportRecord[] = [];
    try {
      const content = readFileSync(this.logPath, 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);
      for (const line of lines) {
        try {
          const record = JSON.parse(line) as ReportRecord;
          if (new Date(record.timestamp) >= after) {
            records.push(record);
          }
        } catch {
          // Skip malformed lines
        }
      }
    } catch {
      // Log file may not exist yet
    }
    return records;
  }

  // ---------------------------------------------------------------------------
  // Anonymized Data Generation
  // ---------------------------------------------------------------------------

  private generateAnonymizedData(
    event: SecurityEvent,
    verdict: ThreatVerdict
  ): AnonymizedThreatData {
    const rawIP =
      (event.metadata?.['sourceIP'] as string) ??
      (event.metadata?.['remoteAddress'] as string) ??
      'unknown';
    const attackSourceIP = anonymizeIP(rawIP);

    const sigmaRuleMatched =
      verdict.evidence
        .filter((e) => e.source === 'rule_match')
        .map((e) => (e.data as Record<string, unknown>)?.['ruleId'] as string)
        .filter(Boolean)
        .join(',') || 'none';

    return {
      attackSourceIP,
      attackType: event.category,
      mitreTechnique: verdict.mitreTechnique ?? 'unknown',
      sigmaRuleMatched,
      timestamp: new Date().toISOString(),
      region: getCountryCode(),
    };
  }

  /** Get total report count */
  getReportCount(): number {
    return this.reportCount;
  }

  /** Get current log file size in bytes */
  getLogSizeBytes(): number {
    try {
      return statSync(this.logPath).size;
    } catch {
      return 0;
    }
  }

  /** Get number of rotated log files */
  getRotatedFileCount(): number {
    const dir = dirname(this.logPath);
    const base = basename(this.logPath);
    try {
      return readdirSync(dir).filter((f) => f.startsWith(base + '.') && /\.\d+$/.test(f)).length;
    } catch {
      return 0;
    }
  }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

function getCountryCode(): string {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const tzCountryMap: Record<string, string> = {
    'Asia/Taipei': 'TW',
    'Asia/Tokyo': 'JP',
    'Asia/Seoul': 'KR',
    'Asia/Shanghai': 'CN',
    'Asia/Hong_Kong': 'HK',
    'Asia/Singapore': 'SG',
    'America/New_York': 'US',
    'America/Chicago': 'US',
    'America/Denver': 'US',
    'America/Los_Angeles': 'US',
    'Europe/London': 'GB',
    'Europe/Berlin': 'DE',
    'Europe/Paris': 'FR',
    'Australia/Sydney': 'AU',
  };
  return tzCountryMap[tz] ?? 'UNKNOWN';
}

/**
 * Anonymize IP: zero last two octets for IPv4, last two segments for IPv6.
 * Stronger anonymization than single-octet zeroing.
 */
function anonymizeIP(ip: string): string {
  if (ip === 'unknown') return ip;

  // IPv4: zero last two octets (x.x.0.0)
  const v4parts = ip.split('.');
  if (v4parts.length === 4) {
    v4parts[2] = '0';
    v4parts[3] = '0';
    return v4parts.join('.');
  }

  // IPv6: zero last two segments
  const v6parts = ip.split(':');
  if (v6parts.length > 2) {
    v6parts[v6parts.length - 1] = '0';
    v6parts[v6parts.length - 2] = '0';
    return v6parts.join(':');
  }

  return ip;
}
