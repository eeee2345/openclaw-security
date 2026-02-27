/**
 * Report Agent - Event logging, baseline updates, and anonymized data generation
 * 報告代理 - 事件記錄、基線更新和匿名化數據產生
 *
 * Fourth and final stage of the multi-agent pipeline. Logs all events to JSONL,
 * updates the baseline during learning mode, and generates anonymized threat data
 * for collective threat intelligence sharing.
 * 多代理管線的第四也是最後一個階段。將所有事件記錄到 JSONL，
 * 在學習模式下更新基線，並產生匿名化威脅數據用於集體威脅情報分享。
 *
 * @module @panguard-ai/panguard-guard/agent/report-agent
 */

import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
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

/** Full report record written to JSONL / 寫入 JSONL 的完整報告記錄 */
export interface ReportRecord {
  event: SecurityEvent;
  verdict: ThreatVerdict;
  response: ResponseResult;
  timestamp: string;
}

/** Daily/weekly summary structure / 日報/週報摘要結構 */
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

/**
 * Report Agent logs events, updates baselines, and generates anonymized data
 * 報告代理記錄事件、更新基線並產生匿名化數據
 */
export class ReportAgent {
  private readonly logPath: string;
  private mode: GuardMode;
  private reportCount = 0;

  /**
   * @param logPath - Path to the JSONL event log / JSONL 事件日誌路徑
   * @param mode - Current operating mode / 當前運作模式
   */
  constructor(logPath: string, mode: GuardMode) {
    this.logPath = logPath;
    this.mode = mode;

    // Ensure log directory exists / 確保日誌目錄存在
    try {
      mkdirSync(dirname(logPath), { recursive: true });
    } catch {
      // Directory may already exist / 目錄可能已存在
    }
  }

  /**
   * Update operating mode / 更新操作模式
   */
  setMode(mode: GuardMode): void {
    this.mode = mode;
  }

  /**
   * Process a complete pipeline result: log, update baseline, generate anonymized data
   * 處理完整的管線結果：記錄、更新基線、產生匿名化數據
   *
   * @param event - The original security event / 原始安全事件
   * @param verdict - The threat verdict from analysis / 分析產生的威脅判決
   * @param response - The response action result / 回應動作結果
   * @param baseline - Current environment baseline / 當前環境基線
   * @returns Updated baseline and optional anonymized threat data /
   *          更新後的基線和可選的匿名化威脅數據
   */
  report(
    event: SecurityEvent,
    verdict: ThreatVerdict,
    response: ResponseResult,
    baseline: EnvironmentBaseline
  ): { updatedBaseline: EnvironmentBaseline; anonymizedData?: AnonymizedThreatData } {
    this.reportCount++;

    // Step 1: Log to JSONL / 步驟 1: 記錄到 JSONL
    const record: ReportRecord = {
      event,
      verdict,
      response,
      timestamp: new Date().toISOString(),
    };
    this.appendLog(record);

    // Step 2: Update baseline (learning mode adds normal patterns)
    // 步驟 2: 更新基線（學習模式下添加正常模式）
    let updatedBaseline = baseline;
    if (this.mode === 'learning') {
      updatedBaseline = updateBaseline(baseline, event);
      logger.info(`Baseline updated during learning / 學習模式下已更新基線`);
    }

    // Step 3: Generate anonymized data for malicious/suspicious verdicts
    // 步驟 3: 為惡意/可疑判決產生匿名化數據
    let anonymizedData: AnonymizedThreatData | undefined;
    if (verdict.conclusion !== 'benign') {
      anonymizedData = this.generateAnonymizedData(event, verdict);
    }

    logger.info(
      `Report #${this.reportCount}: ${verdict.conclusion} ` +
        `(action: ${response.action}, success: ${response.success}) / ` +
        `報告 #${this.reportCount}: ${verdict.conclusion}`
    );

    return { updatedBaseline, anonymizedData };
  }

  /**
   * Generate anonymized threat data for collective intelligence
   * 產生匿名化威脅數據用於集體情報
   */
  private generateAnonymizedData(
    event: SecurityEvent,
    verdict: ThreatVerdict
  ): AnonymizedThreatData {
    // Extract source IP, anonymize last octet / 提取來源 IP，匿名化最後一段
    const rawIP =
      (event.metadata?.['sourceIP'] as string) ??
      (event.metadata?.['remoteAddress'] as string) ??
      'unknown';
    const attackSourceIP = anonymizeIP(rawIP);

    // Find matching Sigma rule ID / 查找匹配的 Sigma 規則 ID
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

  /**
   * Append a record to the JSONL log file / 追加記錄到 JSONL 日誌
   */
  private appendLog(record: ReportRecord): void {
    try {
      const line = JSON.stringify(record) + '\n';
      appendFileSync(this.logPath, line, 'utf-8');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to write log: ${msg} / 寫入日誌失敗: ${msg}`);
    }
  }

  /**
   * Generate a summary for the given time period from the JSONL log
   * 從 JSONL 日誌產生指定時段的摘要
   *
   * @param hoursBack - Number of hours to look back / 回溯小時數
   * @returns Summary of events in the period / 時段內的事件摘要
   */
  generateSummary(hoursBack: number): ReportSummary {
    const now = new Date();
    const cutoff = new Date(now.getTime() - hoursBack * 60 * 60 * 1000);
    const records = this.readLogRecords(cutoff);

    const ipCounts = new Map<string, number>();
    const actionCounts = new Map<string, number>();
    const verdictBreakdown = { benign: 0, suspicious: 0, malicious: 0 };
    let threatsBlocked = 0;

    for (const r of records) {
      // Count verdicts / 統計判決
      const conclusion = r.verdict.conclusion;
      if (conclusion === 'benign' || conclusion === 'suspicious' || conclusion === 'malicious') {
        verdictBreakdown[conclusion]++;
      }

      // Count blocked threats / 統計已阻擋威脅
      if (
        r.response.action !== 'log_only' &&
        r.response.action !== 'notify' &&
        r.response.success
      ) {
        threatsBlocked++;
      }

      // Count attack source IPs / 統計攻擊來源 IP
      const ip =
        (r.event.metadata?.['sourceIP'] as string) ??
        (r.event.metadata?.['remoteAddress'] as string);
      if (ip && conclusion !== 'benign') {
        ipCounts.set(ip, (ipCounts.get(ip) ?? 0) + 1);
      }

      // Count actions / 統計動作
      const act = r.response.action;
      actionCounts.set(act, (actionCounts.get(act) ?? 0) + 1);
    }

    // Top attack sources (sorted by count desc) / 攻擊來源排名
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

  /**
   * Generate daily summary (last 24 hours) / 產生日報（最近 24 小時）
   */
  generateDailySummary(): ReportSummary {
    return this.generateSummary(24);
  }

  /**
   * Generate weekly summary (last 7 days) / 產生週報（最近 7 天）
   */
  generateWeeklySummary(): ReportSummary {
    return this.generateSummary(7 * 24);
  }

  /**
   * Read log records from JSONL after the given cutoff date
   * 讀取指定日期之後的 JSONL 日誌記錄
   */
  private readLogRecords(after: Date): ReportRecord[] {
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
          // Skip malformed lines / 跳過格式錯誤的行
        }
      }
    } catch {
      // Log file may not exist yet / 日誌檔可能尚不存在
    }
    return records;
  }

  /**
   * Get total report count / 取得報告總數
   */
  getReportCount(): number {
    return this.reportCount;
  }
}

/**
 * Get country code from timezone for anonymized data
 * 從時區取得國家碼用於匿名化數據
 *
 * Maps common timezones to country-level codes.
 * Only provides country-level granularity to protect privacy.
 * 僅提供國家級精度以保護隱私。
 */
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
 * Anonymize an IPv4 address by zeroing the last octet
 * 匿名化 IPv4 地址（將最後一段歸零）
 */
function anonymizeIP(ip: string): string {
  if (ip === 'unknown') return ip;
  const parts = ip.split('.');
  if (parts.length === 4) {
    parts[3] = '0';
    return parts.join('.');
  }
  // IPv6 or other: truncate last segment / IPv6 或其他：截斷最後一段
  const v6parts = ip.split(':');
  if (v6parts.length > 1) {
    v6parts[v6parts.length - 1] = '0';
    return v6parts.join(':');
  }
  return ip;
}
