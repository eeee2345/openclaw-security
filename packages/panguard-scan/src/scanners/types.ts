/**
 * PanguardScan scanner type definitions
 * PanguardScan 掃描器型別定義
 *
 * @module @openclaw/panguard-scan/scanners/types
 */

import type { DiscoveryResult, Severity, Language } from '@openclaw/core';

/**
 * Scan configuration options
 * 掃描配置選項
 */
export interface ScanConfig {
  /**
   * Scan depth - 'quick' (~30s) or 'full' (~60s)
   * 掃描深度 - 'quick'（約 30 秒）或 'full'（約 60 秒）
   */
  depth: 'quick' | 'full';

  /**
   * Output language
   * 輸出語言
   */
  lang: Language;

  /**
   * Output PDF file path
   * 輸出 PDF 檔案路徑
   */
  output?: string;

  /**
   * Enable verbose output
   * 啟用詳細輸出
   */
  verbose?: boolean;
}

/**
 * Individual security finding from a scanner
 * 掃描器的個別安全發現
 */
export interface Finding {
  /**
   * Unique finding identifier
   * 唯一發現識別碼
   */
  id: string;

  /**
   * Finding title (human-readable)
   * 發現標題（人類可讀）
   */
  title: string;

  /**
   * Detailed description
   * 詳細描述
   */
  description: string;

  /**
   * Severity level
   * 嚴重等級
   */
  severity: Severity;

  /**
   * Finding category (e.g. 'password', 'network', 'system')
   * 發現分類（如 'password'、'network'、'system'）
   */
  category: string;

  /**
   * Remediation recommendation
   * 修復建議
   */
  remediation: string;

  /**
   * Taiwan ISMS compliance reference (e.g. "4.1.2")
   * 台灣資通安全管理法條目參照（如 "4.1.2"）
   */
  complianceRef?: string;

  /**
   * Additional technical details
   * 額外技術詳情
   */
  details?: string;

  /**
   * Manual fix commands for free-tier users
   * 免費版用戶的手動修復指令
   */
  manualFix?: string[];
}

/**
 * Complete scan result
 * 完整掃描結果
 */
export interface ScanResult {
  /**
   * Environment discovery result from core
   * 來自 core 的環境偵察結果
   */
  discovery: DiscoveryResult;

  /**
   * All security findings (sorted by severity)
   * 所有安全發現（按嚴重度排序）
   */
  findings: Finding[];

  /**
   * Overall risk score (0-100)
   * 總體風險評分（0-100）
   */
  riskScore: number;

  /**
   * Risk level label
   * 風險等級標籤
   */
  riskLevel: Severity;

  /**
   * Scan duration in milliseconds
   * 掃描持續時間（毫秒）
   */
  scanDuration: number;

  /**
   * Scan timestamp (ISO 8601)
   * 掃描時間戳（ISO 8601）
   */
  scannedAt: string;

  /**
   * Scan configuration used
   * 使用的掃描配置
   */
  config: ScanConfig;
}

/**
 * Severity sort order (lower = more severe)
 * 嚴重度排序（越低越嚴重）
 */
export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Sort findings by severity (most severe first)
 * 按嚴重度排序發現（最嚴重的在前）
 *
 * @param a - First finding / 第一個發現
 * @param b - Second finding / 第二個發現
 * @returns Sort comparison value / 排序比較值
 */
export function sortBySeverity(a: Finding, b: Finding): number {
  const aOrder = SEVERITY_ORDER[a.severity] ?? 5;
  const bOrder = SEVERITY_ORDER[b.severity] ?? 5;
  return aOrder - bOrder;
}
