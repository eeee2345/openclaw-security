/**
 * Core type definitions for Panguard AI platform
 * Panguard 安全平台核心類型定義
 *
 * @module @panguard-ai/core/types
 */

/**
 * Supported languages / 支援的語言
 */
export type Language = 'zh-TW' | 'en';

/**
 * Severity levels for security events / 安全事件嚴重等級
 */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * Security event source types / 安全事件來源類型
 */
export type EventSource =
  | 'windows_event'
  | 'syslog'
  | 'authlog'
  | 'journald'
  | 'network'
  | 'process'
  | 'file'
  | 'falco'
  | 'suricata'
  | 'honeypot'
  | 'dpi'
  | 'memory_scanner'
  | 'syscall';

/**
 * Base application configuration / 基礎應用程式配置
 */
export interface BaseConfig {
  /** Application language / 應用語言 */
  language: Language;
  /** Debug mode / 除錯模式 */
  debug: boolean;
  /** Log level / 日誌等級 */
  logLevel: 'info' | 'warn' | 'error' | 'debug';
}

/**
 * Standardized security event format / 標準化安全事件格式
 *
 * All security events from different sources are normalized to this format.
 * 所有來自不同來源的安全事件都會標準化為此格式。
 */
export interface SecurityEvent {
  /** Unique event identifier / 唯一事件識別碼 */
  id: string;
  /** Event timestamp / 事件時間戳 */
  timestamp: Date;
  /** Event source type / 事件來源類型 */
  source: EventSource;
  /** Severity level / 嚴重等級 */
  severity: Severity;
  /** MITRE ATT&CK category / MITRE ATT&CK 分類 */
  category: string;
  /** Event description / 事件描述 */
  description: string;
  /** Raw event data / 原始事件資料 */
  raw: unknown;
  /** Hostname / 主機名稱 */
  host: string;
  /** Additional metadata / 額外中繼資料 */
  metadata: Record<string, unknown>;
}

/**
 * Log entry format for structured logging / 結構化日誌條目格式
 */
export interface LogEntry {
  /** ISO timestamp / ISO 時間戳 */
  timestamp: string;
  /** Log level / 日誌等級 */
  level: 'info' | 'warn' | 'error' | 'debug';
  /** Log message / 日誌訊息 */
  message: string;
  /** Module that generated the log / 產生日誌的模組 */
  module: string;
  /** Additional context / 額外上下文 */
  context?: Record<string, unknown>;
}
