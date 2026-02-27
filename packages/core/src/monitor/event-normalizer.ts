/**
 * Event normalizer - converts raw events to SecurityEvent format
 * 事件正規化器 - 將原始事件轉換為 SecurityEvent 格式
 *
 * @module @panguard-ai/core/monitor/event-normalizer
 */

import { randomUUID } from 'node:crypto';
import { hostname, platform } from 'node:os';

import type { SecurityEvent, EventSource, Severity } from '../types.js';

/**
 * Raw log event input
 * 原始日誌事件輸入
 */
interface RawLogEvent {
  /** Log message / 日誌訊息 */
  message: string;
  /** Log source identifier / 日誌來源識別碼 */
  source: string;
  /** Event timestamp / 事件時間戳 */
  timestamp?: Date;
}

/**
 * Raw network connection input
 * 原始網路連線輸入
 */
interface RawNetworkConnection {
  /** Local IP address / 本地 IP 位址 */
  localAddr: string;
  /** Local port / 本地埠號 */
  localPort: number;
  /** Remote IP address / 遠端 IP 位址 */
  remoteAddr: string;
  /** Remote port / 遠端埠號 */
  remotePort: number;
  /** Connection state / 連線狀態 */
  state: string;
  /** Associated process name / 關聯程序名稱 */
  process?: string;
}

/**
 * Raw process input
 * 原始程序輸入
 */
interface RawProcess {
  /** Process ID / 程序 ID */
  pid: number;
  /** Process name / 程序名稱 */
  name: string;
  /** Executable path / 可執行檔路徑 */
  path?: string;
  /** User running the process / 執行程序的使用者 */
  user?: string;
  /** Full command line / 完整命令列 */
  command?: string;
}

/**
 * Raw file event input
 * 原始檔案事件輸入
 */
interface RawFileEvent {
  /** File path / 檔案路徑 */
  path: string;
  /** Action performed / 執行的動作 */
  action: 'modified' | 'created' | 'deleted';
  /** Previous hash / 先前的雜湊 */
  oldHash?: string;
  /** New hash / 新的雜湊 */
  newHash?: string;
}

/** Current hostname cached / 快取的目前主機名稱 */
const currentHost = hostname();

/**
 * Determine the EventSource based on the current platform
 * 根據目前平台決定 EventSource
 *
 * @returns EventSource for the current OS / 目前作業系統的 EventSource
 */
function getPlatformLogSource(): EventSource {
  const os = platform();
  if (os === 'win32') return 'windows_event';
  return 'syslog';
}

/**
 * Parse severity from log message content by matching keywords
 * 通過匹配關鍵字從日誌訊息內容解析嚴重等級
 *
 * @param message - Log message to parse / 要解析的日誌訊息
 * @returns Severity level / 嚴重等級
 */
function parseSeverityFromMessage(message: string): Severity {
  const lower = message.toLowerCase();

  if (lower.includes('critical') || lower.includes('emergency') || lower.includes('fatal')) {
    return 'critical';
  }
  if (lower.includes('error') || lower.includes('fail') || lower.includes('denied')) {
    return 'high';
  }
  if (lower.includes('warn') || lower.includes('warning') || lower.includes('suspicious')) {
    return 'medium';
  }
  if (lower.includes('notice') || lower.includes('auth')) {
    return 'low';
  }
  return 'info';
}

/**
 * Extract a basic MITRE ATT&CK category from message patterns
 * 從訊息模式中擷取基本的 MITRE ATT&CK 分類
 *
 * @param message - Log message / 日誌訊息
 * @returns Category string / 分類字串
 */
function extractCategoryFromMessage(message: string): string {
  const lower = message.toLowerCase();

  if (
    lower.includes('login') ||
    lower.includes('auth') ||
    lower.includes('ssh') ||
    lower.includes('logon')
  ) {
    return 'Initial Access';
  }
  if (lower.includes('sudo') || lower.includes('privilege') || lower.includes('elevation')) {
    return 'Privilege Escalation';
  }
  if (lower.includes('firewall') || lower.includes('iptables') || lower.includes('blocked')) {
    return 'Defense Evasion';
  }
  if (lower.includes('cron') || lower.includes('scheduled') || lower.includes('persistence')) {
    return 'Persistence';
  }
  if (lower.includes('download') || lower.includes('curl') || lower.includes('wget')) {
    return 'Command and Control';
  }
  if (lower.includes('exec') || lower.includes('spawn') || lower.includes('script')) {
    return 'Execution';
  }
  return 'General';
}

/**
 * Normalize a raw log event into a SecurityEvent
 * 將原始日誌事件正規化為 SecurityEvent
 *
 * @param raw - Raw log event / 原始日誌事件
 * @returns Normalized SecurityEvent / 正規化的 SecurityEvent
 */
export function normalizeLogEvent(raw: RawLogEvent): SecurityEvent {
  return {
    id: randomUUID(),
    timestamp: raw.timestamp ?? new Date(),
    source: getPlatformLogSource(),
    severity: parseSeverityFromMessage(raw.message),
    category: extractCategoryFromMessage(raw.message),
    description: raw.message,
    raw,
    host: currentHost,
    metadata: {
      logSource: raw.source,
    },
  };
}

/**
 * Normalize a network connection into a SecurityEvent
 * 將網路連線正規化為 SecurityEvent
 *
 * @param connection - Raw network connection / 原始網路連線
 * @returns Normalized SecurityEvent / 正規化的 SecurityEvent
 */
export function normalizeNetworkEvent(connection: RawNetworkConnection): SecurityEvent {
  const description = `Network connection: ${connection.localAddr}:${connection.localPort} -> ${connection.remoteAddr}:${connection.remotePort} [${connection.state}]${connection.process ? ` (${connection.process})` : ''}`;

  return {
    id: randomUUID(),
    timestamp: new Date(),
    source: 'network',
    severity: 'info',
    category: 'Network Activity',
    description,
    raw: connection,
    host: currentHost,
    metadata: {
      localAddr: connection.localAddr,
      localPort: connection.localPort,
      remoteAddr: connection.remoteAddr,
      remotePort: connection.remotePort,
      state: connection.state,
      process: connection.process,
    },
  };
}

/**
 * Normalize a process event into a SecurityEvent
 * 將程序事件正規化為 SecurityEvent
 *
 * @param process - Raw process info / 原始程序資訊
 * @param action - Process action / 程序動作
 * @returns Normalized SecurityEvent / 正規化的 SecurityEvent
 */
export function normalizeProcessEvent(
  process: RawProcess,
  action: 'started' | 'stopped'
): SecurityEvent {
  const description = `Process ${action}: ${process.name} (PID: ${process.pid})${process.user ? ` by ${process.user}` : ''}`;

  return {
    id: randomUUID(),
    timestamp: new Date(),
    source: 'process',
    severity: 'info',
    category: action === 'started' ? 'Execution' : 'General',
    description,
    raw: { ...process, action },
    host: currentHost,
    metadata: {
      pid: process.pid,
      processName: process.name,
      action,
      path: process.path,
      user: process.user,
      command: process.command,
    },
  };
}

/**
 * Normalize a file event into a SecurityEvent
 * 將檔案事件正規化為 SecurityEvent
 *
 * @param file - Raw file event / 原始檔案事件
 * @returns Normalized SecurityEvent / 正規化的 SecurityEvent
 */
export function normalizeFileEvent(file: RawFileEvent): SecurityEvent {
  const actionLabels: Record<RawFileEvent['action'], string> = {
    modified: 'modified',
    created: 'created',
    deleted: 'deleted',
  };

  const description = `File ${actionLabels[file.action]}: ${file.path}`;

  let severity: Severity = 'info';
  if (file.action === 'modified' && file.oldHash && file.newHash && file.oldHash !== file.newHash) {
    severity = 'medium';
  }
  if (file.action === 'deleted') {
    severity = 'low';
  }

  return {
    id: randomUUID(),
    timestamp: new Date(),
    source: 'file',
    severity,
    category: 'Defense Evasion',
    description,
    raw: file,
    host: currentHost,
    metadata: {
      filePath: file.path,
      action: file.action,
      oldHash: file.oldHash,
      newHash: file.newHash,
    },
  };
}
