/**
 * Syslog receiver adapter (RFC 5424)
 * Syslog 接收器對接器 (RFC 5424)
 *
 * Receives syslog messages over UDP, parses RFC 5424 format, and converts
 * them to standardized AdapterAlerts. Supports buffered alert retrieval
 * and callback-based real-time alert notification.
 * 透過 UDP 接收 syslog 訊息，解析 RFC 5424 格式，並將其轉換為
 * 標準化的 AdapterAlert。支援緩衝告警取得和基於回呼的即時告警通知。
 *
 * @module @panguard-ai/core/adapters/syslog-adapter
 */

import dgram from 'node:dgram';
import { randomUUID } from 'node:crypto';

import type { AdapterConfig, AdapterAlert } from './types.js';
import { BaseAdapter } from './base-adapter.js';

/**
 * Default UDP port for syslog reception
 * syslog 接收的預設 UDP 埠
 */
const DEFAULT_SYSLOG_PORT = 514;

/**
 * Maximum buffer size for stored alerts before oldest are discarded
 * 在丟棄最舊告警前的最大緩衝區大小
 */
const MAX_BUFFER_SIZE = 10000;

/**
 * RFC 5424 syslog severity levels (0-7)
 * RFC 5424 syslog 嚴重等級 (0-7)
 *
 * See https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
 */
const SYSLOG_SEVERITY_MAP: Record<number, string> = {
  0: 'critical', // Emergency / 緊急
  1: 'critical', // Alert / 警報
  2: 'critical', // Critical / 重大
  3: 'high', // Error / 錯誤
  4: 'medium', // Warning / 警告
  5: 'low', // Notice / 通知
  6: 'info', // Informational / 資訊
  7: 'info', // Debug / 除錯
};

/**
 * RFC 5424 syslog facility names
 * RFC 5424 syslog 設施名稱
 */
const SYSLOG_FACILITY_NAMES: Record<number, string> = {
  0: 'kern',
  1: 'user',
  2: 'mail',
  3: 'daemon',
  4: 'auth',
  5: 'syslog',
  6: 'lpr',
  7: 'news',
  8: 'uucp',
  9: 'cron',
  10: 'authpriv',
  11: 'ftp',
  12: 'ntp',
  13: 'security',
  14: 'console',
  15: 'solaris-cron',
  16: 'local0',
  17: 'local1',
  18: 'local2',
  19: 'local3',
  20: 'local4',
  21: 'local5',
  22: 'local6',
  23: 'local7',
};

/**
 * Parsed RFC 5424 syslog message fields
 * 已解析的 RFC 5424 syslog 訊息欄位
 */
interface ParsedSyslogMessage {
  /** Syslog facility code (0-23) / Syslog 設施碼 (0-23) */
  facility: number;
  /** Syslog severity code (0-7) / Syslog 嚴重等級碼 (0-7) */
  severityCode: number;
  /** RFC 5424 version / RFC 5424 版本 */
  version: number;
  /** Message timestamp (ISO 8601 or NILVALUE) / 訊息時間戳（ISO 8601 或 NILVALUE） */
  timestamp: string;
  /** Hostname / 主機名稱 */
  hostname: string;
  /** Application name / 應用程式名稱 */
  appName: string;
  /** Process ID / 行程 ID */
  procId: string;
  /** Message ID / 訊息 ID */
  msgId: string;
  /** Structured data / 結構化資料 */
  structuredData: string;
  /** Message body / 訊息本體 */
  message: string;
}

/**
 * Regular expression for parsing RFC 5424 syslog messages
 * 用於解析 RFC 5424 syslog 訊息的正則表達式
 *
 * RFC 5424 format:
 * <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]
 *
 * Where PRI = facility * 8 + severity
 */
const RFC5424_REGEX =
  /^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+((?:\[.*?\])+|-)\s*(.*)?$/s;

/**
 * Parse a raw syslog message string into structured fields
 * 將原始 syslog 訊息字串解析為結構化欄位
 *
 * Supports RFC 5424 format. Falls back to a best-effort parse for
 * non-conforming messages by treating the entire string as the message body.
 * 支援 RFC 5424 格式。對於不符合格式的訊息，會以盡力解析方式
 * 將整個字串視為訊息本體。
 *
 * @param raw - Raw syslog message string / 原始 syslog 訊息字串
 * @returns Parsed syslog message fields / 已解析的 syslog 訊息欄位
 */
export function parseSyslogMessage(raw: string): ParsedSyslogMessage {
  const match = RFC5424_REGEX.exec(raw.trim());

  if (!match) {
    // Attempt basic PRI extraction for BSD-style (RFC 3164) messages
    // 嘗試對 BSD 風格 (RFC 3164) 訊息進行基本 PRI 擷取
    const priMatch = /^<(\d{1,3})>(.*)$/s.exec(raw.trim());

    if (priMatch) {
      const pri = parseInt(priMatch[1] ?? '0', 10);
      const facility = Math.floor(pri / 8);
      const severityCode = pri % 8;

      return {
        facility,
        severityCode,
        version: 0,
        timestamp: new Date().toISOString(),
        hostname: '-',
        appName: '-',
        procId: '-',
        msgId: '-',
        structuredData: '-',
        message: (priMatch[2] ?? '').trim(),
      };
    }

    // Completely unparseable - treat as info-level user message
    // 完全無法解析 - 視為資訊等級的使用者訊息
    return {
      facility: 1,
      severityCode: 6,
      version: 0,
      timestamp: new Date().toISOString(),
      hostname: '-',
      appName: '-',
      procId: '-',
      msgId: '-',
      structuredData: '-',
      message: raw.trim(),
    };
  }

  const pri = parseInt(match[1] ?? '0', 10);
  const facility = Math.floor(pri / 8);
  const severityCode = pri % 8;

  const m3 = match[3] ?? '';
  const m4 = match[4] ?? '';
  const m5 = match[5] ?? '';
  const m6 = match[6] ?? '';
  const m7 = match[7] ?? '';
  const m8 = match[8] ?? '';

  return {
    facility,
    severityCode,
    version: parseInt(match[2] ?? '0', 10),
    timestamp: m3 === '-' ? new Date().toISOString() : m3,
    hostname: m4 === '-' ? '' : m4,
    appName: m5 === '-' ? '' : m5,
    procId: m6 === '-' ? '' : m6,
    msgId: m7 === '-' ? '' : m7,
    structuredData: m8 === '-' ? '' : m8,
    message: (match[9] ?? '').trim(),
  };
}

/**
 * Convert a parsed syslog message to an AdapterAlert
 * 將已解析的 syslog 訊息轉換為 AdapterAlert
 *
 * @param parsed - Parsed syslog message / 已解析的 syslog 訊息
 * @param raw - Original raw message string / 原始訊息字串
 * @returns AdapterAlert instance / AdapterAlert 實例
 */
function toAdapterAlert(parsed: ParsedSyslogMessage, raw: string): AdapterAlert {
  const facilityName = SYSLOG_FACILITY_NAMES[parsed.facility] ?? `facility-${parsed.facility}`;
  const severityString = SYSLOG_SEVERITY_MAP[parsed.severityCode] ?? 'info';

  return {
    id: randomUUID(),
    timestamp: parsed.timestamp,
    severity: severityString,
    title: `[${facilityName}] ${parsed.appName || 'syslog'}: ${parsed.msgId || 'message'}`,
    description: parsed.message || raw,
    source: 'syslog',
    raw: {
      parsed,
      original: raw,
    },
  };
}

/**
 * Callback type for real-time alert notification
 * 即時告警通知的回呼型別
 */
export type SyslogAlertCallback = (alert: AdapterAlert) => void;

/**
 * Syslog receiver security adapter (RFC 5424)
 * Syslog 接收器安全對接器 (RFC 5424)
 *
 * Listens for syslog messages on a UDP socket, parses RFC 5424 format,
 * buffers parsed alerts, and provides both callback-based real-time
 * notification and pull-based alert retrieval.
 *
 * 在 UDP socket 上監聽 syslog 訊息，解析 RFC 5424 格式，
 * 緩衝已解析的告警，並提供基於回呼的即時通知和拉取式告警取得。
 *
 * @example
 * ```typescript
 * const adapter = new SyslogAdapter({ enabled: true });
 *
 * // Set up real-time callback / 設定即時回呼
 * adapter.onAlert((alert) => {
 *   console.log('New syslog alert:', alert);
 * });
 *
 * // Start listening on port 514 / 開始在埠 514 上監聽
 * await adapter.start(514);
 *
 * // Later: retrieve buffered alerts / 稍後：取得緩衝的告警
 * const alerts = await adapter.getAlerts();
 *
 * // Stop listening / 停止監聽
 * adapter.stop();
 * ```
 */
export class SyslogAdapter extends BaseAdapter {
  /** @inheritdoc */
  readonly name = 'Syslog Receiver';

  /** @inheritdoc */
  readonly type = 'syslog';

  /**
   * UDP socket for receiving syslog messages
   * 用於接收 syslog 訊息的 UDP socket
   */
  private socket: dgram.Socket | null = null;

  /**
   * Buffer of alerts received since last getAlerts() call
   * 自上次 getAlerts() 呼叫以來接收的告警緩衝區
   */
  private alertBuffer: AdapterAlert[] = [];

  /**
   * Real-time alert callback
   * 即時告警回呼
   */
  private alertCallback: SyslogAlertCallback | null = null;

  /**
   * Whether the socket is currently listening
   * socket 是否正在監聽
   */
  private listening = false;

  /**
   * Port the socket is listening on
   * socket 正在監聽的埠
   */
  private listenPort: number = 0;

  /**
   * Create a new SyslogAdapter instance
   * 建立新的 SyslogAdapter 實例
   *
   * @param config - Adapter configuration / 對接器配置
   */
  constructor(config: AdapterConfig = { enabled: true }) {
    super('adapter-syslog', config);
  }

  /**
   * Register a callback for real-time alert notification
   * 註冊即時告警通知的回呼
   *
   * The callback is invoked for each parsed syslog message as it arrives.
   * Only one callback can be registered at a time; setting a new one
   * replaces the previous.
   * 每收到一筆已解析的 syslog 訊息就會呼叫此回呼。
   * 同一時間只能註冊一個回呼；設定新的會取代前一個。
   *
   * @param callback - Alert callback function / 告警回呼函式
   */
  onAlert(callback: SyslogAlertCallback): void {
    this.alertCallback = callback;
  }

  /**
   * Check if the syslog receiver is available (i.e. listening)
   * 檢查 syslog 接收器是否可用（即正在監聽）
   *
   * @returns True if the UDP socket is bound and listening / 若 UDP socket 已綁定且正在監聽則回傳 true
   */
  async isAvailable(): Promise<boolean> {
    return this.listening;
  }

  /**
   * Start the UDP syslog receiver
   * 啟動 UDP syslog 接收器
   *
   * Binds a UDP4 socket to the specified port and begins listening
   * for incoming syslog messages. Each message is parsed according to
   * RFC 5424 and added to the alert buffer.
   * 將 UDP4 socket 綁定到指定埠並開始監聽傳入的 syslog 訊息。
   * 每筆訊息都會依 RFC 5424 解析並新增到告警緩衝區。
   *
   * @param port - UDP port to listen on (default: 514) / 要監聽的 UDP 埠（預設：514）
   * @returns Promise that resolves when the socket is bound / socket 綁定後 resolve 的 Promise
   */
  start(port: number = DEFAULT_SYSLOG_PORT): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (this.listening) {
        this.logger.warn('Syslog receiver is already listening', { port: this.listenPort });
        resolve();
        return;
      }

      this.socket = dgram.createSocket('udp4');

      this.socket.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
        try {
          const raw = msg.toString('utf8');
          const parsed = parseSyslogMessage(raw);
          const alert = toAdapterAlert(parsed, raw);

          // Add source IP to alert metadata / 新增來源 IP 到告警中繼資料
          (alert.raw as Record<string, unknown>)['remoteAddress'] = rinfo.address;
          (alert.raw as Record<string, unknown>)['remotePort'] = rinfo.port;

          // Buffer the alert / 緩衝告警
          this.alertBuffer.push(alert);

          // Enforce buffer size limit / 強制緩衝區大小限制
          if (this.alertBuffer.length > MAX_BUFFER_SIZE) {
            const discarded = this.alertBuffer.length - MAX_BUFFER_SIZE;
            this.alertBuffer = this.alertBuffer.slice(discarded);
            this.logger.warn(`Alert buffer overflow, discarded ${discarded} oldest alerts`);
          }

          // Invoke real-time callback if registered / 若已註冊則呼叫即時回呼
          if (this.alertCallback) {
            this.alertCallback(alert);
          }

          this.logger.debug('Parsed syslog message', {
            from: `${rinfo.address}:${rinfo.port}`,
            facility: parsed.facility,
            severity: parsed.severityCode,
            hostname: parsed.hostname,
            appName: parsed.appName,
          });
        } catch (err) {
          this.logger.error('Failed to parse syslog message', {
            from: `${rinfo.address}:${rinfo.port}`,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      });

      this.socket.on('error', (err: Error) => {
        this.logger.error('Syslog socket error', { error: err.message });
        if (!this.listening) {
          // Error during binding / 綁定期間的錯誤
          reject(err);
        }
      });

      this.socket.on('close', () => {
        this.listening = false;
        this.listenPort = 0;
        this.logger.info('Syslog socket closed');
      });

      this.socket.bind(port, () => {
        this.listening = true;
        this.listenPort = port;
        const address = this.socket?.address();
        this.logger.info('Syslog receiver started', {
          port: address?.port ?? port,
          address: address?.address ?? '0.0.0.0',
        });
        resolve();
      });
    });
  }

  /**
   * Stop the UDP syslog receiver
   * 停止 UDP syslog 接收器
   *
   * Closes the UDP socket and stops listening for messages.
   * The alert buffer is preserved and can still be read via getAlerts().
   * 關閉 UDP socket 並停止監聽訊息。
   * 告警緩衝區會被保留，仍可透過 getAlerts() 讀取。
   */
  stop(): void {
    if (this.socket) {
      try {
        this.socket.close();
      } catch {
        // Socket may already be closed / Socket 可能已經關閉
      }
      this.socket = null;
    }
    this.listening = false;
    this.listenPort = 0;
    this.logger.info('Syslog receiver stopped');
  }

  /**
   * Retrieve buffered alerts and clear the buffer
   * 取得緩衝的告警並清除緩衝區
   *
   * Returns all alerts accumulated since the last call to getAlerts().
   * Optionally filters by a cutoff date. The buffer is cleared after
   * retrieval to prevent duplicate processing.
   * 回傳自上次呼叫 getAlerts() 以來累積的所有告警。
   * 可選依截止日期過濾。取得後會清除緩衝區以防止重複處理。
   *
   * @param since - Optional cutoff date / 可選截止日期
   * @returns Array of buffered adapter alerts / 緩衝的對接器告警陣列
   */
  async getAlerts(since?: Date): Promise<AdapterAlert[]> {
    // Drain the buffer / 排空緩衝區
    const buffered = this.alertBuffer.splice(0, this.alertBuffer.length);

    if (!since) {
      this.logger.debug(`Returning ${buffered.length} buffered syslog alerts`);
      return buffered;
    }

    // Filter by cutoff date / 依截止日期過濾
    const filtered = buffered.filter((alert) => {
      const alertTime = new Date(alert.timestamp);
      return alertTime >= since;
    });

    this.logger.debug(
      `Returning ${filtered.length} syslog alerts (${buffered.length} total buffered)`,
      {
        since: since.toISOString(),
      }
    );

    return filtered;
  }

  /**
   * Get the current buffer size (number of pending alerts)
   * 取得目前緩衝區大小（待處理告警數量）
   *
   * @returns Number of alerts in the buffer / 緩衝區中的告警數量
   */
  getBufferSize(): number {
    return this.alertBuffer.length;
  }

  /**
   * Check if the receiver is currently listening
   * 檢查接收器是否正在監聽
   *
   * @returns True if listening / 若正在監聽則回傳 true
   */
  isListening(): boolean {
    return this.listening;
  }

  /**
   * Get the port the receiver is listening on
   * 取得接收器正在監聽的埠
   *
   * @returns Port number, or 0 if not listening / 埠號，若未監聽則為 0
   */
  getPort(): number {
    return this.listenPort;
  }
}
