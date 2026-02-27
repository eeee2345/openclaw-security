/**
 * Syslog adapter for audit event forwarding
 * 稽核事件轉發的 Syslog 適配器
 *
 * Sends audit events to a syslog server using RFC 5424 format over UDP.
 * 使用 RFC 5424 格式透過 UDP 將稽核事件發送到 syslog 伺服器。
 *
 * @module @panguard-ai/security-hardening/audit/syslog-adapter
 */

import { createSocket, type Socket } from 'dgram';
import { hostname } from 'os';
import { createLogger } from '@panguard-ai/core';
import type { AuditEvent } from '../types.js';

const logger = createLogger('audit:syslog');

/** Syslog severity mapping / Syslog 嚴重程度映射 */
const SYSLOG_SEVERITY: Record<string, number> = {
  error: 3, // Error
  warn: 4, // Warning
  info: 6, // Informational
};

/** Syslog facility: local0 = 16 / Syslog 設施：local0 = 16 */
const FACILITY = 16;

/**
 * Format an audit event as RFC 5424 syslog message
 * 將稽核事件格式化為 RFC 5424 syslog 訊息
 *
 * @param event - Audit event / 稽核事件
 * @returns RFC 5424 formatted message / RFC 5424 格式化訊息
 */
export function formatSyslogMessage(event: AuditEvent): string {
  const severity = SYSLOG_SEVERITY[event.level] ?? 6;
  const priority = FACILITY * 8 + severity;
  const host = hostname();
  const appName = 'panguard-ai';
  const procId = process.pid;
  const msgId = event.action;
  const timestamp = event.timestamp;

  const structuredData = `[panguard action="${event.action}" target="${event.target}" result="${event.result}"]`;

  // RFC 5424: <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
  return `<${priority}>1 ${timestamp} ${host} ${appName} ${procId} ${msgId} ${structuredData} ${event.action}: ${event.result} -> ${event.target}`;
}

/**
 * Syslog adapter for sending audit events via UDP
 * 透過 UDP 發送稽核事件的 Syslog 適配器
 */
export class SyslogAdapter {
  private socket: Socket | null = null;
  private readonly host: string;
  private readonly port: number;

  /**
   * Create a new syslog adapter
   * 建立新的 syslog 適配器
   *
   * @param host - Syslog server hostname / Syslog 伺服器主機名稱
   * @param port - Syslog server port (default: 514) / Syslog 伺服器連接埠（預設：514）
   */
  constructor(host: string, port = 514) {
    this.host = host;
    this.port = port;
  }

  /**
   * Send an audit event to syslog
   * 將稽核事件發送到 syslog
   *
   * @param event - Audit event to send / 要發送的稽核事件
   */
  send(event: AuditEvent): void {
    if (!this.socket) {
      this.socket = createSocket('udp4');
      this.socket.on('error', (err) => {
        logger.error('Syslog socket error', { error: String(err) });
      });
    }

    const message = formatSyslogMessage(event);
    const buffer = Buffer.from(message, 'utf-8');

    this.socket.send(buffer, 0, buffer.length, this.port, this.host, (err) => {
      if (err) {
        logger.error('Failed to send syslog message', {
          host: this.host,
          port: this.port,
          error: String(err),
        });
      }
    });
  }

  /**
   * Close the syslog socket
   * 關閉 syslog socket
   */
  close(): void {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
      logger.info('Syslog adapter closed');
    }
  }
}
