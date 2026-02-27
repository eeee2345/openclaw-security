/**
 * Structured audit logging for security events
 * 安全事件的結構化稽核日誌
 *
 * All security-relevant operations are logged in JSON format
 * for SIEM integration and compliance.
 * 所有安全相關操作以 JSON 格式記錄，用於 SIEM 整合和合規。
 *
 * @module @panguard-ai/security-hardening/audit/audit-logger
 */

import { createLogger } from '@panguard-ai/core';
import type { AuditEvent } from '../types.js';

const logger = createLogger('audit');

/**
 * Log a security audit event
 * 記錄安全稽核事件
 *
 * @param event - Partial audit event (timestamp auto-filled) / 部分稽核事件（時間戳自動填充）
 */
export function logAuditEvent(event: Omit<AuditEvent, 'timestamp' | 'module'>): void {
  const fullEvent: AuditEvent = {
    timestamp: new Date().toISOString(),
    module: 'audit',
    ...event,
  };

  const logFn = event.result === 'blocked' ? logger.warn : logger.info;
  logFn.call(logger, `[AUDIT] ${event.action}: ${event.result} -> ${event.target}`, {
    action: fullEvent.action,
    target: fullEvent.target,
    result: fullEvent.result,
    ...fullEvent.context,
  });
}

/**
 * Log WebSocket connection attempt
 * 記錄 WebSocket 連線嘗試
 */
export function logWebSocketConnect(
  origin: string,
  result: 'success' | 'blocked',
  ipAddress?: string
): void {
  logAuditEvent({
    level: result === 'blocked' ? 'warn' : 'info',
    action: 'websocket_connect',
    target: origin,
    result,
    context: ipAddress ? { ipAddress } : undefined,
  });
}

/**
 * Log credential access
 * 記錄憑證存取
 */
export function logCredentialAccess(
  service: string,
  account: string,
  result: 'success' | 'failure'
): void {
  logAuditEvent({
    level: result === 'failure' ? 'warn' : 'info',
    action: 'credential_access',
    target: `${service}:${account}`,
    result,
  });
}

/**
 * Log file access attempt
 * 記錄檔案存取嘗試
 */
export function logFileAccess(filePath: string, result: 'success' | 'blocked'): void {
  logAuditEvent({
    level: result === 'blocked' ? 'warn' : 'info',
    action: 'file_access',
    target: filePath,
    result,
  });
}

/**
 * Log command execution attempt
 * 記錄命令執行嘗試
 */
export function logCommandExecution(command: string, result: 'success' | 'blocked'): void {
  logAuditEvent({
    level: result === 'blocked' ? 'warn' : 'info',
    action: 'command_execution',
    target: command,
    result,
  });
}

/**
 * Log security policy check
 * 記錄安全政策檢查
 */
export function logPolicyCheck(operation: string, result: 'success' | 'blocked'): void {
  logAuditEvent({
    level: result === 'blocked' ? 'warn' : 'info',
    action: 'policy_check',
    target: operation,
    result,
  });
}
