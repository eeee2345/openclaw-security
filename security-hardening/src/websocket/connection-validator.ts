/**
 * WebSocket connection validation
 * WebSocket 連線驗證
 *
 * Prevents auto-connection to untrusted external URLs (CVE-2026-25253).
 * 防止自動連線到不受信任的外部 URL（CVE-2026-25253）。
 *
 * @module @panguard-ai/security-hardening/websocket/connection-validator
 */

import { createLogger } from '@panguard-ai/core';

const logger = createLogger('websocket:connection-validator');

/**
 * Check if a URL is a localhost address
 * 檢查 URL 是否為本機位址
 *
 * @param url - URL to check / 要檢查的 URL
 * @returns true if localhost / 為本機則回傳 true
 */
function isLocalhostUrl(url: URL): boolean {
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '::1';
}

/**
 * Validate a gatewayUrl query parameter
 * 驗證 gatewayUrl 查詢參數
 *
 * Prevents automatic connection to external WebSocket URLs.
 * Localhost URLs are always allowed; external URLs require explicit confirmation.
 * 防止自動連線到外部 WebSocket URL。
 * 本機 URL 始終允許；外部 URL 需要明確確認。
 *
 * @param gatewayUrl - Gateway URL from query parameter / 來自查詢參數的 Gateway URL
 * @param confirmCallback - Optional callback to request user confirmation / 可選的使用者確認回呼
 * @returns true if connection is allowed / 連線被允許則回傳 true
 */
export async function validateGatewayUrl(
  gatewayUrl: string | undefined,
  confirmCallback?: (url: string) => Promise<boolean>
): Promise<boolean> {
  if (!gatewayUrl) {
    return true; // No URL = use default, always OK
  }

  let parsed: URL;
  try {
    parsed = new URL(gatewayUrl);
  } catch {
    logger.error('Invalid gateway URL format rejected', { gatewayUrl });
    return false;
  }

  if (isLocalhostUrl(parsed)) {
    logger.info('Localhost gateway URL allowed', { gatewayUrl });
    return true;
  }

  // External URL detected
  logger.warn('External gateway URL detected', { gatewayUrl });

  if (confirmCallback) {
    const confirmed = await confirmCallback(gatewayUrl);
    if (confirmed) {
      logger.info('User confirmed external gateway connection', { gatewayUrl });
      return true;
    }
    logger.warn('User rejected external gateway connection', { gatewayUrl });
    return false;
  }

  // No confirmation mechanism - block by default
  logger.error('External gateway URL blocked (no confirmation mechanism)', { gatewayUrl });
  return false;
}

/**
 * Sanitize a WebSocket URL
 * 清理 WebSocket URL
 *
 * Only allows ws:// and wss:// protocols, strips credentials.
 * 僅允許 ws:// 和 wss:// 協定，移除憑證。
 *
 * @param url - Raw URL / 原始 URL
 * @returns Sanitized URL or null if invalid / 清理後的 URL，無效則為 null
 */
export function sanitizeWebSocketUrl(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    logger.error('Failed to parse WebSocket URL', { url });
    return null;
  }

  if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
    logger.warn('Invalid WebSocket protocol rejected', { url, protocol: parsed.protocol });
    return null;
  }

  // Reconstruct without credentials
  const sanitized = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  return sanitized;
}
