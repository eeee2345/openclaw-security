/**
 * SSL/TLS certificate checker
 * SSL/TLS 憑證檢查器
 *
 * Checks SSL/TLS certificates on HTTPS-capable ports for expiration and
 * validity issues. Connects to localhost on identified ports to inspect
 * the presented certificate.
 * 檢查具有 HTTPS 功能的埠上的 SSL/TLS 憑證是否有到期和有效性問題。
 * 連線到 localhost 上已識別的埠以檢查呈現的憑證。
 *
 * @module @panguard-ai/panguard-scan/scanners/ssl-checker
 */

import tls from 'node:tls';
import { createLogger, type PortInfo } from '@panguard-ai/core';
import type { Finding } from './types.js';

const logger = createLogger('panguard-scan:ssl-checker');

/**
 * Well-known HTTPS port numbers
 * 已知的 HTTPS 埠號
 */
const HTTPS_PORTS = new Set([443, 8443]);

/**
 * Number of days before expiration to trigger a warning
 * 到期前觸發警告的天數
 */
const EXPIRY_WARNING_DAYS = 30;

/**
 * Connection timeout in milliseconds
 * 連線逾時（毫秒）
 */
const CONNECT_TIMEOUT_MS = 5_000;

/**
 * Determine whether a port is likely serving HTTPS
 * 判斷埠是否可能提供 HTTPS 服務
 *
 * @param portInfo - Port information to evaluate / 要評估的埠資訊
 * @returns True if the port likely serves HTTPS / 如果埠可能提供 HTTPS 服務則為 true
 */
function isHttpsPort(portInfo: PortInfo): boolean {
  if (HTTPS_PORTS.has(portInfo.port)) return true;
  if (portInfo.service && portInfo.service.toLowerCase().includes('https')) return true;
  return false;
}

/**
 * Check the SSL certificate on a single port
 * 檢查單一埠上的 SSL 憑證
 *
 * Establishes a TLS connection to localhost on the specified port and
 * inspects the certificate's validity period.
 * 在指定埠上建立到 localhost 的 TLS 連線，並檢查憑證的有效期間。
 *
 * @param port - Port number to check / 要檢查的埠號
 * @returns A Finding if the certificate is expired or expiring soon, or null / 如果憑證已過期或即將到期則回傳 Finding，否則為 null
 */
async function checkCertOnPort(port: number): Promise<Finding | null> {
  return new Promise<Finding | null>((resolve) => {
    const socket = tls.connect(
      {
        host: 'localhost',
        port,
        rejectUnauthorized: false,
        timeout: CONNECT_TIMEOUT_MS,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          if (!cert || !cert.valid_to) {
            logger.debug(`No certificate found on port ${port}`);
            socket.destroy();
            resolve(null);
            return;
          }

          const validTo = new Date(cert.valid_to);
          const validFrom = new Date(cert.valid_from);
          const now = new Date();
          const daysUntilExpiry = Math.floor(
            (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
          );

          const subject = cert.subject?.CN || 'unknown';

          if (now > validTo) {
            // Certificate has expired
            // 憑證已過期
            logger.info(
              `Expired certificate on port ${port}: expired ${Math.abs(daysUntilExpiry)} days ago`
            );
            socket.destroy();
            resolve({
              id: `SCAN-SSL-${port}`,
              title:
                `Expired SSL certificate on port ${port} / ` + `埠 ${port} 上的 SSL 憑證已過期`,
              description:
                `The SSL/TLS certificate on port ${port} (subject: ${subject}) ` +
                `expired on ${validTo.toISOString().split('T')[0]}. ` +
                `It has been expired for ${Math.abs(daysUntilExpiry)} day(s). / ` +
                `埠 ${port} 上的 SSL/TLS 憑證（主體：${subject}）` +
                `已於 ${validTo.toISOString().split('T')[0]} 過期。` +
                `已過期 ${Math.abs(daysUntilExpiry)} 天。`,
              severity: 'high',
              category: 'certificate',
              remediation:
                `Renew the SSL/TLS certificate for port ${port} immediately. ` +
                "Consider using automated certificate management (e.g., Let's Encrypt). / " +
                `立即續期埠 ${port} 的 SSL/TLS 憑證。` +
                "考慮使用自動憑證管理（例如 Let's Encrypt）。",
              complianceRef: '4.4',
              details:
                `Subject: ${subject}, Valid from: ${validFrom.toISOString()}, ` +
                `Valid to: ${validTo.toISOString()}, Days expired: ${Math.abs(daysUntilExpiry)}`,
            });
            return;
          }

          if (daysUntilExpiry <= EXPIRY_WARNING_DAYS) {
            // Certificate expiring soon
            // 憑證即將到期
            logger.info(`Certificate on port ${port} expiring in ${daysUntilExpiry} days`);
            socket.destroy();
            resolve({
              id: `SCAN-SSL-${port}`,
              title:
                `SSL certificate expiring soon on port ${port} / ` +
                `埠 ${port} 上的 SSL 憑證即將到期`,
              description:
                `The SSL/TLS certificate on port ${port} (subject: ${subject}) ` +
                `will expire on ${validTo.toISOString().split('T')[0]} ` +
                `(${daysUntilExpiry} day(s) remaining). / ` +
                `埠 ${port} 上的 SSL/TLS 憑證（主體：${subject}）` +
                `將於 ${validTo.toISOString().split('T')[0]} 到期` +
                `（剩餘 ${daysUntilExpiry} 天）。`,
              severity: 'medium',
              category: 'certificate',
              remediation:
                `Renew the SSL/TLS certificate for port ${port} before it expires. ` +
                'Set up automated renewal to prevent future expirations. / ' +
                `在到期前續期埠 ${port} 的 SSL/TLS 憑證。` +
                '設定自動續期以防止未來過期。',
              complianceRef: '4.4',
              details:
                `Subject: ${subject}, Valid from: ${validFrom.toISOString()}, ` +
                `Valid to: ${validTo.toISOString()}, Days remaining: ${daysUntilExpiry}`,
            });
            return;
          }

          // Certificate is valid and not expiring soon
          // 憑證有效且不會很快到期
          logger.debug(`Certificate on port ${port} is valid (expires in ${daysUntilExpiry} days)`);
          socket.destroy();
          resolve(null);
        } catch (err) {
          logger.debug(`Error reading certificate on port ${port}`, {
            error: err instanceof Error ? err.message : String(err),
          });
          socket.destroy();
          resolve(null);
        }
      }
    );

    // Handle connection errors
    // 處理連線錯誤
    socket.on('error', (err) => {
      logger.debug(`TLS connection error on port ${port}`, {
        error: err.message,
      });
      socket.destroy();
      resolve(null);
    });

    // Handle timeout
    // 處理逾時
    socket.on('timeout', () => {
      logger.debug(`TLS connection timeout on port ${port}`);
      socket.destroy();
      resolve(null);
    });
  });
}

/**
 * Check SSL/TLS certificates on all HTTPS-capable ports
 * 檢查所有具有 HTTPS 功能的埠上的 SSL/TLS 憑證
 *
 * Iterates through the provided port list, identifies ports that are likely
 * serving HTTPS, and checks each certificate for expiration.
 * 遍歷提供的埠列表，識別可能提供 HTTPS 服務的埠，並檢查每個憑證的到期情況。
 *
 * @param ports - Array of open port info from discovery / 來自偵察的開放埠資訊陣列
 * @returns Array of certificate-related findings / 與憑證相關的發現陣列
 */
export async function checkSslCertificates(ports: PortInfo[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  const httpsPorts = ports.filter(isHttpsPort);

  if (httpsPorts.length === 0) {
    logger.info('No HTTPS-capable ports found to check');
    return findings;
  }

  logger.info(`Checking SSL certificates on ${httpsPorts.length} HTTPS-capable port(s)`);

  for (const portInfo of httpsPorts) {
    try {
      const finding = await checkCertOnPort(portInfo.port);
      if (finding) {
        findings.push(finding);
      }
    } catch (err) {
      logger.debug(`Failed to check SSL on port ${portInfo.port}`, {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  logger.info(`SSL certificate check complete: ${findings.length} finding(s)`);
  return findings;
}
