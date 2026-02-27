/**
 * Remote SSL/TLS certificate checker.
 * @module @panguard-ai/panguard-scan/scanners/remote/ssl-checker
 */

import { connect } from 'node:tls';
import type { Finding } from '../types.js';
import type { Language } from '@panguard-ai/core';

export interface SSLResult {
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  selfSigned?: boolean;
  error?: string;
}

/**
 * Check SSL certificate for a remote host.
 */
export async function checkSSL(
  host: string,
  lang: Language,
  timeout = 5000
): Promise<{ findings: Finding[]; result: SSLResult }> {
  const findings: Finding[] = [];

  const result = await new Promise<SSLResult>((resolve) => {
    const socket = connect(
      { host, port: 443, servername: host, timeout, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();

        if (!cert || !cert.valid_from) {
          resolve({ valid: false, error: 'No certificate returned' });
          return;
        }

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / 86400000);
        const selfSigned = cert.issuer?.CN === cert.subject?.CN;

        resolve({
          valid: now >= validFrom && now <= validTo,
          issuer: String(
            Array.isArray(cert.issuer?.O)
              ? cert.issuer.O[0]
              : (cert.issuer?.O ?? cert.issuer?.CN ?? 'unknown')
          ),
          subject: String(
            Array.isArray(cert.subject?.CN) ? cert.subject.CN[0] : (cert.subject?.CN ?? 'unknown')
          ),
          validFrom: validFrom.toISOString(),
          validTo: validTo.toISOString(),
          daysUntilExpiry,
          selfSigned,
        });
      }
    );

    socket.on('error', (err) => {
      socket.destroy();
      resolve({ valid: false, error: err.message });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ valid: false, error: 'Connection timeout' });
    });
  });

  if (result.error) {
    findings.push({
      id: 'remote-ssl-error',
      title:
        lang === 'zh-TW'
          ? 'SSL \u6191\u8B49\u6AA2\u67E5\u5931\u6557'
          : 'SSL certificate check failed',
      description: result.error,
      severity: 'high',
      category: 'ssl',
      remediation:
        lang === 'zh-TW'
          ? '\u78BA\u8A8D\u4F3A\u670D\u5668\u5DF2\u555F\u7528 HTTPS \u4E26\u5B89\u88DD\u6709\u6548\u6191\u8B49'
          : 'Ensure the server has HTTPS enabled with a valid certificate',
    });
  } else {
    if (!result.valid) {
      findings.push({
        id: 'remote-ssl-expired',
        title: lang === 'zh-TW' ? 'SSL \u6191\u8B49\u5DF2\u904E\u671F' : 'SSL certificate expired',
        description:
          lang === 'zh-TW'
            ? `\u6191\u8B49\u5DF2\u65BC ${result.validTo} \u904E\u671F`
            : `Certificate expired on ${result.validTo}`,
        severity: 'critical',
        category: 'ssl',
        remediation:
          lang === 'zh-TW'
            ? '\u7ACB\u5373\u66F4\u65B0 SSL \u6191\u8B49'
            : 'Renew the SSL certificate immediately',
      });
    } else if (result.daysUntilExpiry !== undefined && result.daysUntilExpiry <= 30) {
      findings.push({
        id: 'remote-ssl-expiring',
        title:
          lang === 'zh-TW'
            ? `SSL \u6191\u8B49\u5373\u5C07\u904E\u671F (${result.daysUntilExpiry} \u5929)`
            : `SSL certificate expiring soon (${result.daysUntilExpiry} days)`,
        description:
          lang === 'zh-TW'
            ? `\u6191\u8B49\u5C07\u65BC ${result.validTo} \u904E\u671F`
            : `Certificate will expire on ${result.validTo}`,
        severity: result.daysUntilExpiry <= 7 ? 'high' : 'medium',
        category: 'ssl',
        remediation:
          lang === 'zh-TW'
            ? '\u8ACB\u5118\u5FEB\u66F4\u65B0 SSL \u6191\u8B49'
            : 'Renew the SSL certificate soon',
      });
    }

    if (result.selfSigned) {
      findings.push({
        id: 'remote-ssl-self-signed',
        title:
          lang === 'zh-TW'
            ? '\u4F7F\u7528\u81EA\u7C3D\u6191\u8B49'
            : 'Self-signed certificate detected',
        description:
          lang === 'zh-TW'
            ? '\u81EA\u7C3D\u6191\u8B49\u4E0D\u88AB\u700F\u89BD\u5668\u4FE1\u4EFB'
            : 'Self-signed certificates are not trusted by browsers',
        severity: 'medium',
        category: 'ssl',
        remediation:
          lang === 'zh-TW'
            ? "\u4F7F\u7528 Let's Encrypt \u7B49\u53EF\u4FE1\u4EFB CA \u7C3D\u767C\u7684\u6191\u8B49"
            : "Use a certificate from a trusted CA like Let's Encrypt",
      });
    }
  }

  return { findings, result };
}
