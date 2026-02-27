/**
 * Remote HTTP security headers checker.
 * @module @panguard-ai/panguard-scan/scanners/remote/http-headers
 */

import { get as httpsGet } from 'node:https';
import { get as httpGet } from 'node:http';
import type { Finding } from '../types.js';
import type { Language } from '@panguard-ai/core';

/** Security headers to check */
const SECURITY_HEADERS: Array<{
  header: string;
  name: string;
  severity: 'low' | 'medium' | 'high';
}> = [
  {
    header: 'strict-transport-security',
    name: 'Strict-Transport-Security (HSTS)',
    severity: 'high',
  },
  { header: 'x-frame-options', name: 'X-Frame-Options', severity: 'medium' },
  { header: 'x-content-type-options', name: 'X-Content-Type-Options', severity: 'medium' },
  { header: 'content-security-policy', name: 'Content-Security-Policy', severity: 'medium' },
  { header: 'x-xss-protection', name: 'X-XSS-Protection', severity: 'low' },
  { header: 'referrer-policy', name: 'Referrer-Policy', severity: 'low' },
];

export interface HeaderCheckResult {
  header: string;
  present: boolean;
  value?: string;
}

/**
 * Check HTTP security headers for a remote host.
 */
export async function checkHttpHeaders(
  host: string,
  lang: Language,
  timeout = 5000
): Promise<{ findings: Finding[]; headers: HeaderCheckResult[] }> {
  const findings: Finding[] = [];
  const url = `https://${host}`;

  const responseHeaders = await new Promise<Record<string, string | string[] | undefined>>(
    (resolve) => {
      const getter = url.startsWith('https') ? httpsGet : httpGet;
      const req = getter(url, { timeout, rejectUnauthorized: false }, (res) => {
        res.resume(); // Drain response
        resolve(res.headers);
      });

      req.on('error', () => resolve({}));
      req.on('timeout', () => {
        req.destroy();
        resolve({});
      });
    }
  );

  const headers: HeaderCheckResult[] = SECURITY_HEADERS.map(({ header, name, severity }) => {
    const value = responseHeaders[header];
    const present = value !== undefined;

    if (!present) {
      findings.push({
        id: `remote-header-${header}`,
        title:
          lang === 'zh-TW'
            ? `\u7F3A\u5C11 ${name} HTTP \u6A19\u982D`
            : `Missing ${name} HTTP header`,
        description:
          lang === 'zh-TW'
            ? `\u672A\u8A2D\u5B9A ${name} \u5B89\u5168\u6A19\u982D`
            : `The ${name} security header is not set`,
        severity,
        category: 'http-headers',
        remediation:
          lang === 'zh-TW'
            ? `\u5728\u4F3A\u670D\u5668\u914D\u7F6E\u4E2D\u52A0\u5165 ${name} \u6A19\u982D`
            : `Add the ${name} header to your server configuration`,
      });
    }

    return {
      header: name,
      present,
      value: typeof value === 'string' ? value : value?.[0],
    };
  });

  return { findings, headers };
}
