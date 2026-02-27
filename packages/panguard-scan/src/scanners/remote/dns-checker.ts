/**
 * Remote DNS security record checker (SPF, DMARC, DKIM).
 * @module @panguard-ai/panguard-scan/scanners/remote/dns-checker
 */

import { resolveTxt } from 'node:dns/promises';
import type { Finding } from '../types.js';
import type { Language } from '@panguard-ai/core';

export interface DNSCheckResult {
  hasSPF: boolean;
  hasDMARC: boolean;
  hasDKIM: boolean;
  spfRecord?: string;
  dmarcRecord?: string;
}

/**
 * Check DNS security records for a domain.
 */
export async function checkDNS(
  host: string,
  lang: Language
): Promise<{ findings: Finding[]; result: DNSCheckResult }> {
  const findings: Finding[] = [];
  const result: DNSCheckResult = {
    hasSPF: false,
    hasDMARC: false,
    hasDKIM: false,
  };

  // Strip subdomains for DNS checks (e.g. www.example.com -> example.com)
  const parts = host.split('.');
  const domain = parts.length > 2 ? parts.slice(-2).join('.') : host;

  // Check SPF
  try {
    const txtRecords = await resolveTxt(domain);
    const spf = txtRecords.flat().find((r) => r.startsWith('v=spf1'));
    if (spf) {
      result.hasSPF = true;
      result.spfRecord = spf;
    }
  } catch {
    // DNS query failed - domain may not have TXT records
  }

  // Check DMARC
  try {
    const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
    const dmarc = dmarcRecords.flat().find((r) => r.startsWith('v=DMARC1'));
    if (dmarc) {
      result.hasDMARC = true;
      result.dmarcRecord = dmarc;
    }
  } catch {
    // No DMARC record
  }

  // Check DKIM (common selectors)
  const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1'];
  for (const selector of dkimSelectors) {
    try {
      const dkimRecords = await resolveTxt(`${selector}._domainkey.${domain}`);
      const dkim = dkimRecords.flat().find((r) => r.includes('v=DKIM1'));
      if (dkim) {
        result.hasDKIM = true;
        break;
      }
    } catch {
      // No DKIM record for this selector
    }
  }

  // Generate findings for missing records
  if (!result.hasSPF) {
    findings.push({
      id: 'remote-dns-no-spf',
      title: lang === 'zh-TW' ? '\u7F3A\u5C11 SPF \u8A18\u9304' : 'Missing SPF record',
      description:
        lang === 'zh-TW'
          ? '\u672A\u8A2D\u5B9A SPF \u8A18\u9304\uFF0C\u57DF\u540D\u5BB9\u6613\u88AB\u7528\u65BC\u91E3\u9B5A\u90F5\u4EF6'
          : 'No SPF record found. Domain is vulnerable to email spoofing',
      severity: 'medium',
      category: 'dns',
      remediation:
        lang === 'zh-TW'
          ? '\u5728 DNS \u4E2D\u52A0\u5165 SPF TXT \u8A18\u9304'
          : 'Add an SPF TXT record to your DNS configuration',
    });
  }

  if (!result.hasDMARC) {
    findings.push({
      id: 'remote-dns-no-dmarc',
      title: lang === 'zh-TW' ? '\u7F3A\u5C11 DMARC \u8A18\u9304' : 'Missing DMARC record',
      description:
        lang === 'zh-TW'
          ? '\u672A\u8A2D\u5B9A DMARC \u8A18\u9304\uFF0C\u7121\u6CD5\u9632\u6B62\u57DF\u540D\u88AB\u5048\u9020'
          : 'No DMARC record found. Cannot prevent domain spoofing',
      severity: 'medium',
      category: 'dns',
      remediation:
        lang === 'zh-TW'
          ? '\u5728 DNS \u4E2D\u52A0\u5165 _dmarc TXT \u8A18\u9304'
          : 'Add a _dmarc TXT record to your DNS configuration',
    });
  }

  if (!result.hasDKIM) {
    findings.push({
      id: 'remote-dns-no-dkim',
      title:
        lang === 'zh-TW' ? '\u672A\u5075\u6E2C\u5230 DKIM \u8A18\u9304' : 'No DKIM record detected',
      description:
        lang === 'zh-TW'
          ? '\u672A\u627E\u5230 DKIM \u8A18\u9304\uFF0C\u90F5\u4EF6\u9A57\u8B49\u4E0D\u5B8C\u6574'
          : 'No DKIM record found. Email authentication is incomplete',
      severity: 'low',
      category: 'dns',
      remediation:
        lang === 'zh-TW'
          ? '\u8A2D\u5B9A\u90F5\u4EF6\u4F3A\u670D\u5668\u7684 DKIM \u7C3D\u540D\u4E26\u52A0\u5165 DNS \u8A18\u9304'
          : 'Configure DKIM signing on your mail server and add DNS records',
    });
  }

  return { findings, result };
}
