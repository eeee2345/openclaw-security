/**
 * Remote scan orchestrator.
 * Runs port scan, SSL check, HTTP headers check, and DNS check against a remote target.
 *
 * @module @panguard-ai/panguard-scan/scanners/remote
 */

import { lookup } from 'node:dns/promises';
import type { Language } from '@panguard-ai/core';
import type { Finding, ScanResult } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { scanPorts } from './port-scanner.js';
import { checkSSL } from './ssl-checker.js';
import { checkHttpHeaders } from './http-headers.js';
import { checkDNS } from './dns-checker.js';

export interface RemoteScanConfig {
  target: string;
  lang: Language;
  timeout?: number;
}

/** Check if an IP address is private/reserved (SSRF protection). */
function isPrivateIP(ip: string): boolean {
  // IPv4 private/reserved ranges
  const parts = ip.split('.').map(Number);
  if (parts.length === 4 && parts.every((n) => !isNaN(n))) {
    const [a, b] = parts as [number, number, number, number];
    if (a === 10) return true;                          // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
    if (a === 192 && b === 168) return true;             // 192.168.0.0/16
    if (a === 127) return true;                          // 127.0.0.0/8
    if (a === 0) return true;                            // 0.0.0.0/8
    if (a === 169 && b === 254) return true;             // link-local
    if (a >= 224) return true;                           // multicast + reserved
  }
  // IPv6 loopback and link-local
  if (ip === '::1' || ip === '::' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) {
    return true;
  }
  return false;
}

/**
 * Run a comprehensive remote scan against a target host.
 */
export async function runRemoteScan(config: RemoteScanConfig): Promise<ScanResult> {
  const { target, lang, timeout = 5000 } = config;

  // SSRF protection: resolve hostname and block private/reserved IPs
  try {
    const resolved = await lookup(target);
    if (isPrivateIP(resolved.address)) {
      throw new Error(`Scanning private/reserved IP addresses is not allowed: ${target}`);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes('not allowed')) throw err;
    // DNS resolution failed — let individual scanners handle it
  }
  const startTime = Date.now();
  const allFindings: Finding[] = [];

  // Run all checks in parallel
  const [portResult, sslResult, headerResult, dnsResult] = await Promise.all([
    scanPorts(target, lang, timeout).catch(() => ({
      findings: [] as Finding[],
      openPorts: [] as Array<{ port: number; open: boolean; service: string }>,
    })),
    checkSSL(target, lang, timeout).catch(() => ({
      findings: [] as Finding[],
      result: { valid: false, error: 'failed' },
    })),
    checkHttpHeaders(target, lang, timeout).catch(() => ({
      findings: [] as Finding[],
      headers: [],
    })),
    checkDNS(target, lang).catch(() => ({
      findings: [] as Finding[],
      result: { hasSPF: false, hasDMARC: false, hasDKIM: false },
    })),
  ]);

  allFindings.push(
    ...portResult.findings,
    ...sslResult.findings,
    ...headerResult.findings,
    ...dnsResult.findings
  );

  // Sort findings by severity (comparator function)
  const sortedFindings = [...allFindings].sort((a, b) => {
    const aOrder = SEVERITY_ORDER[a.severity] ?? 5;
    const bOrder = SEVERITY_ORDER[b.severity] ?? 5;
    return aOrder - bOrder;
  });

  // Calculate risk score
  let riskScore = 0;
  for (const f of sortedFindings) {
    switch (f.severity) {
      case 'critical':
        riskScore += 25;
        break;
      case 'high':
        riskScore += 15;
        break;
      case 'medium':
        riskScore += 8;
        break;
      case 'low':
        riskScore += 3;
        break;
    }
  }
  riskScore = Math.min(100, riskScore);

  const riskLevel =
    riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low';

  const scanDuration = Date.now() - startTime;

  return {
    discovery: {
      os: {
        platform: 'remote',
        distro: 'remote',
        version: '',
        arch: '',
        kernel: '',
        hostname: target,
        uptime: 0,
        patchLevel: '',
      },
      hostname: target,
      network: {
        interfaces: [],
        openPorts: [],
        activeConnections: [],
        gateway: '',
        dns: [],
      },
      openPorts: portResult.openPorts.map((p) => ({
        port: p.port,
        protocol: 'tcp',
        state: 'LISTEN',
        service: p.service,
        pid: undefined,
        process: 'remote',
      })),
      services: [],
      security: {
        existingTools: [],
        firewall: { enabled: false, product: '', rules: [] },
        updates: { pendingUpdates: 0, autoUpdateEnabled: false },
        users: [],
      },
      vulnerabilities: [],
      riskScore: 0,
      discoveredAt: new Date().toISOString(),
    },
    findings: sortedFindings,
    riskScore,
    riskLevel: riskLevel as 'low' | 'medium' | 'high' | 'critical',
    scanDuration,
    scannedAt: new Date().toISOString(),
    config: {
      depth: 'full',
      lang,
    },
  };
}

export { scanPorts } from './port-scanner.js';
export { checkSSL } from './ssl-checker.js';
export { checkHttpHeaders } from './http-headers.js';
export { checkDNS } from './dns-checker.js';
