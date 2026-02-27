/**
 * Remote scan orchestrator.
 * Runs port scan, SSL check, HTTP headers check, and DNS check against a remote target.
 *
 * @module @panguard-ai/panguard-scan/scanners/remote
 */

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

/**
 * Run a comprehensive remote scan against a target host.
 */
export async function runRemoteScan(config: RemoteScanConfig): Promise<ScanResult> {
  const { target, lang, timeout = 5000 } = config;
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
