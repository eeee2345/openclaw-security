/**
 * Remote port scanner using TCP connect.
 * @module @panguard-ai/panguard-scan/scanners/remote/port-scanner
 */

import { createConnection } from 'node:net';
import type { Finding } from '../types.js';
import type { Language } from '@panguard-ai/core';

/** Common ports to check */
const TARGET_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 27017];

/** Service names by port */
const PORT_SERVICES: Record<number, string> = {
  22: 'SSH',
  80: 'HTTP',
  443: 'HTTPS',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  27017: 'MongoDB',
};

interface PortResult {
  port: number;
  open: boolean;
  service: string;
}

/**
 * Check if a single port is open on the target.
 */
function checkPort(host: string, port: number, timeout: number): Promise<PortResult> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port, timeout }, () => {
      socket.destroy();
      resolve({ port, open: true, service: PORT_SERVICES[port] ?? 'unknown' });
    });
    socket.on('error', () => {
      socket.destroy();
      resolve({ port, open: false, service: PORT_SERVICES[port] ?? 'unknown' });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, open: false, service: PORT_SERVICES[port] ?? 'unknown' });
    });
  });
}

/**
 * Scan common ports on a remote target.
 */
export async function scanPorts(
  host: string,
  lang: Language,
  timeout = 3000
): Promise<{ findings: Finding[]; openPorts: PortResult[] }> {
  const results = await Promise.all(TARGET_PORTS.map((port) => checkPort(host, port, timeout)));

  const openPorts = results.filter((r) => r.open);
  const findings: Finding[] = [];

  // Flag potentially dangerous open services
  const dangerous = openPorts.filter((p) => [6379, 27017, 3306, 5432].includes(p.port));

  for (const p of dangerous) {
    findings.push({
      id: `remote-port-${p.port}`,
      title:
        lang === 'zh-TW'
          ? `${p.service} (port ${p.port}) \u5C0D\u5916\u958B\u653E`
          : `${p.service} (port ${p.port}) is publicly accessible`,
      description:
        lang === 'zh-TW'
          ? `\u8CC7\u6599\u5EAB\u670D\u52D9 ${p.service} \u4E0D\u61C9\u5C0D\u5916\u958B\u653E`
          : `Database service ${p.service} should not be publicly accessible`,
      severity: 'high',
      category: 'network',
      remediation:
        lang === 'zh-TW'
          ? `\u7528\u9632\u706B\u7246\u9650\u5236 port ${p.port} \u5B58\u53D6`
          : `Restrict access to port ${p.port} using firewall rules`,
    });
  }

  return { findings, openPorts };
}
