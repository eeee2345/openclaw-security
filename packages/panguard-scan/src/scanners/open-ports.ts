/**
 * Unnecessary open ports checker
 * 不必要的開放埠檢查器
 *
 * Analyzes a list of open ports against a known set of risky or unnecessary
 * ports and generates findings for each match.
 * 將開放埠列表與已知的風險或不必要埠集合進行比對，並為每個匹配產生發現。
 *
 * @module @panguard-ai/panguard-scan/scanners/open-ports
 */

import { createLogger, type PortInfo } from '@panguard-ai/core';
import type { Finding } from './types.js';

const logger = createLogger('panguard-scan:open-ports');

/**
 * Map of unnecessary or risky port numbers to their descriptions
 * 不必要或有風險的埠號與其描述的對應表
 *
 * Each entry contains the service name, risk description, and recommended remediation.
 * 每個條目包含服務名稱、風險描述和建議的修復措施。
 */
const UNNECESSARY_PORTS: Map<
  number,
  { name: string; risk: string; remediation: string; manualFix?: string[] }
> = new Map([
  [
    21,
    {
      name: 'FTP',
      risk: 'Unencrypted file transfer',
      remediation: 'Use SFTP instead',
      manualFix: ['sudo ufw deny 21', 'sudo systemctl disable vsftpd'],
    },
  ],
  [
    23,
    {
      name: 'Telnet',
      risk: 'Unencrypted remote access',
      remediation: 'Use SSH instead',
      manualFix: ['sudo ufw deny 23', 'sudo systemctl disable telnetd'],
    },
  ],
  [
    135,
    {
      name: 'MSRPC',
      risk: 'Windows RPC exploitation',
      remediation: 'Block with firewall',
      manualFix: ['sudo ufw deny 135'],
    },
  ],
  [
    139,
    {
      name: 'NetBIOS',
      risk: 'SMB relay attacks',
      remediation: 'Disable NetBIOS over TCP/IP',
      manualFix: ['sudo ufw deny 139'],
    },
  ],
  [
    445,
    {
      name: 'SMB',
      risk: 'EternalBlue and SMB attacks',
      remediation: 'Restrict SMB access',
      manualFix: ['sudo ufw deny 445'],
    },
  ],
  [
    1433,
    {
      name: 'MSSQL',
      risk: 'Database exposure',
      remediation: 'Bind to localhost only',
      manualFix: ['sudo ufw deny 1433'],
    },
  ],
  [
    3306,
    {
      name: 'MySQL',
      risk: 'Database exposure',
      remediation: 'Bind to localhost only',
      manualFix: [
        "sudo sed -i 's/bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf",
        'sudo systemctl restart mysql',
      ],
    },
  ],
  [
    3389,
    {
      name: 'RDP',
      risk: 'Brute force and BlueKeep',
      remediation: 'Use VPN for remote access',
      manualFix: ['sudo ufw deny 3389'],
    },
  ],
  [
    5432,
    {
      name: 'PostgreSQL',
      risk: 'Database exposure',
      remediation: 'Bind to localhost only',
      manualFix: [
        "sudo sed -i \"s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/\" /etc/postgresql/*/main/postgresql.conf",
        'sudo systemctl restart postgresql',
      ],
    },
  ],
  [
    5900,
    {
      name: 'VNC',
      risk: 'Unencrypted remote desktop',
      remediation: 'Use SSH tunnel',
      manualFix: ['sudo ufw deny 5900'],
    },
  ],
  [
    6379,
    {
      name: 'Redis',
      risk: 'Unauthenticated access',
      remediation: 'Enable AUTH and bind to localhost',
      manualFix: [
        "sudo sed -i 's/# requirepass.*/requirepass YOUR_STRONG_PASSWORD/' /etc/redis/redis.conf",
        "sudo sed -i 's/bind .*/bind 127.0.0.1/' /etc/redis/redis.conf",
        'sudo systemctl restart redis',
      ],
    },
  ],
  [
    27017,
    {
      name: 'MongoDB',
      risk: 'Unauthenticated access',
      remediation: 'Enable auth and bind to localhost',
      manualFix: [
        "sudo sed -i 's/bindIp:.*/bindIp: 127.0.0.1/' /etc/mongod.conf",
        'sudo systemctl restart mongod',
      ],
    },
  ],
]);

/**
 * Ports that warrant critical severity due to unencrypted protocols
 * 因未加密協定而需要嚴重等級的埠
 */
const CRITICAL_PORTS = new Set([21, 23]);

/**
 * Check a list of open ports for unnecessary or risky services
 * 檢查開放埠列表中是否有不必要或有風險的服務
 *
 * This is a synchronous function that analyzes existing port data without
 * performing any additional system calls.
 * 這是一個同步函式，分析現有的埠資料而不執行任何額外的系統呼叫。
 *
 * @param ports - Array of open port info from discovery / 來自偵察的開放埠資訊陣列
 * @returns Array of findings for unnecessary ports / 不必要埠的發現陣列
 */
export function checkUnnecessaryPorts(ports: PortInfo[]): Finding[] {
  const findings: Finding[] = [];

  logger.info(`Checking ${ports.length} open ports against unnecessary ports list`);

  for (const portInfo of ports) {
    const unnecessary = UNNECESSARY_PORTS.get(portInfo.port);
    if (!unnecessary) continue;

    const severity = CRITICAL_PORTS.has(portInfo.port) ? 'critical' : 'high';

    const finding: Finding = {
      id: `SCAN-PORT-${portInfo.port}`,
      title:
        `Unnecessary port open: ${portInfo.port}/${portInfo.protocol} (${unnecessary.name}) / ` +
        `不必要的開放埠：${portInfo.port}/${portInfo.protocol} (${unnecessary.name})`,
      description:
        `Port ${portInfo.port} (${unnecessary.name}) is open. ` +
        `Risk: ${unnecessary.risk}. ` +
        `Process: ${portInfo.process || 'unknown'}. / ` +
        `埠 ${portInfo.port} (${unnecessary.name}) 已開放。` +
        `風險：${unnecessary.risk}。` +
        `行程：${portInfo.process || 'unknown'}。`,
      severity,
      category: 'network',
      remediation:
        `${unnecessary.remediation}. ` +
        `If this service is not needed, close port ${portInfo.port} or stop the associated process. / ` +
        `${unnecessary.remediation}。` +
        `如果不需要此服務，請關閉埠 ${portInfo.port} 或停止相關行程。`,
      complianceRef: '4.3',
      details:
        `Port: ${portInfo.port}, Protocol: ${portInfo.protocol}, ` +
        `State: ${portInfo.state}, PID: ${portInfo.pid ?? 'N/A'}, ` +
        `Process: ${portInfo.process || 'N/A'}, Service: ${portInfo.service || 'N/A'}`,
      manualFix: unnecessary.manualFix,
    };

    logger.info(`Found unnecessary port: ${portInfo.port} (${unnecessary.name})`, {
      port: portInfo.port,
      severity,
    });

    findings.push(finding);
  }

  logger.info(`Unnecessary ports check complete: ${findings.length} finding(s)`);
  return findings;
}
