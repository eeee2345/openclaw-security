/**
 * Network information scanner
 * 網路資訊掃描器
 *
 * Scans network interfaces, open ports, active connections,
 * gateway, and DNS configuration across macOS, Linux, and Windows.
 * 掃描跨 macOS、Linux 和 Windows 的網路介面、開放埠、活躍連線、閘道和 DNS 配置。
 *
 * @module @panguard-ai/core/discovery/network-scanner
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import dns from 'dns';
import { networkInterfaces as osNetworkInterfaces, platform as osPlatform } from 'os';
import { readFile } from 'fs/promises';
import { createLogger } from '../utils/logger.js';
import type { NetworkInterface, PortInfo, ActiveConnection } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('discovery:network');

/**
 * Safely execute a command and return stdout, or empty string on failure
 * 安全地執行命令並回傳 stdout，失敗時回傳空字串
 *
 * @param cmd - Command to execute / 要執行的命令
 * @param args - Command arguments / 命令參數
 * @returns stdout output trimmed / 修剪後的 stdout 輸出
 */
async function safeExec(cmd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, { timeout: 15_000 });
    return stdout.trim();
  } catch (err) {
    logger.debug(`Command failed: ${cmd} ${args.join(' ')}`, {
      error: err instanceof Error ? err.message : String(err),
    });
    return '';
  }
}

/**
 * Get all network interfaces from the operating system
 * 從作業系統取得所有網路介面
 *
 * Uses Node.js os.networkInterfaces() for cross-platform compatibility.
 * 使用 Node.js os.networkInterfaces() 實現跨平台相容性。
 *
 * @returns Array of detected network interfaces / 偵測到的網路介面陣列
 */
export function getNetworkInterfaces(): NetworkInterface[] {
  const interfaces: NetworkInterface[] = [];

  try {
    const nets = osNetworkInterfaces();

    for (const [name, addrs] of Object.entries(nets)) {
      if (!addrs) continue;

      for (const addr of addrs) {
        if (addr.family === 'IPv4') {
          interfaces.push({
            name,
            ip: addr.address,
            mac: addr.mac,
            netmask: addr.netmask,
            internal: addr.internal,
          });
        }
      }
    }

    logger.info(`Detected ${interfaces.length} network interfaces`);
  } catch (err) {
    logger.error('Failed to enumerate network interfaces', {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  return interfaces;
}

/**
 * Map a well-known port number to its service name
 * 將常見埠號映射到其服務名稱
 *
 * @param port - Port number / 埠號
 * @returns Service name or 'unknown' / 服務名稱或 'unknown'
 */
function mapPortToService(port: number): string {
  const wellKnownPorts: Record<number, string> = {
    20: 'ftp-data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    67: 'dhcp',
    68: 'dhcp',
    80: 'http',
    110: 'pop3',
    119: 'nntp',
    123: 'ntp',
    135: 'msrpc',
    137: 'netbios-ns',
    138: 'netbios-dgm',
    139: 'netbios-ssn',
    143: 'imap',
    161: 'snmp',
    162: 'snmp-trap',
    389: 'ldap',
    443: 'https',
    445: 'microsoft-ds',
    465: 'smtps',
    514: 'syslog',
    587: 'submission',
    636: 'ldaps',
    993: 'imaps',
    995: 'pop3s',
    1433: 'mssql',
    1434: 'mssql-monitor',
    1521: 'oracle',
    3306: 'mysql',
    3389: 'rdp',
    5432: 'postgresql',
    5900: 'vnc',
    6379: 'redis',
    8080: 'http-proxy',
    8443: 'https-alt',
    9200: 'elasticsearch',
    27017: 'mongodb',
  };

  return wellKnownPorts[port] ?? 'unknown';
}

/**
 * Parse macOS lsof output for open/listening ports
 * 解析 macOS lsof 輸出以取得開放/監聽埠
 *
 * @param output - Raw lsof -i -P -n output / 原始 lsof -i -P -n 輸出
 * @returns Parsed port info array / 解析後的埠資訊陣列
 */
function parseLsofOutput(output: string): PortInfo[] {
  const ports: PortInfo[] = [];
  const seen = new Set<string>();
  const lines = output.split('\n').slice(1);

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 9) continue;

    const processName = parts[0] ?? '';
    const pidStr = parts[1] ?? '';
    const pid = parseInt(pidStr, 10);
    const nameField = parts[8] ?? '';

    if (!nameField) continue;

    const portMatch = nameField.match(/:(\d+)$/);
    if (!portMatch) continue;

    const portStr = portMatch[1];
    if (!portStr) continue;
    const port = parseInt(portStr, 10);
    if (isNaN(port)) continue;

    const state = (parts[9] ?? 'LISTEN').replace(/[()]/g, '');
    const protoField = parts[7] ?? '';
    const protocol = protoField.toLowerCase().includes('udp') ? 'udp' : 'tcp';

    const key = `${port}:${protocol}:${state}`;
    if (seen.has(key)) continue;
    seen.add(key);

    ports.push({
      port,
      protocol,
      state,
      pid: isNaN(pid) ? undefined : pid,
      process: processName,
      service: mapPortToService(port),
    });
  }

  return ports;
}

/**
 * Parse Linux ss output for open/listening ports
 * 解析 Linux ss 輸出以取得開放/監聯埠
 *
 * @param output - Raw ss -tlnp output / 原始 ss -tlnp 輸出
 * @returns Parsed port info array / 解析後的埠資訊陣列
 */
function parseSsOutput(output: string): PortInfo[] {
  const ports: PortInfo[] = [];
  const lines = output.split('\n').slice(1);

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;

    const state = parts[0] ?? 'LISTEN';
    const localAddr = parts[3] ?? '';
    if (!localAddr) continue;

    const portMatch = localAddr.match(/:(\d+)$/);
    if (!portMatch) continue;

    const portStr = portMatch[1];
    if (!portStr) continue;
    const port = parseInt(portStr, 10);
    if (isNaN(port)) continue;

    let processName = '';
    let pid: number | undefined;
    const processField = parts.find((p) => p.startsWith('users:'));
    if (processField) {
      const pidMatch = processField.match(/pid=(\d+)/);
      const nameMatch = processField.match(/\("([^"]+)"/);
      if (pidMatch?.[1]) pid = parseInt(pidMatch[1], 10);
      if (nameMatch?.[1]) processName = nameMatch[1];
    }

    ports.push({
      port,
      protocol: 'tcp',
      state,
      pid,
      process: processName,
      service: mapPortToService(port),
    });
  }

  return ports;
}

/**
 * Parse Windows netstat output for open/listening ports
 * 解析 Windows netstat 輸出以取得開放/監聽埠
 *
 * @param output - Raw netstat -an output / 原始 netstat -an 輸出
 * @returns Parsed port info array / 解析後的埠資訊陣列
 */
function parseNetstatPortsOutput(output: string): PortInfo[] {
  const ports: PortInfo[] = [];
  const seen = new Set<string>();
  const lines = output.split('\n');

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;

    const protocol = (parts[0] ?? '').toLowerCase();
    if (protocol !== 'tcp' && protocol !== 'udp') continue;

    const localAddr = parts[1] ?? '';
    const state = parts[3] ?? 'LISTENING';

    if (protocol === 'tcp' && !state.includes('LISTEN')) continue;

    const portMatch = localAddr.match(/:(\d+)$/);
    if (!portMatch) continue;

    const portStr = portMatch[1];
    if (!portStr) continue;
    const port = parseInt(portStr, 10);
    if (isNaN(port)) continue;

    const key = `${port}:${protocol}`;
    if (seen.has(key)) continue;
    seen.add(key);

    ports.push({
      port,
      protocol,
      state,
      pid: undefined,
      process: '',
      service: mapPortToService(port),
    });
  }

  return ports;
}

/**
 * Scan for open/listening ports on the system
 * 掃描系統上的開放/監聽埠
 *
 * @returns Array of detected open ports / 偵測到的開放埠陣列
 */
export async function scanOpenPorts(): Promise<PortInfo[]> {
  const currentPlatform = osPlatform();
  logger.info(`Scanning open ports on ${currentPlatform}`);

  try {
    switch (currentPlatform) {
      case 'darwin': {
        const output = await safeExec('lsof', ['-i', '-P', '-n']);
        if (!output) return [];
        const ports = parseLsofOutput(output);
        logger.info(`Found ${ports.length} open ports via lsof`);
        return ports;
      }
      case 'linux': {
        const output = await safeExec('ss', ['-tlnp']);
        if (!output) return [];
        const ports = parseSsOutput(output);
        logger.info(`Found ${ports.length} open ports via ss`);
        return ports;
      }
      case 'win32': {
        const output = await safeExec('netstat', ['-an']);
        if (!output) return [];
        const ports = parseNetstatPortsOutput(output);
        logger.info(`Found ${ports.length} open ports via netstat`);
        return ports;
      }
      default:
        logger.warn(`Unsupported platform for port scanning: ${currentPlatform}`);
        return [];
    }
  } catch (err) {
    logger.error('Port scanning failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
}

/**
 * Parse an address:port pair from a regex match result
 * 從正規表達式匹配結果解析 address:port 對
 *
 * @param match - Regex match result / 正規表達式匹配結果
 * @returns Parsed address and port, or null / 解析後的位址和埠，或 null
 */
function parseAddrPort(match: RegExpMatchArray | null): { address: string; port: number } | null {
  if (!match) return null;
  const addr = match[1];
  const portStr = match[2];
  if (!addr || !portStr) return null;
  const port = parseInt(portStr, 10);
  if (isNaN(port)) return null;
  return { address: addr, port };
}

/**
 * Get active network connections
 * 取得活躍網路連線
 *
 * Parses netstat or ss output to enumerate established connections.
 * 解析 netstat 或 ss 輸出以列舉已建立的連線。
 *
 * @returns Array of active connections / 活躍連線陣列
 */
export async function getActiveConnections(): Promise<ActiveConnection[]> {
  const currentPlatform = osPlatform();
  const connections: ActiveConnection[] = [];

  logger.info(`Getting active connections on ${currentPlatform}`);

  try {
    let output = '';

    switch (currentPlatform) {
      case 'darwin':
        output = await safeExec('netstat', ['-an', '-p', 'tcp']);
        break;
      case 'linux':
        output = await safeExec('ss', ['-tnp']);
        break;
      case 'win32':
        output = await safeExec('netstat', ['-an']);
        break;
      default:
        logger.warn(`Unsupported platform for connection scanning: ${currentPlatform}`);
        return [];
    }

    if (!output) return [];

    const lines = output.split('\n');
    const validStates = new Set([
      'ESTABLISHED',
      'TIME_WAIT',
      'CLOSE_WAIT',
      'ESTAB',
      'TIME-WAIT',
      'CLOSE-WAIT',
    ]);

    for (const line of lines) {
      const parts = line.trim().split(/\s+/);

      if (currentPlatform === 'darwin') {
        if (parts.length < 6) continue;
        const proto = parts[0] ?? '';
        if (!proto.startsWith('tcp')) continue;
        const state = parts[5] ?? '';
        if (!validStates.has(state)) continue;

        const localStr = parts[3] ?? '';
        const remoteStr = parts[4] ?? '';
        const localParsed = parseAddrPort(localStr.match(/^(.+)\.(\d+)$/));
        const remoteParsed = parseAddrPort(remoteStr.match(/^(.+)\.(\d+)$/));

        if (localParsed && remoteParsed) {
          connections.push({
            localAddress: localParsed.address,
            localPort: localParsed.port,
            remoteAddress: remoteParsed.address,
            remotePort: remoteParsed.port,
            state,
            pid: undefined,
            process: '',
          });
        }
      } else if (currentPlatform === 'linux') {
        if (parts.length < 5) continue;
        const state = parts[0] ?? '';
        if (!validStates.has(state)) continue;

        const localStr = parts[3] ?? '';
        const remoteStr = parts[4] ?? '';
        const localParsed = parseAddrPort(localStr.match(/^(.+):(\d+)$/));
        const remoteParsed = parseAddrPort(remoteStr.match(/^(.+):(\d+)$/));

        let pid: number | undefined;
        let processName = '';
        const processField = parts.find((p) => p.startsWith('users:'));
        if (processField) {
          const pidMatch = processField.match(/pid=(\d+)/);
          const nameMatch = processField.match(/\("([^"]+)"/);
          if (pidMatch?.[1]) pid = parseInt(pidMatch[1], 10);
          if (nameMatch?.[1]) processName = nameMatch[1];
        }

        if (localParsed && remoteParsed) {
          connections.push({
            localAddress: localParsed.address,
            localPort: localParsed.port,
            remoteAddress: remoteParsed.address,
            remotePort: remoteParsed.port,
            state: state === 'ESTAB' ? 'ESTABLISHED' : state,
            pid,
            process: processName,
          });
        }
      } else if (currentPlatform === 'win32') {
        if (parts.length < 4) continue;
        const proto = (parts[0] ?? '').toLowerCase();
        if (!proto.startsWith('tcp')) continue;
        const state = parts[3] ?? '';
        if (!validStates.has(state)) continue;

        const localStr = parts[1] ?? '';
        const remoteStr = parts[2] ?? '';
        const localParsed = parseAddrPort(localStr.match(/^(.+):(\d+)$/));
        const remoteParsed = parseAddrPort(remoteStr.match(/^(.+):(\d+)$/));

        if (localParsed && remoteParsed) {
          connections.push({
            localAddress: localParsed.address,
            localPort: localParsed.port,
            remoteAddress: remoteParsed.address,
            remotePort: remoteParsed.port,
            state,
            pid: undefined,
            process: '',
          });
        }
      }
    }

    logger.info(`Found ${connections.length} active connections`);
  } catch (err) {
    logger.error('Active connection scanning failed', {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  return connections;
}

/**
 * Get the default gateway IP address
 * 取得預設閘道 IP 位址
 *
 * @returns Gateway IP address, or 'unknown' / 閘道 IP 位址，或 'unknown'
 */
export async function getGateway(): Promise<string> {
  const currentPlatform = osPlatform();

  try {
    switch (currentPlatform) {
      case 'darwin': {
        const output = await safeExec('netstat', ['-rn']);
        if (output) {
          for (const line of output.split('\n')) {
            const parts = line.trim().split(/\s+/);
            const dest = parts[0];
            const gw = parts[1];
            if (dest === 'default' && gw) {
              logger.info(`Default gateway: ${gw}`);
              return gw;
            }
          }
        }
        const routeOutput = await safeExec('route', ['-n', 'get', 'default']);
        if (routeOutput) {
          const gwMatch = routeOutput.match(/gateway:\s*(\S+)/);
          const gw = gwMatch?.[1];
          if (gw) {
            logger.info(`Default gateway (via route): ${gw}`);
            return gw;
          }
        }
        break;
      }
      case 'linux': {
        const output = await safeExec('ip', ['route', 'show', 'default']);
        if (output) {
          const match = output.match(/default via (\S+)/);
          const gw = match?.[1];
          if (gw) {
            logger.info(`Default gateway: ${gw}`);
            return gw;
          }
        }
        break;
      }
      case 'win32': {
        const output = await safeExec('netstat', ['-rn']);
        if (output) {
          for (const line of output.split('\n')) {
            const parts = line.trim().split(/\s+/);
            const dest = parts[0];
            const gw = parts[2];
            if (dest === '0.0.0.0' && gw) {
              logger.info(`Default gateway: ${gw}`);
              return gw;
            }
          }
        }
        break;
      }
    }
  } catch (err) {
    logger.error('Gateway detection failed', {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  logger.warn('Could not determine default gateway');
  return 'unknown';
}

/**
 * Get configured DNS server addresses (synchronous, via Node.js dns module)
 * 取得已配置的 DNS 伺服器位址（同步，透過 Node.js dns 模組）
 *
 * @returns Array of DNS server IP addresses / DNS 伺服器 IP 位址陣列
 */
export function getDnsServers(): string[] {
  try {
    const servers: string[] = dns.getServers();
    if (servers.length > 0) {
      logger.info(`DNS servers: ${servers.join(', ')}`);
      return servers;
    }
  } catch {
    // Fallback: empty / 備用：空陣列
  }
  logger.warn('Could not determine DNS servers via Node.js dns module');
  return [];
}

/**
 * Get configured DNS server addresses with platform-specific fallbacks
 * 取得已配置的 DNS 伺服器位址（含平台特定備用方案）
 *
 * @returns Array of DNS server IP addresses / DNS 伺服器 IP 位址陣列
 */
export async function getDnsServersAsync(): Promise<string[]> {
  const syncServers = getDnsServers();
  if (syncServers.length > 0) return syncServers;

  const currentPlatform = osPlatform();

  try {
    switch (currentPlatform) {
      case 'darwin': {
        const output = await safeExec('scutil', ['--dns']);
        if (output) {
          const servers: string[] = [];
          const matches = output.matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g);
          for (const m of matches) {
            const addr = m[1];
            if (addr && !servers.includes(addr)) servers.push(addr);
          }
          if (servers.length > 0) {
            logger.info(`DNS servers (scutil): ${servers.join(', ')}`);
            return servers;
          }
        }
        break;
      }
      case 'linux': {
        try {
          const content = await readFile('/etc/resolv.conf', 'utf-8');
          const servers: string[] = [];
          for (const line of content.split('\n')) {
            const m = line.match(/^nameserver\s+(\S+)/);
            const addr = m?.[1];
            if (addr && !servers.includes(addr)) servers.push(addr);
          }
          if (servers.length > 0) {
            logger.info(`DNS servers (resolv.conf): ${servers.join(', ')}`);
            return servers;
          }
        } catch {
          logger.debug('Could not read /etc/resolv.conf');
        }
        break;
      }
      case 'win32': {
        const output = await safeExec('netsh', ['interface', 'ip', 'show', 'dns']);
        if (output) {
          const servers: string[] = [];
          const matches = output.matchAll(/(\d+\.\d+\.\d+\.\d+)/g);
          for (const m of matches) {
            const addr = m[1];
            if (addr && !servers.includes(addr)) servers.push(addr);
          }
          if (servers.length > 0) {
            logger.info(`DNS servers (netsh): ${servers.join(', ')}`);
            return servers;
          }
        }
        break;
      }
    }
  } catch (err) {
    logger.error('DNS server detection failed', {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  logger.warn('Could not determine DNS servers');
  return [];
}
