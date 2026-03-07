/**
 * Syscall Monitor - Process and network activity monitoring via /proc polling
 * Syscall 監控器 - 透過 /proc 輪詢實作程序與網路活動監控
 *
 * Provides visibility into system calls without requiring external tools
 * like Falco. Polls /proc to detect:
 * - Process execution (execve/execveat)
 * - File writes to sensitive directories
 * - Network connections to unusual ports
 * - Privilege escalation (setuid/setgid)
 *
 * Linux only with graceful degradation on other platforms.
 *
 * @module @panguard-ai/panguard-guard/monitors/syscall-monitor
 */

import { EventEmitter } from 'node:events';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { platform as osPlatform } from 'node:os';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent, Severity } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:syscall-monitor');

/** Sensitive directories that trigger alerts on write / 寫入時觸發告警的敏感目錄 */
const SENSITIVE_DIRS = [
  '/etc/',
  '/usr/bin/',
  '/usr/sbin/',
  '/usr/local/bin/',
  '/usr/local/sbin/',
  '/boot/',
  '/lib/modules/',
  '/root/',
  '/var/spool/cron/',
] as const;

/** Suspicious process names that always trigger alerts / 始終觸發告警的可疑程序名稱 */
const SUSPICIOUS_PROCESSES = new Set([
  'nc', 'ncat', 'netcat', 'nmap', 'masscan',
  'socat', 'meterpreter', 'mimikatz', 'hydra',
  'john', 'hashcat', 'tcpdump', 'tshark',
  'strace', 'ltrace', 'ptrace', 'gdb',
  'base64', 'xxd',
]);

/** Unusual outbound ports that may indicate C2 / 可能指示 C2 的異常出站端口 */
const SUSPICIOUS_PORTS = new Set([
  4444, 5555, 6666, 1234, 31337, 12345,
  8888, 9999, 4443, 8443, 1337, 6667,
  6697, 9001, 9030, // Tor
]);

/** Normal system ports that should not trigger alerts / 不應觸發告警的正常系統端口 */
const NORMAL_PORTS = new Set([
  22, 53, 80, 443, 993, 995, 587, 25, 110, 143,
  8080, 3306, 5432, 6379, 27017,
]);

let eventCounter = 0;

/**
 * Raw syscall event captured from /proc polling
 * 從 /proc 輪詢擷取的原始 syscall 事件
 */
export interface SyscallEvent {
  readonly syscall: 'execve' | 'write' | 'connect' | 'setuid' | 'setgid' | 'ptrace';
  readonly pid: number;
  readonly uid: number;
  readonly gid: number;
  readonly comm: string;
  readonly timestamp: number;
  readonly args: Record<string, unknown>;
}

/**
 * Determine severity based on syscall type and context
 * 根據 syscall 類型和上下文確定嚴重性
 */
function determineSeverity(event: SyscallEvent): Severity {
  switch (event.syscall) {
    case 'setuid':
    case 'setgid':
      // Privilege escalation is always high severity / 權限提升始終為高嚴重性
      return event.uid === 0 ? 'critical' : 'high';
    case 'ptrace':
      return 'high';
    case 'execve': {
      if (SUSPICIOUS_PROCESSES.has(event.comm)) return 'high';
      // Shell from non-interactive context / 非互動式環境中的 shell
      const parentComm = event.args['parent_comm'] as string | undefined;
      if (
        (event.comm === 'bash' || event.comm === 'sh') &&
        parentComm &&
        !['bash', 'sh', 'zsh', 'fish', 'sshd', 'login', 'su', 'sudo'].includes(parentComm)
      ) {
        return 'high';
      }
      return 'medium';
    }
    case 'write': {
      const path = event.args['path'] as string | undefined;
      if (path && SENSITIVE_DIRS.some((d) => path.startsWith(d))) return 'high';
      return 'medium';
    }
    case 'connect': {
      const port = event.args['port'] as number | undefined;
      if (port && SUSPICIOUS_PORTS.has(port)) return 'high';
      return 'medium';
    }
    default:
      return 'medium';
  }
}

/**
 * Map syscall to security event category
 * 將 syscall 映射到安全事件類別
 */
function mapCategory(event: SyscallEvent): string {
  switch (event.syscall) {
    case 'execve':
      return SUSPICIOUS_PROCESSES.has(event.comm) ? 'suspicious_execution' : 'process_execution';
    case 'write':
      return 'file_modification';
    case 'connect':
      return 'network_activity';
    case 'setuid':
    case 'setgid':
      return 'privilege_escalation';
    case 'ptrace':
      return 'process_injection';
    default:
      return 'unknown';
  }
}

/**
 * Convert a syscall event to a Panguard SecurityEvent
 * 將 syscall 事件轉換為 Panguard SecurityEvent
 */
export function parseSyscallEvent(raw: SyscallEvent): SecurityEvent {
  eventCounter++;

  const severity = determineSeverity(raw);
  const category = mapCategory(raw);

  let description: string;
  switch (raw.syscall) {
    case 'execve':
      description = `Process executed: ${raw.comm} (PID ${raw.pid}, UID ${raw.uid})`;
      break;
    case 'write':
      description = `File write to sensitive path: ${raw.args['path'] ?? 'unknown'} by ${raw.comm} (PID ${raw.pid})`;
      break;
    case 'connect':
      description = `Outbound connection: ${raw.comm} -> ${raw.args['addr'] ?? 'unknown'}:${raw.args['port'] ?? '?'} (PID ${raw.pid})`;
      break;
    case 'setuid':
    case 'setgid':
      description = `Privilege escalation: ${raw.comm} called ${raw.syscall}(${raw.args['target_id'] ?? '?'}) (PID ${raw.pid})`;
      break;
    case 'ptrace':
      description = `Process injection: ${raw.comm} ptrace on PID ${raw.args['target_pid'] ?? '?'}`;
      break;
    default:
      description = `Syscall: ${raw.syscall} by ${raw.comm} (PID ${raw.pid})`;
  }

  return {
    id: `syscall-${Date.now()}-${eventCounter}`,
    timestamp: new Date(raw.timestamp),
    source: 'syscall',
    severity,
    category,
    description,
    raw,
    host: 'localhost',
    metadata: {
      syscall: raw.syscall,
      pid: raw.pid,
      uid: raw.uid,
      gid: raw.gid,
      processName: raw.comm,
      ...raw.args,
    },
  };
}

/**
 * Check Linux kernel version >= 4.18 for /proc-based monitoring
 * 檢查 Linux 核心版本 >= 4.18 以支援基於 /proc 的監控
 */
function checkKernelVersion(): boolean {
  try {
    const release = readFileSync('/proc/version', 'utf-8');
    const match = release.match(/(\d+)\.(\d+)/);
    if (!match) return false;
    const major = parseInt(match[1]!, 10);
    const minor = parseInt(match[2]!, 10);
    return major > 4 || (major === 4 && minor >= 18);
  } catch {
    return false;
  }
}

/**
 * Syscall Monitor provides process and network activity monitoring via /proc polling
 * Syscall 監控器透過 /proc 輪詢提供程序與網路活動監控
 *
 * On Linux systems (4.18+, root or CAP_BPF), this monitor polls /proc
 * for suspicious process execution, privilege escalation, and network
 * connections, emitting SecurityEvent objects for each finding.
 *
 * Falls back gracefully on non-Linux platforms or older kernels.
 *
 * Usage:
 *   const monitor = new SyscallMonitor();
 *   if (await monitor.checkAvailability()) {
 *     monitor.on('event', (event) => processEvent(event));
 *     await monitor.start();
 *   }
 */
export class SyscallMonitor extends EventEmitter {
  private running = false;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private readonly pollIntervalMs: number;

  /** Tracking state for connection pattern detection / 連線模式偵測的追蹤狀態 */
  private readonly recentConnections = new Map<string, { count: number; firstSeen: number }>();

  constructor(pollIntervalMs = 2000) {
    super();
    this.pollIntervalMs = pollIntervalMs;
  }

  /**
   * Check if syscall monitoring is available
   * 檢查 syscall 監控是否可用
   *
   * Requirements:
   * - Linux platform
   * - Kernel >= 4.18
   * - /sys/kernel/debug/tracing available (or tracefs mounted)
   * - Root or CAP_BPF capability
   */
  async checkAvailability(): Promise<boolean> {
    // Platform check / 平台檢查
    if (osPlatform() !== 'linux') {
      logger.info('Syscall monitoring not available: requires Linux platform');
      return false;
    }

    // Kernel version check / 核心版本檢查
    if (!checkKernelVersion()) {
      logger.info('Syscall monitoring not available: requires Linux kernel >= 4.18');
      return false;
    }

    // Check for tracefs / 檢查 tracefs
    const tracingAvailable =
      existsSync('/sys/kernel/debug/tracing') ||
      existsSync('/sys/kernel/tracing');

    if (!tracingAvailable) {
      logger.info('Syscall monitoring not available: tracefs not mounted');
      return false;
    }

    // Check for BPF support via /proc filesystem
    // 透過 /proc 檢查 BPF 支援
    const hasBpf = existsSync('/proc/sys/kernel/unprivileged_bpf_disabled') ||
      existsSync('/sys/fs/bpf');

    if (!hasBpf) {
      logger.info('Syscall monitoring not available: BPF not enabled in kernel');
      return false;
    }

    // Check capabilities (need root or CAP_BPF) / 檢查權限
    const uid = process.getuid?.() ?? -1;
    if (uid !== 0) {
      // Check for CAP_BPF via /proc/self/status
      try {
        const status = readFileSync('/proc/self/status', 'utf-8');
        const capLine = status.split('\n').find((l) => l.startsWith('CapEff:'));
        if (!capLine) {
          logger.info('Syscall monitoring not available: cannot read capabilities');
          return false;
        }
        // CAP_BPF is bit 39, CAP_PERFMON is bit 38
        // Check if these bits are set in the effective capabilities hex
        const capHex = capLine.split(':')[1]?.trim() ?? '0';
        const capBigInt = BigInt('0x' + capHex);
        const hasBpfCap = (capBigInt & (1n << 39n)) !== 0n;
        const hasPerfmon = (capBigInt & (1n << 38n)) !== 0n;

        if (!hasBpfCap && !hasPerfmon) {
          logger.info('Syscall monitoring not available: requires root or CAP_BPF');
          return false;
        }
      } catch {
        logger.info('Syscall monitoring not available: cannot verify capabilities');
        return false;
      }
    }

    logger.info('Syscall monitoring available: Linux kernel with BPF support detected');
    return true;
  }

  /**
   * Start syscall monitoring by polling /proc for suspicious activity
   * 透過輪詢 /proc 啟動 syscall 監控以偵測可疑活動
   *
   * This implementation uses /proc polling as a portable baseline.
   * When native eBPF bindings are available, this can be upgraded
   * to real-time tracepoint monitoring.
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    logger.info('Syscall monitor started (proc-polling mode)');

    // Initial scan of current processes / 初始掃描當前程序
    this.scanProcesses();

    // Periodic process scan / 定期程序掃描
    this.pollTimer = setInterval(() => {
      this.scanProcesses();
      this.scanNetworkConnections();
      this.pruneConnectionTracker();
    }, this.pollIntervalMs);
  }

  /**
   * Scan /proc for suspicious process activity
   * 掃描 /proc 以偵測可疑程序活動
   */
  private scanProcesses(): void {
    try {
      const procDirs = readdirSync('/proc').filter((d) => /^\d+$/.test(d));

      for (const pidStr of procDirs) {
        const pid = parseInt(pidStr, 10);
        if (isNaN(pid) || pid <= 2) continue; // skip kernel threads

        try {
          // Read process comm and cmdline / 讀取程序名稱和命令列
          const comm = readFileSync(`/proc/${pid}/comm`, 'utf-8').trim();
          const statusContent = readFileSync(`/proc/${pid}/status`, 'utf-8');

          // Extract UID from status / 從 status 提取 UID
          const uidLine = statusContent.split('\n').find((l) => l.startsWith('Uid:'));
          const gidLine = statusContent.split('\n').find((l) => l.startsWith('Gid:'));
          const uid = parseInt(uidLine?.split('\t')[1] ?? '0', 10);
          const gid = parseInt(gidLine?.split('\t')[1] ?? '0', 10);

          // Check for suspicious process names / 檢查可疑程序名稱
          if (SUSPICIOUS_PROCESSES.has(comm)) {
            const event: SyscallEvent = {
              syscall: 'execve',
              pid,
              uid,
              gid,
              comm,
              timestamp: Date.now(),
              args: { parent_comm: this.getParentComm(pid) },
            };
            this.emit('event', parseSyscallEvent(event));
          }

          // Check for setuid processes (EUID != RUID) / 檢查 setuid 程序
          const euid = parseInt(uidLine?.split('\t')[2] ?? '0', 10);
          if (euid === 0 && uid !== 0) {
            const event: SyscallEvent = {
              syscall: 'setuid',
              pid,
              uid,
              gid,
              comm,
              timestamp: Date.now(),
              args: { target_id: 0, original_uid: uid },
            };
            this.emit('event', parseSyscallEvent(event));
          }
        } catch {
          // Process may have exited between readdir and read / 程序可能在讀取之間退出
          continue;
        }
      }
    } catch (err: unknown) {
      logger.warn(
        `Process scan failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Scan network connections for suspicious activity
   * 掃描網路連線以偵測可疑活動
   */
  private scanNetworkConnections(): void {
    try {
      // Read /proc/net/tcp and /proc/net/tcp6 for established connections
      // 讀取 /proc/net/tcp 和 /proc/net/tcp6 以取得已建立的連線
      for (const netFile of ['/proc/net/tcp', '/proc/net/tcp6']) {
        if (!existsSync(netFile)) continue;

        const content = readFileSync(netFile, 'utf-8');
        const lines = content.trim().split('\n').slice(1); // skip header

        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length < 4) continue;

          // State 01 = ESTABLISHED / 狀態 01 = 已建立
          const state = parts[3];
          if (state !== '01') continue;

          // Parse remote address and port / 解析遠端地址和端口
          const remoteAddr = parts[2]!;
          const [remoteHex, portHex] = remoteAddr.split(':');
          if (!remoteHex || !portHex) continue;

          const port = parseInt(portHex, 16);
          const uid = parseInt(parts[7] ?? '0', 10);

          // Skip normal ports and local connections / 跳過正常端口和本地連線
          if (NORMAL_PORTS.has(port)) continue;
          if (remoteHex === '00000000' || remoteHex === '0100007F') continue;

          // Parse IP from hex / 從十六進制解析 IP
          const ip = this.hexToIPv4(remoteHex);

          // Track connection frequency / 追蹤連線頻率
          const key = `${ip}:${port}`;
          const existing = this.recentConnections.get(key);
          if (existing) {
            existing.count++;
          } else {
            this.recentConnections.set(key, { count: 1, firstSeen: Date.now() });
          }

          // Only alert on suspicious ports / 僅對可疑端口發出告警
          if (SUSPICIOUS_PORTS.has(port)) {
            const inode = parts[9] ?? '';
            const comm = this.getCommByInode(inode);

            const event: SyscallEvent = {
              syscall: 'connect',
              pid: 0, // PID resolution requires inode lookup
              uid,
              gid: 0,
              comm: comm ?? 'unknown',
              timestamp: Date.now(),
              args: { addr: ip, port },
            };
            this.emit('event', parseSyscallEvent(event));
          }
        }
      }
    } catch (err: unknown) {
      logger.warn(
        `Network scan failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Convert hex IP to dotted decimal / 將十六進制 IP 轉換為點分十進制
   */
  private hexToIPv4(hex: string): string {
    if (hex.length !== 8) return hex;
    const num = parseInt(hex, 16);
    return [
      num & 0xff,
      (num >> 8) & 0xff,
      (num >> 16) & 0xff,
      (num >> 24) & 0xff,
    ].join('.');
  }

  /**
   * Get parent process comm name / 取得父程序名稱
   */
  private getParentComm(pid: number): string | undefined {
    try {
      const status = readFileSync(`/proc/${pid}/status`, 'utf-8');
      const ppidLine = status.split('\n').find((l) => l.startsWith('PPid:'));
      const ppid = parseInt(ppidLine?.split('\t')[1] ?? '0', 10);
      if (ppid <= 1) return undefined;
      return readFileSync(`/proc/${ppid}/comm`, 'utf-8').trim();
    } catch {
      return undefined;
    }
  }

  /**
   * Get process command by socket inode (best-effort) / 透過 socket inode 取得程序命令
   */
  private getCommByInode(inode: string): string | undefined {
    if (!inode || inode === '0') return undefined;
    try {
      const procDirs = readdirSync('/proc').filter((d) => /^\d+$/.test(d));
      for (const pidStr of procDirs.slice(0, 100)) {
        // Limit search to avoid performance issues
        try {
          const fdDir = `/proc/${pidStr}/fd`;
          if (!existsSync(fdDir)) continue;
          const fds = readdirSync(fdDir);
          for (const fd of fds) {
            try {
              const link = readFileSync(`/proc/${pidStr}/fd/${fd}`, 'utf-8');
              if (link.includes(`socket:[${inode}]`)) {
                return readFileSync(`/proc/${pidStr}/comm`, 'utf-8').trim();
              }
            } catch {
              continue;
            }
          }
        } catch {
          continue;
        }
      }
    } catch {
      // Fallthrough
    }
    return undefined;
  }

  /**
   * Prune old connection tracking entries (older than 5 minutes)
   * 修剪舊的連線追蹤記錄（超過 5 分鐘）
   */
  private pruneConnectionTracker(): void {
    const cutoff = Date.now() - 300_000;
    for (const [key, val] of this.recentConnections) {
      if (val.firstSeen < cutoff) {
        this.recentConnections.delete(key);
      }
    }
  }

  /**
   * Stop syscall monitoring / 停止 syscall 監控
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }

    this.recentConnections.clear();
    logger.info('Syscall monitor stopped');
  }

  /**
   * Check if monitoring is active / 檢查監控是否啟用中
   */
  isRunning(): boolean {
    return this.running;
  }
}
