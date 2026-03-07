/**
 * MemoryScanner - Process memory scanning for fileless malware
 * MemoryScanner - 行程記憶體掃描以偵測無檔案惡意軟體
 *
 * Reads /proc/{pid}/mem and applies YARA-like pattern matching
 * to detect:
 * - Fileless malware (code running only in memory)
 * - Injected shellcode
 * - C2 beacon patterns in process memory
 * - Known malware signatures in memory
 *
 * Linux only, requires CAP_SYS_PTRACE or root.
 *
 * @module @panguard-ai/panguard-guard/monitors/memory-scanner
 */

import { EventEmitter } from 'node:events';
import { readFileSync, readdirSync, openSync, readSync, closeSync } from 'node:fs';
import { platform as osPlatform } from 'node:os';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent, Severity } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:memory-scanner');

let eventCounter = 0;

/**
 * Memory region from /proc/{pid}/maps
 * 來自 /proc/{pid}/maps 的記憶體區域
 */
interface MemoryRegion {
  readonly start: bigint;
  readonly end: bigint;
  readonly perms: string;
  readonly pathname: string;
}

/**
 * Memory scan result for a single process
 * 單一行程的記憶體掃描結果
 */
export interface MemoryScanResult {
  readonly pid: number;
  readonly comm: string;
  readonly matches: readonly MemoryMatch[];
  readonly scannedBytes: number;
  readonly regionsScanned: number;
  readonly timestamp: string;
}

/**
 * Individual pattern match in memory
 * 記憶體中的個別模式比對結果
 */
export interface MemoryMatch {
  readonly pattern: string;
  readonly category: string;
  readonly severity: Severity;
  readonly offset: number;
  readonly regionPerms: string;
  readonly description: string;
}

/**
 * Memory pattern definition for scanning
 * 掃描用的記憶體模式定義
 */
interface MemoryPattern {
  readonly name: string;
  readonly category: string;
  readonly severity: Severity;
  readonly description: string;
  readonly bytes: Buffer;
}

/**
 * Built-in memory patterns for common threats
 * 常見威脅的內建記憶體模式
 *
 * These patterns detect known shellcode sequences, C2 beacon
 * signatures, and common exploit payloads.
 */
const MEMORY_PATTERNS: readonly MemoryPattern[] = [
  // Shellcode patterns / Shellcode 模式
  {
    name: 'linux_x64_execve_shellcode',
    category: 'shellcode',
    severity: 'critical',
    description: 'Linux x86_64 execve /bin/sh shellcode',
    // /bin/sh string followed by syscall instruction
    bytes: Buffer.from([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00]),
  },
  {
    name: 'nop_sled_detector',
    category: 'shellcode',
    severity: 'high',
    description: 'NOP sled (64+ consecutive 0x90 bytes)',
    // 64 NOP instructions - classic shellcode prefix
    bytes: Buffer.alloc(64, 0x90),
  },
  {
    name: 'meterpreter_stage_marker',
    category: 'c2_beacon',
    severity: 'critical',
    description: 'Meterpreter stage loading marker',
    bytes: Buffer.from('metsrv.dll', 'ascii'),
  },
  {
    name: 'cobalt_strike_beacon',
    category: 'c2_beacon',
    severity: 'critical',
    description: 'Cobalt Strike beacon configuration marker',
    bytes: Buffer.from([0x00, 0x01, 0x00, 0x01, 0x00, 0x02]),
  },
  {
    name: 'reverse_shell_python',
    category: 'reverse_shell',
    severity: 'critical',
    description: 'Python reverse shell pattern',
    bytes: Buffer.from('socket.socket(socket.AF_INET', 'ascii'),
  },
  {
    name: 'reverse_shell_bash',
    category: 'reverse_shell',
    severity: 'critical',
    description: 'Bash reverse shell pattern',
    bytes: Buffer.from('/dev/tcp/', 'ascii'),
  },
  {
    name: 'privilege_escalation_suid',
    category: 'privilege_escalation',
    severity: 'high',
    description: 'SUID exploit string in memory',
    bytes: Buffer.from('chmod u+s', 'ascii'),
  },
  {
    name: 'crypto_miner_stratum',
    category: 'cryptomining',
    severity: 'high',
    description: 'Stratum mining protocol marker',
    bytes: Buffer.from('stratum+tcp://', 'ascii'),
  },
  {
    name: 'crypto_miner_xmrig',
    category: 'cryptomining',
    severity: 'high',
    description: 'XMRig miner identification',
    bytes: Buffer.from('XMRig', 'ascii'),
  },
  {
    name: 'ssh_key_exfil',
    category: 'data_exfiltration',
    severity: 'high',
    description: 'SSH private key in process memory',
    bytes: Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----', 'ascii'),
  },
  {
    name: 'aws_credential_exfil',
    category: 'data_exfiltration',
    severity: 'critical',
    description: 'AWS credentials in process memory',
    bytes: Buffer.from('AKIA', 'ascii'), // AWS access key prefix
  },
] as const;

/**
 * Parse /proc/{pid}/maps into memory regions
 * 將 /proc/{pid}/maps 解析為記憶體區域
 */
function parseMemoryMaps(pid: number): readonly MemoryRegion[] {
  try {
    const content = readFileSync(`/proc/${pid}/maps`, 'utf-8');
    const regions: MemoryRegion[] = [];

    for (const line of content.split('\n')) {
      if (!line.trim()) continue;

      const parts = line.trim().split(/\s+/);
      const addrRange = parts[0]!;
      const perms = parts[1] ?? '----';
      const pathname = parts[5] ?? '';

      const [startHex, endHex] = addrRange.split('-');
      if (!startHex || !endHex) continue;

      regions.push({
        start: BigInt('0x' + startHex),
        end: BigInt('0x' + endHex),
        perms,
        pathname,
      });
    }

    return regions;
  } catch {
    return [];
  }
}

/**
 * MemoryScanner scans process memory for malicious patterns
 * MemoryScanner 掃描行程記憶體以偵測惡意模式
 *
 * Usage:
 *   const scanner = new MemoryScanner();
 *   if (await scanner.checkAvailability()) {
 *     scanner.on('event', (event) => processEvent(event));
 *     await scanner.start();
 *   }
 */
export class MemoryScanner extends EventEmitter {
  private running = false;
  private scanTimer: ReturnType<typeof setInterval> | null = null;
  private readonly scanIntervalMs: number;
  private readonly maxRegionSize: number;
  private readonly customPatterns: MemoryPattern[] = [];

  /** PIDs already scanned in current cycle to avoid duplicates / 當前週期已掃描的 PID */
  private readonly scannedPids = new Set<number>();

  constructor(scanIntervalMs = 60_000, maxRegionSizeMB = 10) {
    super();
    this.scanIntervalMs = scanIntervalMs;
    this.maxRegionSize = maxRegionSizeMB * 1024 * 1024;
  }

  /**
   * Check if memory scanning is available
   * 檢查記憶體掃描是否可用
   */
  async checkAvailability(): Promise<boolean> {
    if (osPlatform() !== 'linux') {
      logger.info('Memory scanning not available: requires Linux platform');
      return false;
    }

    // Check if /proc/1/maps is readable (needs ptrace or root)
    // 檢查 /proc/1/maps 是否可讀（需要 ptrace 或 root）
    try {
      readFileSync('/proc/1/maps', 'utf-8');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('EACCES') || msg.includes('permission')) {
        logger.info('Memory scanning not available: requires CAP_SYS_PTRACE or root');
        return false;
      }
    }

    // Check ptrace scope / 檢查 ptrace 範圍
    try {
      const scope = readFileSync('/proc/sys/kernel/yama/ptrace_scope', 'utf-8').trim();
      if (scope === '3') {
        logger.info('Memory scanning not available: ptrace_scope=3 (no ptrace allowed)');
        return false;
      }
      if (scope !== '0' && process.getuid?.() !== 0) {
        logger.info('Memory scanning limited: ptrace_scope=' + scope + ' (may need root for some processes)');
      }
    } catch {
      // ptrace_scope file may not exist on some systems
    }

    logger.info('Memory scanning available');
    return true;
  }

  /**
   * Add a custom memory pattern for scanning
   * 新增自訂記憶體掃描模式
   */
  addPattern(pattern: {
    name: string;
    category: string;
    severity: Severity;
    description: string;
    bytes: Buffer;
  }): void {
    this.customPatterns.push({ ...pattern });
    logger.info(`Custom memory pattern added: ${pattern.name}`);
  }

  /**
   * Start periodic memory scanning / 啟動定期記憶體掃描
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    logger.info(`Memory scanner started (interval: ${this.scanIntervalMs}ms)`);

    // Initial scan / 初始掃描
    this.scanAllProcesses();

    // Periodic scans / 定期掃描
    this.scanTimer = setInterval(() => {
      this.scannedPids.clear();
      this.scanAllProcesses();
    }, this.scanIntervalMs);
  }

  /**
   * Scan all accessible processes / 掃描所有可存取的行程
   */
  private scanAllProcesses(): void {
    try {
      const pids = readdirSync('/proc')
        .filter((d) => /^\d+$/.test(d))
        .map((d) => parseInt(d, 10))
        .filter((pid) => pid > 2 && pid !== process.pid);

      for (const pid of pids) {
        if (this.scannedPids.has(pid)) continue;
        this.scannedPids.add(pid);

        try {
          const result = this.scanProcess(pid);
          if (result && result.matches.length > 0) {
            // Emit a SecurityEvent for each match / 為每個比對結果發出 SecurityEvent
            for (const match of result.matches) {
              const event = this.matchToSecurityEvent(result.pid, result.comm, match);
              this.emit('event', event);
            }
          }
        } catch {
          // Process may not be accessible or may have exited
          continue;
        }
      }
    } catch (err: unknown) {
      logger.warn(
        `Memory scan failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Scan a single process's memory / 掃描單一行程的記憶體
   */
  scanProcess(pid: number): MemoryScanResult | null {
    // Read process name / 讀取程序名稱
    let comm: string;
    try {
      comm = readFileSync(`/proc/${pid}/comm`, 'utf-8').trim();
    } catch {
      return null;
    }

    // Skip kernel threads and known safe processes / 跳過核心執行緒和已知安全程序
    if (['kthreadd', 'kworker', 'rcu_gp', 'rcu_par_gp', 'systemd'].some((s) => comm.startsWith(s))) {
      return null;
    }

    const regions = parseMemoryMaps(pid);
    if (regions.length === 0) return null;

    const matches: MemoryMatch[] = [];
    let scannedBytes = 0;
    let regionsScanned = 0;

    // Get all patterns (built-in + custom) / 取得所有模式（內建 + 自訂）
    const allPatterns = [...MEMORY_PATTERNS, ...this.customPatterns];

    for (const region of regions) {
      // Skip non-readable regions / 跳過不可讀的區域
      if (!region.perms.startsWith('r')) continue;

      // Focus on anonymous memory and executable regions
      // 重點掃描匿名記憶體和可執行區域
      const isAnonymous = region.pathname === '' || region.pathname === '[heap]' || region.pathname === '[stack]';
      const isExecutable = region.perms.includes('x');

      // Only scan anonymous+executable or suspicious regions
      // 僅掃描匿名+可執行或可疑區域
      if (!isAnonymous && !isExecutable) continue;

      const regionSize = Number(region.end - region.start);
      if (regionSize > this.maxRegionSize) continue; // Skip very large regions
      if (regionSize < 64) continue; // Skip tiny regions

      try {
        const fd = openSync(`/proc/${pid}/mem`, 'r');
        try {
          const buffer = Buffer.alloc(Math.min(regionSize, this.maxRegionSize));
          const bytesRead = readSync(fd, buffer, 0, buffer.length, Number(region.start));
          scannedBytes += bytesRead;
          regionsScanned++;

          // Search for patterns in the buffer / 在緩衝區中搜尋模式
          const readBuffer = buffer.subarray(0, bytesRead);
          for (const pattern of allPatterns) {
            const offset = readBuffer.indexOf(pattern.bytes);
            if (offset !== -1) {
              matches.push({
                pattern: pattern.name,
                category: pattern.category,
                severity: pattern.severity,
                offset: Number(region.start) + offset,
                regionPerms: region.perms,
                description: pattern.description,
              });
            }
          }
        } finally {
          closeSync(fd);
        }
      } catch {
        // Memory region may not be readable even with correct perms
        continue;
      }
    }

    return {
      pid,
      comm,
      matches,
      scannedBytes,
      regionsScanned,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Convert a memory match to a SecurityEvent
   * 將記憶體比對結果轉換為 SecurityEvent
   */
  private matchToSecurityEvent(pid: number, comm: string, match: MemoryMatch): SecurityEvent {
    eventCounter++;

    return {
      id: `memscan-${Date.now()}-${eventCounter}`,
      timestamp: new Date(),
      source: 'memory_scanner',
      severity: match.severity,
      category: match.category,
      description:
        `Memory pattern detected: ${match.description} in process ${comm} (PID ${pid}) ` +
        `at offset 0x${match.offset.toString(16)} (region: ${match.regionPerms})`,
      raw: { match, pid, comm },
      host: 'localhost',
      metadata: {
        pid,
        processName: comm,
        patternName: match.pattern,
        patternCategory: match.category,
        memoryOffset: match.offset,
        regionPermissions: match.regionPerms,
      },
    };
  }

  /**
   * Get the count of built-in + custom patterns / 取得內建+自訂模式數量
   */
  getPatternCount(): number {
    return MEMORY_PATTERNS.length + this.customPatterns.length;
  }

  /**
   * Stop memory scanning / 停止記憶體掃描
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = null;
    }

    this.scannedPids.clear();
    logger.info('Memory scanner stopped');
  }

  /**
   * Check if scanning is active / 檢查掃描是否啟用中
   */
  isRunning(): boolean {
    return this.running;
  }
}
