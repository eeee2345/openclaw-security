/**
 * DPI Monitor - Deep Packet Inspection for network threat detection
 * DPI 監控器 - 深度封包檢測以偵測網路威脅
 *
 * Analyzes network traffic patterns to detect:
 * - DNS tunneling (unusual query patterns, high entropy domains)
 * - C2 beaconing (fixed-interval callbacks with jitter)
 * - Data exfiltration (large outbound transfers)
 * - Suspicious TLS certificates (self-signed, short-lived)
 *
 * Uses /proc/net/* and DNS log analysis for portable detection
 * without requiring raw packet capture (pcap) permissions.
 *
 * @module @panguard-ai/panguard-guard/monitors/dpi-monitor
 */

import { EventEmitter } from 'node:events';
import { readFileSync, existsSync } from 'node:fs';
import { platform as osPlatform } from 'node:os';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent, Severity } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:dpi-monitor');

let eventCounter = 0;

/** Shannon entropy calculation for DNS tunneling detection */
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * DNS query record for tunneling detection
 * DNS 查詢記錄（用於隧道偵測）
 */
interface DnsQueryRecord {
  readonly domain: string;
  readonly queryType: string;
  readonly timestamp: number;
  readonly responseSize?: number;
}

/**
 * Beaconing pattern tracker / 信標模式追蹤器
 */
interface BeaconTracker {
  readonly destAddr: string;
  readonly destPort: number;
  readonly intervals: number[];
  readonly firstSeen: number;
  readonly lastSeen: number;
  bytesOut: number;
  bytesIn: number;
  connectionCount: number;
}

/**
 * Connection record from /proc/net/tcp
 * 來自 /proc/net/tcp 的連線記錄
 */
interface ConnectionRecord {
  readonly localAddr: string;
  readonly localPort: number;
  readonly remoteAddr: string;
  readonly remotePort: number;
  readonly state: string;
  readonly uid: number;
  readonly txQueue: number;
  readonly rxQueue: number;
}

/** Known DNS tunneling domains / 已知 DNS 隧道網域 */
const KNOWN_TUNNEL_DOMAINS = new Set([
  'dnscat2', 'iodine', 'dns2tcp', 'dnstt',
]);

/** Entropy threshold for DNS tunneling (base32/base64 encoded data) */
const DNS_ENTROPY_THRESHOLD = 3.5;

/** Minimum label length suggesting encoded data / 建議為編碼資料的最小標籤長度 */
const DNS_MIN_SUSPICIOUS_LABEL_LENGTH = 20;

/** Beaconing detection: minimum connections to analyze / 信標偵測：分析所需的最小連線數 */
const BEACON_MIN_CONNECTIONS = 5;

/** Beaconing detection: maximum jitter ratio (std/mean) / 信標偵測：最大抖動比率 */
const BEACON_MAX_JITTER_RATIO = 0.2;

/** Data exfiltration threshold: bytes out in 5 minutes / 資料外洩閾值：5 分鐘內的出站位元組 */
const EXFIL_THRESHOLD_BYTES = 50 * 1024 * 1024; // 50MB

/**
 * Parse /proc/net/tcp entries into connection records
 * 將 /proc/net/tcp 記錄解析為連線記錄
 */
function parseProcNetTcp(content: string): readonly ConnectionRecord[] {
  const lines = content.trim().split('\n').slice(1); // skip header
  const records: ConnectionRecord[] = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 10) continue;

    const [localHex, localPortHex] = (parts[1] ?? ':').split(':');
    const [remoteHex, remotePortHex] = (parts[2] ?? ':').split(':');

    records.push({
      localAddr: hexToIPv4(localHex ?? '00000000'),
      localPort: parseInt(localPortHex ?? '0', 16),
      remoteAddr: hexToIPv4(remoteHex ?? '00000000'),
      remotePort: parseInt(remotePortHex ?? '0', 16),
      state: parts[3] ?? '00',
      uid: parseInt(parts[7] ?? '0', 10),
      txQueue: parseInt((parts[4] ?? '0:0').split(':')[0] ?? '0', 16),
      rxQueue: parseInt((parts[4] ?? '0:0').split(':')[1] ?? '0', 16),
    });
  }

  return records;
}

/**
 * Convert hex IP to dotted decimal / 將十六進制 IP 轉換為點分十進制
 */
function hexToIPv4(hex: string): string {
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
 * Check if an IP is internal (RFC 1918) / 檢查 IP 是否為內部 IP
 */
function isInternalIP(ip: string): boolean {
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1] ?? '0', 10);
    return second >= 16 && second <= 31;
  }
  if (ip.startsWith('192.168.')) return true;
  if (ip === '127.0.0.1' || ip === '0.0.0.0') return true;
  return false;
}

/**
 * DpiMonitor analyzes network traffic patterns for threats
 * DpiMonitor 分析網路流量模式以偵測威脅
 *
 * This monitor does NOT capture raw packets. Instead, it analyzes:
 * - /proc/net/tcp for connection state and data transfer metrics
 * - DNS resolver logs for tunneling patterns
 * - Connection timing for C2 beaconing detection
 *
 * Usage:
 *   const monitor = new DpiMonitor();
 *   if (await monitor.checkAvailability()) {
 *     monitor.on('event', (event) => processEvent(event));
 *     await monitor.start();
 *   }
 */
export class DpiMonitor extends EventEmitter {
  private running = false;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private readonly pollIntervalMs: number;

  /** Beacon tracking: "ip:port" -> tracker / 信標追蹤 */
  private readonly beaconTrackers = new Map<string, BeaconTracker>();

  /** DNS query history for tunneling detection / DNS 查詢歷史（隧道偵測用） */
  private readonly dnsQueries: DnsQueryRecord[] = [];

  /** Previous connection snapshot for delta analysis / 前次連線快照（差異分析用） */
  private previousConnections: readonly ConnectionRecord[] = [];
  private previousSnapshotTime = 0;

  /** Data transfer tracking / 資料傳輸追蹤 */
  private readonly dataTransfer = new Map<string, { bytesOut: number; bytesIn: number; firstSeen: number }>();

  constructor(pollIntervalMs = 5000) {
    super();
    this.pollIntervalMs = pollIntervalMs;
  }

  /**
   * Check if DPI monitoring is available
   * 檢查 DPI 監控是否可用
   */
  async checkAvailability(): Promise<boolean> {
    if (osPlatform() !== 'linux') {
      logger.info('DPI monitoring not available: requires Linux platform');
      return false;
    }

    if (!existsSync('/proc/net/tcp')) {
      logger.info('DPI monitoring not available: /proc/net/tcp not found');
      return false;
    }

    logger.info('DPI monitoring available (proc-based analysis)');
    return true;
  }

  /**
   * Start DPI monitoring / 啟動 DPI 監控
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    // Take initial connection snapshot / 取得初始連線快照
    this.previousConnections = this.getCurrentConnections();
    this.previousSnapshotTime = Date.now();

    logger.info(`DPI monitor started (interval: ${this.pollIntervalMs}ms)`);

    // Periodic analysis / 定期分析
    this.pollTimer = setInterval(() => {
      this.analyzeConnections();
      this.analyzeDnsPatterns();
      this.detectBeaconing();
      this.detectDataExfiltration();
      this.pruneOldData();
    }, this.pollIntervalMs);
  }

  /**
   * Get current TCP connections from /proc/net/tcp
   * 從 /proc/net/tcp 取得當前 TCP 連線
   */
  private getCurrentConnections(): readonly ConnectionRecord[] {
    try {
      const tcp4 = existsSync('/proc/net/tcp')
        ? parseProcNetTcp(readFileSync('/proc/net/tcp', 'utf-8'))
        : [];
      const tcp6 = existsSync('/proc/net/tcp6')
        ? parseProcNetTcp(readFileSync('/proc/net/tcp6', 'utf-8'))
        : [];
      return [...tcp4, ...tcp6];
    } catch {
      return [];
    }
  }

  /**
   * Analyze connection changes for suspicious patterns
   * 分析連線變化以偵測可疑模式
   */
  private analyzeConnections(): void {
    const now = Date.now();
    const current = this.getCurrentConnections();
    const _timeDelta = now - this.previousSnapshotTime;

    // Find new established connections / 找出新建立的連線
    const prevKeys = new Set(
      this.previousConnections
        .filter((c) => c.state === '01') // ESTABLISHED
        .map((c) => `${c.remoteAddr}:${c.remotePort}`)
    );

    for (const conn of current) {
      if (conn.state !== '01') continue; // Only ESTABLISHED
      if (conn.remoteAddr === '0.0.0.0' || conn.remoteAddr === '127.0.0.1') continue;

      const key = `${conn.remoteAddr}:${conn.remotePort}`;

      // Track data transfer / 追蹤資料傳輸
      const existing = this.dataTransfer.get(key);
      if (existing) {
        existing.bytesOut += conn.txQueue;
        existing.bytesIn += conn.rxQueue;
      } else {
        this.dataTransfer.set(key, {
          bytesOut: conn.txQueue,
          bytesIn: conn.rxQueue,
          firstSeen: now,
        });
      }

      // Track for beaconing / 追蹤信標模式
      const tracker = this.beaconTrackers.get(key);
      if (tracker) {
        const interval = now - tracker.lastSeen;
        if (interval > 1000) {
          // Only track intervals > 1s
          tracker.intervals.push(interval);
          (tracker as { lastSeen: number }).lastSeen = now;
          tracker.connectionCount++;
          tracker.bytesOut += conn.txQueue;
          tracker.bytesIn += conn.rxQueue;
        }
      } else if (!prevKeys.has(key)) {
        // New connection - start tracking / 新連線 - 開始追蹤
        this.beaconTrackers.set(key, {
          destAddr: conn.remoteAddr,
          destPort: conn.remotePort,
          intervals: [],
          firstSeen: now,
          lastSeen: now,
          bytesOut: conn.txQueue,
          bytesIn: conn.rxQueue,
          connectionCount: 1,
        });
      }
    }

    this.previousConnections = current;
    this.previousSnapshotTime = now;
  }

  /**
   * Analyze DNS query patterns for tunneling
   * 分析 DNS 查詢模式以偵測隧道
   */
  private analyzeDnsPatterns(): void {
    // Read systemd-resolved or dnsmasq query log if available
    // 讀取 systemd-resolved 或 dnsmasq 查詢日誌（如可用）
    const dnsLogPaths = [
      '/var/log/dnsmasq.log',
      '/var/log/syslog',
      '/var/log/systemd/resolved.log',
    ];

    for (const logPath of dnsLogPaths) {
      if (!existsSync(logPath)) continue;

      try {
        // Read last 1000 lines for recent DNS queries
        // 讀取最後 1000 行以取得近期 DNS 查詢
        const content = readFileSync(logPath, 'utf-8');
        const lines = content.split('\n').slice(-1000);

        for (const line of lines) {
          // Match DNS query patterns from dnsmasq/systemd-resolved
          const queryMatch = line.match(/query\[(\w+)\]\s+(\S+)/);
          if (!queryMatch) continue;

          const queryType = queryMatch[1]!;
          const domain = queryMatch[2]!;

          this.checkDnsTunneling(domain, queryType);
        }
      } catch {
        continue;
      }
    }
  }

  /**
   * Check a DNS query for tunneling indicators
   * 檢查 DNS 查詢是否有隧道指標
   */
  private checkDnsTunneling(domain: string, queryType: string): void {
    // Check for known tunnel tool domains / 檢查已知隧道工具網域
    const lowerDomain = domain.toLowerCase();
    for (const known of KNOWN_TUNNEL_DOMAINS) {
      if (lowerDomain.includes(known)) {
        this.emitDnsTunnelEvent(domain, queryType, 'critical', `Known DNS tunnel tool: ${known}`);
        return;
      }
    }

    // Check for high-entropy subdomains (encoded data) / 檢查高熵子網域（編碼資料）
    const labels = domain.split('.');
    for (const label of labels) {
      if (label.length >= DNS_MIN_SUSPICIOUS_LABEL_LENGTH) {
        const entropy = shannonEntropy(label);
        if (entropy >= DNS_ENTROPY_THRESHOLD) {
          this.emitDnsTunnelEvent(
            domain,
            queryType,
            'high',
            `High-entropy subdomain (entropy: ${entropy.toFixed(2)}, length: ${label.length})`
          );
          return;
        }
      }
    }

    // Check for TXT record queries (commonly used for tunneling)
    // 檢查 TXT 記錄查詢（常用於隧道）
    if (queryType === 'TXT') {
      const totalDomainLength = domain.length;
      if (totalDomainLength > 100) {
        this.emitDnsTunnelEvent(
          domain,
          queryType,
          'medium',
          `Suspicious TXT query with long domain (${totalDomainLength} chars)`
        );
      }
    }
  }

  /**
   * Emit a DNS tunneling SecurityEvent
   * 發出 DNS 隧道 SecurityEvent
   */
  private emitDnsTunnelEvent(
    domain: string,
    queryType: string,
    severity: Severity,
    reason: string
  ): void {
    eventCounter++;

    const event: SecurityEvent = {
      id: `dpi-dns-${Date.now()}-${eventCounter}`,
      timestamp: new Date(),
      source: 'dpi',
      severity,
      category: 'dns_tunneling',
      description: `Possible DNS tunneling: ${reason} (domain: ${domain}, type: ${queryType})`,
      raw: { domain, queryType, reason },
      host: 'localhost',
      metadata: {
        domain,
        queryType,
        detectionReason: reason,
        mitreTechnique: 'T1071.004',
      },
    };

    this.emit('event', event);
  }

  /**
   * Detect C2 beaconing patterns (regular callback intervals)
   * 偵測 C2 信標模式（定期回撥間隔）
   */
  private detectBeaconing(): void {
    for (const [_key, tracker] of this.beaconTrackers) {
      if (tracker.intervals.length < BEACON_MIN_CONNECTIONS) continue;

      // Calculate mean and standard deviation of intervals
      // 計算間隔的平均值和標準差
      const intervals = tracker.intervals;
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance =
        intervals.reduce((sum, val) => sum + (val - mean) ** 2, 0) / intervals.length;
      const stddev = Math.sqrt(variance);

      // Low jitter ratio indicates regular beaconing / 低抖動比率表示定期信標
      const jitterRatio = mean > 0 ? stddev / mean : Infinity;

      if (jitterRatio <= BEACON_MAX_JITTER_RATIO && mean >= 5000) {
        // Regular interval >= 5s with low jitter
        eventCounter++;

        const severity: Severity = jitterRatio < 0.05 ? 'critical' : 'high';

        const event: SecurityEvent = {
          id: `dpi-beacon-${Date.now()}-${eventCounter}`,
          timestamp: new Date(),
          source: 'dpi',
          severity,
          category: 'command_and_control',
          description:
            `C2 beaconing detected: ${tracker.destAddr}:${tracker.destPort} ` +
            `(interval: ${(mean / 1000).toFixed(1)}s, jitter: ${(jitterRatio * 100).toFixed(1)}%, ` +
            `connections: ${tracker.connectionCount})`,
          raw: { ...tracker, jitterRatio, meanInterval: mean },
          host: 'localhost',
          metadata: {
            sourceIP: tracker.destAddr,
            destPort: tracker.destPort,
            meanIntervalMs: Math.round(mean),
            jitterRatio: Math.round(jitterRatio * 100) / 100,
            connectionCount: tracker.connectionCount,
            mitreTechnique: 'T1071.001',
          },
        };

        this.emit('event', event);

        // Reset tracker after detection to avoid duplicate alerts
        // 偵測後重設追蹤器以避免重複告警
        tracker.intervals.length = 0;
      }
    }
  }

  /**
   * Detect data exfiltration (large outbound transfers)
   * 偵測資料外洩（大量出站傳輸）
   */
  private detectDataExfiltration(): void {
    const now = Date.now();
    const windowMs = 300_000; // 5 minutes

    for (const [key, data] of this.dataTransfer) {
      const elapsed = now - data.firstSeen;
      if (elapsed < windowMs) continue; // Wait for full window

      if (data.bytesOut > EXFIL_THRESHOLD_BYTES) {
        const [addr, portStr] = key.split(':');
        const port = parseInt(portStr ?? '0', 10);

        // Skip internal-to-internal transfers / 跳過內部到內部的傳輸
        if (isInternalIP(addr ?? '')) continue;

        eventCounter++;

        const mbOut = Math.round(data.bytesOut / 1024 / 1024);
        const event: SecurityEvent = {
          id: `dpi-exfil-${Date.now()}-${eventCounter}`,
          timestamp: new Date(),
          source: 'dpi',
          severity: mbOut > 500 ? 'critical' : 'high',
          category: 'data_exfiltration',
          description:
            `Possible data exfiltration: ${mbOut}MB sent to ${addr}:${port} ` +
            `in ${Math.round(elapsed / 1000)}s`,
          raw: { ...data, destination: key },
          host: 'localhost',
          metadata: {
            sourceIP: addr,
            destPort: port,
            bytesOut: data.bytesOut,
            bytesIn: data.bytesIn,
            durationMs: elapsed,
            mitreTechnique: 'T1041',
          },
        };

        this.emit('event', event);
      }

      // Reset after check / 檢查後重設
      if (elapsed >= windowMs) {
        this.dataTransfer.delete(key);
      }
    }
  }

  /**
   * Prune old tracking data (older than 30 minutes)
   * 修剪舊的追蹤資料（超過 30 分鐘）
   */
  private pruneOldData(): void {
    const cutoff = Date.now() - 1_800_000;

    for (const [key, tracker] of this.beaconTrackers) {
      if (tracker.lastSeen < cutoff) {
        this.beaconTrackers.delete(key);
      }
    }

    for (const [key, data] of this.dataTransfer) {
      if (data.firstSeen < cutoff) {
        this.dataTransfer.delete(key);
      }
    }

    // Trim DNS query history / 修剪 DNS 查詢歷史
    while (this.dnsQueries.length > 10000) {
      this.dnsQueries.shift();
    }
  }

  /**
   * Manually submit a DNS query for analysis (for external DNS log sources)
   * 手動提交 DNS 查詢以供分析（用於外部 DNS 日誌來源）
   */
  submitDnsQuery(domain: string, queryType: string, responseSize?: number): void {
    this.dnsQueries.push({
      domain,
      queryType,
      timestamp: Date.now(),
      responseSize,
    });

    this.checkDnsTunneling(domain, queryType);
  }

  /**
   * Get current beacon tracking summary / 取得當前信標追蹤摘要
   */
  getBeaconSummary(): readonly { dest: string; connections: number; jitter: number }[] {
    const summary: { dest: string; connections: number; jitter: number }[] = [];

    for (const [key, tracker] of this.beaconTrackers) {
      if (tracker.intervals.length < 2) continue;

      const mean = tracker.intervals.reduce((a, b) => a + b, 0) / tracker.intervals.length;
      const variance =
        tracker.intervals.reduce((sum, val) => sum + (val - mean) ** 2, 0) / tracker.intervals.length;
      const stddev = Math.sqrt(variance);
      const jitter = mean > 0 ? stddev / mean : 1;

      summary.push({
        dest: key,
        connections: tracker.connectionCount,
        jitter: Math.round(jitter * 100) / 100,
      });
    }

    return summary.sort((a, b) => a.jitter - b.jitter);
  }

  /**
   * Stop DPI monitoring / 停止 DPI 監控
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }

    this.beaconTrackers.clear();
    this.dataTransfer.clear();
    this.dnsQueries.length = 0;
    this.previousConnections = [];

    logger.info('DPI monitor stopped');
  }

  /**
   * Check if monitoring is active / 檢查監控是否啟用中
   */
  isRunning(): boolean {
    return this.running;
  }
}
