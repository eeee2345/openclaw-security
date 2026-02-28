/**
 * Threat Intelligence Feed Manager - Real-time threat feeds integration
 * 威脅情報饋送管理器 - 即時威脅情報整合
 *
 * Integrates with free, open-source threat intelligence feeds:
 * - abuse.ch ThreatFox (malware IoCs)
 * - abuse.ch URLhaus (malicious URLs)
 * - abuse.ch Feodo Tracker (banking trojan C2)
 * - GreyNoise Community API (internet scanners)
 *
 * All feeds are free and require no registration (except AbuseIPDB which is optional).
 *
 * @module @panguard-ai/core/monitor/threat-intel-feeds
 */

import { createLogger } from '../utils/logger.js';
import type { ThreatIntelEntry } from './types.js';

const logger = createLogger('threat-intel-feeds');

/** Feed source identifier / 情報源識別 */
export type FeedSource = 'threatfox' | 'urlhaus' | 'feodotracker' | 'greynoise' | 'abuseipdb';

/** Individual IoC (Indicator of Compromise) / 入侵指標 */
export interface IoC {
  type: 'ip' | 'url' | 'domain' | 'hash';
  value: string;
  threatType: string;
  source: FeedSource;
  confidence: number; // 0-100
  firstSeen?: string;
  lastSeen?: string;
  tags: string[];
  reference?: string;
}

/** Feed update result / 情報更新結果 */
export interface FeedUpdateResult {
  source: FeedSource;
  success: boolean;
  iocCount: number;
  durationMs: number;
  error?: string;
}

/** Feed manager configuration / 情報管理器設定 */
export interface FeedManagerConfig {
  /** Update interval in ms (default 1 hour) / 更新間隔 */
  updateIntervalMs: number;
  /** Maximum IoCs to keep in memory / 記憶體中最大 IoC 數量 */
  maxIoCs: number;
  /** Optional AbuseIPDB API key / 可選的 AbuseIPDB API key */
  abuseIPDBKey?: string;
  /** Enable/disable specific feeds / 啟用/停用特定情報源 */
  enabledFeeds: FeedSource[];
  /** Request timeout in ms / 請求逾時 */
  requestTimeoutMs: number;
}

const DEFAULT_CONFIG: FeedManagerConfig = {
  updateIntervalMs: 60 * 60 * 1000, // 1 hour
  maxIoCs: 50000,
  enabledFeeds: ['threatfox', 'urlhaus', 'feodotracker', 'greynoise'],
  requestTimeoutMs: 30000,
};

/**
 * Manages real-time threat intelligence feeds
 * 管理即時威脅情報饋送
 */
export class ThreatIntelFeedManager {
  private readonly config: FeedManagerConfig;
  private iocs: Map<string, IoC> = new Map();
  private ipIndex: Map<string, IoC> = new Map(); // Fast IP lookup
  private updateTimer?: ReturnType<typeof setInterval>;
  private lastUpdate: Map<FeedSource, string> = new Map();

  constructor(config: Partial<FeedManagerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    if (config.abuseIPDBKey && !this.config.enabledFeeds.includes('abuseipdb')) {
      this.config.enabledFeeds.push('abuseipdb');
    }
  }

  /**
   * Start periodic feed updates / 開始定期更新情報
   */
  async start(): Promise<void> {
    await this.updateAll();
    this.updateTimer = setInterval(() => {
      void this.updateAll();
    }, this.config.updateIntervalMs);
    if (this.updateTimer.unref) this.updateTimer.unref();
    logger.info(
      `Feed manager started. Update interval: ${Math.round(this.config.updateIntervalMs / 60000)} min`
    );
  }

  /** Stop periodic updates / 停止定期更新 */
  stop(): void {
    if (this.updateTimer) {
      clearInterval(this.updateTimer);
      this.updateTimer = undefined;
    }
  }

  /**
   * Update all enabled feeds / 更新所有啟用的情報源
   */
  async updateAll(): Promise<FeedUpdateResult[]> {
    const results: FeedUpdateResult[] = [];

    for (const source of this.config.enabledFeeds) {
      const result = await this.updateFeed(source);
      results.push(result);
    }

    // Trim if over max
    if (this.iocs.size > this.config.maxIoCs) {
      this.trimOldest();
    }

    logger.info(
      `Feed update complete. Total IoCs: ${this.iocs.size}, IPs indexed: ${this.ipIndex.size}`
    );
    return results;
  }

  /**
   * Check if an IP is in threat intel / 檢查 IP 是否在威脅情報中
   */
  checkIP(ip: string): IoC | undefined {
    return this.ipIndex.get(ip);
  }

  /**
   * Search IoCs by value / 以值搜尋 IoC
   */
  search(value: string): IoC | undefined {
    return this.iocs.get(value);
  }

  /** Get total IoC count / 取得 IoC 總數 */
  getIoCCount(): number {
    return this.iocs.size;
  }

  /** Get IP index count / 取得 IP 索引數 */
  getIPCount(): number {
    return this.ipIndex.size;
  }

  /** Get last update times / 取得最後更新時間 */
  getLastUpdateTimes(): Map<FeedSource, string> {
    return new Map(this.lastUpdate);
  }

  /**
   * Convert IoC to ThreatIntelEntry for compatibility with existing system
   * 轉換 IoC 為 ThreatIntelEntry 以相容現有系統
   */
  toThreatIntelEntry(ioc: IoC): ThreatIntelEntry | null {
    if (ioc.type !== 'ip') return null;
    const threatType = ioc.threatType.includes('c2')
      ? ('c2' as const)
      : ioc.threatType.includes('scan')
        ? ('scanner' as const)
        : ioc.threatType.includes('botnet')
          ? ('botnet' as const)
          : ('malware' as const);

    return {
      ip: ioc.value,
      type: threatType,
      source: ioc.source,
      lastSeen: ioc.lastSeen,
    };
  }

  /**
   * Add external IPs to the threat intel index (e.g., from Threat Cloud blocklist).
   * 將外部 IP 加入威脅情報索引（例如來自 Threat Cloud 封鎖清單）。
   *
   * @param ips - Array of IPs to add / 要加入的 IP 陣列
   * @param threatType - Threat classification / 威脅分類
   * @param confidence - Confidence score (0-100) / 信心分數
   * @returns Number of IPs added / 新增的 IP 數量
   */
  addExternalIPs(
    ips: string[],
    threatType: string = 'blocklisted',
    confidence: number = 80
  ): number {
    let added = 0;
    const now = new Date().toISOString();

    for (const ip of ips) {
      const trimmed = ip.trim();
      if (!trimmed || !/^[\d.]+$/.test(trimmed)) continue;

      const ioc: IoC = {
        type: 'ip',
        value: trimmed,
        threatType,
        source: 'threatfox', // Use existing FeedSource for compatibility
        confidence,
        lastSeen: now,
        tags: ['threat-cloud-blocklist'],
      };
      this.addIoC(ioc);
      added++;
    }

    if (added > 0) {
      logger.info(`Added ${added} external IPs to threat intel / 已加入 ${added} 個外部 IP`);
    }
    return added;
  }

  /** Get all IP-based IoCs as ThreatIntelEntry array / 取得所有 IP IoC 為 ThreatIntelEntry 陣列 */
  getAllIPEntries(): ThreatIntelEntry[] {
    const entries: ThreatIntelEntry[] = [];
    for (const ioc of this.ipIndex.values()) {
      const entry = this.toThreatIntelEntry(ioc);
      if (entry) entries.push(entry);
    }
    return entries;
  }

  // -- Feed-specific updaters --

  private async updateFeed(source: FeedSource): Promise<FeedUpdateResult> {
    const start = Date.now();
    try {
      let count = 0;
      switch (source) {
        case 'threatfox':
          count = await this.fetchThreatFox();
          break;
        case 'urlhaus':
          count = await this.fetchURLhaus();
          break;
        case 'feodotracker':
          count = await this.fetchFeodoTracker();
          break;
        case 'greynoise':
          count = await this.fetchGreyNoise();
          break;
        case 'abuseipdb':
          count = await this.fetchAbuseIPDB();
          break;
      }
      this.lastUpdate.set(source, new Date().toISOString());
      return { source, success: true, iocCount: count, durationMs: Date.now() - start };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Feed update failed [${source}]: ${msg}`);
      return { source, success: false, iocCount: 0, durationMs: Date.now() - start, error: msg };
    }
  }

  /**
   * abuse.ch ThreatFox - Recent IoCs
   * https://threatfox.abuse.ch/api/
   */
  private async fetchThreatFox(): Promise<number> {
    const res = await fetchWithTimeout(
      'https://threatfox-api.abuse.ch/api/v1/',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_iocs', days: 1 }),
      },
      this.config.requestTimeoutMs
    );

    const data = (await res.json()) as {
      query_status: string;
      data?: Array<{
        ioc: string;
        ioc_type: string;
        threat_type: string;
        malware: string;
        confidence_level: number;
        first_seen_utc: string;
        last_seen_utc: string;
        tags: string[] | null;
        reference: string;
      }>;
    };
    if (data.query_status !== 'ok' || !data.data) return 0;

    let count = 0;
    for (const item of data.data) {
      const type =
        item.ioc_type === 'ip:port'
          ? ('ip' as const)
          : item.ioc_type === 'url'
            ? ('url' as const)
            : item.ioc_type === 'domain'
              ? ('domain' as const)
              : ('hash' as const);

      const value = type === 'ip' ? (item.ioc.split(':')[0] ?? item.ioc) : item.ioc;

      const ioc: IoC = {
        type,
        value,
        threatType: `${item.threat_type}:${item.malware}`,
        source: 'threatfox',
        confidence: item.confidence_level,
        firstSeen: item.first_seen_utc,
        lastSeen: item.last_seen_utc,
        tags: item.tags ?? [],
        reference: item.reference,
      };
      this.addIoC(ioc);
      count++;
    }
    return count;
  }

  /**
   * abuse.ch URLhaus - Recent malicious URLs (last 24h)
   * https://urlhaus-api.abuse.ch/v1/
   */
  private async fetchURLhaus(): Promise<number> {
    const res = await fetchWithTimeout(
      'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/',
      {
        method: 'GET',
      },
      this.config.requestTimeoutMs
    );

    const data = (await res.json()) as {
      urls?: Array<{
        url: string;
        url_status: string;
        threat: string;
        host: string;
        date_added: string;
        tags: string[] | null;
      }>;
    };
    if (!data.urls) return 0;

    let count = 0;
    for (const item of data.urls) {
      // Extract IP from host if possible
      if (/^[\d.]+$/.test(item.host)) {
        const ioc: IoC = {
          type: 'ip',
          value: item.host,
          threatType: `malware_distribution:${item.threat}`,
          source: 'urlhaus',
          confidence: item.url_status === 'online' ? 90 : 50,
          firstSeen: item.date_added,
          tags: item.tags ?? [],
        };
        this.addIoC(ioc);
      }

      const urlIoc: IoC = {
        type: 'url',
        value: item.url,
        threatType: `malware_distribution:${item.threat}`,
        source: 'urlhaus',
        confidence: item.url_status === 'online' ? 90 : 50,
        firstSeen: item.date_added,
        tags: item.tags ?? [],
      };
      this.addIoC(urlIoc);
      count++;
    }
    return count;
  }

  /**
   * abuse.ch Feodo Tracker - Banking trojan C2 servers
   * https://feodotracker.abuse.ch/
   */
  private async fetchFeodoTracker(): Promise<number> {
    const res = await fetchWithTimeout(
      'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
      {
        method: 'GET',
      },
      this.config.requestTimeoutMs
    );

    const data = (await res.json()) as Array<{
      ip_address: string;
      port: number;
      status: string;
      hostname: string;
      as_number: number;
      as_name: string;
      country: string;
      first_seen: string;
      last_online: string;
      malware: string;
    }>;
    if (!Array.isArray(data)) return 0;

    let count = 0;
    for (const item of data) {
      const ioc: IoC = {
        type: 'ip',
        value: item.ip_address,
        threatType: `c2:${item.malware}`,
        source: 'feodotracker',
        confidence: item.status === 'online' ? 95 : 70,
        firstSeen: item.first_seen,
        lastSeen: item.last_online,
        tags: [item.malware, item.country, `AS${item.as_number}`].filter(Boolean),
      };
      this.addIoC(ioc);
      count++;
    }
    return count;
  }

  /**
   * GreyNoise Community API - Internet background noise / scanners
   * Free, no API key required for RIOT endpoint
   */
  private async fetchGreyNoise(): Promise<number> {
    // GreyNoise doesn't have a bulk free endpoint, so we use their
    // popular scanner list which is publicly available
    const res = await fetchWithTimeout(
      'https://api.greynoise.io/v3/community/1.1.1.1',
      {
        method: 'GET',
        headers: { Accept: 'application/json' },
      },
      this.config.requestTimeoutMs
    );

    // For the free tier, we just validate the API is reachable
    // and note that individual IP checks should use checkIPWithGreyNoise()
    if (res.ok) {
      logger.info('GreyNoise API reachable');
    }
    return 0; // GreyNoise is checked per-IP, not bulk
  }

  /**
   * Check a single IP against GreyNoise (free community API)
   * 使用 GreyNoise 免費 API 檢查單一 IP
   */
  async checkIPWithGreyNoise(ip: string): Promise<IoC | null> {
    try {
      const res = await fetchWithTimeout(
        `https://api.greynoise.io/v3/community/${ip}`,
        {
          method: 'GET',
          headers: { Accept: 'application/json' },
        },
        this.config.requestTimeoutMs
      );

      if (!res.ok) return null;

      const data = (await res.json()) as {
        noise: boolean;
        riot: boolean;
        classification: string;
        name: string;
        last_seen: string;
      };

      if (data.noise) {
        return {
          type: 'ip',
          value: ip,
          threatType: `scanner:${data.classification}`,
          source: 'greynoise',
          confidence: data.classification === 'malicious' ? 85 : 50,
          lastSeen: data.last_seen,
          tags: [data.classification, data.name].filter(Boolean),
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * AbuseIPDB check (requires API key, optional)
   */
  private async fetchAbuseIPDB(): Promise<number> {
    if (!this.config.abuseIPDBKey) return 0;
    // AbuseIPDB is checked per-IP via checkIPWithAbuseIPDB()
    logger.info('AbuseIPDB configured (per-IP lookup mode)');
    return 0;
  }

  /**
   * Check a single IP against AbuseIPDB
   * 使用 AbuseIPDB 檢查單一 IP
   */
  async checkIPWithAbuseIPDB(ip: string): Promise<IoC | null> {
    if (!this.config.abuseIPDBKey) return null;

    try {
      const res = await fetchWithTimeout(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
        {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            Key: this.config.abuseIPDBKey,
          },
        },
        this.config.requestTimeoutMs
      );

      if (!res.ok) return null;
      const data = (await res.json()) as {
        data: {
          abuseConfidenceScore: number;
          totalReports: number;
          lastReportedAt: string;
          countryCode: string;
        };
      };

      if (data.data.abuseConfidenceScore > 25) {
        return {
          type: 'ip',
          value: ip,
          threatType: 'reported_abuse',
          source: 'abuseipdb',
          confidence: data.data.abuseConfidenceScore,
          lastSeen: data.data.lastReportedAt,
          tags: [data.data.countryCode, `reports:${data.data.totalReports}`],
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  // -- Internal helpers --

  private addIoC(ioc: IoC): void {
    const key = `${ioc.source}:${ioc.type}:${ioc.value}`;
    this.iocs.set(key, ioc);
    if (ioc.type === 'ip') {
      this.ipIndex.set(ioc.value, ioc);
    }
  }

  private trimOldest(): void {
    const entries = Array.from(this.iocs.entries());
    const toRemove = entries.length - this.config.maxIoCs;
    if (toRemove <= 0) return;

    // Remove oldest entries (first inserted)
    for (let i = 0; i < toRemove; i++) {
      const entry = entries[i];
      if (!entry) continue;
      const [key, ioc] = entry;
      this.iocs.delete(key);
      if (ioc.type === 'ip') {
        this.ipIndex.delete(ioc.value);
      }
    }
  }
}

/** Fetch with timeout / 含逾時的 fetch */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
