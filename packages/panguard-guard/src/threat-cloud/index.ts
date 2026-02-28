/**
 * Collective Threat Intelligence (Threat Cloud)
 * 集體威脅智慧（威脅雲）
 *
 * Provides anonymized threat data upload and community rule distribution.
 * Supports HTTP cloud backend with local file fallback for offline mode.
 * 提供匿名化威脅數據上傳和社群規則分發。
 * 支援 HTTP 雲端後端和離線模式的本地檔案備援。
 *
 * @module @panguard-ai/panguard-guard/threat-cloud
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { request } from 'node:https';
import { createLogger } from '@panguard-ai/core';
import type { AnonymizedThreatData, ThreatCloudUpdate, ThreatCloudStatus } from '../types.js';
import { getAnonymousClientId } from './client-id.js';

const logger = createLogger('panguard-guard:threat-cloud');

/** Local cache file name / 本地快取檔名 */
const CACHE_FILE = 'threat-cloud-cache.json';

/** Local upload queue file name / 本地上傳佇列檔名 */
const QUEUE_FILE = 'threat-cloud-queue.json';

/** Cache data structure / 快取資料結構 */
interface CacheData {
  rules: ThreatCloudUpdate[];
  lastSync: string;
  stats: { totalUploaded: number; totalRulesReceived: number };
}

/**
 * Threat Cloud Client for collective intelligence sharing
 * 集體情報分享的威脅雲客戶端
 */
export class ThreatCloudClient {
  private readonly endpoint: string | undefined;
  private readonly dataDir: string;
  private readonly clientId: string;
  private status: ThreatCloudStatus = 'disconnected';
  private cache: CacheData;
  private uploadQueue: AnonymizedThreatData[] = [];
  private uploadBuffer: AnonymizedThreatData[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  /** Max events before immediate flush */
  private static readonly BATCH_SIZE = 50;
  /** Max buffer size to prevent memory growth */
  private static readonly MAX_BUFFER = 1000;
  /** Periodic flush interval (ms) */
  private static readonly FLUSH_INTERVAL = 60_000;

  /**
   * @param endpoint - Cloud API endpoint URL (undefined = offline mode) / 雲端 API 端點 URL
   * @param dataDir - Local data directory for cache/queue / 本地資料目錄
   */
  constructor(endpoint: string | undefined, dataDir: string) {
    this.endpoint = endpoint;
    this.dataDir = dataDir;
    this.clientId = getAnonymousClientId();

    // Load local cache and upload queue / 載入本地快取和上傳佇列
    this.cache = this.loadCache();
    this.uploadQueue = this.loadQueue();

    if (!endpoint) {
      this.status = 'offline';
      logger.info('Threat Cloud in offline mode (no endpoint configured) / 威脅雲離線模式');
    } else {
      // Start periodic flush timer
      this.flushTimer = setInterval(() => {
        void this.flushBuffer();
      }, ThreatCloudClient.FLUSH_INTERVAL);
    }
  }

  /**
   * Get current connection status / 取得當前連線狀態
   */
  getStatus(): ThreatCloudStatus {
    return this.status;
  }

  /**
   * Upload anonymized threat data to the cloud.
   * Data is buffered and sent in batches of up to 50 events.
   * 上傳匿名化威脅數據至雲端。數據會緩衝並批次上傳（最多 50 筆）。
   *
   * @param data - Anonymized threat data / 匿名化威脅數據
   */
  async upload(data: AnonymizedThreatData): Promise<boolean> {
    if (this.status === 'offline' || !this.endpoint) {
      this.uploadQueue.push(data);
      this.saveQueue();
      return false;
    }

    this.uploadBuffer.push(data);

    // Cap buffer to prevent memory growth
    if (this.uploadBuffer.length > ThreatCloudClient.MAX_BUFFER) {
      this.uploadBuffer = this.uploadBuffer.slice(-ThreatCloudClient.MAX_BUFFER);
    }

    // Flush immediately if batch size reached
    if (this.uploadBuffer.length >= ThreatCloudClient.BATCH_SIZE) {
      return this.flushBuffer();
    }

    return true;
  }

  /**
   * Flush the upload buffer (batch POST to cloud).
   * 清空上傳緩衝區（批次 POST 至雲端）。
   */
  private async flushBuffer(): Promise<boolean> {
    if (this.uploadBuffer.length === 0) return true;
    if (!this.endpoint) return false;

    const batch = [...this.uploadBuffer];
    this.uploadBuffer = [];

    try {
      await this.httpPost(`${this.endpoint}/api/threats`, { events: batch });
      this.cache.stats.totalUploaded += batch.length;
      this.saveCache();
      this.status = 'connected';
      logger.info(`Batch uploaded ${batch.length} events / 批次上傳 ${batch.length} 筆事件`);
      return true;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Batch upload failed: ${msg}, re-buffering / 批次上傳失敗: ${msg}，重新緩衝`);
      // Put batch back at front of buffer
      this.uploadBuffer.unshift(...batch);
      // Enforce max buffer limit
      if (this.uploadBuffer.length > ThreatCloudClient.MAX_BUFFER) {
        this.uploadBuffer = this.uploadBuffer.slice(-ThreatCloudClient.MAX_BUFFER);
      }
      this.status = 'disconnected';
      return false;
    }
  }

  /**
   * Stop the flush timer (call on shutdown).
   * 停止定期清空計時器。
   */
  stopFlushTimer(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  /**
   * Fetch latest community rules from the cloud
   * 從雲端取得最新社群規則
   *
   * @returns Array of rule updates / 規則更新陣列
   */
  async fetchRules(): Promise<ThreatCloudUpdate[]> {
    if (this.status === 'offline' || !this.endpoint) {
      logger.info('Returning cached rules (offline mode) / 回傳快取規則（離線模式）');
      return this.cache.rules;
    }

    try {
      const lastSync = this.cache.lastSync;
      const url = `${this.endpoint}/api/rules?since=${encodeURIComponent(lastSync)}`;
      const response = await this.httpGet(url);
      const rules = JSON.parse(response) as ThreatCloudUpdate[];

      // Merge new rules into cache / 將新規則合併到快取
      for (const rule of rules) {
        const existing = this.cache.rules.findIndex((r) => r.ruleId === rule.ruleId);
        if (existing !== -1) {
          this.cache.rules[existing] = rule;
        } else {
          this.cache.rules.push(rule);
        }
      }

      this.cache.lastSync = new Date().toISOString();
      this.cache.stats.totalRulesReceived += rules.length;
      this.saveCache();
      this.status = 'connected';

      logger.info(`Fetched ${rules.length} rules from cloud / 從雲端取得 ${rules.length} 條規則`);

      return this.cache.rules;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Fetch rules failed: ${msg}, using cache / 取得規則失敗: ${msg}，使用快取`);
      this.status = 'disconnected';
      return this.cache.rules;
    }
  }

  /**
   * Flush the upload queue (sync pending data to cloud)
   * 清空上傳佇列（將待上傳數據同步至雲端）
   *
   * @returns Number of items successfully uploaded / 成功上傳的項目數
   */
  async flushQueue(): Promise<number> {
    // Also flush any buffered events first
    this.stopFlushTimer();
    await this.flushBuffer();

    if (this.uploadQueue.length === 0) return 0;
    if (this.status === 'offline' || !this.endpoint) return 0;

    let uploaded = 0;
    const remaining: AnonymizedThreatData[] = [];

    for (const data of this.uploadQueue) {
      try {
        await this.httpPost(`${this.endpoint}/api/threats`, data);
        uploaded++;
        this.cache.stats.totalUploaded++;
      } catch {
        remaining.push(data);
      }
    }

    this.uploadQueue = remaining;
    this.saveQueue();
    this.saveCache();

    logger.info(
      `Queue flush: ${uploaded} uploaded, ${remaining.length} remaining / ` +
        `佇列清空: ${uploaded} 已上傳, ${remaining.length} 剩餘`
    );

    return uploaded;
  }

  /**
   * Fetch IP blocklist from the cloud (plain text, one IP per line).
   * 從雲端取得 IP 封鎖清單（純文字，每行一個 IP）。
   *
   * @returns Array of blocked IPs / 封鎖 IP 陣列
   */
  async fetchBlocklist(): Promise<string[]> {
    if (this.status === 'offline' || !this.endpoint) {
      return [];
    }

    try {
      const url = `${this.endpoint}/api/feeds/ip-blocklist`;
      const response = await this.httpGet(url);
      const ips = response
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith('#'));

      this.status = 'connected';
      logger.info(`Fetched ${ips.length} IPs from blocklist / 從封鎖清單取得 ${ips.length} 個 IP`);
      return ips;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Fetch blocklist failed: ${msg} / 取得封鎖清單失敗: ${msg}`);
      this.status = 'disconnected';
      return [];
    }
  }

  /**
   * Get cached rules without network call / 取得快取規則（不進行網路呼叫）
   */
  getCachedRules(): ThreatCloudUpdate[] {
    return [...this.cache.rules];
  }

  /**
   * Get queue size / 取得佇列大小
   */
  getQueueSize(): number {
    return this.uploadQueue.length;
  }

  /**
   * Get statistics / 取得統計
   */
  getStats(): { totalUploaded: number; totalRulesReceived: number; queueSize: number } {
    return {
      ...this.cache.stats,
      queueSize: this.uploadQueue.length,
    };
  }

  // ---------------------------------------------------------------------------
  // HTTP helpers / HTTP 輔助函數
  // ---------------------------------------------------------------------------

  private httpPost(url: string, body: unknown): Promise<string> {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify(body);
      const parsed = new URL(url);

      const req = request(
        {
          hostname: parsed.hostname,
          port: parsed.port || 443,
          path: parsed.pathname + parsed.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'X-Panguard-Client-Id': this.clientId,
          },
          timeout: 10000,
        },
        (res) => {
          let data = '';
          res.on('data', (chunk: Buffer) => {
            data += chunk.toString();
          });
          res.on('end', () => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              resolve(data);
            } else {
              reject(new Error(`HTTP ${res.statusCode}: ${data}`));
            }
          });
        }
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
      req.write(payload);
      req.end();
    });
  }

  private httpGet(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);

      const req = request(
        {
          hostname: parsed.hostname,
          port: parsed.port || 443,
          path: parsed.pathname + parsed.search,
          method: 'GET',
          headers: {
            'X-Panguard-Client-Id': this.clientId,
          },
          timeout: 10000,
        },
        (res) => {
          let data = '';
          res.on('data', (chunk: Buffer) => {
            data += chunk.toString();
          });
          res.on('end', () => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              resolve(data);
            } else {
              reject(new Error(`HTTP ${res.statusCode}: ${data}`));
            }
          });
        }
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
      req.end();
    });
  }

  // ---------------------------------------------------------------------------
  // Cache/queue persistence / 快取/佇列持久化
  // ---------------------------------------------------------------------------

  private loadCache(): CacheData {
    const filePath = join(this.dataDir, CACHE_FILE);
    try {
      if (existsSync(filePath)) {
        return JSON.parse(readFileSync(filePath, 'utf-8')) as CacheData;
      }
    } catch {
      logger.warn('Failed to load threat cloud cache / 載入威脅雲快取失敗');
    }
    return {
      rules: [],
      lastSync: new Date(0).toISOString(),
      stats: { totalUploaded: 0, totalRulesReceived: 0 },
    };
  }

  private saveCache(): void {
    try {
      const filePath = join(this.dataDir, CACHE_FILE);
      mkdirSync(dirname(filePath), { recursive: true });
      writeFileSync(filePath, JSON.stringify(this.cache, null, 2), 'utf-8');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to save cache: ${msg} / 儲存快取失敗: ${msg}`);
    }
  }

  private loadQueue(): AnonymizedThreatData[] {
    const filePath = join(this.dataDir, QUEUE_FILE);
    try {
      if (existsSync(filePath)) {
        return JSON.parse(readFileSync(filePath, 'utf-8')) as AnonymizedThreatData[];
      }
    } catch {
      logger.warn('Failed to load upload queue / 載入上傳佇列失敗');
    }
    return [];
  }

  private saveQueue(): void {
    try {
      const filePath = join(this.dataDir, QUEUE_FILE);
      mkdirSync(dirname(filePath), { recursive: true });
      writeFileSync(filePath, JSON.stringify(this.uploadQueue, null, 2), 'utf-8');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to save queue: ${msg} / 儲存佇列失敗: ${msg}`);
    }
  }
}
