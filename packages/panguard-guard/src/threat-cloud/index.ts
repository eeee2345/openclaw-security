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
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
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
  private readonly apiKey: string | undefined;
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
   * @param apiKey - API key for authentication / 認證用 API 金鑰
   */
  constructor(endpoint: string | undefined, dataDir: string, apiKey?: string) {
    this.endpoint = endpoint;
    this.apiKey = apiKey ?? process.env['TC_API_KEY'];
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
   * Fetch ATR (Agent Threat Rules) from the cloud
   * 從雲端取得 ATR（代理威脅規則）
   *
   * @param since - Optional ISO timestamp for incremental sync / 可選 ISO 時間戳用於增量同步
   * @returns Array of ATR rule updates / ATR 規則更新陣列
   */
  async fetchATRRules(since?: string): Promise<ThreatCloudUpdate[]> {
    if (this.status === 'offline' || !this.endpoint) {
      logger.info('Returning empty ATR rules (offline mode) / 回傳空 ATR 規則（離線模式）');
      return [];
    }

    try {
      const sinceParam = since ?? this.cache.lastSync;
      const url = `${this.endpoint}/api/atr-rules?since=${encodeURIComponent(sinceParam)}`;
      const response = await this.httpGet(url);
      const rules = JSON.parse(response) as ThreatCloudUpdate[];

      this.status = 'connected';
      logger.info(
        `Fetched ${rules.length} ATR rules from cloud / 從雲端取得 ${rules.length} 條 ATR 規則`
      );

      return rules;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(
        `Fetch ATR rules failed: ${msg}, returning empty / 取得 ATR 規則失敗: ${msg}，回傳空陣列`
      );
      this.status = 'disconnected';
      return [];
    }
  }

  /**
   * Fetch YARA rules from Threat Cloud (auto-generated from threat patterns).
   * 從 Threat Cloud 取得 YARA 規則（自動從威脅模式產生）
   *
   * @param since - Optional ISO timestamp for incremental sync
   * @returns Array of YARA rule updates / YARA 規則更新陣列
   */
  async fetchYaraRules(since?: string): Promise<ThreatCloudUpdate[]> {
    if (this.status === 'offline' || !this.endpoint) {
      return [];
    }

    try {
      let url = `${this.endpoint}/api/yara-rules`;
      const lastSync = since ?? this.cache.lastSync;
      if (lastSync) {
        url += `?since=${encodeURIComponent(lastSync)}`;
      }

      const body = await this.httpGet(url);
      const rules = JSON.parse(body) as ThreatCloudUpdate[];
      this.status = 'connected';
      if (rules.length > 0) {
        logger.info(
          `Fetched ${rules.length} YARA rules from Threat Cloud / ` +
            `從 Threat Cloud 取得 ${rules.length} 條 YARA 規則`
        );
      }
      return rules;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Fetch YARA rules failed: ${msg} / 取得 YARA 規則失敗: ${msg}`);
      this.status = 'disconnected';
      return [];
    }
  }

  /**
   * Fetch domain blocklist from the cloud (plain text, one domain per line).
   * 從雲端取得網域封鎖清單（純文字，每行一個網域）
   *
   * @returns Array of blocked domains / 封鎖網域陣列
   */
  async fetchDomainBlocklist(): Promise<string[]> {
    if (this.status === 'offline' || !this.endpoint) {
      return [];
    }

    try {
      const url = `${this.endpoint}/api/feeds/domain-blocklist`;
      const response = await this.httpGet(url);
      const domains = response
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith('#'));

      this.status = 'connected';
      if (domains.length > 0) {
        logger.info(
          `Fetched ${domains.length} domains from blocklist / 從封鎖清單取得 ${domains.length} 個網域`
        );
      }
      return domains;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Fetch domain blocklist failed: ${msg} / 取得網域封鎖清單失敗: ${msg}`);
      this.status = 'disconnected';
      return [];
    }
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
   * Report a safe skill to Threat Cloud (audit passed)
   * 回報安全 skill 到 Threat Cloud（審計通過）
   */
  async reportSafeSkill(skillName: string, fingerprintHash?: string): Promise<void> {
    if (this.status === 'offline' || !this.endpoint) return;

    try {
      const url = `${this.endpoint}/api/skill-whitelist`;
      const body = JSON.stringify({ skillName, fingerprintHash });
      await this.httpPost(url, body);
      logger.info(`Reported safe skill: ${skillName}`);
    } catch (err: unknown) {
      logger.warn(`Report safe skill failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Fetch community skill whitelist from Threat Cloud
   * 從 Threat Cloud 取得社群 skill 白名單
   */
  async fetchSkillWhitelist(): Promise<Array<{ name: string; hash?: string }>> {
    if (this.status === 'offline' || !this.endpoint) return [];

    try {
      const url = `${this.endpoint}/api/skill-whitelist`;
      const response = await this.httpGet(url);
      const parsed = JSON.parse(response) as { ok?: boolean; data?: Array<{ name: string; hash?: string }> };
      const skills = parsed.data ?? [];
      this.status = 'connected';
      logger.info(`Fetched ${skills.length} skills from community whitelist`);
      return skills;
    } catch (err: unknown) {
      logger.warn(`Fetch skill whitelist failed: ${err instanceof Error ? err.message : String(err)}`);
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
  // ATR Proposal Submission / ATR 提案提交
  // ---------------------------------------------------------------------------

  /**
   * Submit a locally-drafted ATR rule proposal to Threat Cloud.
   * The proposal will go through community consensus voting.
   * 提交本地 LLM 產生的 ATR 規則提案至 Threat Cloud（經社群共識投票）
   */
  async submitATRProposal(proposal: {
    patternHash: string;
    ruleContent: string;
    llmProvider: string;
    llmModel: string;
    selfReviewVerdict: string;
  }): Promise<boolean> {
    if (this.status === 'offline' || !this.endpoint) {
      logger.info('Cannot submit ATR proposal in offline mode / 離線模式無法提交 ATR 提案');
      return false;
    }

    try {
      const url = `${this.endpoint}/api/atr-proposals`;
      await this.httpPost(url, proposal);
      logger.info(
        `ATR proposal submitted for pattern ${proposal.patternHash} / ` +
          `ATR 提案已提交 (pattern: ${proposal.patternHash})`
      );
      return true;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn(`ATR proposal submission failed: ${msg} / ATR 提案提交失敗: ${msg}`);
      return false;
    }
  }

  /**
   * Report ATR rule match feedback (true/false positive) to Threat Cloud.
   * 回報 ATR 規則比對結果（正確/誤報）至 Threat Cloud
   */
  async reportATRFeedback(ruleId: string, isTruePositive: boolean): Promise<void> {
    if (this.status === 'offline' || !this.endpoint) return;

    try {
      const url = `${this.endpoint}/api/atr-feedback`;
      await this.httpPost(url, { ruleId, isTruePositive });
    } catch {
      // Best effort, don't fail the main flow
    }
  }

  // ---------------------------------------------------------------------------
  // Skill Threat Submission / Skill 威脅提交
  // ---------------------------------------------------------------------------

  /**
   * Submit a skill audit result to Threat Cloud.
   * Anonymized: only hash, name, score, and finding IDs are sent.
   * 提交 Skill 審計結果至 Threat Cloud（匿名化：只傳 hash、名稱、分數和 finding ID）
   */
  async submitSkillThreat(submission: {
    skillHash: string;
    skillName: string;
    riskScore: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    findingSummaries?: Array<{
      id: string;
      category: string;
      severity: string;
      title: string;
    }>;
  }): Promise<boolean> {
    if (this.status === 'offline' || !this.endpoint) {
      logger.info('Cannot submit skill threat in offline mode');
      return false;
    }

    try {
      const url = `${this.endpoint}/api/skill-threats`;
      await this.httpPost(url, submission);
      logger.info(
        `Skill threat submitted: ${submission.skillName} (risk: ${submission.riskLevel})`
      );
      return true;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn(`Skill threat submission failed: ${msg}`);
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // HTTP helpers / HTTP 輔助函數
  // ---------------------------------------------------------------------------

  /** Select http or https request function based on URL protocol */
  private selectTransport(url: string) {
    return url.startsWith('https') ? httpsRequest : httpRequest;
  }

  /** Build common headers including Authorization if API key is configured */
  private baseHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'X-Panguard-Client-Id': this.clientId,
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  private httpPost(url: string, body: unknown): Promise<string> {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify(body);
      const parsed = new URL(url);
      const transport = this.selectTransport(url);
      const defaultPort = parsed.protocol === 'https:' ? 443 : 80;

      const req = transport(
        {
          hostname: parsed.hostname,
          port: parsed.port || defaultPort,
          path: parsed.pathname + parsed.search,
          method: 'POST',
          headers: {
            ...this.baseHeaders(),
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload).toString(),
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
      const transport = this.selectTransport(url);
      const defaultPort = parsed.protocol === 'https:' ? 443 : 80;

      const req = transport(
        {
          hostname: parsed.hostname,
          port: parsed.port || defaultPort,
          path: parsed.pathname + parsed.search,
          method: 'GET',
          headers: this.baseHeaders(),
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
