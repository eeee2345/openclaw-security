/**
 * Three-layer AI Funnel Router with automatic fallback
 * 三層 AI 漏斗路由器（自動降級）
 *
 * Layer 1: Rules (always available) / 規則（永遠可用）
 * Layer 2: Local AI via Ollama (server only) / 本地 AI（僅伺服器）
 * Layer 3: Cloud AI via Claude/OpenAI / 雲端 AI
 *
 * Each layer catches failures and falls back to the next available layer.
 * 每層捕捉失敗並降級到下一個可用層。
 *
 * @module @panguard-ai/core/ai/funnel-router
 */

import { createLogger } from '../utils/logger.js';
import type { LLMProvider, AnalysisResult } from './types.js';

const logger = createLogger('ai:funnel-router');

/** Funnel layer status / 漏斗層狀態 */
export interface FunnelLayerStatus {
  name: string;
  available: boolean;
  lastChecked: number;
  failCount: number;
}

/** Funnel router configuration / 漏斗路由器配置 */
export interface FunnelRouterConfig {
  /** Local AI provider (Ollama) / 本地 AI 供應商 */
  localProvider?: LLMProvider;
  /** Cloud AI provider (Claude/OpenAI) / 雲端 AI 供應商 */
  cloudProvider?: LLMProvider;
  /** Health check interval in ms (default: 60000) / 健康檢查間隔 */
  healthCheckInterval?: number;
  /** Max consecutive failures before disabling a layer / 連續失敗次數上限 */
  maxFailures?: number;
}

/**
 * Three-layer funnel router with automatic degradation
 * 三層漏斗路由器（自動降級）
 */
export class FunnelRouter {
  private readonly localProvider: LLMProvider | null;
  private readonly cloudProvider: LLMProvider | null;
  private readonly maxFailures: number;

  private localStatus: FunnelLayerStatus;
  private cloudStatus: FunnelLayerStatus;
  private healthTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: FunnelRouterConfig) {
    this.localProvider = config.localProvider ?? null;
    this.cloudProvider = config.cloudProvider ?? null;
    this.maxFailures = config.maxFailures ?? 3;

    this.localStatus = {
      name: 'local-ai',
      available: !!this.localProvider,
      lastChecked: 0,
      failCount: 0,
    };

    this.cloudStatus = {
      name: 'cloud-ai',
      available: !!this.cloudProvider,
      lastChecked: 0,
      failCount: 0,
    };

    logger.info('FunnelRouter initialized', {
      hasLocal: !!this.localProvider,
      hasCloud: !!this.cloudProvider,
    });
  }

  /**
   * Start periodic health checks / 開始定期健康檢查
   */
  startHealthChecks(intervalMs = 60_000): void {
    if (this.healthTimer) return;
    this.healthTimer = setInterval(() => void this.checkHealth(), intervalMs);
    void this.checkHealth();
  }

  /**
   * Stop health checks / 停止健康檢查
   */
  stopHealthChecks(): void {
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
  }

  /**
   * Run health check on all providers / 對所有供應商執行健康檢查
   */
  async checkHealth(): Promise<void> {
    const now = Date.now();

    if (this.localProvider) {
      try {
        const ok = await this.localProvider.isAvailable();
        this.localStatus.available = ok;
        if (ok) this.localStatus.failCount = 0;
      } catch {
        this.localStatus.available = false;
      }
      this.localStatus.lastChecked = now;
    }

    if (this.cloudProvider) {
      try {
        const ok = await this.cloudProvider.isAvailable();
        this.cloudStatus.available = ok;
        if (ok) this.cloudStatus.failCount = 0;
      } catch {
        this.cloudStatus.available = false;
      }
      this.cloudStatus.lastChecked = now;
    }
  }

  /**
   * Analyze using the funnel: try local AI first, then cloud, then return null
   * 使用漏斗分析：先嘗試本地 AI，然後雲端，最後回傳 null
   *
   * @param prompt - Analysis prompt / 分析提示詞
   * @param context - Optional context / 可選上下文
   * @returns Analysis result or null if all AI layers failed / 分析結果或 null
   */
  async analyze(prompt: string, context?: string): Promise<AnalysisResult | null> {
    // Layer 2: Try local AI (Ollama)
    if (
      this.localProvider &&
      this.localStatus.available &&
      this.localStatus.failCount < this.maxFailures
    ) {
      try {
        logger.debug('Attempting Layer 2 (local AI) analysis');
        const result = await this.localProvider.analyze(prompt, context);
        this.localStatus.failCount = 0;
        logger.info('Layer 2 (local AI) analysis succeeded');
        return result;
      } catch (err) {
        this.localStatus.failCount++;
        logger.warn('Layer 2 (local AI) failed, falling back', {
          error: err instanceof Error ? err.message : String(err),
          failCount: this.localStatus.failCount,
        });
        if (this.localStatus.failCount >= this.maxFailures) {
          this.localStatus.available = false;
          logger.error('Layer 2 (local AI) disabled after max failures');
        }
      }
    }

    // Layer 3: Try cloud AI (Claude/OpenAI)
    if (
      this.cloudProvider &&
      this.cloudStatus.available &&
      this.cloudStatus.failCount < this.maxFailures
    ) {
      try {
        logger.debug('Attempting Layer 3 (cloud AI) analysis');
        const result = await this.cloudProvider.analyze(prompt, context);
        this.cloudStatus.failCount = 0;
        logger.info('Layer 3 (cloud AI) analysis succeeded');
        return result;
      } catch (err) {
        this.cloudStatus.failCount++;
        logger.warn('Layer 3 (cloud AI) failed', {
          error: err instanceof Error ? err.message : String(err),
          failCount: this.cloudStatus.failCount,
        });
        if (this.cloudStatus.failCount >= this.maxFailures) {
          this.cloudStatus.available = false;
          logger.error('Layer 3 (cloud AI) disabled after max failures');
        }
      }
    }

    // All AI layers failed, return null (caller should use rules-only mode)
    logger.warn('All AI layers unavailable, falling back to rules-only mode');
    return null;
  }

  /**
   * Get current funnel status / 取得目前漏斗狀態
   */
  getStatus(): { local: FunnelLayerStatus; cloud: FunnelLayerStatus; activeLayer: string } {
    let activeLayer = 'rules-only';
    if (this.localStatus.available && this.localStatus.failCount < this.maxFailures) {
      activeLayer = 'local-ai';
    } else if (this.cloudStatus.available && this.cloudStatus.failCount < this.maxFailures) {
      activeLayer = 'cloud-ai';
    }

    return {
      local: { ...this.localStatus },
      cloud: { ...this.cloudStatus },
      activeLayer,
    };
  }
}
