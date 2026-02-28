/**
 * Threat Cloud Uploader for PanguardTrap
 * PanguardTrap 的 Threat Cloud 上傳器
 *
 * Batches and uploads TrapIntelligence reports to the Threat Cloud server.
 * Supports offline queueing and automatic retry.
 *
 * 批次上傳 TrapIntelligence 報告至 Threat Cloud 伺服器。
 * 支援離線排隊和自動重試。
 *
 * @module @panguard-ai/panguard-trap/threat-cloud-uploader
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapIntelligence } from './types.js';

const logger = createLogger('panguard-trap:cloud-uploader');

/** Serializable form of TrapIntelligence for HTTP POST */
interface TrapIntelPayload {
  timestamp: string;
  serviceType: string;
  sourceIP: string;
  attackType: string;
  mitreTechniques: string[];
  skillLevel: string;
  intent: string;
  tools: string[];
  topCredentials: Array<{ username: string; count: number }>;
  region?: string;
}

/**
 * Uploads TrapIntelligence to the Threat Cloud server in batches.
 * 批次上傳蜜罐情報至 Threat Cloud。
 */
export class ThreatCloudUploader {
  private readonly endpoint: string;
  private buffer: TrapIntelPayload[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  /** Max items before immediate flush / 觸發立即上傳的最大數量 */
  private static readonly BATCH_SIZE = 20;
  /** Max buffer size to prevent memory growth / 防止記憶體膨脹的上限 */
  private static readonly MAX_BUFFER = 500;
  /** Periodic flush interval (ms) / 定期上傳間隔 */
  private static readonly FLUSH_INTERVAL = 30_000;

  constructor(endpoint: string) {
    this.endpoint = endpoint.replace(/\/+$/, '');

    this.flushTimer = setInterval(() => {
      void this.flush();
    }, ThreatCloudUploader.FLUSH_INTERVAL);

    // Allow Node process to exit if this is the only timer
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  /**
   * Queue a TrapIntelligence report for upload.
   * 將蜜罐情報加入上傳佇列。
   */
  enqueue(intel: TrapIntelligence): void {
    const payload = this.toPayload(intel);
    this.buffer.push(payload);

    // Cap buffer
    if (this.buffer.length > ThreatCloudUploader.MAX_BUFFER) {
      this.buffer = this.buffer.slice(-ThreatCloudUploader.MAX_BUFFER);
    }

    // Flush immediately if batch size reached
    if (this.buffer.length >= ThreatCloudUploader.BATCH_SIZE) {
      void this.flush();
    }
  }

  /**
   * Flush all buffered intel to the server.
   * 上傳所有緩衝中的情報。
   */
  async flush(): Promise<number> {
    if (this.buffer.length === 0) return 0;

    const batch = [...this.buffer];
    this.buffer = [];

    try {
      const url = `${this.endpoint}/api/trap-intel`;
      const payload = JSON.stringify(batch);

      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }

      logger.info(
        `Uploaded ${batch.length} trap intel reports to Threat Cloud / ` +
          `已上傳 ${batch.length} 筆蜜罐情報`
      );
      return batch.length;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Trap intel upload failed: ${msg} / 上傳失敗: ${msg}`);

      // Re-buffer failed batch (at front so ordering is preserved)
      this.buffer.unshift(...batch);
      if (this.buffer.length > ThreatCloudUploader.MAX_BUFFER) {
        this.buffer = this.buffer.slice(-ThreatCloudUploader.MAX_BUFFER);
      }
      return 0;
    }
  }

  /**
   * Stop the periodic flush timer.
   * 停止定期上傳計時器。
   */
  stop(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  /** Get pending buffer size / 取得待上傳數量 */
  getPendingCount(): number {
    return this.buffer.length;
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private toPayload(intel: TrapIntelligence): TrapIntelPayload {
    return {
      timestamp: intel.timestamp.toISOString(),
      serviceType: intel.serviceType,
      sourceIP: intel.sourceIP,
      attackType: intel.attackType,
      mitreTechniques: [...intel.mitreTechniques],
      skillLevel: intel.skillLevel,
      intent: intel.intent,
      tools: [...intel.tools],
      topCredentials: intel.topCredentials.map((c) => ({
        username: c.username,
        count: c.count,
      })),
      region: intel.region,
    };
  }
}
