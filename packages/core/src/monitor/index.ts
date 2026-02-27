/**
 * System Monitoring Engine
 * 系統監控引擎
 *
 * Real-time monitoring of system events including log monitoring,
 * network connections, process activity, and file integrity.
 * Aggregates all sub-monitors into a single MonitorEngine with
 * unified event emission and threat intelligence correlation.
 * 即時監控系統事件，包括日誌監控、網路連線、程序活動和檔案完整性。
 * 將所有子監控器彙整到單一 MonitorEngine，具備統一事件發送和威脅情報關聯。
 *
 * @module @panguard-ai/core/monitor
 */

import { EventEmitter } from 'node:events';

import { createLogger } from '../utils/index.js';
import type { SecurityEvent } from '../types.js';
import type { MonitorConfig, MonitorStatus } from './types.js';
import { DEFAULT_MONITOR_CONFIG } from './types.js';
import { LogMonitor } from './log-monitor.js';
import { NetworkMonitor } from './network-monitor.js';
import { ProcessMonitor } from './process-monitor.js';
import { FileMonitor } from './file-monitor.js';
import { checkThreatIntel } from './threat-intel.js';

const logger = createLogger('monitor-engine');

/** Monitor engine version / 監控引擎版本 */
export const MONITOR_VERSION = '0.1.0';

/**
 * MonitorEngine - unified system monitoring engine
 * MonitorEngine - 統一系統監控引擎
 *
 * Orchestrates all sub-monitors (log, network, process, file) and provides
 * a single event stream with integrated threat intelligence correlation.
 * 統籌所有子監控器（日誌、網路、程序、檔案），提供整合威脅情報關聯的
 * 單一事件串流。
 *
 * Events emitted:
 * - 'event': SecurityEvent - for all normalized security events / 所有正規化的安全事件
 * - 'threat': { event: SecurityEvent, threat: ThreatIntelEntry } - when a threat match is found / 當找到威脅比對時
 * - 'error': Error - when a sub-monitor encounters an error / 當子監控器遇到錯誤時
 *
 * @example
 * ```typescript
 * const engine = new MonitorEngine({
 *   logMonitor: true,
 *   networkMonitor: true,
 *   processMonitor: true,
 *   fileMonitor: false,
 *   networkPollInterval: 30000,
 *   processPollInterval: 15000,
 * });
 *
 * engine.on('event', (event) => console.log('Event:', event));
 * engine.on('threat', ({ event, threat }) => console.log('THREAT:', threat));
 *
 * engine.start();
 * // ... later ...
 * engine.stop();
 * ```
 */
export class MonitorEngine extends EventEmitter {
  /** Log monitor instance / 日誌監控器實例 */
  private logMonitor?: LogMonitor;
  /** Network monitor instance / 網路監控器實例 */
  private networkMonitor?: NetworkMonitor;
  /** Process monitor instance / 程序監控器實例 */
  private processMonitor?: ProcessMonitor;
  /** File monitor instance / 檔案監控器實例 */
  private fileMonitor?: FileMonitor;
  /** Current engine status / 目前引擎狀態 */
  private status: MonitorStatus = 'stopped';
  /** Resolved configuration / 解析後的配置 */
  private config: MonitorConfig;

  /**
   * Create a new MonitorEngine instance
   * 建立新的 MonitorEngine 實例
   *
   * @param config - Partial monitor configuration (merged with defaults) / 部分監控配置（與預設值合併）
   */
  constructor(config: Partial<MonitorConfig> = {}) {
    super();
    this.config = { ...DEFAULT_MONITOR_CONFIG, ...config };
  }

  /**
   * Start all enabled monitors
   * 啟動所有已啟用的監控器
   *
   * Initializes and starts each sub-monitor based on configuration,
   * wires up event forwarding, and applies threat intelligence checks
   * to all incoming events.
   * 根據配置初始化並啟動每個子監控器，連接事件轉發，並對所有
   * 傳入事件套用威脅情報檢查。
   */
  start(): void {
    if (this.status === 'running') {
      logger.warn('MonitorEngine is already running');
      return;
    }

    logger.info('Starting MonitorEngine', {
      logMonitor: this.config.logMonitor,
      networkMonitor: this.config.networkMonitor,
      processMonitor: this.config.processMonitor,
      fileMonitor: this.config.fileMonitor,
    });

    try {
      if (this.config.logMonitor) {
        this.startLogMonitor();
      }

      if (this.config.networkMonitor) {
        this.startNetworkMonitor();
      }

      if (this.config.processMonitor) {
        this.startProcessMonitor();
      }

      if (this.config.fileMonitor && this.config.watchPaths && this.config.watchPaths.length > 0) {
        this.startFileMonitor();
      }

      this.status = 'running';
      logger.info('MonitorEngine started successfully');
    } catch (err) {
      this.status = 'error';
      logger.error('Failed to start MonitorEngine', { error: String(err) });
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
    }
  }

  /**
   * Stop all running monitors and clean up resources
   * 停止所有執行中的監控器並清理資源
   */
  stop(): void {
    if (this.status === 'stopped') {
      logger.warn('MonitorEngine is already stopped');
      return;
    }

    logger.info('Stopping MonitorEngine');

    if (this.logMonitor) {
      this.logMonitor.removeAllListeners();
      this.logMonitor.stop();
      this.logMonitor = undefined;
    }

    if (this.networkMonitor) {
      this.networkMonitor.removeAllListeners();
      this.networkMonitor.stop();
      this.networkMonitor = undefined;
    }

    if (this.processMonitor) {
      this.processMonitor.removeAllListeners();
      this.processMonitor.stop();
      this.processMonitor = undefined;
    }

    if (this.fileMonitor) {
      this.fileMonitor.removeAllListeners();
      this.fileMonitor.stop();
      this.fileMonitor = undefined;
    }

    this.status = 'stopped';
    logger.info('MonitorEngine stopped');
  }

  /**
   * Get the current engine status
   * 取得目前引擎狀態
   *
   * @returns Current monitor status / 目前監控狀態
   */
  getStatus(): MonitorStatus {
    return this.status;
  }

  /**
   * Get the current configuration
   * 取得目前配置
   *
   * @returns Current monitor configuration / 目前監控配置
   */
  getConfig(): Readonly<MonitorConfig> {
    return this.config;
  }

  /**
   * Process an incoming event: emit it and check against threat intelligence
   * 處理傳入事件：發送事件並對照威脅情報檢查
   *
   * @param event - Security event to process / 要處理的安全事件
   */
  private processEvent(event: SecurityEvent): void {
    // Emit the raw event / 發送原始事件
    this.emit('event', event);

    // Check for threat intelligence matches on network events
    // 對網路事件檢查威脅情報比對
    if (event.source === 'network' && event.metadata['remoteAddr']) {
      const remoteAddr = String(event.metadata['remoteAddr']);
      const threat = checkThreatIntel(remoteAddr);
      if (threat) {
        logger.warn(`Threat intelligence match: ${remoteAddr}`, {
          type: threat.type,
          source: threat.source,
        });
        this.emit('threat', { event, threat });
      }
    }
  }

  /**
   * Forward errors from sub-monitors
   * 從子監控器轉發錯誤
   *
   * @param source - Sub-monitor name / 子監控器名稱
   * @param err - Error instance / 錯誤實例
   */
  private handleSubMonitorError(source: string, err: Error): void {
    logger.error(`Error from ${source}`, { error: err.message });
    this.emit('error', err);
  }

  /**
   * Initialize and start the log monitor
   * 初始化並啟動日誌監控器
   */
  private startLogMonitor(): void {
    this.logMonitor = new LogMonitor();

    this.logMonitor.on('event', (event: SecurityEvent) => {
      this.processEvent(event);
    });

    this.logMonitor.on('error', (err: Error) => {
      this.handleSubMonitorError('LogMonitor', err);
    });

    this.logMonitor.start();
    logger.info('LogMonitor sub-module started');
  }

  /**
   * Initialize and start the network monitor
   * 初始化並啟動網路監控器
   */
  private startNetworkMonitor(): void {
    this.networkMonitor = new NetworkMonitor(this.config.networkPollInterval);

    this.networkMonitor.on('new_connection', (event: SecurityEvent) => {
      this.processEvent(event);
    });

    this.networkMonitor.on('closed_connection', (event: SecurityEvent) => {
      this.processEvent(event);
    });

    this.networkMonitor.on('error', (err: Error) => {
      this.handleSubMonitorError('NetworkMonitor', err);
    });

    this.networkMonitor.start();
    logger.info('NetworkMonitor sub-module started');
  }

  /**
   * Initialize and start the process monitor
   * 初始化並啟動程序監控器
   */
  private startProcessMonitor(): void {
    this.processMonitor = new ProcessMonitor(this.config.processPollInterval);

    this.processMonitor.on('process_started', (event: SecurityEvent) => {
      this.processEvent(event);
    });

    this.processMonitor.on('process_stopped', (event: SecurityEvent) => {
      this.processEvent(event);
    });

    this.processMonitor.on('error', (err: Error) => {
      this.handleSubMonitorError('ProcessMonitor', err);
    });

    this.processMonitor.start();
    logger.info('ProcessMonitor sub-module started');
  }

  /**
   * Initialize and start the file monitor
   * 初始化並啟動檔案監控器
   */
  private startFileMonitor(): void {
    const watchPaths = this.config.watchPaths ?? [];
    this.fileMonitor = new FileMonitor(watchPaths);

    this.fileMonitor.on('file_changed', (event: SecurityEvent) => {
      this.processEvent(event);
    });

    this.fileMonitor.on('file_created', (event: SecurityEvent) => {
      this.processEvent(event);
    });

    this.fileMonitor.on('file_deleted', (event: SecurityEvent) => {
      this.processEvent(event);
    });

    this.fileMonitor.on('error', (err: Error) => {
      this.handleSubMonitorError('FileMonitor', err);
    });

    this.fileMonitor.start();
    logger.info('FileMonitor sub-module started');
  }
}

// Re-export sub-modules / 重新匯出子模組
export { LogMonitor } from './log-monitor.js';
export { NetworkMonitor } from './network-monitor.js';
export { ProcessMonitor } from './process-monitor.js';
export type { ProcessListEntry } from './process-monitor.js';
export { FileMonitor } from './file-monitor.js';
export {
  checkThreatIntel,
  isPrivateIP,
  addThreatIntelEntry,
  getThreatIntelEntries,
  setFeedManager,
  getFeedManager,
} from './threat-intel.js';
export {
  normalizeLogEvent,
  normalizeNetworkEvent,
  normalizeProcessEvent,
  normalizeFileEvent,
} from './event-normalizer.js';

// Re-export threat intel feeds / 重新匯出威脅情報饋送
export {
  ThreatIntelFeedManager,
  type IoC,
  type FeedSource,
  type FeedUpdateResult,
  type FeedManagerConfig,
} from './threat-intel-feeds.js';

// Re-export types / 重新匯出型別
export type { MonitorConfig, MonitorStatus, ThreatIntelEntry, FileHashRecord } from './types.js';
export { DEFAULT_MONITOR_CONFIG } from './types.js';
