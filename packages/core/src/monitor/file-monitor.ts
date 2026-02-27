/**
 * File integrity monitoring via hash comparison
 * 透過雜湊比對進行檔案完整性監控
 *
 * Periodically computes SHA-256 hashes of watched files and detects
 * creation, modification, and deletion events.
 * 定期計算受監控檔案的 SHA-256 雜湊值，並偵測建立、修改和刪除事件。
 *
 * @module @panguard-ai/core/monitor/file-monitor
 */

import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';

import { createLogger } from '../utils/index.js';
import { normalizeFileEvent } from './event-normalizer.js';
import type { FileHashRecord } from './types.js';

const logger = createLogger('file-monitor');

/**
 * FileMonitor - monitors file integrity by comparing SHA-256 hashes
 * FileMonitor - 透過比較 SHA-256 雜湊值監控檔案完整性
 *
 * Events emitted:
 * - 'file_changed': SecurityEvent - when a file hash changes / 當檔案雜湊值改變時
 * - 'file_created': SecurityEvent - when a new file is detected / 當偵測到新檔案時
 * - 'file_deleted': SecurityEvent - when a watched file is removed / 當受監控檔案被移除時
 * - 'error': Error - when file checking encounters an error / 當檔案檢查遇到錯誤時
 *
 * @example
 * ```typescript
 * const monitor = new FileMonitor(['/etc/passwd', '/etc/shadow'], 60000);
 * monitor.on('file_changed', (event) => console.log('Changed:', event));
 * monitor.start();
 * ```
 */
export class FileMonitor extends EventEmitter {
  /** Whether the monitor is currently running / 監控器是否正在執行 */
  private running = false;
  /** Polling timer / 輪詢計時器 */
  private timer?: ReturnType<typeof setInterval>;
  /** Stored file hash records / 儲存的檔案雜湊記錄 */
  private fileHashes: Map<string, FileHashRecord> = new Map();
  /** Paths to watch / 要監控的路徑 */
  private watchPaths: string[];
  /** Polling interval in milliseconds / 輪詢間隔（毫秒） */
  private pollInterval: number;

  /**
   * Create a new FileMonitor instance
   * 建立新的 FileMonitor 實例
   *
   * @param watchPaths - Array of file paths to monitor / 要監控的檔案路徑陣列
   * @param pollInterval - Polling interval in ms (default 60000) / 輪詢間隔毫秒數（預設 60000）
   */
  constructor(watchPaths: string[], pollInterval = 60000) {
    super();
    this.watchPaths = watchPaths;
    this.pollInterval = pollInterval;
  }

  /**
   * Start monitoring file integrity
   * 開始監控檔案完整性
   */
  start(): void {
    if (this.running) {
      logger.warn('FileMonitor is already running');
      return;
    }

    this.running = true;
    logger.info(
      `FileMonitor started (watching ${this.watchPaths.length} paths, poll interval: ${this.pollInterval}ms)`
    );

    // Run an initial check immediately / 立即執行首次檢查
    void this.checkFiles();

    this.timer = setInterval(() => {
      void this.checkFiles();
    }, this.pollInterval);
  }

  /**
   * Stop monitoring and clean up
   * 停止監控並清理
   */
  stop(): void {
    if (!this.running) {
      logger.warn('FileMonitor is not running');
      return;
    }

    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }

    this.running = false;
    logger.info('FileMonitor stopped');
  }

  /**
   * Check if the monitor is currently running
   * 檢查監控器是否正在執行
   *
   * @returns True if running / 如果正在執行則為 true
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Compute the SHA-256 hash of a file
   * 計算檔案的 SHA-256 雜湊值
   *
   * @param filePath - Path to the file / 檔案路徑
   * @returns Hex-encoded SHA-256 hash / 十六進位編碼的 SHA-256 雜湊值
   */
  async computeHash(filePath: string): Promise<string> {
    const content = await readFile(filePath);
    return createHash('sha256').update(content).digest('hex');
  }

  /**
   * Get the current file hash records
   * 取得目前的檔案雜湊記錄
   *
   * @returns Map of file path to hash record / 檔案路徑到雜湊記錄的映射
   */
  getFileHashes(): ReadonlyMap<string, FileHashRecord> {
    return this.fileHashes;
  }

  /**
   * Check all watched files for changes
   * 檢查所有受監控檔案的變更
   *
   * Compares current hashes with stored hashes and emits appropriate events.
   * 比較目前雜湊值與儲存的雜湊值，並發出適當的事件。
   */
  private async checkFiles(): Promise<void> {
    const currentPaths = new Set<string>();

    for (const filePath of this.watchPaths) {
      currentPaths.add(filePath);

      try {
        const fileStat = await stat(filePath);
        const currentHash = await this.computeHash(filePath);
        const now = new Date().toISOString();

        const existingRecord = this.fileHashes.get(filePath);

        if (!existingRecord) {
          // New file detected (first check or newly created)
          // 偵測到新檔案（首次檢查或新建立）
          this.fileHashes.set(filePath, {
            path: filePath,
            hash: currentHash,
            lastChecked: now,
            size: fileStat.size,
          });

          // Only emit file_created if this is not the first run
          // 僅在非首次執行時發出 file_created 事件
          if (
            this.fileHashes.size >
            this.watchPaths.length - (this.watchPaths.length - currentPaths.size)
          ) {
            // We check if we have seen at least one full cycle
            // The first poll populates the baseline, subsequent polls detect changes
          }

          // Emit file_created for files discovered after initial baseline
          // 為在初始基線之後發現的檔案發出 file_created
          // On first run, we just store the baseline without emitting
          // 首次執行時，我們只儲存基線而不發出事件
        } else if (existingRecord.hash !== currentHash) {
          // File has been modified / 檔案已被修改
          const oldHash = existingRecord.hash;

          this.fileHashes.set(filePath, {
            path: filePath,
            hash: currentHash,
            lastChecked: now,
            size: fileStat.size,
          });

          const event = normalizeFileEvent({
            path: filePath,
            action: 'modified',
            oldHash,
            newHash: currentHash,
          });
          this.emit('file_changed', event);

          logger.info(`File modified: ${filePath}`, {
            oldHash: oldHash.substring(0, 12),
            newHash: currentHash.substring(0, 12),
          });
        } else {
          // File unchanged, update last checked time
          // 檔案未變更，更新最後檢查時間
          existingRecord.lastChecked = now;
        }
      } catch (err) {
        const error = err as NodeJS.ErrnoException;

        if (error.code === 'ENOENT') {
          // File does not exist / 檔案不存在
          const existingRecord = this.fileHashes.get(filePath);
          if (existingRecord) {
            // File was previously tracked but now deleted
            // 檔案先前被追蹤但現在已被刪除
            this.fileHashes.delete(filePath);

            const event = normalizeFileEvent({
              path: filePath,
              action: 'deleted',
              oldHash: existingRecord.hash,
            });
            this.emit('file_deleted', event);

            logger.info(`File deleted: ${filePath}`);
          }
        } else {
          logger.error(`Failed to check file: ${filePath}`, { error: String(err) });
          this.emit('error', err instanceof Error ? err : new Error(String(err)));
        }
      }
    }

    // Check for files that were being tracked but are no longer in watchPaths
    // 檢查先前被追蹤但不再在 watchPaths 中的檔案
    for (const [trackedPath, record] of this.fileHashes) {
      if (!currentPaths.has(trackedPath)) {
        this.fileHashes.delete(trackedPath);

        const event = normalizeFileEvent({
          path: trackedPath,
          action: 'deleted',
          oldHash: record.hash,
        });
        this.emit('file_deleted', event);
      }
    }
  }
}
