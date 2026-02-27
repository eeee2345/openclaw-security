/**
 * Process monitoring via polling
 * 透過輪詢進行程序監控
 *
 * Periodically polls the system process list and emits events
 * for newly started or stopped processes.
 * 定期輪詢系統程序列表，並為新啟動或停止的程序發出事件。
 *
 * @module @panguard-ai/core/monitor/process-monitor
 */

import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { platform } from 'node:os';
import { promisify } from 'node:util';

import { createLogger } from '../utils/index.js';
import { normalizeProcessEvent } from './event-normalizer.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('process-monitor');

/**
 * Minimal process info for tracking state
 * 用於追蹤狀態的最小程序資訊
 */
interface ProcessInfo {
  /** Process ID / 程序 ID */
  pid: number;
  /** Process name / 程序名稱 */
  name: string;
  /** Full command line / 完整命令列 */
  command?: string;
}

/**
 * Full process list entry
 * 完整程序列表條目
 */
export interface ProcessListEntry {
  /** Process ID / 程序 ID */
  pid: number;
  /** Process name / 程序名稱 */
  name: string;
  /** User running the process / 執行程序的使用者 */
  user?: string;
  /** Full command line / 完整命令列 */
  command?: string;
}

/**
 * ProcessMonitor - monitors system processes by polling the process list
 * ProcessMonitor - 透過輪詢程序列表監控系統程序
 *
 * Events emitted:
 * - 'process_started': SecurityEvent - when a new process is detected / 當偵測到新程序時
 * - 'process_stopped': SecurityEvent - when a process disappears / 當程序消失時
 * - 'error': Error - when polling encounters an error / 當輪詢遇到錯誤時
 *
 * @example
 * ```typescript
 * const monitor = new ProcessMonitor(15000);
 * monitor.on('process_started', (event) => console.log('Started:', event));
 * monitor.on('process_stopped', (event) => console.log('Stopped:', event));
 * monitor.start();
 * ```
 */
export class ProcessMonitor extends EventEmitter {
  /** Whether the monitor is currently running / 監控器是否正在執行 */
  private running = false;
  /** Polling timer / 輪詢計時器 */
  private timer?: ReturnType<typeof setInterval>;
  /** Previous process snapshot for diff detection / 用於差異偵測的先前程序快照 */
  private previousProcesses: Map<number, ProcessInfo> = new Map();
  /** Polling interval in milliseconds / 輪詢間隔（毫秒） */
  private pollInterval: number;

  /**
   * Create a new ProcessMonitor instance
   * 建立新的 ProcessMonitor 實例
   *
   * @param pollInterval - Polling interval in ms (default 15000) / 輪詢間隔毫秒數（預設 15000）
   */
  constructor(pollInterval = 15000) {
    super();
    this.pollInterval = pollInterval;
  }

  /**
   * Start polling for process changes
   * 開始輪詢程序變更
   */
  start(): void {
    if (this.running) {
      logger.warn('ProcessMonitor is already running');
      return;
    }

    this.running = true;
    logger.info(`ProcessMonitor started (poll interval: ${this.pollInterval}ms)`);

    // Run an initial poll immediately / 立即執行首次輪詢
    void this.pollProcesses();

    this.timer = setInterval(() => {
      void this.pollProcesses();
    }, this.pollInterval);
  }

  /**
   * Stop polling and clean up
   * 停止輪詢並清理
   */
  stop(): void {
    if (!this.running) {
      logger.warn('ProcessMonitor is not running');
      return;
    }

    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }

    this.running = false;
    this.previousProcesses.clear();
    logger.info('ProcessMonitor stopped');
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
   * Poll the process list and emit events for changes
   * 輪詢程序列表並為變更發出事件
   */
  private async pollProcesses(): Promise<void> {
    try {
      const currentList = await this.getProcessList();
      const currentMap = new Map<number, ProcessInfo>();

      for (const proc of currentList) {
        currentMap.set(proc.pid, {
          pid: proc.pid,
          name: proc.name,
          command: proc.command,
        });

        // Emit event for new processes not in previous snapshot
        // 為不在先前快照中的新程序發出事件
        if (!this.previousProcesses.has(proc.pid)) {
          const event = normalizeProcessEvent(
            {
              pid: proc.pid,
              name: proc.name,
              user: proc.user,
              command: proc.command,
            },
            'started'
          );
          this.emit('process_started', event);
        }
      }

      // Emit event for processes that no longer exist
      // 為不再存在的程序發出事件
      for (const [pid, proc] of this.previousProcesses) {
        if (!currentMap.has(pid)) {
          const event = normalizeProcessEvent(
            {
              pid,
              name: proc.name,
              command: proc.command,
            },
            'stopped'
          );
          this.emit('process_stopped', event);
        }
      }

      this.previousProcesses = currentMap;
    } catch (err) {
      logger.error('Failed to poll processes', { error: String(err) });
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
    }
  }

  /**
   * Get the current system process list
   * 取得目前系統程序列表
   *
   * Uses platform-specific tools:
   * 使用平台特定工具：
   * - macOS/Linux: `ps -eo pid,user,comm,args`
   * - Windows: `tasklist /FO CSV`
   *
   * @returns Array of process entries / 程序條目陣列
   */
  async getProcessList(): Promise<ProcessListEntry[]> {
    const os = platform();

    try {
      if (os === 'darwin' || os === 'linux') {
        return await this.parsePs();
      } else if (os === 'win32') {
        return await this.parseTasklist();
      } else {
        logger.warn(`Unsupported platform for process monitoring: ${os}`);
        return [];
      }
    } catch (err) {
      logger.error('Failed to get process list', { error: String(err) });
      return [];
    }
  }

  /**
   * Parse Unix ps output into ProcessListEntry array
   * 將 Unix ps 輸出解析為 ProcessListEntry 陣列
   *
   * @returns Parsed process entries / 解析後的程序條目
   */
  private async parsePs(): Promise<ProcessListEntry[]> {
    const { stdout } = await execFileAsync('ps', ['-eo', 'pid,user,comm,args'], {
      timeout: 10000,
    });

    const processes: ProcessListEntry[] = [];
    const lines = stdout.split('\n');

    // Skip header line / 跳過標頭行
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line || line.trim().length === 0) continue;

      const trimmed = line.trimStart();
      // Format: PID USER COMM ARGS (ARGS may contain spaces)
      // 格式：PID USER COMM ARGS（ARGS 可能包含空格）
      const match = trimmed.match(/^(\d+)\s+(\S+)\s+(\S+)\s+(.*)$/);
      if (!match) continue;

      const pid = parseInt(match[1] ?? '0', 10);
      const user = match[2];
      const name = match[3] ?? '';
      const command = match[4] ?? '';

      if (isNaN(pid) || pid === 0) continue;

      processes.push({
        pid,
        name,
        user,
        command: command.trim() || undefined,
      });
    }

    return processes;
  }

  /**
   * Parse Windows tasklist CSV output into ProcessListEntry array
   * 將 Windows tasklist CSV 輸出解析為 ProcessListEntry 陣列
   *
   * @returns Parsed process entries / 解析後的程序條目
   */
  private async parseTasklist(): Promise<ProcessListEntry[]> {
    const { stdout } = await execFileAsync('tasklist', ['/FO', 'CSV'], {
      timeout: 10000,
    });

    const processes: ProcessListEntry[] = [];
    const lines = stdout.split('\n');

    // Skip header line / 跳過標頭行
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line || line.trim().length === 0) continue;

      // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
      // CSV 格式："Image Name","PID","Session Name","Session#","Mem Usage"
      const csvMatch = line.match(/"([^"]+)","(\d+)"/);
      if (!csvMatch) continue;

      const name = csvMatch[1] ?? '';
      const pid = parseInt(csvMatch[2] ?? '0', 10);

      if (isNaN(pid) || pid === 0) continue;

      processes.push({
        pid,
        name,
      });
    }

    return processes;
  }
}
