/**
 * Daemon / Service Management
 * Daemon / 服務管理
 *
 * Cross-platform daemon support:
 * - macOS: launchd plist
 * - Linux: systemd unit file
 * - Windows: sc.exe service
 * Includes PID file management and watchdog functionality.
 *
 * 跨平台 daemon 支援：
 * - macOS: launchd plist
 * - Linux: systemd unit 檔案
 * - Windows: sc.exe 服務
 * 包含 PID 檔案管理和看門狗功能。
 *
 * @module @panguard-ai/panguard-guard/daemon
 */

import { writeFileSync, readFileSync, unlinkSync, existsSync, mkdirSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { platform, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:daemon');

/** Service name constants / 服務名稱常數 */
const SERVICE_NAME = 'com.panguard.panguard-guard';
const SERVICE_DISPLAY_NAME = 'PanguardGuard Security Monitor';

/**
 * PID file management / PID 檔案管理
 */
export class PidFile {
  private readonly pidPath: string;

  constructor(dataDir: string) {
    this.pidPath = join(dataDir, 'panguard-guard.pid');
  }

  /** Write current PID to file / 將目前 PID 寫入檔案 */
  write(): void {
    mkdirSync(dirname(this.pidPath), { recursive: true });
    writeFileSync(this.pidPath, String(process.pid), 'utf-8');
    logger.info(`PID file written: ${this.pidPath} (PID: ${process.pid}) / PID 檔案已寫入`);
  }

  /** Read PID from file / 從檔案讀取 PID */
  read(): number | null {
    try {
      if (!existsSync(this.pidPath)) return null;
      const pid = parseInt(readFileSync(this.pidPath, 'utf-8').trim(), 10);
      return isNaN(pid) ? null : pid;
    } catch {
      return null;
    }
  }

  /** Remove PID file / 移除 PID 檔案 */
  remove(): void {
    try {
      if (existsSync(this.pidPath)) {
        unlinkSync(this.pidPath);
        logger.info('PID file removed / PID 檔案已移除');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to remove PID file: ${msg} / 移除 PID 檔案失敗`);
    }
  }

  /** Check if process with stored PID is running / 檢查儲存的 PID 程序是否執行中 */
  isRunning(): boolean {
    const pid = this.read();
    if (pid === null) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Watchdog - monitors the guard engine and restarts if needed
 * 看門狗 - 監控守護引擎，需要時重新啟動
 */
export class Watchdog {
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly intervalMs: number;
  private lastHeartbeat: number = Date.now();
  private readonly onFailure: () => void;

  /**
   * @param intervalMs - Check interval in milliseconds / 檢查間隔（毫秒）
   * @param onFailure - Callback when engine appears unresponsive / 引擎無回應時的回呼
   */
  constructor(intervalMs: number, onFailure: () => void) {
    this.intervalMs = intervalMs;
    this.onFailure = onFailure;
  }

  /** Start watchdog monitoring / 啟動看門狗監控 */
  start(): void {
    if (this.timer) return;

    this.lastHeartbeat = Date.now();
    this.timer = setInterval(() => {
      const elapsed = Date.now() - this.lastHeartbeat;
      // If no heartbeat for 3x the interval, trigger failure
      // 如果超過 3 倍間隔無心跳，觸發失敗
      if (elapsed > this.intervalMs * 3) {
        logger.error(
          `Watchdog: no heartbeat for ${elapsed}ms, triggering restart / ` +
            `看門狗: ${elapsed}ms 無心跳，觸發重啟`
        );
        this.onFailure();
      }
    }, this.intervalMs);

    logger.info(
      `Watchdog started with ${this.intervalMs}ms interval / ` +
        `看門狗已啟動，間隔 ${this.intervalMs}ms`
    );
  }

  /** Record a heartbeat / 記錄心跳 */
  heartbeat(): void {
    this.lastHeartbeat = Date.now();
  }

  /** Stop watchdog / 停止看門狗 */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      logger.info('Watchdog stopped / 看門狗已停止');
    }
  }
}

/**
 * Install as a system service / 安裝為系統服務
 *
 * @param execPath - Path to the panguard-guard executable / PanguardGuard 可執行檔路徑
 * @param dataDir - Data directory path / 資料目錄路徑
 */
export async function installService(execPath: string, dataDir: string): Promise<string> {
  const os = platform();

  switch (os) {
    case 'darwin':
      return installLaunchd(execPath, dataDir);
    case 'linux':
      return installSystemd(execPath, dataDir);
    case 'win32':
      return installWindowsService(execPath);
    default:
      throw new Error(`Unsupported platform: ${os} / 不支援的平台: ${os}`);
  }
}

/**
 * Uninstall system service / 解除安裝系統服務
 */
export async function uninstallService(): Promise<string> {
  const os = platform();

  switch (os) {
    case 'darwin':
      return uninstallLaunchd();
    case 'linux':
      return uninstallSystemd();
    case 'win32':
      return uninstallWindowsService();
    default:
      throw new Error(`Unsupported platform: ${os} / 不支援的平台: ${os}`);
  }
}

// ---------------------------------------------------------------------------
// macOS launchd / macOS launchd
// ---------------------------------------------------------------------------

async function installLaunchd(execPath: string, dataDir: string): Promise<string> {
  const plistPath = join(homedir(), 'Library', 'LaunchAgents', `${SERVICE_NAME}.plist`);

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SERVICE_NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${execPath}</string>
    <string>start</string>
    <string>--data-dir</string>
    <string>${dataDir}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${join(dataDir, 'panguard-guard.log')}</string>
  <key>StandardErrorPath</key>
  <string>${join(dataDir, 'panguard-guard-error.log')}</string>
</dict>
</plist>`;

  mkdirSync(dirname(plistPath), { recursive: true });
  writeFileSync(plistPath, plist, 'utf-8');

  await execFileAsync('/bin/launchctl', ['load', plistPath]);

  logger.info(`launchd service installed at ${plistPath} / launchd 服務已安裝`);
  return plistPath;
}

async function uninstallLaunchd(): Promise<string> {
  const plistPath = join(homedir(), 'Library', 'LaunchAgents', `${SERVICE_NAME}.plist`);

  if (existsSync(plistPath)) {
    await execFileAsync('/bin/launchctl', ['unload', plistPath]);
    unlinkSync(plistPath);
    logger.info('launchd service uninstalled / launchd 服務已解除安裝');
  }

  return plistPath;
}

// ---------------------------------------------------------------------------
// Linux systemd / Linux systemd
// ---------------------------------------------------------------------------

async function installSystemd(execPath: string, dataDir: string): Promise<string> {
  const unitPath = `/etc/systemd/system/${SERVICE_NAME}.service`;

  const unit = `[Unit]
Description=${SERVICE_DISPLAY_NAME}
After=network.target

[Service]
Type=simple
ExecStart=${execPath} start --data-dir ${dataDir}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`;

  writeFileSync(unitPath, unit, 'utf-8');
  await execFileAsync('/bin/systemctl', ['daemon-reload']);
  await execFileAsync('/bin/systemctl', ['enable', SERVICE_NAME]);
  await execFileAsync('/bin/systemctl', ['start', SERVICE_NAME]);

  logger.info(`systemd service installed at ${unitPath} / systemd 服務已安裝`);
  return unitPath;
}

async function uninstallSystemd(): Promise<string> {
  const unitPath = `/etc/systemd/system/${SERVICE_NAME}.service`;

  await execFileAsync('/bin/systemctl', ['stop', SERVICE_NAME]);
  await execFileAsync('/bin/systemctl', ['disable', SERVICE_NAME]);

  if (existsSync(unitPath)) {
    unlinkSync(unitPath);
    await execFileAsync('/bin/systemctl', ['daemon-reload']);
  }

  logger.info('systemd service uninstalled / systemd 服務已解除安裝');
  return unitPath;
}

// ---------------------------------------------------------------------------
// Windows sc.exe / Windows sc.exe
// ---------------------------------------------------------------------------

async function installWindowsService(execPath: string): Promise<string> {
  await execFileAsync('sc', [
    'create',
    SERVICE_NAME,
    `binpath=${execPath} start`,
    `displayname=${SERVICE_DISPLAY_NAME}`,
    'start=auto',
  ]);

  await execFileAsync('sc', ['start', SERVICE_NAME]);

  logger.info('Windows service installed / Windows 服務已安裝');
  return SERVICE_NAME;
}

async function uninstallWindowsService(): Promise<string> {
  try {
    execFileAsync('sc', ['stop', SERVICE_NAME]);
  } catch {
    // Service may not be running / 服務可能未執行
  }
  await execFileAsync('sc', ['delete', SERVICE_NAME]);

  logger.info('Windows service uninstalled / Windows 服務已解除安裝');
  return SERVICE_NAME;
}

// ---------------------------------------------------------------------------
// Async execFile helper / 非同步 execFile 輔助函數
// ---------------------------------------------------------------------------

function execFileAsync(command: string, args: string[]): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    execFile(command, args, { timeout: 15000 }, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
