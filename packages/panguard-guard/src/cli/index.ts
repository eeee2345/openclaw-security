/**
 * PanguardGuard CLI
 * PanguardGuard 命令列介面
 *
 * Commands:
 * - start: Start the guard engine / 啟動守護引擎
 * - stop: Stop the guard engine / 停止守護引擎
 * - status: Show engine status / 顯示引擎狀態
 * - install: Install as system service / 安裝為系統服務
 * - uninstall: Remove system service / 移除系統服務
 * - config: Show current configuration / 顯示當前配置
 * - generate-key: Generate a test license key / 產生測試授權金鑰
 *
 * @module @openclaw/panguard-guard/cli
 */

import { join } from 'node:path';
import { homedir } from 'node:os';
import { GuardEngine } from '../guard-engine.js';
import { loadConfig, DEFAULT_DATA_DIR } from '../config.js';
import { PidFile } from '../daemon/index.js';
import { installService, uninstallService } from '../daemon/index.js';
import { generateTestLicenseKey } from '../license/index.js';
import { generateInstallScript } from '../install/index.js';

/** CLI version / CLI 版本 */
export const CLI_VERSION = '0.1.0';

/**
 * Parse and execute CLI commands / 解析並執行 CLI 命令
 *
 * @param args - Command line arguments (process.argv.slice(2)) / 命令列引數
 */
export async function runCLI(args: string[]): Promise<void> {
  const command = args[0] ?? 'help';
  const dataDir = extractOption(args, '--data-dir') ?? DEFAULT_DATA_DIR;

  switch (command) {
    case 'start':
      await commandStart(dataDir);
      break;
    case 'stop':
      commandStop(dataDir);
      break;
    case 'status':
      commandStatus(dataDir);
      break;
    case 'install':
      await commandInstall(dataDir);
      break;
    case 'uninstall':
      await commandUninstall();
      break;
    case 'config':
      commandConfig(dataDir);
      break;
    case 'generate-key': {
      const tier = (args[1] ?? 'pro') as 'free' | 'pro' | 'enterprise';
      const key = generateTestLicenseKey(tier);
      console.log(`Generated ${tier} license key: ${key}`);
      break;
    }
    case 'install-script': {
      const licenseKey = extractOption(args, '--license-key');
      const script = generateInstallScript({ dataDir, licenseKey });
      console.log(script);
      break;
    }
    case 'help':
    default:
      printHelp();
      break;
  }
}

/**
 * Start the guard engine / 啟動守護引擎
 */
async function commandStart(dataDir: string): Promise<void> {
  const pidFile = new PidFile(dataDir);

  if (pidFile.isRunning()) {
    console.log('PanguardGuard is already running / PanguardGuard 已在執行中');
    return;
  }

  console.log('Starting PanguardGuard... / 正在啟動 PanguardGuard...');
  const config = loadConfig(dataDir);
  const engine = new GuardEngine(config);

  // Handle shutdown signals / 處理關閉信號
  const shutdown = async () => {
    console.log('\nShutting down PanguardGuard... / 正在關閉 PanguardGuard...');
    await engine.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());

  await engine.start();

  console.log(`PanguardGuard started (PID: ${process.pid}) / PanguardGuard 已啟動`);
  console.log(`Mode: ${config.mode} / 模式: ${config.mode}`);
  if (config.dashboardEnabled) {
    console.log(`Dashboard: http://localhost:${config.dashboardPort}`);
  }
}

/**
 * Stop the guard engine / 停止守護引擎
 */
function commandStop(dataDir: string): void {
  const pidFile = new PidFile(dataDir);
  const pid = pidFile.read();

  if (!pid) {
    console.log('PanguardGuard is not running / PanguardGuard 未在執行中');
    return;
  }

  if (!pidFile.isRunning()) {
    console.log('PanguardGuard process not found, cleaning up PID file / 找不到程序，清理 PID 檔案');
    pidFile.remove();
    return;
  }

  try {
    process.kill(pid, 'SIGTERM');
    console.log(`PanguardGuard stopped (PID: ${pid}) / PanguardGuard 已停止`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Failed to stop PanguardGuard: ${msg} / 停止失敗: ${msg}`);
  }
}

/**
 * Show engine status / 顯示引擎狀態
 */
function commandStatus(dataDir: string): void {
  const pidFile = new PidFile(dataDir);
  const pid = pidFile.read();
  const running = pidFile.isRunning();

  console.log('PanguardGuard Status / PanguardGuard 狀態');
  console.log('================================');
  console.log(`Running: ${running ? 'Yes' : 'No'} / 執行中: ${running ? '是' : '否'}`);
  if (pid) {
    console.log(`PID: ${pid}`);
  }
  console.log(`Data Dir: ${dataDir} / 資料目錄: ${dataDir}`);

  try {
    const config = loadConfig(dataDir);
    console.log(`Mode: ${config.mode} / 模式: ${config.mode}`);
    console.log(`Dashboard: ${config.dashboardEnabled ? `http://localhost:${config.dashboardPort}` : 'disabled'}`);
    console.log(`License: ${config.licenseKey ? 'configured' : 'free tier'} / 授權: ${config.licenseKey ? '已配置' : '免費等級'}`);
  } catch {
    console.log('Config: not found / 配置: 未找到');
  }
}

/**
 * Install as system service / 安裝為系統服務
 */
async function commandInstall(dataDir: string): Promise<void> {
  console.log('Installing PanguardGuard as system service... / 正在安裝為系統服務...');
  try {
    const execPath = process.argv[1] ?? join(homedir(), '.npm-global', 'bin', 'panguard-guard');
    const result = await installService(execPath, dataDir);
    console.log(`Service installed: ${result} / 服務已安裝: ${result}`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Install failed: ${msg} / 安裝失敗: ${msg}`);
    console.error('You may need to run this command with elevated privileges (sudo/admin).');
  }
}

/**
 * Uninstall system service / 解除安裝系統服務
 */
async function commandUninstall(): Promise<void> {
  console.log('Uninstalling PanguardGuard service... / 正在解除安裝服務...');
  try {
    const result = await uninstallService();
    console.log(`Service uninstalled: ${result} / 服務已解除安裝: ${result}`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Uninstall failed: ${msg} / 解除安裝失敗: ${msg}`);
  }
}

/**
 * Show current configuration / 顯示當前配置
 */
function commandConfig(dataDir: string): void {
  try {
    const config = loadConfig(dataDir);
    console.log(JSON.stringify(config, null, 2));
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Failed to load config: ${msg} / 載入配置失敗: ${msg}`);
  }
}

/**
 * Print help message / 列印幫助訊息
 */
function printHelp(): void {
  console.log(`
PanguardGuard - AI Real-time Endpoint Security
PanguardGuard - AI 即時端點安全

Usage: panguard-guard <command> [options]

Commands:
  start             Start the guard engine / 啟動守護引擎
  stop              Stop the guard engine / 停止守護引擎
  status            Show engine status / 顯示引擎狀態
  install           Install as system service / 安裝為系統服務
  uninstall         Remove system service / 移除系統服務
  config            Show current configuration / 顯示當前配置
  generate-key      Generate a test license key / 產生測試授權金鑰
  install-script    Generate install script / 產生安裝腳本
  help              Show this help / 顯示此說明

Options:
  --data-dir <path>    Data directory (default: ~/.panguard-guard) / 資料目錄
  --license-key <key>  License key for install-script / 安裝腳本的授權金鑰

Version: ${CLI_VERSION}
`);
}

/**
 * Extract and validate option value from args / 從引數中提取並驗證選項值
 */
function extractOption(args: string[], option: string): string | undefined {
  const idx = args.indexOf(option);
  if (idx !== -1 && idx + 1 < args.length) {
    const value = args[idx + 1];
    if (value === undefined) return undefined;
    // Reject values starting with - (likely another flag) / 拒絕以 - 開頭的值
    if (value.startsWith('-')) return undefined;
    // Sanitize path traversal attempts / 清除路徑遍歷嘗試
    if (option === '--data-dir') {
      if (/\.\.[\\/]/.test(value) || /[;&|`$]/.test(value)) {
        console.error(`Invalid ${option} value: contains unsafe characters / 不安全的字元`);
        return undefined;
      }
    }
    return value;
  }
  return undefined;
}
