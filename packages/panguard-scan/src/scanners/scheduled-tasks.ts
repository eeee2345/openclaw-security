/**
 * Scheduled tasks checker
 * 排程任務檢查器
 *
 * Checks for suspicious scheduled tasks, cron jobs, and launch agents
 * that may indicate persistence mechanisms or malicious activity.
 * Supports macOS (launchctl), Linux (crontab/cron.d), and Windows (schtasks).
 * 檢查可疑的排程任務、cron 工作和啟動代理，
 * 這些可能表示持久化機制或惡意活動。
 * 支援 macOS (launchctl)、Linux (crontab/cron.d) 和 Windows (schtasks)。
 *
 * @module @panguard-ai/panguard-scan/scanners/scheduled-tasks
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { readdir, readFile } from 'fs/promises';
import { platform as osPlatform } from 'os';
import { createLogger } from '@panguard-ai/core';
import type { Finding } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('panguard-scan:scheduled-tasks');

/**
 * Safely execute a command and return stdout, or empty string on failure
 * 安全地執行命令並回傳 stdout，失敗時回傳空字串
 *
 * @param cmd - Command to execute / 要執行的命令
 * @param args - Command arguments / 命令參數
 * @returns stdout output trimmed / 修剪後的 stdout 輸出
 */
async function safeExecFile(cmd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, { timeout: 15_000 });
    return stdout.trim();
  } catch (err) {
    logger.debug(`Command failed: ${cmd} ${args.join(' ')}`, {
      error: err instanceof Error ? err.message : String(err),
    });
    return '';
  }
}

/**
 * Patterns that indicate suspicious scheduled task entries
 * 表示可疑排程任務條目的模式
 *
 * Includes temp directories, downloads folders, base64-encoded strings,
 * and single-letter executables.
 * 包含暫存目錄、下載資料夾、base64 編碼字串和單字母執行檔。
 */
const SUSPICIOUS_PATTERNS: RegExp[] = [
  /\/tmp\//i,
  /\/temp\//i,
  /\/downloads\//i,
  /\\tmp\\/i,
  /\\temp\\/i,
  /\\downloads\\/i,
  /[A-Za-z0-9+/]{40,}={0,2}/, // Base64-encoded strings / Base64 編碼字串
  /\/[a-zA-Z](\s|$)/, // Single-letter executables in paths / 路徑中的單字母執行檔
  /\\[a-zA-Z]\.\w{2,4}(\s|$)/, // Single-letter executables on Windows / Windows 上的單字母執行檔
];

/**
 * Check if a string contains any suspicious patterns
 * 檢查字串是否包含任何可疑模式
 *
 * @param value - String to check / 要檢查的字串
 * @returns True if any suspicious pattern matches / 如果任何可疑模式匹配則為 true
 */
function isSuspicious(value: string): boolean {
  return SUSPICIOUS_PATTERNS.some((pattern) => pattern.test(value));
}

/**
 * Check scheduled tasks on macOS via launchctl
 * 透過 launchctl 檢查 macOS 上的排程任務
 *
 * Lists all launch agents/daemons and flags entries with suspicious paths
 * or characteristics.
 * 列出所有啟動代理/守護行程，並標記具有可疑路徑或特徵的條目。
 *
 * @returns Array of findings for suspicious macOS tasks / macOS 可疑任務的發現陣列
 */
async function checkMacOSTasks(): Promise<Finding[]> {
  const findings: Finding[] = [];
  let findingCounter = 1;

  const output = await safeExecFile('launchctl', ['list']);
  if (!output) {
    logger.warn('launchctl list returned no output');
    return findings;
  }

  const lines = output.split('\n').slice(1); // Skip header / 跳過標頭

  for (const line of lines) {
    const parts = line.trim().split(/\t+/);
    if (parts.length < 3) continue;

    const label = (parts[2] ?? '').trim();
    if (!label) continue;

    // Check for suspicious labels/paths
    // 檢查可疑的標籤/路徑
    if (isSuspicious(label)) {
      findings.push({
        id: `SCAN-TASK-${String(findingCounter).padStart(3, '0')}`,
        title: `Suspicious scheduled task: ${label} / ` + `可疑的排程任務：${label}`,
        description:
          `The launch agent/daemon "${label}" has characteristics associated with ` +
          'potentially suspicious activity (e.g., paths in temp/downloads directories, ' +
          'base64-encoded strings, or single-letter executables). / ' +
          `啟動代理/守護行程「${label}」具有與潛在可疑活動相關的特徵` +
          '（例如暫存/下載目錄中的路徑、base64 編碼字串或單字母執行檔）。',
        severity: 'medium',
        category: 'system',
        remediation:
          `Investigate the launch agent/daemon "${label}" and verify its legitimacy. ` +
          'Remove it if it is not recognized or not needed. / ' +
          `調查啟動代理/守護行程「${label}」並驗證其合法性。` +
          '如果不認識或不需要，請將其移除。',
        complianceRef: '4.6',
        details: `launchctl label: ${label}`,
      });
      findingCounter++;
    }
  }

  return findings;
}

/**
 * Check scheduled tasks on Linux via crontab and /etc/cron.d/
 * 透過 crontab 和 /etc/cron.d/ 檢查 Linux 上的排程任務
 *
 * Reads the current user's crontab and system cron.d files, flagging
 * entries with suspicious paths or commands.
 * 讀取目前使用者的 crontab 和系統 cron.d 檔案，標記具有可疑路徑或命令的條目。
 *
 * @returns Array of findings for suspicious Linux cron tasks / Linux 可疑 cron 任務的發現陣列
 */
async function checkLinuxTasks(): Promise<Finding[]> {
  const findings: Finding[] = [];
  let findingCounter = 1;

  // Check user crontab
  // 檢查使用者 crontab
  const crontabOutput = await safeExecFile('crontab', ['-l']);
  if (crontabOutput) {
    const lines = crontabOutput.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      // Skip comments and empty lines
      // 跳過註解和空行
      if (!trimmed || trimmed.startsWith('#')) continue;

      if (isSuspicious(trimmed)) {
        findings.push({
          id: `SCAN-TASK-${String(findingCounter).padStart(3, '0')}`,
          title: `Suspicious cron job detected / ` + `偵測到可疑的 cron 工作`,
          description:
            `A cron job entry contains suspicious patterns (temp/downloads paths, ` +
            'base64-encoded strings, or single-letter executables). / ' +
            `cron 工作條目包含可疑模式（暫存/下載路徑、base64 編碼字串或單字母執行檔）。`,
          severity: 'medium',
          category: 'system',
          remediation:
            'Review this cron job entry and verify its purpose. ' +
            'Remove it if it is not legitimate. / ' +
            '審查此 cron 工作條目並驗證其用途。如果不合法，請將其移除。',
          complianceRef: '4.6',
          details: `Cron entry: ${trimmed}`,
        });
        findingCounter++;
      }
    }
  }

  // Check /etc/cron.d/ files
  // 檢查 /etc/cron.d/ 檔案
  try {
    const cronDirEntries = await readdir('/etc/cron.d');
    for (const entry of cronDirEntries) {
      try {
        const content = await readFile(`/etc/cron.d/${entry}`, 'utf-8');
        const lines = content.split('\n');

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;

          if (isSuspicious(trimmed)) {
            findings.push({
              id: `SCAN-TASK-${String(findingCounter).padStart(3, '0')}`,
              title:
                `Suspicious system cron job in /etc/cron.d/${entry} / ` +
                `在 /etc/cron.d/${entry} 中偵測到可疑的系統 cron 工作`,
              description:
                `A system cron job in /etc/cron.d/${entry} contains suspicious patterns ` +
                '(temp/downloads paths, base64-encoded strings, or single-letter executables). / ' +
                `/etc/cron.d/${entry} 中的系統 cron 工作包含可疑模式` +
                '（暫存/下載路徑、base64 編碼字串或單字母執行檔）。',
              severity: 'medium',
              category: 'system',
              remediation:
                `Review the cron job in /etc/cron.d/${entry} and verify its legitimacy. ` +
                'Remove the entry or file if it is not recognized. / ' +
                `審查 /etc/cron.d/${entry} 中的 cron 工作並驗證其合法性。` +
                '如果不認識，請移除條目或檔案。',
              complianceRef: '4.6',
              details: `File: /etc/cron.d/${entry}, Entry: ${trimmed}`,
            });
            findingCounter++;
          }
        }
      } catch {
        logger.debug(`Could not read /etc/cron.d/${entry}`);
      }
    }
  } catch {
    logger.debug('Could not read /etc/cron.d/ directory');
  }

  return findings;
}

/**
 * Check scheduled tasks on Windows via schtasks
 * 透過 schtasks 檢查 Windows 上的排程任務
 *
 * Queries all scheduled tasks and flags those with suspicious paths
 * (e.g., temp directories, downloads folders).
 * 查詢所有排程任務並標記具有可疑路徑的任務（例如暫存目錄、下載資料夾）。
 *
 * @returns Array of findings for suspicious Windows tasks / Windows 可疑任務的發現陣列
 */
async function checkWindowsTasks(): Promise<Finding[]> {
  const findings: Finding[] = [];
  let findingCounter = 1;

  const output = await safeExecFile('schtasks', ['/query', '/fo', 'csv', '/nh']);
  if (!output) {
    logger.warn('schtasks /query returned no output');
    return findings;
  }

  const lines = output.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // CSV format: "TaskName","Next Run Time","Status"
    // CSV 格式："TaskName","Next Run Time","Status"
    const parts = trimmed.split('","').map((p) => p.replace(/^"|"$/g, ''));
    const taskName = parts[0] ?? '';

    if (!taskName) continue;

    if (isSuspicious(taskName)) {
      findings.push({
        id: `SCAN-TASK-${String(findingCounter).padStart(3, '0')}`,
        title: `Suspicious scheduled task: ${taskName} / ` + `可疑的排程任務：${taskName}`,
        description:
          `The Windows scheduled task "${taskName}" has characteristics associated ` +
          'with potentially suspicious activity (e.g., paths in temp/downloads directories, ' +
          'base64-encoded strings, or single-letter executables). / ' +
          `Windows 排程任務「${taskName}」具有與潛在可疑活動相關的特徵` +
          '（例如暫存/下載目錄中的路徑、base64 編碼字串或單字母執行檔）。',
        severity: 'medium',
        category: 'system',
        remediation:
          `Investigate the scheduled task "${taskName}" and verify its legitimacy. ` +
          'Disable or remove it if it is not recognized. / ' +
          `調查排程任務「${taskName}」並驗證其合法性。` +
          '如果不認識，請停用或移除。',
        complianceRef: '4.6',
        details: `Task: ${trimmed}`,
      });
      findingCounter++;
    }
  }

  return findings;
}

/**
 * Check for suspicious scheduled tasks on the current platform
 * 檢查目前平台上的可疑排程任務
 *
 * Cross-platform scheduled task checker that dispatches to the appropriate
 * platform-specific implementation.
 * 跨平台排程任務檢查器，分派到適當的平台特定實作。
 *
 * @returns Array of findings for suspicious scheduled tasks / 可疑排程任務的發現陣列
 */
export async function checkScheduledTasks(): Promise<Finding[]> {
  const currentPlatform = osPlatform();

  logger.info(`Checking scheduled tasks on ${currentPlatform}`);

  try {
    let findings: Finding[] = [];

    switch (currentPlatform) {
      case 'darwin':
        findings = await checkMacOSTasks();
        break;
      case 'linux':
        findings = await checkLinuxTasks();
        break;
      case 'win32':
        findings = await checkWindowsTasks();
        break;
      default:
        logger.warn(`Unsupported platform for scheduled task check: ${currentPlatform}`);
        return [];
    }

    logger.info(`Scheduled tasks check complete: ${findings.length} finding(s)`);
    return findings;
  } catch (err) {
    logger.error('Scheduled tasks check failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
}
