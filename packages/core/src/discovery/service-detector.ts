/**
 * Running services detection
 * 執行中服務偵測
 *
 * Detects and enumerates running services across macOS, Linux, and Windows
 * using platform-specific service management commands.
 * 使用平台特定的服務管理命令，跨 macOS、Linux 和 Windows 偵測並列舉執行中的服務。
 *
 * @module @panguard-ai/core/discovery/service-detector
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { platform as osPlatform } from 'os';
import { createLogger } from '../utils/logger.js';
import type { ServiceInfo } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('discovery:services');

/**
 * Safely execute a command and return stdout, or empty string on failure
 * 安全地執行命令並回傳 stdout，失敗時回傳空字串
 *
 * @param cmd - Command to execute / 要執行的命令
 * @param args - Command arguments / 命令參數
 * @returns stdout output trimmed / 修剪後的 stdout 輸出
 */
async function safeExec(cmd: string, args: string[]): Promise<string> {
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
 * Detect running services on macOS via launchctl
 * 透過 launchctl 偵測 macOS 上的執行中服務
 *
 * Parses the output of 'launchctl list' which returns:
 * PID  Status  Label
 * 解析 'launchctl list' 的輸出，格式為：
 * PID  Status  Label
 *
 * @returns Array of detected services / 偵測到的服務陣列
 */
async function detectMacOSServices(): Promise<ServiceInfo[]> {
  const services: ServiceInfo[] = [];

  const output = await safeExec('launchctl', ['list']);
  if (!output) {
    logger.warn('launchctl list returned no output');
    return services;
  }

  const lines = output.split('\n').slice(1); // Skip header / 跳過標頭

  for (const line of lines) {
    const parts = line.trim().split(/\t+/);
    if (parts.length < 3) continue;

    const pidStr = (parts[0] ?? '').trim();
    const statusStr = (parts[1] ?? '').trim();
    const label = (parts[2] ?? '').trim();

    // Skip empty labels or Apple internal services with very long names
    // 跳過空標籤或名稱很長的 Apple 內部服務
    if (!label) continue;

    const pid = pidStr === '-' ? undefined : parseInt(pidStr, 10);
    const isRunning = pid !== undefined && !isNaN(pid);

    // Derive a display name from the label
    // 從標籤衍生顯示名稱
    const displayName = label.split('.').pop() ?? label;

    services.push({
      name: label,
      displayName,
      status: isRunning ? 'running' : statusStr === '0' ? 'stopped' : 'unknown',
      pid: isRunning ? pid : undefined,
      startType: undefined,
      description: undefined,
    });
  }

  return services;
}

/**
 * Detect running services on Linux via systemctl
 * 透過 systemctl 偵測 Linux 上的執行中服務
 *
 * Parses the output of 'systemctl list-units --type=service --state=running'.
 * 解析 'systemctl list-units --type=service --state=running' 的輸出。
 *
 * @returns Array of detected services / 偵測到的服務陣列
 */
async function detectLinuxServices(): Promise<ServiceInfo[]> {
  const services: ServiceInfo[] = [];

  const output = await safeExec('systemctl', [
    'list-units',
    '--type=service',
    '--state=running',
    '--no-pager',
    '--plain',
  ]);

  if (!output) {
    logger.warn('systemctl list-units returned no output');
    return services;
  }

  const lines = output.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines, header, and footer
    // 跳過空行、標頭和尾部
    if (!trimmed || trimmed.startsWith('UNIT') || trimmed.startsWith('LOAD')) continue;
    if (trimmed.includes('loaded units listed')) continue;

    // Format: UNIT LOAD ACTIVE SUB DESCRIPTION
    // 格式：UNIT LOAD ACTIVE SUB DESCRIPTION
    const parts = trimmed.split(/\s+/);
    if (parts.length < 4) continue;

    const unitName = parts[0] ?? '';
    const active = parts[2] ?? '';
    const sub = parts[3] ?? '';
    if (!unitName) continue;

    // Extract service name without .service suffix
    // 擷取不含 .service 後綴的服務名稱
    const serviceName = unitName.replace(/\.service$/, '');

    // Description is everything after the 4th column
    // 描述是第四欄之後的所有內容
    const description = parts.slice(4).join(' ') || undefined;

    services.push({
      name: serviceName,
      displayName: serviceName,
      status: active === 'active' && sub === 'running' ? 'running' : 'stopped',
      pid: undefined,
      startType: undefined,
      description,
    });
  }

  // Try to get PIDs for running services
  // 嘗試取得執行中服務的 PID
  for (const service of services) {
    if (service.status === 'running') {
      const showOutput = await safeExec('systemctl', [
        'show',
        `${service.name}.service`,
        '--property=MainPID',
        '--no-pager',
      ]);
      if (showOutput) {
        const match = showOutput.match(/MainPID=(\d+)/);
        if (match?.[1]) {
          const pid = parseInt(match[1], 10);
          if (pid > 0) {
            service.pid = pid;
          }
        }
      }
    }
  }

  return services;
}

/**
 * Detect running services on Windows via sc query
 * 透過 sc query 偵測 Windows 上的執行中服務
 *
 * Parses the output of 'sc query state= all'.
 * 解析 'sc query state= all' 的輸出。
 *
 * @returns Array of detected services / 偵測到的服務陣列
 */
async function detectWindowsServices(): Promise<ServiceInfo[]> {
  const services: ServiceInfo[] = [];

  const output = await safeExec('sc', ['query', 'state=', 'all']);

  if (!output) {
    // Fallback to 'net start' for running services only
    // 備用：使用 'net start' 僅取得執行中服務
    const netOutput = await safeExec('net', ['start']);
    if (netOutput) {
      const lines = netOutput.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (
          trimmed &&
          !trimmed.startsWith('These Windows services') &&
          !trimmed.startsWith('The command completed')
        ) {
          services.push({
            name: trimmed,
            displayName: trimmed,
            status: 'running',
            pid: undefined,
            startType: undefined,
            description: undefined,
          });
        }
      }
    }
    return services;
  }

  // Parse sc query output blocks
  // 解析 sc query 輸出區塊
  const blocks = output.split(/\n\n+/);

  for (const block of blocks) {
    const lines = block.trim().split('\n');
    if (lines.length < 3) continue;

    let name = '';
    let displayName = '';
    let status: ServiceInfo['status'] = 'unknown';
    let pid: number | undefined;

    for (const line of lines) {
      const trimmed = line.trim();

      const nameMatch = trimmed.match(/^SERVICE_NAME:\s*(.+)/i);
      if (nameMatch?.[1]) {
        name = nameMatch[1].trim();
        continue;
      }

      const displayMatch = trimmed.match(/^DISPLAY_NAME:\s*(.+)/i);
      if (displayMatch?.[1]) {
        displayName = displayMatch[1].trim();
        continue;
      }

      const stateMatch = trimmed.match(/STATE\s*:\s*\d+\s+(\w+)/i);
      if (stateMatch?.[1]) {
        const stateStr = stateMatch[1].toUpperCase();
        if (stateStr === 'RUNNING') {
          status = 'running';
        } else if (stateStr === 'STOPPED') {
          status = 'stopped';
        } else {
          status = 'unknown';
        }
        continue;
      }

      const pidMatch = trimmed.match(/PID\s*:\s*(\d+)/i);
      if (pidMatch?.[1]) {
        const parsedPid = parseInt(pidMatch[1], 10);
        if (parsedPid > 0) {
          pid = parsedPid;
        }
      }
    }

    if (name) {
      services.push({
        name,
        displayName: displayName || name,
        status,
        pid,
        startType: undefined,
        description: undefined,
      });
    }
  }

  return services;
}

/**
 * Detect all running services on the current platform
 * 偵測目前平台上所有執行中的服務
 *
 * Dispatches to platform-specific detection methods:
 * - macOS: launchctl list
 * - Linux: systemctl list-units
 * - Windows: sc query / net start
 * 分派到平台特定的偵測方法：
 * - macOS：launchctl list
 * - Linux：systemctl list-units
 * - Windows：sc query / net start
 *
 * @returns Array of detected services / 偵測到的服務陣列
 */
export async function detectServices(): Promise<ServiceInfo[]> {
  const currentPlatform = osPlatform();

  logger.info(`Detecting services on ${currentPlatform}`);

  try {
    let services: ServiceInfo[] = [];

    switch (currentPlatform) {
      case 'darwin':
        services = await detectMacOSServices();
        break;
      case 'linux':
        services = await detectLinuxServices();
        break;
      case 'win32':
        services = await detectWindowsServices();
        break;
      default:
        logger.warn(`Unsupported platform for service detection: ${currentPlatform}`);
        return [];
    }

    logger.info(
      `Detected ${services.length} services (${services.filter((s) => s.status === 'running').length} running)`
    );
    return services;
  } catch (err) {
    logger.error('Service detection failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
}
