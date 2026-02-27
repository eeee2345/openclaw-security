/**
 * Shared folders checker
 * 共用資料夾檢查器
 *
 * Checks for shared network folders that may expose sensitive data to
 * unauthorized users. Supports macOS (sharing), Linux (Samba), and
 * Windows (net share).
 * 檢查可能將敏感資料暴露給未授權使用者的共用網路資料夾。
 * 支援 macOS (sharing)、Linux (Samba) 和 Windows (net share)。
 *
 * @module @panguard-ai/panguard-scan/scanners/shared-folders
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { platform as osPlatform } from 'os';
import { createLogger } from '@panguard-ai/core';
import type { Finding } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('panguard-scan:shared-folders');

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
 * Default Windows administrative shares that are expected and safe to ignore
 * 預設的 Windows 管理共用，可以安全忽略
 */
const DEFAULT_ADMIN_SHARES = new Set(['C$', 'D$', 'E$', 'IPC$', 'ADMIN$']);

/**
 * Check shared folders on macOS via the sharing command
 * 透過 sharing 命令檢查 macOS 上的共用資料夾
 *
 * Lists all shares and flags those with 'everyone' access.
 * 列出所有共用並標記具有 'everyone' 存取權的共用。
 *
 * @returns Array of findings for macOS shared folders / macOS 共用資料夾的發現陣列
 */
async function checkMacOSShares(): Promise<Finding[]> {
  const findings: Finding[] = [];
  let findingCounter = 1;

  const output = await safeExecFile('sharing', ['-l']);
  if (!output) {
    logger.info('No shared folders found on macOS (sharing -l returned no output)');
    return findings;
  }

  // Parse sharing -l output - blocks separated by share entries
  // 解析 sharing -l 輸出 - 以共用條目分隔的區塊
  const lines = output.split('\n');
  let currentShareName = '';
  let currentSharePath = '';
  let hasEveryoneAccess = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Detect share name
    // 偵測共用名稱
    const nameMatch = trimmed.match(/^name:\s*(.+)/i);
    if (nameMatch?.[1]) {
      // Process previous share if it had everyone access
      // 如果前一個共用有 everyone 存取權則處理
      if (currentShareName && hasEveryoneAccess) {
        findings.push(
          createShareFinding(findingCounter++, currentShareName, currentSharePath, 'macOS')
        );
      }
      currentShareName = nameMatch[1].trim();
      currentSharePath = '';
      hasEveryoneAccess = false;
      continue;
    }

    // Detect share path
    // 偵測共用路徑
    const pathMatch = trimmed.match(/^path:\s*(.+)/i);
    if (pathMatch?.[1]) {
      currentSharePath = pathMatch[1].trim();
      continue;
    }

    // Check for everyone/guest access
    // 檢查 everyone/guest 存取權
    if (trimmed.toLowerCase().includes('everyone') || trimmed.toLowerCase().includes('guest')) {
      hasEveryoneAccess = true;
    }
  }

  // Process last share
  // 處理最後一個共用
  if (currentShareName && hasEveryoneAccess) {
    findings.push(
      createShareFinding(findingCounter++, currentShareName, currentSharePath, 'macOS')
    );
  }

  return findings;
}

/**
 * Check shared folders on Linux via Samba configuration
 * 透過 Samba 配置檢查 Linux 上的共用資料夾
 *
 * Reads /etc/samba/smb.conf and flags shares with guest ok or public access.
 * 讀取 /etc/samba/smb.conf 並標記具有訪客或公開存取權的共用。
 *
 * @returns Array of findings for Linux Samba shares / Linux Samba 共用的發現陣列
 */
async function checkLinuxShares(): Promise<Finding[]> {
  const findings: Finding[] = [];
  let findingCounter = 1;

  let smbConf: string;
  try {
    smbConf = await readFile('/etc/samba/smb.conf', 'utf-8');
  } catch {
    logger.debug('Could not read /etc/samba/smb.conf - Samba may not be installed');
    return findings;
  }

  // Parse smb.conf sections
  // 解析 smb.conf 區段
  const lines = smbConf.split('\n');
  let currentSection = '';
  let currentPath = '';
  let hasGuestAccess = false;

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip comments and empty lines
    // 跳過註解和空行
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;

    // Detect section headers
    // 偵測區段標頭
    const sectionMatch = trimmed.match(/^\[(.+)\]$/);
    if (sectionMatch?.[1]) {
      // Process previous section
      // 處理前一個區段
      if (currentSection && hasGuestAccess && currentSection !== 'global') {
        findings.push(createShareFinding(findingCounter++, currentSection, currentPath, 'Samba'));
      }
      currentSection = sectionMatch[1].trim();
      currentPath = '';
      hasGuestAccess = false;
      continue;
    }

    // Parse key = value pairs
    // 解析 key = value 對
    const kvMatch = trimmed.match(/^(\S+)\s*=\s*(.+)$/);
    if (kvMatch?.[1] && kvMatch[2]) {
      const key = kvMatch[1].toLowerCase();
      const value = kvMatch[2].trim().toLowerCase();

      if (key === 'path') {
        currentPath = kvMatch[2].trim();
      }

      // Check for guest/public access
      // 檢查訪客/公開存取
      if ((key === 'guest ok' && value === 'yes') || (key === 'public' && value === 'yes')) {
        hasGuestAccess = true;
      }
    }
  }

  // Process last section
  // 處理最後一個區段
  if (currentSection && hasGuestAccess && currentSection !== 'global') {
    findings.push(createShareFinding(findingCounter++, currentSection, currentPath, 'Samba'));
  }

  return findings;
}

/**
 * Check shared folders on Windows via net share
 * 透過 net share 檢查 Windows 上的共用資料夾
 *
 * Lists all network shares and flags non-default administrative shares.
 * 列出所有網路共用並標記非預設管理共用。
 *
 * @returns Array of findings for Windows shared folders / Windows 共用資料夾的發現陣列
 */
async function checkWindowsShares(): Promise<Finding[]> {
  const findings: Finding[] = [];
  let findingCounter = 1;

  const output = await safeExecFile('net', ['share']);
  if (!output) {
    logger.info('No shared folders found on Windows (net share returned no output)');
    return findings;
  }

  const lines = output.split('\n');
  let inShareSection = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Detect the separator line that precedes share entries
    // 偵測共用條目前的分隔線
    if (trimmed.startsWith('---')) {
      inShareSection = true;
      continue;
    }

    // Stop at the footer
    // 在尾部停止
    if (trimmed.startsWith('The command completed')) {
      break;
    }

    if (!inShareSection || !trimmed) continue;

    // Parse share entries - format: ShareName Resource Remark
    // 解析共用條目 - 格式：ShareName Resource Remark
    const parts = trimmed.split(/\s{2,}/);
    const shareName = (parts[0] ?? '').trim();
    const resource = (parts[1] ?? '').trim();

    if (!shareName) continue;

    // Skip default administrative shares
    // 跳過預設管理共用
    if (DEFAULT_ADMIN_SHARES.has(shareName)) continue;

    findings.push({
      id: `SCAN-SHARE-${String(findingCounter).padStart(3, '0')}`,
      title: `Network share found: ${shareName} / ` + `發現網路共用：${shareName}`,
      description:
        `A network share "${shareName}" is configured on this Windows system. ` +
        `Non-default shares may expose data to unauthorized network users. ` +
        `Path: ${resource || 'unknown'}. / ` +
        `在此 Windows 系統上配置了網路共用「${shareName}」。` +
        `非預設共用可能將資料暴露給未授權的網路使用者。` +
        `路徑：${resource || 'unknown'}。`,
      severity: 'medium',
      category: 'access',
      remediation:
        `Review the permissions on share "${shareName}" and ensure only authorized ` +
        'users have access. Remove the share if it is no longer needed. / ' +
        `審查共用「${shareName}」上的權限，並確保只有授權使用者有存取權。` +
        '如果不再需要，請移除共用。',
      complianceRef: '4.2',
      details: `Share: ${shareName}, Resource: ${resource || 'N/A'}`,
    });
    findingCounter++;
  }

  return findings;
}

/**
 * Create a standardized Finding for a shared folder with everyone/guest access
 * 為具有 everyone/guest 存取權的共用資料夾建立標準化的 Finding
 *
 * @param counter - Finding counter for ID generation / 用於 ID 生成的發現計數器
 * @param shareName - Name of the shared folder / 共用資料夾名稱
 * @param sharePath - Path of the shared folder / 共用資料夾路徑
 * @param platform - Platform descriptor (macOS, Samba, etc.) / 平台描述（macOS、Samba 等）
 * @returns A Finding for the insecure share / 不安全共用的 Finding
 */
function createShareFinding(
  counter: number,
  shareName: string,
  sharePath: string,
  platform: string
): Finding {
  return {
    id: `SCAN-SHARE-${String(counter).padStart(3, '0')}`,
    title:
      `Shared folder with open access: ${shareName} / ` +
      `具有開放存取權的共用資料夾：${shareName}`,
    description:
      `The ${platform} share "${shareName}" allows guest or everyone access. ` +
      'This may expose sensitive data to unauthorized users on the network. ' +
      `Path: ${sharePath || 'unknown'}. / ` +
      `${platform} 共用「${shareName}」允許訪客或所有人存取。` +
      '這可能將敏感資料暴露給網路上未授權的使用者。' +
      `路徑：${sharePath || 'unknown'}。`,
    severity: 'medium',
    category: 'access',
    remediation:
      `Restrict access to the share "${shareName}" by removing guest/everyone ` +
      'permissions and configuring explicit user or group-based access controls. / ' +
      `限制共用「${shareName}」的存取，移除訪客/所有人權限，` +
      '並配置明確的使用者或群組存取控制。',
    complianceRef: '4.2',
    details: `Share: ${shareName}, Path: ${sharePath || 'N/A'}, Platform: ${platform}`,
  };
}

/**
 * Check for insecure shared folders on the current platform
 * 檢查目前平台上的不安全共用資料夾
 *
 * Cross-platform shared folder checker that dispatches to the appropriate
 * platform-specific implementation.
 * 跨平台共用資料夾檢查器，分派到適當的平台特定實作。
 *
 * @returns Array of findings for shared folder issues / 共用資料夾問題的發現陣列
 */
export async function checkSharedFolders(): Promise<Finding[]> {
  const currentPlatform = osPlatform();

  logger.info(`Checking shared folders on ${currentPlatform}`);

  try {
    let findings: Finding[] = [];

    switch (currentPlatform) {
      case 'darwin':
        findings = await checkMacOSShares();
        break;
      case 'linux':
        findings = await checkLinuxShares();
        break;
      case 'win32':
        findings = await checkWindowsShares();
        break;
      default:
        logger.warn(`Unsupported platform for shared folder check: ${currentPlatform}`);
        return [];
    }

    logger.info(`Shared folders check complete: ${findings.length} finding(s)`);
    return findings;
  } catch (err) {
    logger.error('Shared folders check failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
}
