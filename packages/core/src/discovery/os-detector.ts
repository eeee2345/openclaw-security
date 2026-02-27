/**
 * Cross-platform OS detection
 * 跨平台作業系統偵測
 *
 * Detects operating system information including distribution, version,
 * architecture, kernel, and patch level across macOS, Linux, and Windows.
 * 偵測作業系統資訊，包括跨 macOS、Linux 和 Windows 的發行版、版本、架構、核心和修補等級。
 *
 * @module @panguard-ai/core/discovery/os-detector
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import {
  platform as osPlatform,
  arch as osArch,
  hostname as osHostname,
  uptime as osUptime,
  release as osRelease,
  type as osType,
} from 'os';
import { readFile } from 'fs/promises';
import { createLogger } from '../utils/logger.js';
import type { OSInfo } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('discovery:os');

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
    const { stdout } = await execFileAsync(cmd, args, { timeout: 10_000 });
    return stdout.trim();
  } catch (err) {
    logger.debug(`Command failed: ${cmd} ${args.join(' ')}`, {
      error: err instanceof Error ? err.message : String(err),
    });
    return '';
  }
}

/**
 * Detect macOS-specific OS information
 * 偵測 macOS 特定的作業系統資訊
 *
 * @returns Partial OSInfo with macOS-specific fields / 包含 macOS 特定欄位的部分 OSInfo
 */
async function detectMacOS(): Promise<Partial<OSInfo>> {
  const result: Partial<OSInfo> = { distro: 'macOS' };

  try {
    const productName = await safeExec('sw_vers', ['-productName']);
    const productVersion = await safeExec('sw_vers', ['-productVersion']);

    if (productName) {
      result.distro = productName;
    }
    if (productVersion) {
      result.version = productVersion;
    }
  } catch (err) {
    logger.warn('Failed to detect macOS version via sw_vers', {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  // Detect patch level via softwareupdate
  // 透過 softwareupdate 偵測修補等級
  try {
    const updateOutput = await safeExec('softwareupdate', ['-l']);
    if (updateOutput.includes('No new software available')) {
      result.patchLevel = 'up-to-date';
    } else {
      const lines = updateOutput.split('\n').filter((l) => l.includes('*'));
      result.patchLevel = lines.length > 0 ? `${lines.length} updates available` : 'unknown';
    }
  } catch {
    result.patchLevel = 'unknown';
  }

  return result;
}

/**
 * Detect Linux-specific OS information
 * 偵測 Linux 特定的作業系統資訊
 *
 * @returns Partial OSInfo with Linux-specific fields / 包含 Linux 特定欄位的部分 OSInfo
 */
async function detectLinux(): Promise<Partial<OSInfo>> {
  const result: Partial<OSInfo> = { distro: 'Linux' };

  // Try lsb_release first
  // 優先嘗試 lsb_release
  try {
    const lsbOutput = await safeExec('lsb_release', ['-a']);
    if (lsbOutput) {
      const descMatch = lsbOutput.match(/Description:\s*(.+)/);
      const releaseMatch = lsbOutput.match(/Release:\s*(.+)/);
      if (descMatch?.[1]) {
        result.distro = descMatch[1].trim();
      }
      if (releaseMatch?.[1]) {
        result.version = releaseMatch[1].trim();
      }
      return result;
    }
  } catch {
    // lsb_release not available, try /etc/os-release
    // lsb_release 不可用，嘗試 /etc/os-release
  }

  // Fallback: read /etc/os-release
  // 備用：讀取 /etc/os-release
  try {
    const osReleaseContent = await readFile('/etc/os-release', 'utf-8');
    const nameMatch = osReleaseContent.match(/^PRETTY_NAME="?(.+?)"?\s*$/m);
    const versionMatch = osReleaseContent.match(/^VERSION_ID="?(.+?)"?\s*$/m);

    if (nameMatch?.[1]) {
      result.distro = nameMatch[1];
    }
    if (versionMatch?.[1]) {
      result.version = versionMatch[1];
    }
  } catch {
    logger.warn('Failed to read /etc/os-release');
  }

  // Detect patch level
  // 偵測修補等級
  try {
    const kernelVersion = await safeExec('uname', ['-r']);
    result.patchLevel = kernelVersion || 'unknown';
  } catch {
    result.patchLevel = 'unknown';
  }

  return result;
}

/**
 * Detect Windows-specific OS information
 * 偵測 Windows 特定的作業系統資訊
 *
 * @returns Partial OSInfo with Windows-specific fields / 包含 Windows 特定欄位的部分 OSInfo
 */
async function detectWindows(): Promise<Partial<OSInfo>> {
  const result: Partial<OSInfo> = {
    distro: 'Windows',
    version: osRelease(),
  };

  try {
    const wmicOutput = await safeExec('wmic', ['os', 'get', 'Caption,Version', '/format:csv']);
    if (wmicOutput) {
      const lines = wmicOutput.split('\n').filter((l) => l.trim().length > 0);
      // CSV format: Node,Caption,Version
      // CSV 格式：Node,Caption,Version
      const lastLine = lines[lines.length - 1];
      if (lastLine) {
        const parts = lastLine.split(',');
        const caption = parts[1];
        const ver = parts[2];
        if (caption && ver) {
          result.distro = caption.trim();
          result.version = ver.trim();
        }
      }
    }
  } catch {
    logger.warn('Failed to detect Windows version via wmic');
  }

  // Detect patch level via systeminfo
  // 透過 systeminfo 偵測修補等級
  try {
    const sysinfoOutput = await safeExec('wmic', ['qfe', 'get', 'HotFixID', '/format:csv']);
    if (sysinfoOutput) {
      const hotfixes = sysinfoOutput
        .split('\n')
        .filter((l) => l.trim().length > 0 && !l.includes('HotFixID'))
        .map((l) => l.split(',').pop()?.trim())
        .filter((h): h is string => Boolean(h));
      const latest = hotfixes[hotfixes.length - 1];
      result.patchLevel =
        hotfixes.length > 0
          ? `${hotfixes.length} hotfixes installed (latest: ${latest ?? 'unknown'})`
          : 'unknown';
    }
  } catch {
    result.patchLevel = 'unknown';
  }

  return result;
}

/**
 * Detect comprehensive operating system information
 * 偵測完整的作業系統資訊
 *
 * Uses platform-specific commands to gather detailed OS information.
 * Falls back to Node.js os module data when commands fail.
 * 使用平台特定命令收集詳細的作業系統資訊。
 * 當命令失敗時，回退到 Node.js os 模組資料。
 *
 * @returns Complete OS information / 完整的作業系統資訊
 */
export async function detectOS(): Promise<OSInfo> {
  const currentPlatform = osPlatform();

  logger.info(`Detecting OS on platform: ${currentPlatform}`);

  // Build base info from Node.js os module
  // 從 Node.js os 模組建立基本資訊
  const baseInfo: OSInfo = {
    platform: currentPlatform,
    distro: osType(),
    version: osRelease(),
    arch: osArch(),
    kernel: osRelease(),
    hostname: osHostname(),
    uptime: osUptime(),
    patchLevel: 'unknown',
  };

  try {
    let platformSpecific: Partial<OSInfo> = {};

    switch (currentPlatform) {
      case 'darwin':
        platformSpecific = await detectMacOS();
        break;
      case 'linux':
        platformSpecific = await detectLinux();
        break;
      case 'win32':
        platformSpecific = await detectWindows();
        break;
      default:
        logger.warn(`Unsupported platform: ${currentPlatform}, using defaults`);
    }

    // Get kernel version on UNIX-like systems
    // 在類 UNIX 系統上取得核心版本
    if (currentPlatform === 'darwin' || currentPlatform === 'linux') {
      const kernelVersion = await safeExec('uname', ['-r']);
      if (kernelVersion) {
        baseInfo.kernel = kernelVersion;
      }
    }

    const result: OSInfo = {
      ...baseInfo,
      ...platformSpecific,
    };

    logger.info(`OS detected: ${result.distro} ${result.version}`, {
      platform: result.platform,
      arch: result.arch,
    });

    return result;
  } catch (err) {
    logger.error('OS detection failed, returning base info', {
      error: err instanceof Error ? err.message : String(err),
    });
    return baseInfo;
  }
}
