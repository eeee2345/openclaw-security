/**
 * Firewall status checker
 * 防火牆狀態檢查器
 *
 * Checks firewall status and retrieves active rules across macOS, Linux,
 * and Windows using platform-specific firewall management commands.
 * 使用平台特定的防火牆管理命令，跨 macOS、Linux 和 Windows 檢查防火牆狀態並擷取啟用規則。
 *
 * @module @panguard-ai/core/discovery/firewall-checker
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { platform as osPlatform } from 'os';
import { createLogger } from '../utils/logger.js';
import type { FirewallStatus, FirewallRule } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('discovery:firewall');

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
 * Check macOS Application Firewall (ALF) status
 * 檢查 macOS 應用程式防火牆 (ALF) 狀態
 *
 * Uses socketfilterfw to check global state and defaults read for detailed config.
 * 使用 socketfilterfw 檢查全域狀態，並使用 defaults read 取得詳細配置。
 *
 * @returns Firewall status for macOS / macOS 防火牆狀態
 */
async function checkMacOSFirewall(): Promise<FirewallStatus> {
  let enabled = false;
  const rules: FirewallRule[] = [];

  // Method 1: Use socketfilterfw --getglobalstate
  // 方法 1：使用 socketfilterfw --getglobalstate
  const sfwOutput = await safeExec('/usr/libexec/ApplicationFirewall/socketfilterfw', [
    '--getglobalstate',
  ]);

  if (sfwOutput) {
    enabled = sfwOutput.toLowerCase().includes('enabled');
    logger.info(`macOS firewall (socketfilterfw): ${enabled ? 'enabled' : 'disabled'}`);
  } else {
    // Method 2: Read from defaults
    // 方法 2：從 defaults 讀取
    const defaultsOutput = await safeExec('defaults', [
      'read',
      '/Library/Preferences/com.apple.alf',
      'globalstate',
    ]);

    if (defaultsOutput) {
      // globalstate: 0 = off, 1 = on (specific services), 2 = on (essential services only)
      // globalstate：0 = 關閉，1 = 開啟（特定服務），2 = 開啟（僅基本服務）
      const state = parseInt(defaultsOutput, 10);
      enabled = state > 0;
      logger.info(`macOS firewall (defaults): globalstate=${state}, enabled=${enabled}`);
    }
  }

  // Try to list allowed/blocked apps via socketfilterfw
  // 嘗試透過 socketfilterfw 列出允許/封鎖的應用程式
  const listOutput = await safeExec('/usr/libexec/ApplicationFirewall/socketfilterfw', [
    '--listapps',
  ]);

  if (listOutput) {
    const lines = listOutput.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();

      // Lines like: "Allow incoming connections" or "Block incoming connections"
      // 行內容如："Allow incoming connections" 或 "Block incoming connections"
      if (
        trimmed.includes('Allow incoming connections') ||
        trimmed.includes('Block incoming connections')
      ) {
        // The previous line typically has the app path
        // 前一行通常包含應用程式路徑
        continue;
      }

      // Match app entries: index  app-path  (Allow/Block incoming connections)
      // 比對應用程式條目：index  app-path  (Allow/Block incoming connections)
      const appMatch = trimmed.match(/^\d+\s*:\s*(.+)$/);
      if (appMatch?.[1]) {
        const appPath = appMatch[1].trim();
        // Check the next relevant context to determine if allow/block
        // 檢查下一個相關上下文以判斷允許/封鎖
        const appName = appPath.split('/').pop() ?? appPath;
        const isAllow = !trimmed.toLowerCase().includes('block');

        rules.push({
          name: appName,
          direction: 'in',
          action: isAllow ? 'allow' : 'block',
          protocol: undefined,
          port: undefined,
          enabled: true,
        });
      }
    }
  }

  // Check stealth mode
  // 檢查隱身模式
  const stealthOutput = await safeExec('/usr/libexec/ApplicationFirewall/socketfilterfw', [
    '--getstealthmode',
  ]);

  if (stealthOutput && stealthOutput.toLowerCase().includes('enabled')) {
    rules.push({
      name: 'Stealth Mode',
      direction: 'in',
      action: 'block',
      protocol: 'icmp',
      port: undefined,
      enabled: true,
    });
  }

  return {
    enabled,
    product: 'macOS Application Firewall (ALF)',
    rules,
  };
}

/**
 * Check Linux firewall status (iptables / ufw)
 * 檢查 Linux 防火牆狀態（iptables / ufw）
 *
 * Tries ufw first, then falls back to iptables.
 * 優先嘗試 ufw，然後回退到 iptables。
 *
 * @returns Firewall status for Linux / Linux 防火牆狀態
 */
async function checkLinuxFirewall(): Promise<FirewallStatus> {
  let enabled = false;
  const rules: FirewallRule[] = [];
  let product = 'iptables';

  // Try ufw first
  // 優先嘗試 ufw
  const ufwOutput = await safeExec('ufw', ['status', 'verbose']);

  if (ufwOutput) {
    product = 'ufw';
    enabled = ufwOutput.toLowerCase().includes('status: active');
    logger.info(`Linux firewall (ufw): ${enabled ? 'active' : 'inactive'}`);

    if (enabled) {
      const lines = ufwOutput.split('\n');
      let inRulesSection = false;

      for (const line of lines) {
        const trimmed = line.trim();

        // Detect the rules section header
        // 偵測規則區段標頭
        if (trimmed.startsWith('--')) {
          inRulesSection = true;
          continue;
        }

        if (!inRulesSection || !trimmed) continue;

        // Parse ufw rule lines like:
        // 22/tcp    ALLOW IN    Anywhere
        // 80/tcp    DENY IN     Anywhere
        // 解析 ufw 規則行，格式如：
        // 22/tcp    ALLOW IN    Anywhere
        // 80/tcp    DENY IN     Anywhere
        const ruleMatch = trimmed.match(/^(\S+)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)/i);
        if (ruleMatch?.[1] && ruleMatch[2] && ruleMatch[3]) {
          const target = ruleMatch[1];
          const action = ruleMatch[2].toUpperCase();
          const direction = ruleMatch[3].toUpperCase();

          // Parse port/protocol from target
          // 從目標解析埠/協定
          const portProtoMatch = target.match(/^(\d+(?::\d+)?)\/(tcp|udp)$/i);
          const port = portProtoMatch?.[1];
          const protocol = portProtoMatch?.[2]?.toLowerCase();

          rules.push({
            name: `ufw-${target}`,
            direction: direction === 'IN' ? 'in' : 'out',
            action: action === 'ALLOW' || action === 'LIMIT' ? 'allow' : 'block',
            protocol,
            port,
            enabled: true,
          });
        }
      }
    }

    return { enabled, product, rules };
  }

  // Fallback: check iptables
  // 備用：檢查 iptables
  const iptablesOutput = await safeExec('iptables', ['-L', '-n', '--line-numbers']);

  if (iptablesOutput) {
    product = 'iptables';
    // If iptables has any non-default rules, consider it enabled
    // 如果 iptables 有任何非預設規則，視為已啟用
    const lines = iptablesOutput.split('\n');
    const ruleLines = lines.filter(
      (l) => l.trim() && !l.startsWith('Chain') && !l.startsWith('num') && !l.startsWith('target')
    );
    enabled = ruleLines.length > 0;

    logger.info(`Linux firewall (iptables): ${enabled ? 'rules present' : 'no rules'}`);

    // Parse iptables rules
    // 解析 iptables 規則
    let currentChain = '';

    for (const line of lines) {
      const chainMatch = line.match(/^Chain\s+(\w+)/);
      if (chainMatch?.[1]) {
        currentChain = chainMatch[1];
        continue;
      }

      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('num') || trimmed.startsWith('target')) continue;

      const parts = trimmed.split(/\s+/);
      if (parts.length < 4) continue;

      const num = parts[0] ?? '0';
      const target = parts[1] ?? '';
      const proto = parts[2] ?? '';
      const dpt = trimmed.match(/dpt:(\d+)/);

      if (target === 'ACCEPT' || target === 'DROP' || target === 'REJECT') {
        rules.push({
          name: `${currentChain}-rule-${num}`,
          direction: currentChain === 'INPUT' ? 'in' : currentChain === 'OUTPUT' ? 'out' : 'in',
          action: target === 'ACCEPT' ? 'allow' : 'block',
          protocol: proto === 'all' ? undefined : proto,
          port: dpt?.[1],
          enabled: true,
        });
      }
    }
  } else {
    // Check nftables as another fallback
    // 檢查 nftables 作為另一個備用方案
    const nftOutput = await safeExec('nft', ['list', 'ruleset']);
    if (nftOutput) {
      product = 'nftables';
      enabled = nftOutput.includes('chain') && nftOutput.includes('rule');
      logger.info(`Linux firewall (nftables): ${enabled ? 'rules present' : 'no rules'}`);
    }
  }

  return { enabled, product, rules };
}

/**
 * Check Windows Firewall status via netsh
 * 透過 netsh 檢查 Windows 防火牆狀態
 *
 * Uses 'netsh advfirewall show allprofiles' to check status.
 * 使用 'netsh advfirewall show allprofiles' 檢查狀態。
 *
 * @returns Firewall status for Windows / Windows 防火牆狀態
 */
async function checkWindowsFirewall(): Promise<FirewallStatus> {
  let enabled = false;
  const rules: FirewallRule[] = [];

  const output = await safeExec('netsh', ['advfirewall', 'show', 'allprofiles']);

  if (output) {
    // Check if any profile has the firewall ON
    // 檢查是否有任何設定檔已開啟防火牆
    enabled = output.toLowerCase().includes('state                                 on');
    logger.info(`Windows Firewall: ${enabled ? 'enabled' : 'disabled'}`);

    // Get firewall rules
    // 取得防火牆規則
    const rulesOutput = await safeExec('netsh', [
      'advfirewall',
      'firewall',
      'show',
      'rule',
      'name=all',
    ]);

    if (rulesOutput) {
      // Parse rule blocks separated by blank lines
      // 解析以空行分隔的規則區塊
      const blocks = rulesOutput.split(/\n\s*\n/);

      for (const block of blocks) {
        if (!block.trim()) continue;

        let name = '';
        let direction: 'in' | 'out' = 'in';
        let action: 'allow' | 'block' = 'allow';
        let protocol: string | undefined;
        let port: string | undefined;
        let ruleEnabled = true;

        const lines = block.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();

          const nameMatch = trimmed.match(/^Rule Name:\s*(.+)/i);
          if (nameMatch?.[1]) name = nameMatch[1].trim();

          const dirMatch = trimmed.match(/^Direction:\s*(.+)/i);
          if (dirMatch?.[1]) direction = dirMatch[1].trim().toLowerCase() === 'out' ? 'out' : 'in';

          const actMatch = trimmed.match(/^Action:\s*(.+)/i);
          if (actMatch?.[1])
            action = actMatch[1].trim().toLowerCase() === 'block' ? 'block' : 'allow';

          const protoMatch = trimmed.match(/^Protocol:\s*(.+)/i);
          if (protoMatch?.[1]) {
            const p = protoMatch[1].trim().toLowerCase();
            protocol = p === 'any' ? undefined : p;
          }

          const portMatch = trimmed.match(/^LocalPort:\s*(.+)/i);
          if (portMatch?.[1]) {
            const p = portMatch[1].trim();
            port = p === 'Any' ? undefined : p;
          }

          const enabledMatch = trimmed.match(/^Enabled:\s*(.+)/i);
          if (enabledMatch?.[1]) ruleEnabled = enabledMatch[1].trim().toLowerCase() === 'yes';
        }

        if (name) {
          rules.push({
            name,
            direction,
            action,
            protocol,
            port,
            enabled: ruleEnabled,
          });
        }
      }
    }
  }

  return {
    enabled,
    product: 'Windows Defender Firewall',
    rules,
  };
}

/**
 * Check firewall status on the current platform
 * 檢查目前平台的防火牆狀態
 *
 * Dispatches to platform-specific firewall check methods:
 * - macOS: socketfilterfw / defaults read
 * - Linux: ufw / iptables / nftables
 * - Windows: netsh advfirewall
 * 分派到平台特定的防火牆檢查方法：
 * - macOS：socketfilterfw / defaults read
 * - Linux：ufw / iptables / nftables
 * - Windows：netsh advfirewall
 *
 * @returns Firewall status and rules / 防火牆狀態和規則
 */
export async function checkFirewall(): Promise<FirewallStatus> {
  const currentPlatform = osPlatform();

  logger.info(`Checking firewall on ${currentPlatform}`);

  try {
    switch (currentPlatform) {
      case 'darwin':
        return await checkMacOSFirewall();
      case 'linux':
        return await checkLinuxFirewall();
      case 'win32':
        return await checkWindowsFirewall();
      default:
        logger.warn(`Unsupported platform for firewall check: ${currentPlatform}`);
        return {
          enabled: false,
          product: 'unknown',
          rules: [],
        };
    }
  } catch (err) {
    logger.error('Firewall check failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return {
      enabled: false,
      product: 'unknown',
      rules: [],
    };
  }
}
