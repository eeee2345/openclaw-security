/**
 * Respond Agent - Execute response actions based on threat verdicts
 * 回應代理 - 根據威脅判決執行回應動作
 *
 * Third stage of the multi-agent pipeline. Determines and executes
 * the appropriate response action based on verdict confidence levels
 * and the configured action policy thresholds.
 * 多代理管線的第三階段。根據判決信心度和配置的動作策略閾值
 * 決定並執行適當的回應動作。
 *
 * Uses execFile (never exec) for all system commands to prevent
 * command injection vulnerabilities.
 * 所有系統命令使用 execFile（絕不使用 exec）以防止命令注入漏洞。
 *
 * @module @panguard-ai/panguard-guard/agent/respond-agent
 */

import { execFile } from 'node:child_process';
import { platform } from 'node:os';
import { createLogger } from '@panguard-ai/core';
import type {
  ThreatVerdict,
  ActionPolicy,
  ResponseResult,
  ResponseAction,
  GuardMode,
} from '../types.js';

const logger = createLogger('panguard-guard:respond-agent');

/**
 * Safety rules for auto-response actions
 * 自動回應動作的安全規則
 *
 * Prevents accidental self-lockout and system disruption.
 * 防止意外自鎖和系統中斷。
 */
const SAFETY_RULES = {
  /** IPs that must never be auto-blocked / 不可自動封鎖的 IP */
  whitelistedIPs: new Set(['127.0.0.1', '::1', 'localhost', '0.0.0.0']),

  /** Processes that must never be auto-killed / 不可自動終止的程序 */
  protectedProcesses: new Set([
    'sshd',
    'systemd',
    'init',
    'launchd',
    'loginwindow',
    'explorer.exe',
    'svchost.exe',
    'csrss.exe',
    'lsass.exe',
    'services.exe',
    'winlogon.exe',
    'wininit.exe',
    'panguard-guard',
    'node',
  ]),

  /** Accounts that must never be auto-disabled / 不可自動停用的帳號 */
  protectedAccounts: new Set(['root', 'Administrator', 'admin', 'SYSTEM', 'LocalSystem']),

  /** Max auto-block duration in ms (24 hours) / 最大自動封鎖時長 */
  maxAutoBlockDurationMs: 24 * 60 * 60 * 1000,

  /** Network isolation requires confidence >= 95 / 網路隔離需信心度 >= 95 */
  networkIsolationMinConfidence: 95,
} as const;

/**
 * Respond Agent determines and executes appropriate response actions
 * 回應代理決定並執行適當的回應動作
 */
export class RespondAgent {
  private readonly actionPolicy: ActionPolicy;
  private mode: GuardMode;
  private actionCount = 0;
  private readonly additionalWhitelistedIPs: Set<string>;

  /**
   * @param actionPolicy - Confidence thresholds for response levels / 回應等級的信心度閾值
   * @param mode - Current operating mode / 當前運作模式
   * @param whitelistedIPs - Additional user-configured whitelisted IPs / 使用者配置的額外白名單 IP
   */
  constructor(actionPolicy: ActionPolicy, mode: GuardMode, whitelistedIPs: string[] = []) {
    this.actionPolicy = actionPolicy;
    this.mode = mode;
    this.additionalWhitelistedIPs = new Set(whitelistedIPs);
  }

  /**
   * Update operating mode / 更新操作模式
   */
  setMode(mode: GuardMode): void {
    this.mode = mode;
  }

  /**
   * Execute response based on verdict
   * 根據判決執行回應
   *
   * Logic:
   * - Learning mode: always log_only (observation only)
   * - confidence >= autoRespond: execute recommended action
   * - confidence >= notifyAndWait: send notification only
   * - otherwise: log only
   *
   * 邏輯：
   * - 學習模式：總是僅記錄（僅觀察）
   * - 信心度 >= autoRespond：執行建議動作
   * - 信心度 >= notifyAndWait：僅發送通知
   * - 其他：僅記錄
   *
   * @param verdict - The threat verdict to respond to / 要回應的威脅判決
   * @returns ResponseResult with action outcome / 包含動作結果的回應結果
   */
  async respond(verdict: ThreatVerdict): Promise<ResponseResult> {
    // Learning mode: never take active response / 學習模式：不執行主動回應
    if (this.mode === 'learning') {
      logger.info('Learning mode: no response action taken / 學習模式: 未執行回應動作');
      return {
        action: 'log_only',
        success: true,
        details: 'Learning mode - observation only / 學習模式 - 僅觀察',
        timestamp: new Date().toISOString(),
      };
    }

    const { confidence } = verdict;

    // Auto-respond: execute the recommended action
    // 自動回應：執行建議的動作
    if (confidence >= this.actionPolicy.autoRespond) {
      logger.info(
        `Auto-responding (confidence ${confidence}% >= ${this.actionPolicy.autoRespond}%): ` +
          `${verdict.recommendedAction} / ` +
          `自動回應 (信心度 ${confidence}%): ${verdict.recommendedAction}`
      );
      return this.executeAction(verdict.recommendedAction, verdict);
    }

    // Notify: send alert but do not auto-execute
    // 通知：發送警報但不自動執行
    if (confidence >= this.actionPolicy.notifyAndWait) {
      logger.info(
        `Notify mode (confidence ${confidence}%): will notify user / ` +
          `通知模式 (信心度 ${confidence}%): 將通知用戶`
      );
      return {
        action: 'notify',
        success: true,
        details:
          `Notification sent. Verdict: ${verdict.conclusion}, ` +
          `recommended: ${verdict.recommendedAction} / 已發送通知`,
        timestamp: new Date().toISOString(),
      };
    }

    // Log only / 僅記錄
    logger.info(`Log only (confidence ${confidence}%) / 僅記錄 (信心度 ${confidence}%)`);
    return {
      action: 'log_only',
      success: true,
      details: `Logged: ${verdict.conclusion} (confidence: ${confidence}%) / 已記錄`,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Execute a specific response action / 執行特定回應動作
   */
  private async executeAction(
    action: ResponseAction,
    verdict: ThreatVerdict
  ): Promise<ResponseResult> {
    this.actionCount++;

    switch (action) {
      case 'block_ip':
        return this.blockIP(verdict);
      case 'kill_process':
        return this.killProcess(verdict);
      case 'disable_account':
        return this.disableAccount(verdict);
      case 'isolate_file':
        return this.isolateFile(verdict);
      case 'notify':
        return {
          action: 'notify',
          success: true,
          details: 'Notification dispatched / 已派發通知',
          timestamp: new Date().toISOString(),
        };
      default:
        return {
          action: 'log_only',
          success: true,
          details: 'Action logged / 動作已記錄',
          timestamp: new Date().toISOString(),
        };
    }
  }

  /**
   * Block an IP address using platform-specific firewall
   * 使用平台防火牆封鎖 IP
   */
  private async blockIP(verdict: ThreatVerdict): Promise<ResponseResult> {
    const ip = this.extractIP(verdict);
    if (!ip) {
      return {
        action: 'block_ip',
        success: false,
        details: 'No IP address found in verdict evidence / 判決證據中未找到 IP 地址',
        timestamp: new Date().toISOString(),
      };
    }

    // Safety: check whitelisted IPs / 安全：檢查白名單 IP
    if (SAFETY_RULES.whitelistedIPs.has(ip) || this.additionalWhitelistedIPs.has(ip)) {
      logger.warn(`Refusing to block whitelisted IP: ${ip} / 拒絕封鎖白名單 IP: ${ip}`);
      return {
        action: 'block_ip',
        success: false,
        details: `IP ${ip} is whitelisted and cannot be blocked / IP ${ip} 在白名單中，無法封鎖`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }

    // Validate IP format to prevent injection / 驗證 IP 格式以防止注入
    if (!/^[\d.]+$/.test(ip) && !/^[a-fA-F\d:]+$/.test(ip)) {
      return {
        action: 'block_ip',
        success: false,
        details: `Invalid IP format: ${ip} / 無效的 IP 格式`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }

    const os = platform();
    try {
      if (os === 'darwin') {
        // macOS: use pfctl (requires root)
        await execFilePromise('/sbin/pfctl', ['-t', 'panguard-guard_blocked', '-T', 'add', ip]);
      } else if (os === 'linux') {
        // Linux: use iptables
        await execFilePromise('/sbin/iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
      } else if (os === 'win32') {
        // Windows: use netsh
        await execFilePromise('netsh', [
          'advfirewall',
          'firewall',
          'add',
          'rule',
          `name=PanguardGuard_Block_${ip}`,
          'dir=in',
          'action=block',
          `remoteip=${ip}`,
        ]);
      }

      logger.info(`Blocked IP: ${ip} / 已封鎖 IP: ${ip}`);
      return {
        action: 'block_ip',
        success: true,
        details: `IP ${ip} blocked via ${os} firewall / 已透過 ${os} 防火牆封鎖 IP ${ip}`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to block IP ${ip}: ${msg} / 封鎖 IP 失敗: ${msg}`);
      return {
        action: 'block_ip',
        success: false,
        details: `Failed to block IP ${ip}: ${msg} / 封鎖失敗: ${msg}`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }
  }

  /**
   * Kill a process / 終止程序
   */
  private async killProcess(verdict: ThreatVerdict): Promise<ResponseResult> {
    const pid = this.extractPID(verdict);
    if (!pid) {
      return {
        action: 'kill_process',
        success: false,
        details: 'No PID found in verdict evidence / 判決證據中未找到 PID',
        timestamp: new Date().toISOString(),
      };
    }

    // Safety: check protected processes / 安全：檢查受保護程序
    const processName = this.extractProcessName(verdict);
    if (processName && SAFETY_RULES.protectedProcesses.has(processName)) {
      logger.warn(
        `Refusing to kill protected process: ${processName} (PID ${pid}) / ` +
          `拒絕終止受保護程序: ${processName} (PID ${pid})`
      );
      return {
        action: 'kill_process',
        success: false,
        details:
          `Process ${processName} is protected and cannot be killed / ` +
          `程序 ${processName} 受保護，無法終止`,
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    }

    // Safety: never kill our own process / 安全：不可終止自身程序
    if (pid === process.pid) {
      logger.warn('Refusing to kill own process / 拒絕終止自身程序');
      return {
        action: 'kill_process',
        success: false,
        details: 'Cannot kill own process / 無法終止自身程序',
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    }

    try {
      process.kill(pid, 'SIGTERM');
      logger.info(`Terminated process PID ${pid} / 已終止程序 PID ${pid}`);
      return {
        action: 'kill_process',
        success: true,
        details: `Process PID ${pid} terminated / 已終止程序 PID ${pid}`,
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to kill process ${pid}: ${msg} / 終止程序失敗: ${msg}`);
      return {
        action: 'kill_process',
        success: false,
        details: `Failed to kill process ${pid}: ${msg} / 終止失敗: ${msg}`,
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    }
  }

  /**
   * Disable a user account / 停用使用者帳號
   */
  private async disableAccount(verdict: ThreatVerdict): Promise<ResponseResult> {
    const username = this.extractUsername(verdict);
    if (!username) {
      return {
        action: 'disable_account',
        success: false,
        details: 'No username found in verdict evidence / 判決證據中未找到使用者名稱',
        timestamp: new Date().toISOString(),
      };
    }

    // Safety: check protected accounts / 安全：檢查受保護帳號
    if (SAFETY_RULES.protectedAccounts.has(username)) {
      logger.warn(
        `Refusing to disable protected account: ${username} / ` + `拒絕停用受保護帳號: ${username}`
      );
      return {
        action: 'disable_account',
        success: false,
        details:
          `Account ${username} is protected and cannot be disabled / ` +
          `帳號 ${username} 受保護，無法停用`,
        timestamp: new Date().toISOString(),
        target: username,
      };
    }

    // Validate username to prevent injection / 驗證使用者名稱以防止注入
    if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
      return {
        action: 'disable_account',
        success: false,
        details: `Invalid username format: ${username} / 無效的使用者名稱格式`,
        timestamp: new Date().toISOString(),
        target: username,
      };
    }

    const os = platform();
    try {
      if (os === 'darwin') {
        await execFilePromise('/usr/bin/dscl', [
          '.',
          '-create',
          `/Users/${username}`,
          'AuthenticationAuthority',
          ';DisabledUser;',
        ]);
      } else if (os === 'linux') {
        await execFilePromise('/usr/sbin/usermod', ['-L', username]);
      } else if (os === 'win32') {
        await execFilePromise('net', ['user', username, '/active:no']);
      }

      logger.info(`Disabled account: ${username} / 已停用帳號: ${username}`);
      return {
        action: 'disable_account',
        success: true,
        details: `Account ${username} disabled / 帳號 ${username} 已停用`,
        timestamp: new Date().toISOString(),
        target: username,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to disable account ${username}: ${msg} / 停用帳號失敗: ${msg}`);
      return {
        action: 'disable_account',
        success: false,
        details: `Failed to disable account: ${msg} / 停用失敗: ${msg}`,
        timestamp: new Date().toISOString(),
        target: username,
      };
    }
  }

  /**
   * Isolate a file (move to quarantine) / 隔離檔案（移至隔離區）
   */
  private async isolateFile(verdict: ThreatVerdict): Promise<ResponseResult> {
    const filePath = this.extractFilePath(verdict);
    if (!filePath) {
      return {
        action: 'isolate_file',
        success: false,
        details: 'No file path found in verdict evidence / 判決證據中未找到檔案路徑',
        timestamp: new Date().toISOString(),
      };
    }

    try {
      const quarantineDir = '/var/panguard-guard/quarantine';
      const os = platform();
      const mvCmd = os === 'win32' ? 'move' : '/bin/mv';
      const fileName = filePath.split(/[/\\]/).pop() ?? 'unknown';
      const dest = `${quarantineDir}/${Date.now()}_${fileName}`;

      // Ensure quarantine directory exists / 確保隔離目錄存在
      if (os !== 'win32') {
        await execFilePromise('/bin/mkdir', ['-p', quarantineDir]);
      }

      await execFilePromise(mvCmd, [filePath, dest]);

      logger.info(`Isolated file: ${filePath} -> ${dest} / 已隔離檔案`);
      return {
        action: 'isolate_file',
        success: true,
        details: `File isolated: ${filePath} -> ${dest} / 檔案已隔離`,
        timestamp: new Date().toISOString(),
        target: filePath,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to isolate file: ${msg} / 隔離檔案失敗: ${msg}`);
      return {
        action: 'isolate_file',
        success: false,
        details: `Failed to isolate file: ${msg} / 隔離失敗: ${msg}`,
        timestamp: new Date().toISOString(),
        target: filePath,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Evidence extraction helpers / 證據提取輔助函數
  // ---------------------------------------------------------------------------

  /** Extract IP from verdict evidence / 從判決證據中提取 IP */
  private extractIP(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['ip']) return data['ip'] as string;
    }
    return undefined;
  }

  /** Extract PID from verdict evidence / 從判決證據中提取 PID */
  private extractPID(verdict: ThreatVerdict): number | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['pid']) return Number(data['pid']);
    }
    return undefined;
  }

  /** Extract username from verdict evidence / 從判決證據中提取使用者名稱 */
  private extractUsername(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['username']) return data['username'] as string;
    }
    return undefined;
  }

  /** Extract file path from verdict evidence / 從判決證據中提取檔案路徑 */
  private extractFilePath(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['filePath']) return data['filePath'] as string;
    }
    return undefined;
  }

  /** Extract process name from verdict evidence / 從判決證據中提取程序名稱 */
  private extractProcessName(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['processName']) return data['processName'] as string;
    }
    return undefined;
  }

  /**
   * Get total action count / 取得動作計數
   */
  getActionCount(): number {
    return this.actionCount;
  }
}

// ---------------------------------------------------------------------------
// Utility / 工具函數
// ---------------------------------------------------------------------------

/**
 * Promise wrapper for execFile / execFile 的 Promise 封裝
 * Uses execFile exclusively (never exec) to prevent command injection.
 * 專門使用 execFile（絕不使用 exec）以防止命令注入。
 */
function execFilePromise(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 10000 }, (error, stdout) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}
