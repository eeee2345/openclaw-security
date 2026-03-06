/**
 * Respond Agent - Execute response actions with persistence, rollback, and escalation
 * 回應代理 - 執行回應動作，支援持久化、回滾和漸進升級
 *
 * Third stage of the multi-agent pipeline. Determines and executes
 * the appropriate response action based on verdict confidence levels
 * and the configured action policy thresholds.
 *
 * Uses execFile (never exec) for all system commands to prevent
 * command injection vulnerabilities.
 *
 * @module @panguard-ai/panguard-guard/agent/respond-agent
 */

import { execFile } from 'node:child_process';
import { platform } from 'node:os';
import { appendFileSync, readFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type {
  ThreatVerdict,
  ActionPolicy,
  ResponseResult,
  ResponseAction,
  GuardMode,
} from '../types.js';
import type { PlaybookEngine, PlaybookCorrelationMatch } from '../playbook/index.js';

const logger = createLogger('panguard-guard:respond-agent');

/** Action manifest record for persistence and rollback */
interface ActionManifestEntry {
  id: string;
  action: ResponseAction;
  target: string;
  timestamp: string;
  expiresAt?: string;
  rolledBack: boolean;
  verdict: { conclusion: string; confidence: number };
}

/** Escalation tracker: IP/target → violation count */
interface EscalationRecord {
  target: string;
  violationCount: number;
  firstSeen: string;
  lastSeen: string;
}

/**
 * Safety rules for auto-response actions
 */
const SAFETY_RULES = {
  whitelistedIPs: new Set(['127.0.0.1', '::1', 'localhost', '0.0.0.0']),

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

  protectedAccounts: new Set(['root', 'Administrator', 'admin', 'SYSTEM', 'LocalSystem']),

  /** Default auto-unblock duration: 1 hour */
  defaultBlockDurationMs: 60 * 60 * 1000,

  /** Extended block duration for repeat offenders: 24 hours */
  repeatOffenderBlockDurationMs: 24 * 60 * 60 * 1000,

  /** SIGKILL timeout after SIGTERM: 5 seconds */
  sigkillTimeoutMs: 5000,

  /** Network isolation requires confidence >= 95 */
  networkIsolationMinConfidence: 95,

  /** Violations before escalation */
  escalationThreshold: 3,
} as const;

/**
 * Rate limiter for response actions — prevents runaway auto-responses
 * from causing self-DoS if DetectAgent produces false-positive loops.
 * 回應動作速率限制器 — 防止偵測代理誤報迴圈導致自我 DoS。
 */
class ActionRateLimiter {
  private readonly windows = new Map<ResponseAction, number[]>();
  private consecutiveFailures = 0;
  private circuitBreakerUntil = 0;

  /** Per-action limits: max invocations per 60-second window */
  private readonly limits: Record<string, number> = {
    block_ip: 10,
    kill_process: 5,
    disable_account: 2,
    isolate_file: 5,
    notify: 30,
    log_only: Infinity,
  };

  /** Circuit breaker: pause all actions after N consecutive failures */
  private readonly maxConsecutiveFailures = 5;
  /** Circuit breaker cooldown: 60 seconds */
  private readonly circuitBreakerCooldownMs = 60_000;
  /** Sliding window size: 60 seconds */
  private readonly windowMs = 60_000;

  /**
   * Check whether the given action is allowed under rate limits.
   * Returns true if allowed, false if rate-limited or circuit-broken.
   */
  allow(action: ResponseAction): boolean {
    const now = Date.now();

    // Circuit breaker check
    if (now < this.circuitBreakerUntil) {
      return false;
    }

    const limit = this.limits[action] ?? 10;
    if (limit === Infinity) return true;

    // Sliding window: prune old entries, count recent
    const timestamps = this.windows.get(action) ?? [];
    const cutoff = now - this.windowMs;
    const recent = timestamps.filter((t) => t > cutoff);
    this.windows.set(action, recent);

    return recent.length < limit;
  }

  /** Record that an action was executed (adds to sliding window) */
  record(action: ResponseAction): void {
    const timestamps = this.windows.get(action) ?? [];
    timestamps.push(Date.now());
    this.windows.set(action, timestamps);
  }

  /** Record a successful action — resets consecutive failure counter */
  recordSuccess(): void {
    this.consecutiveFailures = 0;
  }

  /** Record a failed action execution. Trips circuit breaker after threshold. */
  recordFailure(): void {
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
      this.circuitBreakerUntil = Date.now() + this.circuitBreakerCooldownMs;
      logger.error(
        `Circuit breaker tripped: ${this.consecutiveFailures} consecutive failures. ` +
          `All auto-responses paused for ${this.circuitBreakerCooldownMs / 1000}s.`
      );
      this.consecutiveFailures = 0;
    }
  }

  /** Check if circuit breaker is currently active */
  isCircuitBroken(): boolean {
    return Date.now() < this.circuitBreakerUntil;
  }

  /** Get current rate limit status for monitoring */
  getStatus(): { circuitBroken: boolean; consecutiveFailures: number; windowCounts: Record<string, number> } {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const windowCounts: Record<string, number> = {};
    for (const [action, timestamps] of this.windows) {
      windowCounts[action] = timestamps.filter((t) => t > cutoff).length;
    }
    return {
      circuitBroken: this.isCircuitBroken(),
      consecutiveFailures: this.consecutiveFailures,
      windowCounts,
    };
  }
}

/**
 * Respond Agent determines and executes appropriate response actions
 * with persistence, auto-unblock timers, SIGKILL fallback, and escalation.
 */
export class RespondAgent {
  private actionPolicy: ActionPolicy;
  private mode: GuardMode;
  private actionCount = 0;
  private readonly additionalWhitelistedIPs: Set<string>;
  private readonly rateLimiter = new ActionRateLimiter();

  /** Action manifest for persistence and rollback */
  private readonly manifest: ActionManifestEntry[] = [];
  private readonly manifestPath: string;

  /** Escalation tracker: target → record */
  private readonly escalationMap = new Map<string, EscalationRecord>();

  /** Active unblock timers */
  private readonly unblockTimers = new Map<string, ReturnType<typeof setTimeout>>();

  /** Optional SOAR playbook engine for custom response strategies / 選用的 SOAR 劇本引擎 */
  private playbookEngine: PlaybookEngine | null = null;

  constructor(
    actionPolicy: ActionPolicy,
    mode: GuardMode,
    whitelistedIPs: string[] = [],
    dataDir = '/var/panguard-guard'
  ) {
    this.actionPolicy = actionPolicy;
    this.mode = mode;
    this.additionalWhitelistedIPs = new Set(whitelistedIPs);
    this.manifestPath = `${dataDir}/action-manifest.jsonl`;

    // Ensure manifest directory exists
    try {
      mkdirSync(dirname(this.manifestPath), { recursive: true });
    } catch {
      // Directory may already exist
    }

    // Load existing manifest on startup
    this.loadManifest();
  }

  /** Update operating mode */
  setMode(mode: GuardMode): void {
    this.mode = mode;
  }

  /**
   * Set the SOAR playbook engine for custom response strategies.
   * 設定 SOAR 劇本引擎以使用自訂回應策略。
   *
   * When a playbook engine is set, it is consulted BEFORE the hardcoded
   * response logic. If a playbook matches, its actions are executed.
   * If no playbook matches, the existing hardcoded logic is used as fallback.
   */
  setPlaybookEngine(engine: PlaybookEngine): void {
    this.playbookEngine = engine;
    logger.info(`PlaybookEngine attached with ${engine.count} playbooks`);
  }

  /**
   * Execute response based on verdict with escalation awareness.
   * If a PlaybookEngine is attached, it is consulted first.
   * 根據判定執行回應，支援升級感知。若有附加劇本引擎，會優先查詢。
   *
   * @param verdict - Threat verdict from Analyze Agent / 分析代理的威脅判定
   * @param correlationPatterns - Optional correlation patterns for playbook matching / 選用的關聯模式
   */
  async respond(
    verdict: ThreatVerdict,
    correlationPatterns?: PlaybookCorrelationMatch[]
  ): Promise<ResponseResult> {
    // Learning mode: never take active response
    if (this.mode === 'learning') {
      logger.info('Learning mode: no response action taken');
      return {
        action: 'log_only',
        success: true,
        details: 'Learning mode - observation only',
        timestamp: new Date().toISOString(),
      };
    }

    // --- Playbook Engine check (before hardcoded logic) ---
    // 劇本引擎檢查（在硬編碼邏輯之前）
    if (this.playbookEngine) {
      const matchedPlaybook = this.playbookEngine.match(verdict, correlationPatterns);
      if (matchedPlaybook) {
        const target = this.extractTarget(verdict);
        const sourceKey = target ?? verdict.conclusion;

        // Record occurrence for escalation tracking / 記錄發生次數以追蹤升級
        const compositeKey = `${matchedPlaybook.name}:${sourceKey}`;
        this.playbookEngine.recordOccurrence(compositeKey);

        const actions = this.playbookEngine.getActions(matchedPlaybook, sourceKey);
        logger.info(
          `Playbook "${matchedPlaybook.name}" matched. Executing ${actions.length} action(s).`
        );

        // Execute all playbook actions and return the result of the first action
        // 執行所有劇本動作，回傳第一個動作的結果
        const results: ResponseResult[] = [];
        for (const action of actions) {
          const result = await this.executeAction(action.type, verdict);
          results.push(result);
        }

        // Track escalation in the existing system too / 在現有系統中也追蹤升級
        if (target) this.trackEscalation(target);

        // Return first result, or a summary if multiple actions / 回傳第一個結果
        if (results.length === 1) {
          return results[0]!;
        }

        // Multiple actions: return composite result / 多個動作：回傳複合結果
        const allSuccess = results.every((r) => r.success);
        const details = results
          .map((r) => `[${r.action}] ${r.details}`)
          .join(' | ');

        return {
          action: results[0]!.action,
          success: allSuccess,
          details: `Playbook "${matchedPlaybook.name}": ${details}`,
          timestamp: new Date().toISOString(),
          target: results[0]!.target,
        };
      }
    }

    // --- Fallback: hardcoded response logic ---
    // 後備方案：硬編碼回應邏輯
    const { confidence } = verdict;

    // Check escalation: repeat offenders get lower thresholds
    const target = this.extractTarget(verdict);
    const escalation = target ? this.escalationMap.get(target) : undefined;
    const isRepeatOffender =
      escalation && escalation.violationCount >= SAFETY_RULES.escalationThreshold;

    // Repeat offenders: lower auto-respond threshold by 10%
    const effectiveAutoRespond = isRepeatOffender
      ? Math.max(50, this.actionPolicy.autoRespond - 10)
      : this.actionPolicy.autoRespond;

    // Auto-respond: execute the recommended action
    if (confidence >= effectiveAutoRespond) {
      if (isRepeatOffender) {
        logger.warn(
          `Repeat offender ${target}: auto-responding at lower threshold ` +
            `(${effectiveAutoRespond}% instead of ${this.actionPolicy.autoRespond}%)`
        );
      }

      // Track escalation
      if (target) this.trackEscalation(target);

      return this.executeAction(verdict.recommendedAction, verdict);
    }

    // Notify: send alert but do not auto-execute
    if (confidence >= this.actionPolicy.notifyAndWait) {
      // Track escalation even for notify-level events
      if (target) this.trackEscalation(target);

      return {
        action: 'notify',
        success: true,
        details:
          `Notification sent. Verdict: ${verdict.conclusion}, ` +
          `recommended: ${verdict.recommendedAction}`,
        timestamp: new Date().toISOString(),
      };
    }

    // Log only
    return {
      action: 'log_only',
      success: true,
      details: `Logged: ${verdict.conclusion} (confidence: ${confidence}%)`,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Rollback a previous action by manifest entry ID
   */
  async rollback(entryId: string): Promise<ResponseResult> {
    const entry = this.manifest.find((e) => e.id === entryId && !e.rolledBack);
    if (!entry) {
      return {
        action: 'log_only',
        success: false,
        details: `No rollback-able action found for ID ${entryId}`,
        timestamp: new Date().toISOString(),
      };
    }

    let result: ResponseResult;

    switch (entry.action) {
      case 'block_ip':
        result = await this.unblockIP(entry.target);
        break;
      case 'isolate_file':
        result = {
          action: 'isolate_file',
          success: false,
          details: 'File restore requires manual intervention. Check quarantine directory.',
          timestamp: new Date().toISOString(),
          target: entry.target,
        };
        break;
      default:
        result = {
          action: entry.action,
          success: false,
          details: `Rollback not supported for action: ${entry.action}`,
          timestamp: new Date().toISOString(),
        };
    }

    if (result.success) {
      entry.rolledBack = true;
      this.persistManifestEntry(entry);
    }

    return result;
  }

  /**
   * Get all active (non-rolled-back) actions
   */
  getActiveActions(): ActionManifestEntry[] {
    return this.manifest.filter((e) => !e.rolledBack);
  }

  // ---------------------------------------------------------------------------
  // Action execution
  // ---------------------------------------------------------------------------

  private async executeAction(
    action: ResponseAction,
    verdict: ThreatVerdict
  ): Promise<ResponseResult> {
    // Rate limit check — prevent runaway auto-responses
    if (!this.rateLimiter.allow(action)) {
      const status = this.rateLimiter.getStatus();
      const reason = status.circuitBroken
        ? 'Circuit breaker active — all auto-responses paused'
        : `Rate limit exceeded for ${action} (${status.windowCounts[action] ?? 0} in last 60s)`;
      logger.warn(`Action ${action} rate-limited: ${reason}`);
      return {
        action,
        success: false,
        details: `Rate-limited: ${reason}`,
        timestamp: new Date().toISOString(),
      };
    }

    this.rateLimiter.record(action);
    this.actionCount++;

    let result: ResponseResult;
    switch (action) {
      case 'block_ip':
        result = await this.blockIP(verdict);
        break;
      case 'kill_process':
        result = await this.killProcess(verdict);
        break;
      case 'disable_account':
        result = await this.disableAccount(verdict);
        break;
      case 'isolate_file':
        result = await this.isolateFile(verdict);
        break;
      case 'notify':
        result = {
          action: 'notify',
          success: true,
          details: 'Notification dispatched',
          timestamp: new Date().toISOString(),
        };
        break;
      default:
        result = {
          action: 'log_only',
          success: true,
          details: 'Action logged',
          timestamp: new Date().toISOString(),
        };
    }

    // Track consecutive failures/successes for circuit breaker
    if (result.success) {
      this.rateLimiter.recordSuccess();
    } else {
      this.rateLimiter.recordFailure();
    }

    return result;
  }

  /**
   * Block an IP address with auto-unblock timer
   */
  private async blockIP(verdict: ThreatVerdict): Promise<ResponseResult> {
    const ip = this.extractIP(verdict);
    if (!ip) {
      return {
        action: 'block_ip',
        success: false,
        details: 'No IP address found in verdict evidence',
        timestamp: new Date().toISOString(),
      };
    }

    // Safety: check whitelisted IPs
    if (SAFETY_RULES.whitelistedIPs.has(ip) || this.additionalWhitelistedIPs.has(ip)) {
      logger.warn(`Refusing to block whitelisted IP: ${ip}`);
      return {
        action: 'block_ip',
        success: false,
        details: `IP ${ip} is whitelisted and cannot be blocked`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }

    // Validate IP format (IPv4 or IPv6)
    if (!/^[\d.]+$/.test(ip) && !/^[a-fA-F\d:]+$/.test(ip)) {
      return {
        action: 'block_ip',
        success: false,
        details: `Invalid IP format: ${ip}`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }

    // Determine block duration based on repeat offender status
    const escalation = this.escalationMap.get(ip);
    const isRepeat = escalation && escalation.violationCount >= SAFETY_RULES.escalationThreshold;
    const blockDuration = isRepeat
      ? SAFETY_RULES.repeatOffenderBlockDurationMs
      : SAFETY_RULES.defaultBlockDurationMs;

    const os = platform();
    try {
      if (os === 'darwin') {
        await execFilePromise('/sbin/pfctl', ['-t', 'panguard-guard_blocked', '-T', 'add', ip]);
      } else if (os === 'linux') {
        await execFilePromise('/sbin/iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
      } else if (os === 'win32') {
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

      const expiresAt = new Date(Date.now() + blockDuration).toISOString();

      // Persist action to manifest
      const entry = this.recordAction('block_ip', ip, verdict, expiresAt);

      // Set auto-unblock timer
      this.scheduleUnblock(ip, blockDuration, entry.id);

      const durationStr = isRepeat ? '24h (repeat offender)' : '1h';
      logger.info(`Blocked IP: ${ip} for ${durationStr} (auto-unblock scheduled)`);

      return {
        action: 'block_ip',
        success: true,
        details: `IP ${ip} blocked via ${os} firewall for ${durationStr}. Auto-unblock at ${expiresAt}`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to block IP ${ip}: ${msg}`);
      return {
        action: 'block_ip',
        success: false,
        details: `Failed to block IP ${ip}: ${msg}`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }
  }

  /**
   * Unblock a previously blocked IP
   */
  private async unblockIP(ip: string): Promise<ResponseResult> {
    const os = platform();
    try {
      if (os === 'darwin') {
        await execFilePromise('/sbin/pfctl', ['-t', 'panguard-guard_blocked', '-T', 'delete', ip]);
      } else if (os === 'linux') {
        await execFilePromise('/sbin/iptables', ['-D', 'INPUT', '-s', ip, '-j', 'DROP']);
      } else if (os === 'win32') {
        await execFilePromise('netsh', [
          'advfirewall',
          'firewall',
          'delete',
          'rule',
          `name=PanguardGuard_Block_${ip}`,
        ]);
      }

      // Clear the unblock timer
      const timer = this.unblockTimers.get(ip);
      if (timer) {
        clearTimeout(timer);
        this.unblockTimers.delete(ip);
      }

      logger.info(`Unblocked IP: ${ip}`);
      return {
        action: 'block_ip',
        success: true,
        details: `IP ${ip} unblocked`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to unblock IP ${ip}: ${msg}`);
      return {
        action: 'block_ip',
        success: false,
        details: `Failed to unblock IP ${ip}: ${msg}`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }
  }

  /**
   * Schedule auto-unblock after duration
   */
  private scheduleUnblock(ip: string, durationMs: number, entryId: string): void {
    // Clear existing timer for this IP
    const existing = this.unblockTimers.get(ip);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(async () => {
      logger.info(`Auto-unblock timer expired for IP: ${ip}`);
      const result = await this.unblockIP(ip);
      if (result.success) {
        const entry = this.manifest.find((e) => e.id === entryId);
        if (entry) {
          entry.rolledBack = true;
          this.persistManifestEntry(entry);
        }
      }
      this.unblockTimers.delete(ip);
    }, durationMs);

    // Don't hold the process open for unblock timers
    if (timer.unref) timer.unref();

    this.unblockTimers.set(ip, timer);
  }

  /**
   * Kill a process with SIGKILL fallback
   */
  private async killProcess(verdict: ThreatVerdict): Promise<ResponseResult> {
    const pid = this.extractPID(verdict);
    if (!pid) {
      return {
        action: 'kill_process',
        success: false,
        details: 'No PID found in verdict evidence',
        timestamp: new Date().toISOString(),
      };
    }

    // Safety: check protected processes
    const processName = this.extractProcessName(verdict);
    if (processName && SAFETY_RULES.protectedProcesses.has(processName)) {
      logger.warn(`Refusing to kill protected process: ${processName} (PID ${pid})`);
      return {
        action: 'kill_process',
        success: false,
        details: `Process ${processName} is protected and cannot be killed`,
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    }

    // Safety: never kill our own process
    if (pid === process.pid) {
      logger.warn('Refusing to kill own process');
      return {
        action: 'kill_process',
        success: false,
        details: 'Cannot kill own process',
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    }

    try {
      // Step 1: Try SIGTERM (graceful)
      process.kill(pid, 'SIGTERM');
      logger.info(`Sent SIGTERM to PID ${pid}`);

      // Step 2: Verify process is gone, fallback to SIGKILL
      const isAlive = await this.waitForProcessExit(pid, SAFETY_RULES.sigkillTimeoutMs);
      if (isAlive) {
        try {
          process.kill(pid, 'SIGKILL');
          logger.warn(`SIGTERM failed, sent SIGKILL to PID ${pid}`);
        } catch {
          // Process may have exited between check and kill
        }
      }

      this.recordAction('kill_process', String(pid), verdict);

      return {
        action: 'kill_process',
        success: true,
        details: `Process PID ${pid} terminated${isAlive ? ' (SIGKILL required)' : ''}`,
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to kill process ${pid}: ${msg}`);
      return {
        action: 'kill_process',
        success: false,
        details: `Failed to kill process ${pid}: ${msg}`,
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    }
  }

  /**
   * Wait for a process to exit, return true if still alive after timeout
   */
  private async waitForProcessExit(pid: number, timeoutMs: number): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        // Signal 0 checks if process exists without killing it
        process.kill(pid, 0);
        // Process still alive, wait a bit
        await new Promise((resolve) => setTimeout(resolve, 500));
      } catch {
        // Process is gone
        return false;
      }
    }
    // Still alive after timeout
    return true;
  }

  /**
   * Disable a user account
   */
  private async disableAccount(verdict: ThreatVerdict): Promise<ResponseResult> {
    const username = this.extractUsername(verdict);
    if (!username) {
      return {
        action: 'disable_account',
        success: false,
        details: 'No username found in verdict evidence',
        timestamp: new Date().toISOString(),
      };
    }

    if (SAFETY_RULES.protectedAccounts.has(username)) {
      logger.warn(`Refusing to disable protected account: ${username}`);
      return {
        action: 'disable_account',
        success: false,
        details: `Account ${username} is protected and cannot be disabled`,
        timestamp: new Date().toISOString(),
        target: username,
      };
    }

    if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
      return {
        action: 'disable_account',
        success: false,
        details: `Invalid username format: ${username}`,
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

      this.recordAction('disable_account', username, verdict);

      logger.info(`Disabled account: ${username}`);
      return {
        action: 'disable_account',
        success: true,
        details: `Account ${username} disabled`,
        timestamp: new Date().toISOString(),
        target: username,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to disable account ${username}: ${msg}`);
      return {
        action: 'disable_account',
        success: false,
        details: `Failed to disable account: ${msg}`,
        timestamp: new Date().toISOString(),
        target: username,
      };
    }
  }

  /**
   * Isolate a file (move to quarantine) with metadata tracking
   */
  private async isolateFile(verdict: ThreatVerdict): Promise<ResponseResult> {
    const filePath = this.extractFilePath(verdict);
    if (!filePath) {
      return {
        action: 'isolate_file',
        success: false,
        details: 'No file path found in verdict evidence',
        timestamp: new Date().toISOString(),
      };
    }

    try {
      const quarantineDir = '/var/panguard-guard/quarantine';
      const os = platform();
      const mvCmd = os === 'win32' ? 'move' : '/bin/mv';
      const fileName = filePath.split(/[/\\]/).pop() ?? 'unknown';
      const dest = `${quarantineDir}/${Date.now()}_${fileName}`;

      // Ensure quarantine directory exists
      if (os !== 'win32') {
        await execFilePromise('/bin/mkdir', ['-p', quarantineDir]);
      }

      await execFilePromise(mvCmd, [filePath, dest]);

      // Record with metadata for forensics
      this.recordAction('isolate_file', filePath, verdict);

      // Write quarantine metadata alongside the file
      try {
        const metadata = {
          originalPath: filePath,
          quarantinedAt: new Date().toISOString(),
          verdict: { conclusion: verdict.conclusion, confidence: verdict.confidence },
          reasoning: verdict.reasoning,
        };
        appendFileSync(`${dest}.meta.json`, JSON.stringify(metadata, null, 2), 'utf-8');
      } catch {
        // Non-critical: metadata write failure
      }

      logger.info(`Isolated file: ${filePath} -> ${dest}`);
      return {
        action: 'isolate_file',
        success: true,
        details: `File isolated: ${filePath} -> ${dest}`,
        timestamp: new Date().toISOString(),
        target: filePath,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to isolate file: ${msg}`);
      return {
        action: 'isolate_file',
        success: false,
        details: `Failed to isolate file: ${msg}`,
        timestamp: new Date().toISOString(),
        target: filePath,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Action Manifest (persistence)
  // ---------------------------------------------------------------------------

  private recordAction(
    action: ResponseAction,
    target: string,
    verdict: ThreatVerdict,
    expiresAt?: string
  ): ActionManifestEntry {
    const entry: ActionManifestEntry = {
      id: `act-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      action,
      target,
      timestamp: new Date().toISOString(),
      expiresAt,
      rolledBack: false,
      verdict: { conclusion: verdict.conclusion, confidence: verdict.confidence },
    };

    this.manifest.push(entry);
    this.persistManifestEntry(entry);
    return entry;
  }

  private persistManifestEntry(entry: ActionManifestEntry): void {
    try {
      appendFileSync(this.manifestPath, JSON.stringify(entry) + '\n', 'utf-8');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to persist action manifest: ${msg}`);
    }
  }

  private loadManifest(): void {
    try {
      const content = readFileSync(this.manifestPath, 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);
      for (const line of lines) {
        try {
          const entry = JSON.parse(line) as ActionManifestEntry;
          this.manifest.push(entry);
        } catch {
          // Skip malformed lines
        }
      }
      logger.info(`Loaded ${this.manifest.length} action manifest entries`);
    } catch {
      // Manifest file may not exist yet
    }
  }

  // ---------------------------------------------------------------------------
  // Escalation tracking
  // ---------------------------------------------------------------------------

  private trackEscalation(target: string): void {
    const now = new Date().toISOString();
    const existing = this.escalationMap.get(target);
    if (existing) {
      existing.violationCount += 1;
      existing.lastSeen = now;
    } else {
      this.escalationMap.set(target, {
        target,
        violationCount: 1,
        firstSeen: now,
        lastSeen: now,
      });
    }
  }

  private extractTarget(verdict: ThreatVerdict): string | undefined {
    return (
      this.extractIP(verdict) ??
      this.extractProcessName(verdict) ??
      this.extractUsername(verdict) ??
      this.extractFilePath(verdict)
    );
  }

  // ---------------------------------------------------------------------------
  // Evidence extraction helpers
  // ---------------------------------------------------------------------------

  private extractIP(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['ip']) return data['ip'] as string;
      if (data?.['sourceIP']) return data['sourceIP'] as string;
    }
    return undefined;
  }

  private extractPID(verdict: ThreatVerdict): number | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['pid']) return Number(data['pid']);
    }
    return undefined;
  }

  private extractUsername(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['username']) return data['username'] as string;
    }
    return undefined;
  }

  private extractFilePath(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['filePath']) return data['filePath'] as string;
    }
    return undefined;
  }

  private extractProcessName(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['processName']) return data['processName'] as string;
    }
    return undefined;
  }

  /** Get total action count */
  getActionCount(): number {
    return this.actionCount;
  }

  /** Get rate limiter status for monitoring */
  getRateLimiterStatus(): { circuitBroken: boolean; consecutiveFailures: number; windowCounts: Record<string, number> } {
    return this.rateLimiter.getStatus();
  }

  /** Get escalation records */
  getEscalationRecords(): Map<string, EscalationRecord> {
    return new Map(this.escalationMap);
  }

  /**
   * Block an IP address directly by IP string (policy-driven block).
   * Validates the IP, checks whitelist, and calls the firewall.
   * 直接透過 IP 字串封鎖 IP 位址（策略驅動封鎖）。
   *
   * @param ip - The IP address to block / 要封鎖的 IP 位址
   * @returns ResponseResult indicating success or failure / 回應結果
   */
  async addBlockedIP(ip: string): Promise<ResponseResult> {
    // Safety: check whitelisted IPs
    if (SAFETY_RULES.whitelistedIPs.has(ip) || this.additionalWhitelistedIPs.has(ip)) {
      logger.warn(`Refusing to block whitelisted IP: ${ip}`);
      return {
        action: 'block_ip',
        success: false,
        details: `IP ${ip} is whitelisted and cannot be blocked`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }

    // Validate IP format (IPv4 or IPv6)
    if (!/^[\d.]+$/.test(ip) && !/^[a-fA-F\d:]+$/.test(ip)) {
      return {
        action: 'block_ip',
        success: false,
        details: `Invalid IP format: ${ip}`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }

    // Synthesize a minimal verdict for the block
    const policyVerdict = {
      conclusion: 'policy_block',
      confidence: 100,
      reasoning: `Policy-driven block of IP ${ip}`,
      evidence: [{ source: 'policy', description: `Block IP: ${ip}`, confidence: 100, data: { ip } }],
      recommendedAction: 'block_ip',
    } as unknown as ThreatVerdict;

    this.actionCount++;
    const result = await this.blockIP(policyVerdict);
    // Annotate result as policy-driven block
    if (result.success) {
      return { ...result, details: `[policy] ${result.details}` };
    }
    return result;
  }

  /**
   * Update the action policy thresholds.
   * 更新動作策略閾值。
   *
   * @param updates - Partial policy update / 部分策略更新
   */
  updateActionPolicy(updates: Partial<ActionPolicy>): void {
    this.actionPolicy = { ...this.actionPolicy, ...updates };
    logger.info(`Action policy updated: ${JSON.stringify(updates)}`);
  }

  /** Cleanup: clear all timers (for graceful shutdown) */
  destroy(): void {
    for (const timer of this.unblockTimers.values()) {
      clearTimeout(timer);
    }
    this.unblockTimers.clear();
  }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

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
