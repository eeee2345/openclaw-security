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
 * Respond Agent determines and executes appropriate response actions
 * with persistence, auto-unblock timers, SIGKILL fallback, and escalation.
 */
export class RespondAgent {
  private readonly actionPolicy: ActionPolicy;
  private mode: GuardMode;
  private actionCount = 0;
  private readonly additionalWhitelistedIPs: Set<string>;

  /** Action manifest for persistence and rollback */
  private readonly manifest: ActionManifestEntry[] = [];
  private readonly manifestPath: string;

  /** Escalation tracker: target → record */
  private readonly escalationMap = new Map<string, EscalationRecord>();

  /** Active unblock timers */
  private readonly unblockTimers = new Map<string, ReturnType<typeof setTimeout>>();

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
   * Execute response based on verdict with escalation awareness
   */
  async respond(verdict: ThreatVerdict): Promise<ResponseResult> {
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
          details: 'Notification dispatched',
          timestamp: new Date().toISOString(),
        };
      default:
        return {
          action: 'log_only',
          success: true,
          details: 'Action logged',
          timestamp: new Date().toISOString(),
        };
    }
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

  /** Get escalation records */
  getEscalationRecords(): Map<string, EscalationRecord> {
    return new Map(this.escalationMap);
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
