/**
 * Respond Agent - Execute response actions with persistence, rollback, and escalation
 *
 * Third stage of the multi-agent pipeline. Determines and executes
 * the appropriate response action based on verdict confidence levels
 * and the configured action policy thresholds.
 *
 * @module @panguard-ai/panguard-guard/agent/respond-agent
 */

import { createLogger } from '@panguard-ai/core';
import type {
  ThreatVerdict,
  ActionPolicy,
  ResponseResult,
  ResponseAction,
  GuardMode,
} from '../types.js';
import type { PlaybookEngine, PlaybookCorrelationMatch } from '../playbook/index.js';
import { ATRActionHandlers } from './atr-action-handlers.js';
import type { SkillWhitelistManager } from '../engines/skill-whitelist.js';

import { SAFETY_RULES } from './respond/safety-rules.js';
import { ActionRateLimiter } from './respond/action-rate-limiter.js';
import { ActionManifest } from './respond/action-manifest.js';
import { EscalationTracker } from './respond/escalation-tracker.js';
import { extractTarget, extractIP } from './respond/evidence-extractor.js';
import { blockIP, unblockIP, killProcess, disableAccount, isolateFile } from './respond/os-actions.js';
import type { ActionManifestEntry } from './respond/types.js';

const logger = createLogger('panguard-guard:respond-agent');

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
  private readonly manifest: ActionManifest;
  private readonly escalation = new EscalationTracker();
  private readonly unblockTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private playbookEngine: PlaybookEngine | null = null;
  private readonly atrHandlers: ATRActionHandlers;

  constructor(
    actionPolicy: ActionPolicy,
    mode: GuardMode,
    whitelistedIPs: string[] = [],
    dataDir = '/var/panguard-guard'
  ) {
    this.actionPolicy = actionPolicy;
    this.mode = mode;
    this.additionalWhitelistedIPs = new Set(whitelistedIPs);
    this.manifest = new ActionManifest(dataDir);
    this.atrHandlers = new ATRActionHandlers(dataDir);
  }

  /** Update operating mode */
  setMode(mode: GuardMode): void {
    this.mode = mode;
  }

  /** Set the SOAR playbook engine for custom response strategies. */
  setPlaybookEngine(engine: PlaybookEngine): void {
    this.playbookEngine = engine;
    logger.info(`PlaybookEngine attached with ${engine.count} playbooks`);
  }

  /** Set the SkillWhitelistManager for revoke_skill actions. */
  setWhitelistManager(manager: SkillWhitelistManager): void {
    this.atrHandlers.setWhitelistManager(manager);
  }

  /**
   * Execute response based on verdict with escalation awareness.
   * If a PlaybookEngine is attached, it is consulted first.
   */
  async respond(
    verdict: ThreatVerdict,
    correlationPatterns?: PlaybookCorrelationMatch[]
  ): Promise<ResponseResult> {
    if (this.mode === 'learning') {
      logger.info('Learning mode: no response action taken');
      return {
        action: 'log_only',
        success: true,
        details: 'Learning mode - observation only',
        timestamp: new Date().toISOString(),
      };
    }

    // Playbook Engine check (before hardcoded logic)
    if (this.playbookEngine) {
      const result = this.tryPlaybook(verdict, correlationPatterns);
      if (result) return result;
    }

    // Hardcoded response logic
    return this.respondWithPolicy(verdict);
  }

  /** Rollback a previous action by manifest entry ID */
  async rollback(entryId: string): Promise<ResponseResult> {
    const entry = this.manifest.findRollbackable(entryId);
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
        result = await unblockIP(entry.target, this.unblockTimers);
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
      this.manifest.markRolledBack(entryId);
    }

    return result;
  }

  /** Get all active (non-rolled-back) actions */
  getActiveActions(): ActionManifestEntry[] {
    return this.manifest.getActive();
  }

  /**
   * Block an IP address directly by IP string (policy-driven block).
   */
  async addBlockedIP(ip: string): Promise<ResponseResult> {
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

    if (!/^[\d.]+$/.test(ip) && !/^[a-fA-F\d:]+$/.test(ip)) {
      return {
        action: 'block_ip',
        success: false,
        details: `Invalid IP format: ${ip}`,
        timestamp: new Date().toISOString(),
        target: ip,
      };
    }

    const policyVerdict = {
      conclusion: 'policy_block',
      confidence: 100,
      reasoning: `Policy-driven block of IP ${ip}`,
      evidence: [
        { source: 'policy', description: `Block IP: ${ip}`, confidence: 100, data: { ip } },
      ],
      recommendedAction: 'block_ip',
    } as unknown as ThreatVerdict;

    this.actionCount++;
    const result = await blockIP(policyVerdict, this.blockIPDeps());
    if (result.success) {
      return { ...result, details: `[policy] ${result.details}` };
    }
    return result;
  }

  /** Update the action policy thresholds. */
  updateActionPolicy(updates: Partial<ActionPolicy>): void {
    this.actionPolicy = { ...this.actionPolicy, ...updates };
    logger.info(`Action policy updated: ${JSON.stringify(updates)}`);
  }

  /** Get total action count */
  getActionCount(): number {
    return this.actionCount;
  }

  /** Get rate limiter status for monitoring */
  getRateLimiterStatus(): {
    circuitBroken: boolean;
    consecutiveFailures: number;
    windowCounts: Record<string, number>;
  } {
    return this.rateLimiter.getStatus();
  }

  /** Get escalation records */
  getEscalationRecords(): Map<string, { target: string; violationCount: number; firstSeen: string; lastSeen: string }> {
    return this.escalation.getAll();
  }

  /** Cleanup: clear all timers (for graceful shutdown) */
  destroy(): void {
    for (const timer of this.unblockTimers.values()) {
      clearTimeout(timer);
    }
    this.unblockTimers.clear();
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async tryPlaybook(
    verdict: ThreatVerdict,
    correlationPatterns?: PlaybookCorrelationMatch[]
  ): Promise<ResponseResult | undefined> {
    const engine = this.playbookEngine!;
    const matchedPlaybook = engine.match(verdict, correlationPatterns);
    if (!matchedPlaybook) return undefined;

    const target = extractTarget(verdict);
    const sourceKey = target ?? verdict.conclusion;
    const compositeKey = `${matchedPlaybook.name}:${sourceKey}`;
    engine.recordOccurrence(compositeKey);

    const actions = engine.getActions(matchedPlaybook, sourceKey);
    logger.info(
      `Playbook "${matchedPlaybook.name}" matched. Executing ${actions.length} action(s).`
    );

    const results: ResponseResult[] = [];
    for (const action of actions) {
      const result = await this.executeAction(action.type, verdict);
      results.push(result);
    }

    if (target) this.escalation.track(target);

    if (results.length === 1) return results[0]!;

    const allSuccess = results.every((r) => r.success);
    const details = results.map((r) => `[${r.action}] ${r.details}`).join(' | ');
    return {
      action: results[0]!.action,
      success: allSuccess,
      details: `Playbook "${matchedPlaybook.name}": ${details}`,
      timestamp: new Date().toISOString(),
      target: results[0]!.target,
    };
  }

  private async respondWithPolicy(verdict: ThreatVerdict): Promise<ResponseResult> {
    const { confidence } = verdict;
    const target = extractTarget(verdict);
    const isRepeatOffender = target
      ? this.escalation.isRepeatOffender(target, SAFETY_RULES.escalationThreshold)
      : false;

    const effectiveAutoRespond = isRepeatOffender
      ? Math.max(50, this.actionPolicy.autoRespond - 10)
      : this.actionPolicy.autoRespond;

    if (confidence >= effectiveAutoRespond) {
      if (isRepeatOffender) {
        logger.warn(
          `Repeat offender ${target}: auto-responding at lower threshold ` +
            `(${effectiveAutoRespond}% instead of ${this.actionPolicy.autoRespond}%)`
        );
      }
      if (target) this.escalation.track(target);
      return this.executeAction(verdict.recommendedAction, verdict);
    }

    if (confidence >= this.actionPolicy.notifyAndWait) {
      if (target) this.escalation.track(target);
      return {
        action: 'notify',
        success: true,
        details:
          `Notification sent. Verdict: ${verdict.conclusion}, ` +
          `recommended: ${verdict.recommendedAction}`,
        timestamp: new Date().toISOString(),
      };
    }

    return {
      action: 'log_only',
      success: true,
      details: `Logged: ${verdict.conclusion} (confidence: ${confidence}%)`,
      timestamp: new Date().toISOString(),
    };
  }

  private async executeAction(
    action: ResponseAction,
    verdict: ThreatVerdict
  ): Promise<ResponseResult> {
    if (!this.rateLimiter.allow(action)) {
      const status = this.rateLimiter.getStatus();
      const reason = status.circuitBroken
        ? 'Circuit breaker active -- all auto-responses paused'
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

    const result = await this.dispatchAction(action, verdict);

    if (result.success) {
      this.rateLimiter.recordSuccess();
    } else {
      this.rateLimiter.recordFailure();
    }

    return result;
  }

  private async dispatchAction(
    action: ResponseAction,
    verdict: ThreatVerdict
  ): Promise<ResponseResult> {
    switch (action) {
      case 'block_ip':
        return blockIP(verdict, this.blockIPDeps());
      case 'kill_process':
        return killProcess(verdict, this.manifest);
      case 'disable_account':
        return disableAccount(verdict, this.manifest);
      case 'isolate_file':
        return isolateFile(verdict, this.manifest);
      case 'block_tool':
        return this.atrHandlers.blockTool(verdict);
      case 'kill_agent':
        return this.atrHandlers.killAgent(verdict);
      case 'quarantine_session':
        return this.atrHandlers.quarantineSession(verdict);
      case 'revoke_skill':
        return this.atrHandlers.revokeSkill(verdict);
      case 'reduce_permissions':
        return this.atrHandlers.reducePermissions(verdict);
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

  private blockIPDeps() {
    return {
      additionalWhitelistedIPs: this.additionalWhitelistedIPs as ReadonlySet<string>,
      manifest: this.manifest,
      escalation: this.escalation,
      unblockTimers: this.unblockTimers,
    };
  }
}
