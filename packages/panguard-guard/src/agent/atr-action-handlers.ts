/**
 * ATR Action Handlers - Execute ATR-specific response actions
 * ATR 動作處理器 - 執行 ATR 專用回應動作
 *
 * Extracted from RespondAgent to keep file sizes manageable.
 * Handles: block_tool, kill_agent, quarantine_session, revoke_skill, reduce_permissions
 *
 * @module @panguard-ai/panguard-guard/agent/atr-action-handlers
 */

import { createLogger, sanitizeFilename } from '@panguard-ai/core';
import type { ThreatVerdict, ResponseResult } from '../types.js';
import type { SkillWhitelistManager } from '../engines/skill-whitelist.js';

const logger = createLogger('panguard-guard:atr-actions');

/** Safety: agents that must not be killed */
const PROTECTED_AGENTS = new Set(['panguard-guard', 'panguard-manager', 'system-agent']);

/**
 * ATR action handler collection.
 * Each method produces a ResponseResult for the corresponding ATR action.
 * ATR 動作處理器集合。每個方法為對應 ATR 動作產生 ResponseResult。
 */
export class ATRActionHandlers {
  private whitelistManager: SkillWhitelistManager | null = null;
  private readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
  }

  /**
   * Set the whitelist manager reference (injected after construction).
   * 設定白名單管理器參考（建構後注入）。
   */
  setWhitelistManager(manager: SkillWhitelistManager): void {
    this.whitelistManager = manager;
    logger.info('WhitelistManager attached to ATR action handlers');
  }

  /**
   * Block a tool invocation.
   * The actual blocking happens via hook handler; this records the decision.
   * 封鎖工具呼叫。實際封鎖由 hook handler 處理，此處記錄決策。
   */
  async blockTool(verdict: ThreatVerdict): Promise<ResponseResult> {
    const toolName = this.extractToolName(verdict);
    const label = toolName ?? 'unknown';

    logger.info(`ATR action: block_tool for tool "${label}"`);

    return {
      action: 'block_tool',
      success: true,
      details:
        `Tool "${label}" blocked by ATR rule. ` +
        `Conclusion: ${verdict.conclusion}, confidence: ${verdict.confidence}%`,
      timestamp: new Date().toISOString(),
      target: label,
    };
  }

  /**
   * Kill an agent process.
   * Uses SIGTERM followed by SIGKILL fallback, similar to killProcess.
   * 終止代理程序。使用 SIGTERM，後備 SIGKILL。
   */
  async killAgent(verdict: ThreatVerdict): Promise<ResponseResult> {
    const agentId = this.extractAgentId(verdict);
    const pid = this.extractAgentPID(verdict);

    if (!pid && !agentId) {
      return {
        action: 'kill_agent',
        success: false,
        details: 'No agent PID or agentId found in verdict evidence',
        timestamp: new Date().toISOString(),
      };
    }

    // Safety: check protected agents
    if (agentId && PROTECTED_AGENTS.has(agentId)) {
      logger.warn(`Refusing to kill protected agent: ${agentId}`);
      return {
        action: 'kill_agent',
        success: false,
        details: `Agent "${agentId}" is protected and cannot be killed`,
        timestamp: new Date().toISOString(),
        target: agentId,
      };
    }

    if (pid) {
      // Safety: never kill own process
      if (pid === process.pid) {
        return {
          action: 'kill_agent',
          success: false,
          details: 'Cannot kill own process',
          timestamp: new Date().toISOString(),
          target: String(pid),
        };
      }

      try {
        process.kill(pid, 'SIGTERM');
        logger.info(`ATR action: SIGTERM sent to agent PID ${pid} (agentId: ${agentId ?? 'n/a'})`);

        // Wait briefly for graceful exit, then SIGKILL
        const isAlive = await this.waitForExit(pid, 5000);
        if (isAlive) {
          try {
            process.kill(pid, 'SIGKILL');
            logger.warn(`SIGTERM failed, sent SIGKILL to agent PID ${pid}`);
          } catch {
            // Process may have exited between check and kill
          }
        }

        return {
          action: 'kill_agent',
          success: true,
          details:
            `Agent PID ${pid} terminated${isAlive ? ' (SIGKILL required)' : ''}` +
            (agentId ? ` [agentId: ${agentId}]` : ''),
          timestamp: new Date().toISOString(),
          target: String(pid),
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`Failed to kill agent PID ${pid}: ${msg}`);
        return {
          action: 'kill_agent',
          success: false,
          details: `Failed to kill agent PID ${pid}: ${msg}`,
          timestamp: new Date().toISOString(),
          target: String(pid),
        };
      }
    }

    // PID not available, log the decision for external handler
    logger.info(`ATR action: kill_agent requested for agentId "${agentId}" (no PID available)`);
    return {
      action: 'kill_agent',
      success: true,
      details: `Kill requested for agent "${agentId}" (no PID, deferred to external handler)`,
      timestamp: new Date().toISOString(),
      target: agentId,
    };
  }

  /**
   * Quarantine an agent session.
   * Writes a session quarantine marker to the data directory.
   * 隔離代理 session。寫入 session 隔離標記到資料目錄。
   */
  async quarantineSession(verdict: ThreatVerdict): Promise<ResponseResult> {
    const sessionId = this.extractSessionId(verdict);
    const label = sessionId ?? 'unknown';

    try {
      const { writeFileSync, mkdirSync } = await import('node:fs');
      const { join } = await import('node:path');

      const quarantineDir = join(this.dataDir, 'quarantined-sessions');
      mkdirSync(quarantineDir, { recursive: true });

      const marker = {
        sessionId: label,
        quarantinedAt: new Date().toISOString(),
        verdict: { conclusion: verdict.conclusion, confidence: verdict.confidence },
        reasoning: verdict.reasoning,
      };

      const safeLabel = sanitizeFilename(label);
      const markerPath = join(quarantineDir, `${safeLabel}.json`);
      writeFileSync(markerPath, JSON.stringify(marker, null, 2), 'utf-8');

      logger.info(`ATR action: session "${label}" quarantined`);

      return {
        action: 'quarantine_session',
        success: true,
        details: `Session "${label}" quarantined. Marker written to ${markerPath}`,
        timestamp: new Date().toISOString(),
        target: label,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to quarantine session "${label}": ${msg}`);
      return {
        action: 'quarantine_session',
        success: false,
        details: `Failed to quarantine session "${label}": ${msg}`,
        timestamp: new Date().toISOString(),
        target: label,
      };
    }
  }

  /**
   * Revoke a skill from the whitelist.
   * Requires a whitelist manager to be set.
   * 從白名單撤銷 skill。需要設定白名單管理器。
   */
  async revokeSkill(verdict: ThreatVerdict): Promise<ResponseResult> {
    const skillName = this.extractToolName(verdict);
    if (!skillName) {
      return {
        action: 'revoke_skill',
        success: false,
        details: 'No skill/tool name found in verdict evidence',
        timestamp: new Date().toISOString(),
      };
    }

    if (!this.whitelistManager) {
      logger.warn('revoke_skill requested but no WhitelistManager available');
      return {
        action: 'revoke_skill',
        success: false,
        details: `Cannot revoke skill "${skillName}": no whitelist manager configured`,
        timestamp: new Date().toISOString(),
        target: skillName,
      };
    }

    const revoked = this.whitelistManager.revoke(
      skillName,
      `ATR rule triggered: ${verdict.conclusion} (confidence: ${verdict.confidence}%)`
    );

    if (revoked) {
      logger.info(`ATR action: skill "${skillName}" revoked from whitelist`);
    } else {
      logger.info(`ATR action: skill "${skillName}" was not on whitelist (no-op)`);
    }

    return {
      action: 'revoke_skill',
      success: true,
      details: revoked
        ? `Skill "${skillName}" revoked from whitelist`
        : `Skill "${skillName}" was not whitelisted (no change)`,
      timestamp: new Date().toISOString(),
      target: skillName,
    };
  }

  /**
   * Reduce permissions for an agent session.
   * Writes a permission reduction config to the data directory.
   * 降低代理 session 的權限。寫入權限降低設定到資料目錄。
   */
  async reducePermissions(verdict: ThreatVerdict): Promise<ResponseResult> {
    const sessionId = this.extractSessionId(verdict);
    const agentId = this.extractAgentId(verdict);
    const label = sessionId ?? agentId ?? 'unknown';

    try {
      const { writeFileSync, mkdirSync } = await import('node:fs');
      const { join } = await import('node:path');

      const configDir = join(this.dataDir, 'permission-overrides');
      mkdirSync(configDir, { recursive: true });

      const override = {
        targetId: label,
        reducedAt: new Date().toISOString(),
        verdict: { conclusion: verdict.conclusion, confidence: verdict.confidence },
        restrictions: ['deny_write', 'deny_exec', 'deny_network'],
      };

      const safeLabel = sanitizeFilename(label);
      const overridePath = join(configDir, `${safeLabel}.json`);
      writeFileSync(overridePath, JSON.stringify(override, null, 2), 'utf-8');

      logger.info(`ATR action: permissions reduced for "${label}"`);

      return {
        action: 'reduce_permissions',
        success: true,
        details: `Permissions reduced for "${label}". Override written to ${overridePath}`,
        timestamp: new Date().toISOString(),
        target: label,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to reduce permissions for "${label}": ${msg}`);
      return {
        action: 'reduce_permissions',
        success: false,
        details: `Failed to reduce permissions for "${label}": ${msg}`,
        timestamp: new Date().toISOString(),
        target: label,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Evidence extraction helpers
  // ---------------------------------------------------------------------------

  private extractToolName(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['tool_name']) return data['tool_name'] as string;
      if (data?.['toolName']) return data['toolName'] as string;
      if (data?.['skillName']) return data['skillName'] as string;
    }
    return undefined;
  }

  private extractAgentId(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['agentId']) return data['agentId'] as string;
      if (data?.['agent_id']) return data['agent_id'] as string;
    }
    return undefined;
  }

  private extractAgentPID(verdict: ThreatVerdict): number | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['agentPid']) return Number(data['agentPid']);
      if (data?.['pid']) return Number(data['pid']);
    }
    return undefined;
  }

  private extractSessionId(verdict: ThreatVerdict): string | undefined {
    for (const e of verdict.evidence) {
      const data = e.data as Record<string, unknown> | undefined;
      if (data?.['sessionId']) return data['sessionId'] as string;
      if (data?.['session_id']) return data['session_id'] as string;
    }
    return undefined;
  }

  /**
   * Wait for a process to exit, return true if still alive after timeout.
   */
  private async waitForExit(pid: number, timeoutMs: number): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        process.kill(pid, 0);
        await new Promise((resolve) => setTimeout(resolve, 500));
      } catch {
        return false;
      }
    }
    return true;
  }
}
