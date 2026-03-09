/**
 * ATR Engine Integration for PanguardGuard
 *
 * Bridges the ATR (Agent Threat Rules) engine with the existing
 * GuardEngine pipeline. Converts SecurityEvents into AgentEvents
 * and routes ATR matches into the DetectionResult pipeline.
 *
 * @module @panguard-ai/panguard-guard/engines/atr-engine
 */

import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent } from '@panguard-ai/core';
import { ATREngine, SessionTracker } from 'agent-threat-rules';
import type { ATRMatch, ATRRule, AgentEvent, AgentEventType } from 'agent-threat-rules';

const logger = createLogger('panguard-guard:atr-engine');

/**
 * Resolve the bundled ATR rules directory from the installed agent-threat-rules package.
 * Falls back to null if the package can't be resolved.
 */
function resolveBundledRulesDir(): string | null {
  try {
    const require = createRequire(import.meta.url);
    const atrPkgPath = require.resolve('agent-threat-rules/package.json');
    return join(dirname(atrPkgPath), 'rules');
  } catch {
    return null;
  }
}

export interface GuardATREngineConfig {
  /** Directory containing custom ATR YAML rules */
  rulesDir?: string;
  /** Directory containing bundled ATR rules (auto-resolved from agent-threat-rules if omitted) */
  bundledRulesDir?: string;
  /** Enable hot-reload of rule files */
  hotReload?: boolean;
}

/**
 * GuardATREngine wraps the ATR engine for integration with
 * the PanguardGuard event processing pipeline.
 *
 * Rules are loaded from:
 * 1. Bundled rules shipped with the agent-threat-rules package
 * 2. Custom rules from the user's configured rulesDir
 */
export class GuardATREngine {
  private readonly engine: ATREngine;
  private readonly bundledEngine: ATREngine | null;
  private readonly cloudRuleIds = new Set<string>();
  private matchCount = 0;
  private readonly sessionTracker: SessionTracker;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: GuardATREngineConfig = {}) {
    // Shared session tracker for behavioral detection across events
    const sessionTracker = new SessionTracker();

    // Primary engine for custom user rules
    this.engine = new ATREngine({
      rulesDir: config.rulesDir,
      hotReload: config.hotReload,
      sessionTracker,
    });

    // Bundled rules from the agent-threat-rules package
    const bundledDir = config.bundledRulesDir ?? resolveBundledRulesDir();
    if (bundledDir) {
      this.bundledEngine = new ATREngine({ rulesDir: bundledDir, sessionTracker });
    } else {
      this.bundledEngine = null;
    }

    this.sessionTracker = sessionTracker;
  }

  /**
   * Load ATR rules from both bundled and custom sources.
   * Call during GuardEngine.start().
   */
  async loadRules(): Promise<number> {
    let total = 0;

    // Load bundled rules from agent-threat-rules package
    if (this.bundledEngine) {
      const bundled = await this.bundledEngine.loadRules();
      total += bundled;
      logger.info(`ATR bundled rules loaded: ${bundled} rules`);
    }

    // Load custom user rules
    const custom = await this.engine.loadRules();
    total += custom;
    if (custom > 0) {
      logger.info(`ATR custom rules loaded: ${custom} rules`);
    }

    logger.info(`ATR total rules: ${total}`);
    return total;
  }

  /**
   * Evaluate a SecurityEvent against ATR rules.
   * Converts SecurityEvent to AgentEvent format and runs evaluation.
   */
  evaluate(event: SecurityEvent): ATRMatch[] {
    const agentEvent = this.toAgentEvent(event);
    if (!agentEvent) return [];

    // Evaluate against both bundled and custom rules
    const bundledMatches = this.bundledEngine?.evaluate(agentEvent) ?? [];
    const customMatches = this.engine.evaluate(agentEvent);
    const matches = [...bundledMatches, ...customMatches];
    if (matches.length > 0) {
      this.matchCount += matches.length;
      logger.warn(
        `ATR match: ${matches.length} rules triggered for event ${event.id} ` +
        `[${matches.map((m) => m.rule.id).join(', ')}]`
      );
    }

    return matches;
  }

  /**
   * Add a rule from Threat Cloud. Skips if already loaded.
   * 新增從 Threat Cloud 接收的規則（避免重複）
   */
  addCloudRule(rule: ATRRule): void {
    if (this.cloudRuleIds.has(rule.id)) return;
    this.engine.addRule(rule);
    this.cloudRuleIds.add(rule.id);
  }

  /**
   * Convert a SecurityEvent into an AgentEvent for ATR evaluation.
   * Returns null if the event is not relevant to agent threat detection.
   */
  private toAgentEvent(event: SecurityEvent): AgentEvent | null {
    const meta = event.metadata ?? {};

    // Determine event type based on SecurityEvent source and metadata
    let type: AgentEventType;
    let content: string;
    const fields: Record<string, string> = {};

    switch (event.source) {
      case 'agent_input':
      case 'llm_input':
        type = 'llm_input';
        content = (meta['prompt'] as string) ?? (meta['input'] as string) ?? event.description;
        if (meta['user_input']) fields['user_input'] = meta['user_input'] as string;
        break;

      case 'agent_output':
      case 'llm_output':
        type = 'llm_output';
        content = (meta['response'] as string) ?? (meta['output'] as string) ?? event.description;
        if (meta['agent_output']) fields['agent_output'] = meta['agent_output'] as string;
        break;

      case 'tool_call':
      case 'function_call':
        type = 'tool_call';
        content = (meta['tool_name'] as string) ?? event.description;
        if (meta['tool_name']) fields['tool_name'] = meta['tool_name'] as string;
        if (meta['tool_args']) fields['tool_args'] = JSON.stringify(meta['tool_args']);
        break;

      case 'tool_response':
      case 'mcp_response':
        type = 'tool_response';
        content = (meta['tool_response'] as string) ?? (meta['result'] as string) ?? event.description;
        if (meta['tool_name']) fields['tool_name'] = meta['tool_name'] as string;
        if (meta['tool_response']) fields['tool_response'] = meta['tool_response'] as string;
        break;

      case 'agent_behavior':
        type = 'agent_behavior';
        content = event.description;
        break;

      case 'multi_agent':
        type = 'multi_agent_message';
        content = (meta['message'] as string) ?? event.description;
        if (meta['source_agent']) fields['source_agent'] = meta['source_agent'] as string;
        if (meta['target_agent']) fields['target_agent'] = meta['target_agent'] as string;
        break;

      default:
        // Not an agent-related event
        return null;
    }

    // Extract behavioral metrics if present
    const metrics: Record<string, number> = {};
    for (const [key, value] of Object.entries(meta)) {
      if (typeof value === 'number' && key.startsWith('metric_')) {
        metrics[key.slice(7)] = value;
      }
    }

    return {
      type,
      timestamp: new Date().toISOString(),
      content,
      fields: Object.keys(fields).length > 0 ? fields : undefined,
      metrics: Object.keys(metrics).length > 0 ? metrics : undefined,
      sessionId: meta['sessionId'] as string | undefined,
      agentId: meta['agentId'] as string | undefined,
      metadata: meta,
    };
  }

  /** Get total match count */
  getMatchCount(): number {
    return this.matchCount;
  }

  /** Get loaded rule count (bundled + custom) */
  getRuleCount(): number {
    return (this.bundledEngine?.getRuleCount() ?? 0) + this.engine.getRuleCount();
  }

  /**
   * Start periodic session cleanup (evict sessions idle > 30 minutes).
   * Call after loadRules() to begin maintenance.
   */
  startSessionCleanup(): void {
    if (this.cleanupTimer) return;
    const CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes
    const SESSION_MAX_AGE = 30 * 60 * 1000; // 30 minutes
    this.cleanupTimer = setInterval(() => {
      const evicted = this.sessionTracker.cleanup(SESSION_MAX_AGE);
      if (evicted > 0) {
        logger.info(`ATR session cleanup: evicted ${evicted} idle sessions`);
      }
    }, CLEANUP_INTERVAL);
  }

  /** Stop session cleanup timer */
  stop(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /** Get active session count */
  getSessionCount(): number {
    return this.sessionTracker.getSessionCount();
  }
}
