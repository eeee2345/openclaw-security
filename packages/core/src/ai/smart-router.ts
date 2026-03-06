/**
 * Smart AI Router - Cost-optimized routing with knowledge distillation
 * 智慧 AI 路由器 - 成本最佳化路由與知識蒸餾
 *
 * Wraps FunnelRouter with intelligent decision-making:
 * - Skip AI entirely for high-confidence rule matches (>=80%)
 * - Route simple/known patterns to local Ollama (free)
 * - Route only complex/unknown patterns to cloud Claude/OpenAI
 * - Enforce per-tier quotas via AIQuotaManager
 * - Distill AI analysis results into rules to avoid repeat cloud calls
 *
 * @module @panguard-ai/core/ai/smart-router
 */

import { createLogger } from '../utils/logger.js';
import type { AnalysisResult, LLMProvider } from './types.js';
import { FunnelRouter } from './funnel-router.js';
import type { FunnelRouterConfig } from './funnel-router.js';
import { AIQuotaManager } from './quota-manager.js';
import type { QuotaTier, QuotaConfig } from './quota-manager.js';

const logger = createLogger('ai:smart-router');

/** Complexity assessment for routing decisions */
export type EventComplexity = 'skip' | 'simple' | 'complex';

/** Smart router configuration */
export interface SmartRouterConfig extends FunnelRouterConfig {
  /** License tier for quota enforcement */
  tier: QuotaTier;
  /** Optional quota config override */
  quotaOverride?: Partial<QuotaConfig>;
  /** Rule confidence threshold to skip AI entirely (default: 80) */
  skipAIThreshold?: number;
  /** Confidence threshold to prefer local AI over cloud (default: 60) */
  preferLocalThreshold?: number;
}

/** Routing decision metadata */
export interface RoutingDecision {
  complexity: EventComplexity;
  provider: 'rules-only' | 'local-ai' | 'cloud-ai' | 'quota-blocked';
  reason: string;
  quotaAllowed: boolean;
}

/**
 * Smart Router wrapping FunnelRouter with cost optimization
 */
export class SmartRouter {
  private readonly funnel: FunnelRouter;
  private readonly quota: AIQuotaManager;
  private readonly skipAIThreshold: number;
  private readonly preferLocalThreshold: number;
  private readonly localProvider: LLMProvider | null;
  private readonly cloudProvider: LLMProvider | null;

  /** Knowledge cache: pattern hash -> cached result (avoids repeat AI calls) */
  private readonly knowledgeCache = new Map<string, { result: AnalysisResult; timestamp: number }>();
  private readonly cacheTTL = 3_600_000; // 1 hour

  /** Stats */
  private stats = {
    totalRequests: 0,
    skippedByRules: 0,
    routedToLocal: 0,
    routedToCloud: 0,
    servedFromCache: 0,
    blockedByQuota: 0,
  };

  constructor(config: SmartRouterConfig) {
    this.funnel = new FunnelRouter(config);
    this.quota = new AIQuotaManager(config.tier, config.quotaOverride);
    this.skipAIThreshold = config.skipAIThreshold ?? 80;
    this.preferLocalThreshold = config.preferLocalThreshold ?? 60;
    this.localProvider = config.localProvider ?? null;
    this.cloudProvider = config.cloudProvider ?? null;

    logger.info('SmartRouter initialized', {
      tier: config.tier,
      skipAIThreshold: this.skipAIThreshold,
      preferLocalThreshold: this.preferLocalThreshold,
    });
  }

  /**
   * Assess event complexity based on rule confidence
   */
  assessComplexity(ruleConfidence: number, hasAttackChain: boolean): EventComplexity {
    // High confidence rule match: AI not needed
    if (ruleConfidence >= this.skipAIThreshold && !hasAttackChain) {
      return 'skip';
    }

    // Medium confidence or attack chain: local AI can handle
    if (ruleConfidence >= this.preferLocalThreshold) {
      return 'simple';
    }

    // Low confidence or unknown: needs cloud AI
    return 'complex';
  }

  /**
   * Route an analysis request with smart cost optimization
   *
   * @param prompt - Analysis prompt
   * @param ruleConfidence - Confidence from rule matches (0-100)
   * @param hasAttackChain - Whether an attack chain was detected
   * @param patternHash - Optional hash for knowledge cache lookup
   * @param context - Optional analysis context
   */
  async analyze(
    prompt: string,
    ruleConfidence: number,
    hasAttackChain: boolean,
    patternHash?: string,
    context?: string
  ): Promise<{ result: AnalysisResult | null; decision: RoutingDecision }> {
    this.stats.totalRequests++;
    const complexity = this.assessComplexity(ruleConfidence, hasAttackChain);

    // Skip AI entirely for high-confidence rule matches
    if (complexity === 'skip') {
      this.stats.skippedByRules++;
      return {
        result: null,
        decision: {
          complexity: 'skip',
          provider: 'rules-only',
          reason: `Rule confidence ${ruleConfidence}% >= ${this.skipAIThreshold}% threshold`,
          quotaAllowed: true,
        },
      };
    }

    // Check knowledge cache
    if (patternHash) {
      const cached = this.knowledgeCache.get(patternHash);
      if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
        this.stats.servedFromCache++;
        return {
          result: cached.result,
          decision: {
            complexity,
            provider: 'local-ai',
            reason: 'Served from knowledge cache (previously analyzed pattern)',
            quotaAllowed: true,
          },
        };
      }
    }

    // Check quota
    const quotaCheck = this.quota.checkQuota();
    if (!quotaCheck.allowed) {
      this.stats.blockedByQuota++;
      logger.warn('AI request blocked by quota', { reason: quotaCheck.reason });
      return {
        result: null,
        decision: {
          complexity,
          provider: 'quota-blocked',
          reason: quotaCheck.reason ?? 'Quota exceeded',
          quotaAllowed: false,
        },
      };
    }

    // Route based on complexity
    let result: AnalysisResult | null = null;
    let provider: RoutingDecision['provider'] = 'rules-only';

    if (complexity === 'simple' && this.localProvider) {
      // Simple events -> local AI (free)
      try {
        result = await this.localProvider.analyze(prompt, context);
        provider = 'local-ai';
        this.stats.routedToLocal++;
        this.quota.recordCall(0); // Local is free
      } catch {
        // Fall through to cloud
        logger.debug('Local AI failed for simple event, trying cloud');
      }
    }

    if (!result) {
      // Complex events or local failure -> use funnel (tries local first, then cloud)
      result = await this.funnel.analyze(prompt, context);

      if (result) {
        const funnelStatus = this.funnel.getStatus();
        const usedCloud = funnelStatus.activeLayer === 'cloud-ai' ||
          (!funnelStatus.local.available && funnelStatus.cloud.available);

        if (usedCloud) {
          provider = 'cloud-ai';
          this.stats.routedToCloud++;
          // Estimate cost: ~800 input tokens + ~200 output tokens at Claude Sonnet pricing
          this.quota.recordCall(0.0054);
        } else {
          provider = 'local-ai';
          this.stats.routedToLocal++;
          this.quota.recordCall(0);
        }
      }
    }

    // Cache the result for knowledge distillation
    if (patternHash && result) {
      this.knowledgeCache.set(patternHash, { result, timestamp: Date.now() });
    }

    return {
      result,
      decision: {
        complexity,
        provider,
        reason: `Routed ${complexity} event to ${provider}`,
        quotaAllowed: true,
      },
    };
  }

  /**
   * Record a distilled rule for a pattern (so future occurrences skip AI)
   */
  recordDistilledPattern(patternHash: string, result: AnalysisResult): void {
    this.knowledgeCache.set(patternHash, { result, timestamp: Date.now() });
  }

  /** Get routing statistics */
  getStats() {
    return { ...this.stats };
  }

  /** Get quota usage */
  getQuotaUsage() {
    return this.quota.getUsage();
  }

  /** Get funnel status */
  getFunnelStatus() {
    return this.funnel.getStatus();
  }

  /** Start health checks on underlying funnel */
  startHealthChecks(intervalMs?: number): void {
    this.funnel.startHealthChecks(intervalMs);
  }

  /** Stop health checks */
  stopHealthChecks(): void {
    this.funnel.stopHealthChecks();
  }
}
