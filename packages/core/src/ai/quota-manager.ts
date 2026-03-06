/**
 * AI Quota Manager - Per-tier rate limiting and cost control
 * AI 配額管理器 - 各等級速率限制與費用控制
 *
 * Enforces hourly AI call quotas per license tier and tracks
 * cumulative cost with hard budget caps to prevent overspending.
 *
 * @module @panguard-ai/core/ai/quota-manager
 */

import { createLogger } from '../utils/logger.js';

const logger = createLogger('ai:quota-manager');

/** License tier for quota purposes */
export type QuotaTier = 'free' | 'pro' | 'business' | 'enterprise';

/** Quota configuration per tier */
export interface QuotaConfig {
  /** Max AI calls per hour (0 = blocked, -1 = unlimited) */
  maxCallsPerHour: number;
  /** Max monthly budget in USD (0 = no budget, -1 = unlimited) */
  maxMonthlyBudgetUSD: number;
  /** Whether user provides own API key (BYOK) */
  isBYOK: boolean;
}

/** Default quota limits per tier */
const DEFAULT_QUOTAS: Record<QuotaTier, QuotaConfig> = {
  free: { maxCallsPerHour: 0, maxMonthlyBudgetUSD: 0, isBYOK: false },
  pro: { maxCallsPerHour: 200, maxMonthlyBudgetUSD: 10, isBYOK: false },
  business: { maxCallsPerHour: 500, maxMonthlyBudgetUSD: 50, isBYOK: true },
  enterprise: { maxCallsPerHour: -1, maxMonthlyBudgetUSD: -1, isBYOK: true },
};

/** Result of a quota check */
export interface QuotaCheckResult {
  allowed: boolean;
  reason?: string;
  remainingCalls: number;
  remainingBudgetUSD: number;
}

/** Quota usage snapshot */
export interface QuotaUsage {
  tier: QuotaTier;
  callsThisHour: number;
  maxCallsPerHour: number;
  costThisMonth: number;
  maxMonthlyBudgetUSD: number;
  isBYOK: boolean;
}

/**
 * AI Quota Manager
 *
 * Uses a sliding window for hourly call counting and tracks
 * cumulative monthly cost.
 */
export class AIQuotaManager {
  private readonly config: QuotaConfig;
  private readonly tier: QuotaTier;

  /** Timestamps of recent AI calls (sliding window) */
  private callTimestamps: number[] = [];
  /** Cumulative cost this month in USD */
  private monthlyCost = 0;
  /** Month key for cost reset (e.g. "2026-03") */
  private currentMonth: string;

  constructor(tier: QuotaTier, configOverride?: Partial<QuotaConfig>) {
    this.tier = tier;
    this.config = { ...DEFAULT_QUOTAS[tier], ...configOverride };
    this.currentMonth = AIQuotaManager.getMonthKey();

    logger.info(`AIQuotaManager initialized for tier=${tier}`, {
      maxCallsPerHour: this.config.maxCallsPerHour,
      maxMonthlyBudgetUSD: this.config.maxMonthlyBudgetUSD,
      isBYOK: this.config.isBYOK,
    });
  }

  /**
   * Check if an AI call is allowed under current quota
   */
  checkQuota(): QuotaCheckResult {
    this.maybeResetMonth();
    this.pruneOldTimestamps();

    const callsThisHour = this.callTimestamps.length;
    const maxCalls = this.config.maxCallsPerHour;
    const maxBudget = this.config.maxMonthlyBudgetUSD;

    // BYOK users skip vendor cost checks (they pay their own API)
    if (this.config.isBYOK) {
      return {
        allowed: true,
        remainingCalls: maxCalls === -1 ? Infinity : Math.max(0, maxCalls - callsThisHour),
        remainingBudgetUSD: Infinity,
      };
    }

    // Free tier: no AI access
    if (maxCalls === 0) {
      return {
        allowed: false,
        reason: 'AI analysis not available on free tier. Upgrade to Pro for AI-powered detection.',
        remainingCalls: 0,
        remainingBudgetUSD: 0,
      };
    }

    // Hourly rate limit check
    if (maxCalls !== -1 && callsThisHour >= maxCalls) {
      return {
        allowed: false,
        reason: `Hourly AI quota exceeded (${callsThisHour}/${maxCalls}). Resets next hour.`,
        remainingCalls: 0,
        remainingBudgetUSD: Math.max(0, maxBudget - this.monthlyCost),
      };
    }

    // Monthly budget check
    if (maxBudget !== -1 && this.monthlyCost >= maxBudget) {
      return {
        allowed: false,
        reason: `Monthly AI budget exceeded ($${this.monthlyCost.toFixed(2)}/$${maxBudget.toFixed(2)}).`,
        remainingCalls: maxCalls === -1 ? Infinity : Math.max(0, maxCalls - callsThisHour),
        remainingBudgetUSD: 0,
      };
    }

    return {
      allowed: true,
      remainingCalls: maxCalls === -1 ? Infinity : maxCalls - callsThisHour,
      remainingBudgetUSD: maxBudget === -1 ? Infinity : maxBudget - this.monthlyCost,
    };
  }

  /**
   * Record a completed AI call with its cost
   */
  recordCall(costUSD: number): void {
    this.maybeResetMonth();
    this.callTimestamps.push(Date.now());
    if (!this.config.isBYOK) {
      this.monthlyCost += costUSD;
    }
  }

  /**
   * Get current usage snapshot
   */
  getUsage(): QuotaUsage {
    this.maybeResetMonth();
    this.pruneOldTimestamps();

    return {
      tier: this.tier,
      callsThisHour: this.callTimestamps.length,
      maxCallsPerHour: this.config.maxCallsPerHour,
      costThisMonth: Math.round(this.monthlyCost * 1_000_000) / 1_000_000,
      maxMonthlyBudgetUSD: this.config.maxMonthlyBudgetUSD,
      isBYOK: this.config.isBYOK,
    };
  }

  /** Remove timestamps older than 1 hour */
  private pruneOldTimestamps(): void {
    const oneHourAgo = Date.now() - 3_600_000;
    this.callTimestamps = this.callTimestamps.filter((t) => t > oneHourAgo);
  }

  /** Reset monthly cost if we crossed into a new month */
  private maybeResetMonth(): void {
    const now = AIQuotaManager.getMonthKey();
    if (now !== this.currentMonth) {
      logger.info(`Monthly quota reset (${this.currentMonth} -> ${now})`);
      this.monthlyCost = 0;
      this.currentMonth = now;
    }
  }

  /** Get current month key (e.g. "2026-03") */
  static getMonthKey(): string {
    const d = new Date();
    return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
  }
}
