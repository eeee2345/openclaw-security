/**
 * Token usage tracking and cost estimation
 * Token 使用追蹤與費用估算
 *
 * Tracks cumulative token usage across LLM requests and calculates
 * estimated costs based on provider-specific pricing.
 * 追蹤跨 LLM 請求的累計 Token 使用量，並根據供應商定價計算估算費用。
 *
 * @module @panguard-ai/core/ai/token-tracker
 */

import type { LLMProviderType, TokenUsage } from './types.js';

/**
 * Pricing per 1M tokens in USD (approximate)
 * 每 1M Token 的價格（美元，近似值）
 *
 * @internal
 */
interface PricingTier {
  /** Cost per 1M input/prompt tokens / 每 1M 輸入 Token 費用 */
  input: number;
  /** Cost per 1M output/completion tokens / 每 1M 輸出 Token 費用 */
  output: number;
}

/**
 * Approximate pricing table for supported providers and models
 * 支援的供應商和模型的近似定價表
 *
 * Pricing is per 1M tokens in USD.
 * 定價為每 1M Token 的美元費用。
 *
 * @internal
 */
const PRICING: Record<string, PricingTier> = {
  // Ollama: free (local inference)
  // Ollama：免費（本地推論）
  'ollama:default': { input: 0, output: 0 },

  // Claude models (current generation)
  'claude:claude-opus-4-6': { input: 15, output: 75 },
  'claude:claude-sonnet-4-6': { input: 3, output: 15 },
  'claude:claude-haiku-4-5-20251001': { input: 0.8, output: 4 },
  // Claude models (previous generation)
  'claude:claude-sonnet-4-20250514': { input: 3, output: 15 },
  'claude:claude-3-5-sonnet-20241022': { input: 3, output: 15 },
  'claude:claude-3-haiku-20240307': { input: 0.25, output: 1.25 },
  'claude:claude-3-opus-20240229': { input: 15, output: 75 },

  // OpenAI models
  'openai:gpt-4o': { input: 2.5, output: 10 },
  'openai:gpt-4o-mini': { input: 0.15, output: 0.6 },
  'openai:gpt-4-turbo': { input: 10, output: 30 },
  'openai:gpt-3.5-turbo': { input: 0.5, output: 1.5 },
};

/**
 * Tracks token usage and estimates cost for an LLM provider
 * 追蹤 LLM 供應商的 Token 使用量並估算費用
 */
export class TokenTracker {
  /**
   * Cumulative token usage / 累計 Token 使用量
   * @internal
   */
  private usage: TokenUsage = {
    promptTokens: 0,
    completionTokens: 0,
    totalTokens: 0,
    estimatedCost: 0,
  };

  /**
   * Create a new TokenTracker instance
   * 建立新的 TokenTracker 實例
   *
   * @param provider - The LLM provider type / LLM 供應商類型
   * @param model - The model name / 模型名稱
   */
  constructor(
    private readonly provider: LLMProviderType,
    private readonly model: string
  ) {}

  /**
   * Record token usage from a single request
   * 記錄單次請求的 Token 使用量
   *
   * @param promptTokens - Number of prompt tokens used / 使用的提示詞 Token 數
   * @param completionTokens - Number of completion tokens used / 使用的完成回應 Token 數
   */
  track(promptTokens: number, completionTokens: number): void {
    this.usage.promptTokens += promptTokens;
    this.usage.completionTokens += completionTokens;
    this.usage.totalTokens += promptTokens + completionTokens;
    this.usage.estimatedCost = this.calculateCost();
  }

  /**
   * Get current cumulative token usage
   * 取得目前累計 Token 使用量
   *
   * @returns A copy of the current token usage / 目前 Token 使用量的副本
   */
  getUsage(): TokenUsage {
    return { ...this.usage };
  }

  /**
   * Reset all usage counters to zero
   * 重置所有使用量計數器為零
   */
  reset(): void {
    this.usage = {
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      estimatedCost: 0,
    };
  }

  /**
   * Calculate the estimated cost based on cumulative usage
   * 根據累計使用量計算估算費用
   *
   * @returns Estimated cost in USD / 估算費用（美元）
   * @internal
   */
  private calculateCost(): number {
    const pricing = this.getPricing();
    const inputCost = (this.usage.promptTokens / 1_000_000) * pricing.input;
    const outputCost = (this.usage.completionTokens / 1_000_000) * pricing.output;
    return Math.round((inputCost + outputCost) * 1_000_000) / 1_000_000;
  }

  /**
   * Look up pricing for the current provider and model
   * 查詢目前供應商和模型的定價
   *
   * Falls back to provider default, then to zero cost.
   * 回退到供應商預設值，然後回退到零費用。
   *
   * @returns Pricing tier / 定價層級
   * @internal
   */
  private getPricing(): PricingTier {
    const key = `${this.provider}:${this.model}`;
    if (PRICING[key]) {
      return PRICING[key];
    }

    // Fallback: match by provider prefix
    // 回退：按供應商前綴匹配
    const providerDefault = `${this.provider}:default`;
    if (PRICING[providerDefault]) {
      return PRICING[providerDefault];
    }

    // All Ollama models are free (local)
    // 所有 Ollama 模型免費（本地推論）
    if (this.provider === 'ollama') {
      return { input: 0, output: 0 };
    }

    // Unknown model: return zero to avoid incorrect charges
    // 未知模型：回傳零以避免錯誤計費
    return { input: 0, output: 0 };
  }
}
