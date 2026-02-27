/**
 * AI/LLM Unified Interface Layer
 * AI/LLM 統一介面層
 *
 * Provides a unified interface for multiple LLM providers
 * including Ollama (local), Claude API, and OpenAI API.
 * Factory function `createLLM()` instantiates the appropriate provider
 * based on configuration.
 * 提供多個 LLM 供應商的統一介面，包括 Ollama（本地）、Claude API 和 OpenAI API。
 * 工廠函式 `createLLM()` 根據配置實例化適當的供應商。
 *
 * @module @panguard-ai/core/ai
 *
 * @example
 * ```typescript
 * import { createLLM } from '@panguard-ai/core/ai';
 *
 * // Local Ollama provider (no API key needed)
 * const ollama = createLLM({
 *   provider: 'ollama',
 *   model: 'llama3',
 *   lang: 'en',
 * });
 *
 * // Claude provider (requires @anthropic-ai/sdk installed)
 * const claude = createLLM({
 *   provider: 'claude',
 *   model: 'claude-sonnet-4-20250514',
 *   apiKey: process.env.ANTHROPIC_API_KEY,
 *   lang: 'zh-TW',
 * });
 *
 * // Analyze a security threat
 * const result = await ollama.analyze('Suspicious SSH brute force attempts detected');
 * ```
 */

import type { LLMConfig, LLMProvider } from './types.js';
import { OllamaProvider } from './ollama-provider.js';
import { ClaudeProvider } from './claude-provider.js';
import { OpenAIProvider } from './openai-provider.js';

/** AI module version / AI 模組版本 */
export const AI_VERSION = '0.1.0';

/**
 * Create an LLM provider instance based on configuration
 * 根據配置建立 LLM 供應商實例
 *
 * Factory function that instantiates the appropriate provider class
 * based on the `provider` field in the config.
 * 工廠函式，根據配置中的 `provider` 欄位實例化適當的供應商類別。
 *
 * @param config - LLM provider configuration / LLM 供應商配置
 * @returns An LLMProvider instance / LLMProvider 實例
 * @throws Error if the provider type is unknown / 供應商類型不明時拋出錯誤
 *
 * @example
 * ```typescript
 * const provider = createLLM({
 *   provider: 'ollama',
 *   model: 'llama3',
 *   lang: 'en',
 * });
 *
 * if (await provider.isAvailable()) {
 *   const analysis = await provider.analyze('Suspicious activity detected');
 *   console.log(analysis.summary);
 * }
 * ```
 */
export function createLLM(config: LLMConfig): LLMProvider {
  switch (config.provider) {
    case 'ollama':
      return new OllamaProvider(config);
    case 'claude':
      return new ClaudeProvider(config);
    case 'openai':
      return new OpenAIProvider(config);
    default:
      throw new Error(
        `Unknown LLM provider: "${(config as LLMConfig).provider}". ` +
          'Supported providers: ollama, claude, openai'
      );
  }
}

// Re-export types
// 重新匯出型別
export type {
  LLMProviderType,
  LLMConfig,
  AnalysisResult,
  ThreatClassification,
  TokenUsage,
  LLMProvider,
} from './types.js';

// Re-export classes (for advanced usage / testing)
// 重新匯出類別（供進階使用 / 測試）
export { LLMProviderBase } from './provider-base.js';
export { OllamaProvider } from './ollama-provider.js';
export { ClaudeProvider } from './claude-provider.js';
export { OpenAIProvider } from './openai-provider.js';

// Re-export utilities
// 重新匯出工具
export { TokenTracker } from './token-tracker.js';
export { FunnelRouter } from './funnel-router.js';
export type { FunnelRouterConfig, FunnelLayerStatus } from './funnel-router.js';
export { parseAnalysisResponse, parseClassificationResponse } from './response-parser.js';

// Re-export prompts
// 重新匯出提示詞
export {
  getEventClassifierPrompt,
  getThreatAnalysisPrompt,
  getReportPrompt,
} from './prompts/index.js';
