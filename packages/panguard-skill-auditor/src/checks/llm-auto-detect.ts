/**
 * LLM auto-detection for Skill Auditor
 * LLM 自動偵測（技能審計器）
 *
 * Attempts to find an available LLM provider in this order:
 *   1. Ollama (local, no API key needed)
 *   2. Claude API (ANTHROPIC_API_KEY env var)
 *   3. OpenAI API (OPENAI_API_KEY env var)
 *
 * Returns a SkillAnalysisLLM adapter or null if nothing is available.
 */

import type { SkillAnalysisLLM } from './ai-check.js';

/**
 * Attempt to auto-detect and create a SkillAnalysisLLM from available providers.
 *
 * Priority: ANTHROPIC_API_KEY > OPENAI_API_KEY > Ollama (local fallback).
 * Returns null if no provider can be reached.
 */
export async function autoDetectSkillLLM(): Promise<SkillAnalysisLLM | null> {
  try {
    const { createLLM } = await import('@panguard-ai/core');

    type ProviderType = 'ollama' | 'claude' | 'openai';

    let provider: ProviderType;
    let apiKey: string | undefined;
    let model: string;

    const defaultModels: Record<ProviderType, string> = {
      claude: 'claude-sonnet-4-20250514',
      openai: 'gpt-4o',
      ollama: 'llama3',
    };

    // Check environment variables first (cloud providers), then fall back to Ollama
    if (process.env['ANTHROPIC_API_KEY']) {
      provider = 'claude';
      apiKey = process.env['ANTHROPIC_API_KEY'];
    } else if (process.env['OPENAI_API_KEY']) {
      provider = 'openai';
      apiKey = process.env['OPENAI_API_KEY'];
    } else {
      provider = 'ollama';
    }

    // Allow override via PANGUARD_LLM_MODEL env var
    model = process.env['PANGUARD_LLM_MODEL'] ?? defaultModels[provider];

    const llmProvider = createLLM({ provider, model, apiKey, lang: 'en' });

    const available = await llmProvider.isAvailable();
    if (!available) {
      return null;
    }

    // Adapt core LLMProvider to the SkillAnalysisLLM interface
    const adapter: SkillAnalysisLLM = {
      async analyze(prompt: string, context?: string) {
        const result = await llmProvider.analyze(prompt, context);
        return {
          summary: result.summary,
          severity: result.severity,
          confidence: result.confidence,
          recommendations: result.recommendations,
        };
      },
      async isAvailable() {
        return llmProvider.isAvailable();
      },
    };

    return adapter;
  } catch {
    // Auto-detect failure should not break auditing
    return null;
  }
}
