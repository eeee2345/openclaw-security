/**
 * OpenAI LLM provider implementation
 * OpenAI LLM 供應商實作
 *
 * Uses the openai package via dynamic import to avoid hard dependencies.
 * Users must install the SDK separately.
 * 透過動態匯入使用 openai 套件以避免硬性相依。
 * 使用者必須另外安裝 SDK。
 *
 * @module @panguard-ai/core/ai/openai-provider
 */

import type { LLMConfig } from './types.js';
import { LLMProviderBase } from './provider-base.js';

/**
 * Minimal type definitions for OpenAI SDK to avoid compile-time dependency
 * OpenAI SDK 的最小型別定義，以避免編譯時相依
 * @internal
 */
interface OpenAIChatCompletion {
  id: string;
  choices: Array<{
    index: number;
    message: {
      role: 'assistant';
      content: string | null;
    };
    finish_reason: string;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

interface OpenAIClient {
  chat: {
    completions: {
      create(params: {
        model: string;
        messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>;
        temperature?: number;
        max_tokens?: number;
      }): Promise<OpenAIChatCompletion>;
    };
  };
}

interface OpenAIConstructor {
  new (options: { apiKey: string; timeout?: number }): OpenAIClient;
}

/**
 * OpenAI LLM provider
 * OpenAI LLM 供應商
 *
 * Requires the openai package to be installed separately.
 * The SDK is loaded via dynamic import() on first use.
 * 需要另外安裝 openai 套件。
 * SDK 在首次使用時透過動態 import() 載入。
 */
export class OpenAIProvider extends LLMProviderBase {
  /**
   * Cached OpenAI client instance / 快取的 OpenAI 客戶端實例
   * @internal
   */
  private client: OpenAIClient | null = null;

  /**
   * Create a new OpenAIProvider instance
   * 建立新的 OpenAIProvider 實例
   *
   * @param config - LLM configuration (apiKey required) / LLM 配置（需要 apiKey）
   */
  constructor(config: LLMConfig) {
    super(config);
    this.logger.info('OpenAI provider initialized', { model: this.model });
  }

  /**
   * Lazily initialize the OpenAI SDK client via dynamic import
   * 透過動態匯入延遲初始化 OpenAI SDK 客戶端
   *
   * @returns Initialized OpenAI client / 初始化的 OpenAI 客戶端
   * @throws Error if the SDK is not installed or API key is missing
   *         如果 SDK 未安裝或 API 金鑰遺失則拋出錯誤
   * @internal
   */
  private async getClient(): Promise<OpenAIClient> {
    if (this.client) {
      return this.client;
    }

    if (!this.config.apiKey) {
      throw new Error(
        'OpenAI API key is required. Set the apiKey field in LLMConfig or the OPENAI_API_KEY environment variable.'
      );
    }

    let OpenAI: OpenAIConstructor;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const module = await (import('openai' as string) as Promise<Record<string, unknown>>);
      OpenAI = (module['default'] ?? module) as unknown as OpenAIConstructor;
    } catch (error) {
      const message =
        error instanceof Error && error.message.includes('Cannot find')
          ? 'Install openai package to use OpenAI provider: npm install openai'
          : `Failed to load openai package: ${error instanceof Error ? error.message : String(error)}. ` +
            'Install it with: npm install openai';
      throw new Error(message);
    }

    this.client = new OpenAI({
      apiKey: this.config.apiKey,
      timeout: this.config.timeout,
    });

    return this.client;
  }

  /**
   * Check if the OpenAI API is available and the API key is valid
   * 檢查 OpenAI API 是否可用且 API 金鑰有效
   *
   * Attempts to create a minimal chat completion to verify connectivity.
   * 嘗試建立最小聊天完成以驗證連接性。
   *
   * @returns True if OpenAI API is reachable / OpenAI API 可連接時回傳 true
   */
  async isAvailable(): Promise<boolean> {
    try {
      if (!this.config.apiKey) {
        this.logger.debug('OpenAI provider: no API key configured');
        return false;
      }

      const client = await this.getClient();

      // Send a minimal test request
      // 發送最小測試請求
      const response = await client.chat.completions.create({
        model: this.model,
        messages: [{ role: 'user', content: 'Reply with "ok".' }],
        max_tokens: 10,
      });

      const isOk = response.choices.length > 0;
      this.logger.debug('OpenAI availability check', { available: isOk });
      return isOk;
    } catch (error) {
      this.logger.debug('OpenAI not available', {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Send a prompt to the OpenAI Chat Completions API
   * 向 OpenAI Chat Completions API 發送提示詞
   *
   * Uses a system message to establish the security analyst role,
   * followed by the user prompt.
   * 使用系統訊息建立安全分析師角色，接著是使用者提示詞。
   *
   * @param prompt - The prompt to send / 要發送的提示詞
   * @returns Raw response text / 原始回應文字
   * @throws Error if the API call fails / API 呼叫失敗時拋出錯誤
   */
  protected async sendRequest(prompt: string): Promise<string> {
    const client = await this.getClient();

    const systemMessage =
      this.config.lang === 'zh-TW'
        ? '你是一位專業的資安分析師，專精於威脅偵測、事件分析和安全報告撰寫。請以繁體中文回應。'
        : 'You are a professional cybersecurity analyst specializing in threat detection, incident analysis, and security report writing.';

    try {
      const response = await client.chat.completions.create({
        model: this.model,
        messages: [
          { role: 'system', content: systemMessage },
          { role: 'user', content: prompt },
        ],
        temperature: this.config.temperature,
        max_tokens: this.config.maxTokens,
      });

      // Track token usage from API response
      // 從 API 回應追蹤 Token 使用量
      if (response.usage) {
        this.tokenTracker.track(response.usage.prompt_tokens, response.usage.completion_tokens);
      }

      // Extract the assistant's message content
      // 提取助手的訊息內容
      const choice = response.choices[0];
      const content = choice?.message?.content ?? '';

      this.logger.debug('OpenAI request completed', {
        model: this.model,
        finishReason: choice?.finish_reason,
        promptTokens: response.usage?.prompt_tokens,
        completionTokens: response.usage?.completion_tokens,
      });

      if (!content) {
        throw new Error('OpenAI returned an empty response');
      }

      return content;
    } catch (error) {
      // Provide more specific error messages for common failures
      // 為常見失敗提供更具體的錯誤訊息
      if (error instanceof Error) {
        if (error.message.includes('401') || error.message.includes('Incorrect API key')) {
          throw new Error('OpenAI API authentication failed. Check your API key.');
        }
        if (error.message.includes('429') || error.message.includes('Rate limit')) {
          throw new Error('OpenAI API rate limit exceeded. Please wait and try again.');
        }
        if (error.message.includes('timeout') || error.message.includes('ETIMEDOUT')) {
          throw new Error(`OpenAI API request timed out after ${this.config.timeout}ms.`);
        }
        if (error.message.includes('model_not_found') || error.message.includes('does not exist')) {
          throw new Error(`OpenAI model "${this.model}" not found. Check the model name.`);
        }
      }

      throw error;
    }
  }
}
