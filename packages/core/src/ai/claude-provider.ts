/**
 * Claude (Anthropic) LLM provider implementation
 * Claude (Anthropic) LLM 供應商實作
 *
 * Uses the @anthropic-ai/sdk package via dynamic import to avoid
 * hard dependencies. Users must install the SDK separately.
 * 透過動態匯入使用 @anthropic-ai/sdk 套件以避免硬性相依。
 * 使用者必須另外安裝 SDK。
 *
 * @module @openclaw/core/ai/claude-provider
 */

import type { LLMConfig } from './types.js';
import { LLMProviderBase } from './provider-base.js';

/**
 * Minimal type definitions for Anthropic SDK to avoid compile-time dependency
 * Anthropic SDK 的最小型別定義，以避免編譯時相依
 * @internal
 */
interface AnthropicMessage {
  id: string;
  type: 'message';
  role: 'assistant';
  content: Array<{ type: 'text'; text: string }>;
  model: string;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

interface AnthropicClient {
  messages: {
    create(params: {
      model: string;
      max_tokens: number;
      temperature?: number;
      system?: string;
      messages: Array<{ role: 'user'; content: string }>;
    }): Promise<AnthropicMessage>;
  };
}

interface AnthropicConstructor {
  new (options: { apiKey: string; timeout?: number }): AnthropicClient;
}

/**
 * Claude (Anthropic) LLM provider
 * Claude (Anthropic) LLM 供應商
 *
 * Requires the @anthropic-ai/sdk package to be installed separately.
 * The SDK is loaded via dynamic import() on first use.
 * 需要另外安裝 @anthropic-ai/sdk 套件。
 * SDK 在首次使用時透過動態 import() 載入。
 */
export class ClaudeProvider extends LLMProviderBase {
  /**
   * Cached Anthropic client instance / 快取的 Anthropic 客戶端實例
   * @internal
   */
  private client: AnthropicClient | null = null;

  /**
   * Create a new ClaudeProvider instance
   * 建立新的 ClaudeProvider 實例
   *
   * @param config - LLM configuration (apiKey required) / LLM 配置（需要 apiKey）
   */
  constructor(config: LLMConfig) {
    super(config);
    this.logger.info('Claude provider initialized', { model: this.model });
  }

  /**
   * Lazily initialize the Anthropic SDK client via dynamic import
   * 透過動態匯入延遲初始化 Anthropic SDK 客戶端
   *
   * @returns Initialized Anthropic client / 初始化的 Anthropic 客戶端
   * @throws Error if the SDK is not installed or API key is missing
   *         如果 SDK 未安裝或 API 金鑰遺失則拋出錯誤
   * @internal
   */
  private async getClient(): Promise<AnthropicClient> {
    if (this.client) {
      return this.client;
    }

    if (!this.config.apiKey) {
      throw new Error(
        'Claude API key is required. Set the apiKey field in LLMConfig or the ANTHROPIC_API_KEY environment variable.',
      );
    }

    let Anthropic: AnthropicConstructor;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const module = await (import('@anthropic-ai/sdk' as string) as Promise<Record<string, unknown>>);
      Anthropic = (module['default'] ?? module['Anthropic'] ?? module) as unknown as AnthropicConstructor;
    } catch (error) {
      const message =
        error instanceof Error && error.message.includes('Cannot find')
          ? 'Install @anthropic-ai/sdk to use Claude provider: npm install @anthropic-ai/sdk'
          : `Failed to load @anthropic-ai/sdk: ${error instanceof Error ? error.message : String(error)}. ` +
            'Install it with: npm install @anthropic-ai/sdk';
      throw new Error(message);
    }

    this.client = new Anthropic({
      apiKey: this.config.apiKey,
      timeout: this.config.timeout,
    });

    return this.client;
  }

  /**
   * Check if the Claude API is available and the API key is valid
   * 檢查 Claude API 是否可用且 API 金鑰有效
   *
   * Attempts to create a minimal message to verify connectivity.
   * 嘗試建立最小訊息以驗證連接性。
   *
   * @returns True if Claude API is reachable / Claude API 可連接時回傳 true
   */
  async isAvailable(): Promise<boolean> {
    try {
      if (!this.config.apiKey) {
        this.logger.debug('Claude provider: no API key configured');
        return false;
      }

      const client = await this.getClient();

      // Send a minimal test request
      // 發送最小測試請求
      const response = await client.messages.create({
        model: this.model,
        max_tokens: 10,
        messages: [{ role: 'user', content: 'Reply with "ok".' }],
      });

      const isOk = response.content.length > 0;
      this.logger.debug('Claude availability check', { available: isOk });
      return isOk;
    } catch (error) {
      this.logger.debug('Claude not available', {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Send a prompt to the Claude API via the Anthropic SDK
   * 透過 Anthropic SDK 向 Claude API 發送提示詞
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
      const response = await client.messages.create({
        model: this.model,
        max_tokens: this.config.maxTokens,
        temperature: this.config.temperature,
        system: systemMessage,
        messages: [{ role: 'user', content: prompt }],
      });

      // Track token usage from API response
      // 從 API 回應追蹤 Token 使用量
      if (response.usage) {
        this.tokenTracker.track(
          response.usage.input_tokens,
          response.usage.output_tokens,
        );
      }

      // Extract text from content blocks
      // 從內容區塊中提取文字
      const textContent = response.content
        .filter((block): block is { type: 'text'; text: string } => block.type === 'text')
        .map((block) => block.text)
        .join('\n');

      this.logger.debug('Claude request completed', {
        model: response.model,
        inputTokens: response.usage?.input_tokens,
        outputTokens: response.usage?.output_tokens,
      });

      return textContent;
    } catch (error) {
      // Provide more specific error messages for common failures
      // 為常見失敗提供更具體的錯誤訊息
      if (error instanceof Error) {
        if (error.message.includes('401') || error.message.includes('authentication')) {
          throw new Error(
            'Claude API authentication failed. Check your API key.',
          );
        }
        if (error.message.includes('429') || error.message.includes('rate')) {
          throw new Error(
            'Claude API rate limit exceeded. Please wait and try again.',
          );
        }
        if (error.message.includes('timeout') || error.message.includes('ETIMEDOUT')) {
          throw new Error(
            `Claude API request timed out after ${this.config.timeout}ms.`,
          );
        }
      }

      throw error;
    }
  }
}
