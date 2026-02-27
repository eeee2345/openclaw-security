/**
 * Ollama LLM provider implementation
 * Ollama LLM 供應商實作
 *
 * Communicates with a local Ollama instance via its HTTP API.
 * Uses native fetch (Node 18+) with no external dependencies.
 * 透過 HTTP API 與本地 Ollama 實例通訊。
 * 使用原生 fetch（Node 18+），無需外部相依。
 *
 * @module @panguard-ai/core/ai/ollama-provider
 */

import type { LLMConfig } from './types.js';
import { LLMProviderBase } from './provider-base.js';

/**
 * Default Ollama API endpoint
 * 預設 Ollama API 端點
 * @internal
 */
const DEFAULT_ENDPOINT = 'http://localhost:11434';

/**
 * Response shape from Ollama /api/generate endpoint
 * Ollama /api/generate 端點的回應結構
 * @internal
 */
interface OllamaGenerateResponse {
  model: string;
  response: string;
  done: boolean;
  total_duration?: number;
  prompt_eval_count?: number;
  eval_count?: number;
}

/**
 * Response shape from Ollama /api/tags endpoint
 * Ollama /api/tags 端點的回應結構
 * @internal
 */
interface OllamaTagsResponse {
  models: Array<{ name: string }>;
}

/**
 * Ollama LLM provider using the local HTTP API
 * 使用本地 HTTP API 的 Ollama LLM 供應商
 *
 * Connects to a running Ollama instance (default: localhost:11434)
 * and uses the /api/generate endpoint for text generation.
 * 連接到正在執行的 Ollama 實例（預設：localhost:11434），
 * 並使用 /api/generate 端點進行文字生成。
 */
export class OllamaProvider extends LLMProviderBase {
  /** Resolved API endpoint / 解析後的 API 端點 */
  private readonly endpoint: string;

  /**
   * Create a new OllamaProvider instance
   * 建立新的 OllamaProvider 實例
   *
   * @param config - LLM configuration / LLM 配置
   */
  constructor(config: LLMConfig) {
    super(config);
    this.endpoint = (config.endpoint ?? DEFAULT_ENDPOINT).replace(/\/+$/, '');
    this.logger.info('Ollama provider initialized', {
      endpoint: this.endpoint,
      model: this.model,
    });
  }

  /**
   * Check if the Ollama instance is reachable and running
   * 檢查 Ollama 實例是否可連接且正在執行
   *
   * Sends a GET request to /api/tags to verify connectivity.
   * 發送 GET 請求到 /api/tags 以驗證連接性。
   *
   * @returns True if Ollama is reachable / Ollama 可連接時回傳 true
   */
  async isAvailable(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5_000);

      const response = await fetch(`${this.endpoint}/api/tags`, {
        method: 'GET',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        this.logger.warn('Ollama returned non-OK status', {
          status: response.status,
        });
        return false;
      }

      const data = (await response.json()) as OllamaTagsResponse;
      const models = data.models?.map((m) => m.name) ?? [];

      // Check if the configured model is pulled
      // 檢查配置的模型是否已下載
      const modelPulled = models.some((m) => m === this.model || m.startsWith(`${this.model}:`));

      if (!modelPulled && models.length > 0) {
        this.logger.warn('Configured model not found in Ollama', {
          requestedModel: this.model,
          availableModels: models,
          hint: `Run: ollama pull ${this.model}`,
        });
      }

      this.logger.debug('Ollama available', {
        availableModels: models.length,
        modelPulled,
      });
      return true;
    } catch (error) {
      this.logger.debug('Ollama not available', {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Check if the configured model has been pulled in Ollama
   * 檢查配置的模型是否已在 Ollama 中下載
   *
   * @returns True if model is available locally / 模型在本地可用時回傳 true
   */
  async isModelPulled(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5_000);

      const response = await fetch(`${this.endpoint}/api/tags`, {
        method: 'GET',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!response.ok) return false;

      const data = (await response.json()) as OllamaTagsResponse;
      const models = data.models?.map((m) => m.name) ?? [];
      return models.some((m) => m === this.model || m.startsWith(`${this.model}:`));
    } catch {
      return false;
    }
  }

  /**
   * Send a prompt to the Ollama /api/generate endpoint
   * 向 Ollama /api/generate 端點發送提示詞
   *
   * @param prompt - The prompt to send / 要發送的提示詞
   * @returns Raw response text / 原始回應文字
   * @throws Error if the request fails or times out / 請求失敗或逾時時拋出錯誤
   */
  protected async sendRequest(prompt: string): Promise<string> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(`${this.endpoint}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.model,
          prompt,
          stream: false,
          options: {
            temperature: this.config.temperature,
            num_predict: this.config.maxTokens,
          },
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new Error(`Ollama API error (${response.status}): ${errorText}`);
      }

      const data = (await response.json()) as OllamaGenerateResponse;

      // Track token usage from Ollama response metrics
      // 從 Ollama 回應指標追蹤 Token 使用量
      const promptTokens = data.prompt_eval_count ?? this.estimateTokens(prompt);
      const completionTokens = data.eval_count ?? this.estimateTokens(data.response);
      this.tokenTracker.track(promptTokens, completionTokens);

      this.logger.debug('Ollama request completed', {
        model: data.model,
        done: data.done,
        promptTokens,
        completionTokens,
      });

      return data.response;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(
          `Ollama request timed out after ${this.config.timeout}ms. ` +
            `Ensure Ollama is running at ${this.endpoint} and the model "${this.model}" is available.`
        );
      }

      // Handle connection refused specifically
      // 特別處理連線被拒絕的情況
      if (
        error instanceof TypeError &&
        (error.message.includes('fetch failed') || error.message.includes('ECONNREFUSED'))
      ) {
        throw new Error(
          `Cannot connect to Ollama at ${this.endpoint}. ` +
            `Ensure Ollama is installed and running: https://ollama.ai`
        );
      }

      throw error;
    }
  }

  /**
   * Rough token count estimation (for when Ollama doesn't report counts)
   * 粗略的 Token 計數估算（當 Ollama 不報告計數時使用）
   *
   * Uses a simple heuristic: ~4 characters per token for English,
   * ~2 characters per token for CJK text.
   * 使用簡單啟發式方法：英文約每 4 個字元一個 Token，CJK 文字約每 2 個字元一個 Token。
   *
   * @param text - Text to estimate / 要估算的文字
   * @returns Estimated token count / 估算的 Token 數量
   * @internal
   */
  private estimateTokens(text: string): number {
    // Count CJK characters
    // 計算 CJK 字元數
    const cjkCount = (text.match(/[\u4e00-\u9fff\u3400-\u4dbf]/g) ?? []).length;
    const nonCjkLength = text.length - cjkCount;
    return Math.ceil(nonCjkLength / 4) + Math.ceil(cjkCount / 1.5);
  }
}
