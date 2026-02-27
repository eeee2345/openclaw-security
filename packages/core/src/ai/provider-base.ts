/**
 * Abstract base class for LLM providers
 * LLM 供應商抽象基礎類別
 *
 * Implements shared logic for all LLM providers including prompt
 * construction, response parsing, and token tracking.
 * 實作所有 LLM 供應商的共用邏輯，包括提示詞建構、回應解析和 Token 追蹤。
 *
 * @module @panguard-ai/core/ai/provider-base
 */

import type { SecurityEvent } from '../types.js';
import type {
  LLMConfig,
  LLMProvider,
  LLMProviderType,
  AnalysisResult,
  ThreatClassification,
  TokenUsage,
} from './types.js';
import { TokenTracker } from './token-tracker.js';
import { parseAnalysisResponse, parseClassificationResponse } from './response-parser.js';
import { getEventClassifierPrompt } from './prompts/event-classifier.js';
import { getThreatAnalysisPrompt } from './prompts/threat-analyzer.js';
import { getReportPrompt } from './prompts/report-generator.js';
import { createLogger } from '../utils/logger.js';

/**
 * Abstract base class that all LLM providers extend
 * 所有 LLM 供應商繼承的抽象基礎類別
 *
 * Subclasses must implement `sendRequest()` and `isAvailable()`.
 * The base class handles prompt construction, response parsing,
 * error wrapping, and token tracking.
 * 子類別必須實作 `sendRequest()` 和 `isAvailable()`。
 * 基礎類別處理提示詞建構、回應解析、錯誤包裝和 Token 追蹤。
 */
export abstract class LLMProviderBase implements LLMProvider {
  /** The provider type identifier / 供應商類型識別碼 */
  public readonly providerType: LLMProviderType;
  /** The model name being used / 使用的模型名稱 */
  public readonly model: string;

  /** Provider configuration / 供應商配置 */
  protected readonly config: Required<
    Pick<LLMConfig, 'provider' | 'model' | 'lang' | 'temperature' | 'maxTokens' | 'timeout'>
  > &
    Pick<LLMConfig, 'endpoint' | 'apiKey'>;

  /** Token usage tracker / Token 使用追蹤器 */
  protected readonly tokenTracker: TokenTracker;

  /** Module logger / 模組日誌記錄器 */
  protected readonly logger;

  /**
   * Create a new LLM provider base instance
   * 建立新的 LLM 供應商基礎實例
   *
   * @param config - LLM configuration / LLM 配置
   */
  constructor(config: LLMConfig) {
    this.providerType = config.provider;
    this.model = config.model;
    this.config = {
      provider: config.provider,
      model: config.model,
      lang: config.lang,
      temperature: config.temperature ?? 0.3,
      maxTokens: config.maxTokens ?? 2048,
      timeout: config.timeout ?? 30_000,
      endpoint: config.endpoint,
      apiKey: config.apiKey,
    };
    this.tokenTracker = new TokenTracker(config.provider, config.model);
    this.logger = createLogger(`ai:${config.provider}`);
  }

  /**
   * Send a raw prompt to the LLM and return the response text
   * 向 LLM 發送原始提示詞並回傳回應文字
   *
   * Must be implemented by each provider subclass.
   * 必須由每個供應商子類別實作。
   *
   * @param prompt - The prompt to send / 要發送的提示詞
   * @returns Raw response text from the LLM / LLM 的原始回應文字
   */
  protected abstract sendRequest(prompt: string): Promise<string>;

  /**
   * Check if the provider is available and properly configured
   * 檢查供應商是否可用且配置正確
   *
   * Must be implemented by each provider subclass.
   * 必須由每個供應商子類別實作。
   *
   * @returns True if provider is ready / 供應商就緒時回傳 true
   */
  abstract isAvailable(): Promise<boolean>;

  /**
   * Analyze a security prompt with optional context
   * 分析安全提示詞，可附帶上下文
   *
   * Constructs a threat analysis prompt, sends it to the LLM,
   * and parses the response into an AnalysisResult.
   * 建構威脅分析提示詞，發送至 LLM，並將回應解析為 AnalysisResult。
   *
   * @param prompt - The analysis prompt / 分析提示詞
   * @param context - Optional additional context / 可選的額外上下文
   * @returns Analysis result / 分析結果
   */
  async analyze(prompt: string, context?: string): Promise<AnalysisResult> {
    this.logger.info('Starting threat analysis', { promptLength: prompt.length });

    try {
      const fullPrompt = getThreatAnalysisPrompt(prompt, context, this.config.lang);
      const raw = await this.sendRequest(fullPrompt);
      const result = parseAnalysisResponse(raw);

      this.logger.info('Threat analysis completed', {
        severity: result.severity,
        confidence: result.confidence,
      });

      return result;
    } catch (error) {
      this.logger.error('Threat analysis failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw new Error(
        `Analysis failed (${this.providerType}/${this.model}): ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Classify a security event using MITRE ATT&CK framework
   * 使用 MITRE ATT&CK 框架分類安全事件
   *
   * @param event - The security event to classify / 要分類的安全事件
   * @returns Threat classification / 威脅分類
   */
  async classify(event: SecurityEvent): Promise<ThreatClassification> {
    this.logger.info('Classifying security event', {
      eventId: event.id,
      source: event.source,
    });

    try {
      const prompt = getEventClassifierPrompt(event, this.config.lang);
      const raw = await this.sendRequest(prompt);
      const result = parseClassificationResponse(raw);

      this.logger.info('Event classification completed', {
        eventId: event.id,
        category: result.category,
        technique: result.technique,
        severity: result.severity,
      });

      return result;
    } catch (error) {
      this.logger.error('Event classification failed', {
        eventId: event.id,
        error: error instanceof Error ? error.message : String(error),
      });
      throw new Error(
        `Classification failed (${this.providerType}/${this.model}): ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Summarize multiple security events into a report
   * 將多個安全事件摘要為報告
   *
   * @param events - Array of security events / 安全事件陣列
   * @returns Summary text / 摘要文字
   */
  async summarize(events: SecurityEvent[]): Promise<string> {
    this.logger.info('Generating security summary', {
      eventCount: events.length,
    });

    if (events.length === 0) {
      return this.config.lang === 'zh-TW'
        ? '沒有安全事件需要摘要。'
        : 'No security events to summarize.';
    }

    try {
      const prompt = getReportPrompt(events, this.config.lang);
      const summary = await this.sendRequest(prompt);

      this.logger.info('Security summary generated', {
        eventCount: events.length,
        summaryLength: summary.length,
      });

      return summary;
    } catch (error) {
      this.logger.error('Summary generation failed', {
        eventCount: events.length,
        error: error instanceof Error ? error.message : String(error),
      });
      throw new Error(
        `Summarization failed (${this.providerType}/${this.model}): ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Get cumulative token usage statistics
   * 取得累計 Token 使用統計
   *
   * @returns Token usage data / Token 使用資料
   */
  getTokenUsage(): TokenUsage {
    return this.tokenTracker.getUsage();
  }
}
