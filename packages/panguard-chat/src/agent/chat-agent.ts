/**
 * Chat Agent Core
 * Chat Agent 核心
 *
 * The Chat Agent translates technical security events into human-readable
 * messages, handles follow-up questions, and manages user confirmations.
 * Chat Agent 將技術安全事件翻譯為人類可讀的訊息，
 * 處理用戶追問，並管理用戶確認流程。
 *
 * @module @panguard-ai/panguard-chat/agent/chat-agent
 */

import { createLogger } from '@panguard-ai/core';
import type {
  UserProfile,
  MessageLanguage,
  ThreatAlert,
  SummaryReport,
  LearningProgress,
  FormattedMessage,
  ConfirmationRequest,
  ConfirmationResponse,
  FollowUpContext,
  ConversationTurn,
  ChatConfig,
  MessagingChannel,
  ChannelResult,
} from '../types.js';
import { buildSystemPrompt } from './prompts.js';
import {
  formatAlert,
  formatSummary,
  formatLearningProgress,
  formatConfirmation,
  formatPeacefulReport,
} from './formatter.js';

const logger = createLogger('panguard-chat:agent');

// ---------------------------------------------------------------------------
// Follow-up Context Store (in-memory, keyed by verdictId)
// 追問上下文儲存（記憶體內，以 verdictId 為鍵）
// ---------------------------------------------------------------------------

/** Maximum conversation turns to keep per context / 每個上下文保留的最大對話輪數 */
const MAX_CONVERSATION_TURNS = 10;

/** Maximum token budget for follow-up responses / 追問回應的最大 token 預算 */
const MAX_FOLLOWUP_TOKENS = 2000;

/** Context expiry in ms (24 hours) / 上下文過期時間（24 小時） */
const CONTEXT_EXPIRY_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// ChatAgent class
// ---------------------------------------------------------------------------

/**
 * Chat Agent - the user-facing AI security assistant
 * Chat Agent - 面向用戶的 AI 資安助手
 *
 * Responsibilities:
 * - Translate technical verdicts into human language based on user type
 * - Manage follow-up conversations with low token cost
 * - Handle user confirmations for suspicious/malicious findings
 * - Send daily/weekly summary reports
 * - Send learning progress updates
 *
 * 職責：
 * - 根據用戶類型將技術判決翻譯為人話
 * - 以低 token 成本管理追問對話
 * - 處理用戶對可疑/惡意發現的確認
 * - 發送日報/週報摘要
 * - 發送學習進度更新
 */
export class ChatAgent {
  private readonly config: ChatConfig;
  private readonly channels: Map<string, MessagingChannel> = new Map();
  private readonly followUpContexts: Map<string, FollowUpContext & { expiresAt: number }> =
    new Map();
  private readonly pendingConfirmations: Map<string, ConfirmationRequest> = new Map();
  private readonly systemPrompt: string;

  constructor(config: ChatConfig) {
    this.config = config;
    this.systemPrompt =
      config.systemPromptOverride ??
      buildSystemPrompt(config.userProfile.type, config.userProfile.language);

    logger.info(
      `ChatAgent initialized for ${config.userProfile.type} user (${config.userProfile.language}) / ` +
        `ChatAgent 已為 ${config.userProfile.type} 用戶初始化 (${config.userProfile.language})`
    );
  }

  // -------------------------------------------------------------------------
  // Channel Management
  // 管道管理
  // -------------------------------------------------------------------------

  /**
   * Register a messaging channel / 註冊通訊管道
   */
  registerChannel(channel: MessagingChannel): void {
    this.channels.set(channel.channelType, channel);
    logger.info(`Channel registered: ${channel.channelType} / 管道已註冊: ${channel.channelType}`);

    // Register reply handler for interactive channels
    // 為互動管道註冊回覆處理器
    channel.onReply(async (userId: string, text: string): Promise<string> => {
      return this.handleReply(userId, text);
    });
  }

  /**
   * Get the primary messaging channel / 取得主要通訊管道
   */
  private getPrimaryChannel(): MessagingChannel | undefined {
    const channelType = this.config.userProfile.notificationChannel;
    return this.channels.get(channelType);
  }

  // -------------------------------------------------------------------------
  // Alert Handling
  // 告警處理
  // -------------------------------------------------------------------------

  /**
   * Send a threat alert to the user
   * 發送威脅告警給用戶
   *
   * @param userId - User identifier / 用戶識別碼
   * @param alert - Threat alert data / 威脅告警資料
   * @returns Channel result / 管道結果
   */
  async sendAlert(userId: string, alert: ThreatAlert): Promise<ChannelResult> {
    const { userProfile } = this.config;

    // Format message based on user type
    const message = formatAlert(alert, userProfile.type, userProfile.language);
    logger.info(
      `Sending alert: ${alert.severity} ${alert.conclusion} / ` +
        `發送告警: ${alert.severity} ${alert.conclusion}`
    );

    // Store context for follow-up
    this.storeFollowUpContext(alert);

    // Send via primary channel
    return this.sendMessage(userId, message);
  }

  /**
   * Send a summary report (daily or weekly)
   * 發送摘要報告（日報或週報）
   *
   * @param userId - User identifier / 用戶識別碼
   * @param report - Summary report data / 摘要報告資料
   * @returns Channel result / 管道結果
   */
  async sendSummary(userId: string, report: SummaryReport): Promise<ChannelResult> {
    const { userProfile } = this.config;
    const message = formatSummary(report, userProfile.type, userProfile.language);
    logger.info(
      `Sending ${report.period} summary / 發送${report.period === 'daily' ? '日' : '週'}報`
    );
    return this.sendMessage(userId, message);
  }

  /**
   * Send learning progress update
   * 發送學習期進度更新
   *
   * @param userId - User identifier / 用戶識別碼
   * @param progress - Learning progress data / 學習進度資料
   * @returns Channel result / 管道結果
   */
  async sendLearningUpdate(userId: string, progress: LearningProgress): Promise<ChannelResult> {
    const message = formatLearningProgress(progress, this.config.userProfile.language);
    logger.info(
      `Sending learning progress: day ${progress.day}/${progress.totalDays} / ` +
        `發送學習進度: 第 ${progress.day}/${progress.totalDays} 天`
    );
    return this.sendMessage(userId, message);
  }

  /**
   * Send a peaceful "all clear" report
   * 發送平安報告
   *
   * @param userId - User identifier / 用戶識別碼
   * @returns Channel result / 管道結果
   */
  async sendPeacefulReport(userId: string): Promise<ChannelResult> {
    const message = formatPeacefulReport(this.config.userProfile.language);
    return this.sendMessage(userId, message);
  }

  // -------------------------------------------------------------------------
  // Confirmation Flow
  // 確認流程
  // -------------------------------------------------------------------------

  /**
   * Request user confirmation for a proposed action
   * 請求用戶確認建議的動作
   *
   * @param userId - User identifier / 用戶識別碼
   * @param request - Confirmation request / 確認請求
   * @returns Channel result / 管道結果
   */
  async requestConfirmation(userId: string, request: ConfirmationRequest): Promise<ChannelResult> {
    this.pendingConfirmations.set(request.verdictId, request);
    const message = formatConfirmation(request, this.config.userProfile.language);
    logger.info(
      `Requesting confirmation for verdict ${request.verdictId} / ` +
        `請求確認判決 ${request.verdictId}`
    );
    return this.sendMessage(userId, message);
  }

  /**
   * Process a confirmation response
   * 處理確認回應
   *
   * @param verdictId - Verdict identifier / 判決識別碼
   * @param confirmed - Whether user confirmed / 用戶是否確認
   * @param reason - Optional reason / 選填原因
   * @returns Confirmation response object / 確認回應物件
   */
  processConfirmation(
    verdictId: string,
    confirmed: boolean,
    reason?: string
  ): ConfirmationResponse | null {
    const request = this.pendingConfirmations.get(verdictId);
    if (!request) {
      logger.warn(
        `No pending confirmation for verdict ${verdictId} / ` +
          `找不到判決 ${verdictId} 的待確認請求`
      );
      return null;
    }

    // Check expiry
    if (new Date(request.expiresAt).getTime() < Date.now()) {
      this.pendingConfirmations.delete(verdictId);
      logger.warn(
        `Confirmation expired for verdict ${verdictId} / ` + `判決 ${verdictId} 的確認已過期`
      );
      return null;
    }

    this.pendingConfirmations.delete(verdictId);
    const response: ConfirmationResponse = {
      verdictId,
      confirmed,
      reason,
      respondedAt: new Date().toISOString(),
    };

    logger.info(
      `Confirmation ${confirmed ? 'accepted' : 'rejected'} for ${verdictId} / ` +
        `判決 ${verdictId} 已${confirmed ? '確認' : '拒絕'}`
    );

    return response;
  }

  // -------------------------------------------------------------------------
  // Follow-up / Q&A
  // 追問處理
  // -------------------------------------------------------------------------

  /**
   * Handle an incoming user reply (follow-up question or confirmation)
   * 處理用戶的回覆訊息（追問或確認）
   *
   * @param userId - User identifier / 用戶識別碼
   * @param text - Reply text / 回覆文字
   * @returns Response text / 回應文字
   */
  async handleReply(userId: string, text: string): Promise<string> {
    const lang = this.config.userProfile.language;

    // Check if it's a confirmation response
    const confirmMatch = text.match(/^(confirm|reject|details):(.+)$/);
    if (confirmMatch) {
      const [, action, verdictId] = confirmMatch;
      if (action === 'confirm') {
        const result = this.processConfirmation(verdictId!, true);
        return result
          ? lang === 'zh-TW'
            ? '已確認，正在執行動作。'
            : 'Confirmed. Executing action.'
          : lang === 'zh-TW'
            ? '此確認請求已過期或不存在。'
            : 'This confirmation request has expired or does not exist.';
      }
      if (action === 'reject') {
        const result = this.processConfirmation(verdictId!, false, text);
        return result
          ? lang === 'zh-TW'
            ? '已取消，不會執行動作。'
            : 'Cancelled. Action will not be taken.'
          : lang === 'zh-TW'
            ? '此確認請求已過期或不存在。'
            : 'This confirmation request has expired or does not exist.';
      }
      // details action - fall through to follow-up handling
    }

    // Handle follow-up questions
    return this.handleFollowUp(userId, text);
  }

  /**
   * Handle a follow-up question about a previous alert
   * 處理關於之前告警的追問
   *
   * Token budget: <2000 tokens as per README spec.
   * Token 預算: 依照 README 規格 <2000 tokens。
   */
  private async handleFollowUp(_userId: string, question: string): Promise<string> {
    const lang = this.config.userProfile.language;

    // Find the most recent context
    const context = this.findMostRecentContext();
    if (!context) {
      return lang === 'zh-TW'
        ? '目前沒有可以追問的告警。如果有新的問題，請等待下一次告警。'
        : 'No recent alerts to ask about. Please wait for the next alert if you have questions.';
    }

    // Add the question to conversation history
    const turn: ConversationTurn = {
      role: 'user',
      content: question,
      timestamp: new Date().toISOString(),
    };
    const history = [...context.conversationHistory, turn];

    // Try LLM first, then fall back to pattern matching
    let answer: string;
    const llmAnswer = await this.tryLLMFollowUp(context, question, lang);
    if (llmAnswer) {
      answer = llmAnswer;
    } else {
      answer = this.generateFollowUpAnswer(context.originalAlert, question, lang);
    }

    // Add answer to history
    const answerTurn: ConversationTurn = {
      role: 'assistant',
      content: answer,
      timestamp: new Date().toISOString(),
    };

    // Update context with trimmed history
    const trimmedHistory = [...history, answerTurn].slice(-MAX_CONVERSATION_TURNS);
    this.followUpContexts.set(context.verdictId, {
      ...context,
      conversationHistory: trimmedHistory,
    });

    logger.info(
      `Follow-up answered for ${context.verdictId} (${trimmedHistory.length} turns) / ` +
        `已回答追問 ${context.verdictId} (${trimmedHistory.length} 輪)`
    );

    return answer;
  }

  /**
   * Try to answer a follow-up question using the LLM provider.
   * Returns null if LLM is not available or fails.
   */
  private async tryLLMFollowUp(
    context: FollowUpContext & { expiresAt: number },
    question: string,
    lang: string
  ): Promise<string | null> {
    const llm = this.config.llmProvider;
    if (!llm) return null;

    try {
      const available = await llm.isAvailable();
      if (!available) return null;

      const alert = context.originalAlert;
      const prompt = [
        this.systemPrompt,
        '',
        `Alert: ${alert.eventDescription}`,
        `Severity: ${alert.severity}, Conclusion: ${alert.conclusion}`,
        `Summary: ${alert.humanSummary}`,
        `Recommended action: ${alert.recommendedAction}`,
        '',
        `User question (respond in ${lang === 'zh-TW' ? 'Traditional Chinese' : 'English'}):`,
        question,
      ].join('\n');

      const result = await llm.analyze(prompt);
      if (result.summary) {
        logger.info('Follow-up answered via LLM');
        return result.summary;
      }
      return null;
    } catch (err) {
      logger.warn(
        `LLM follow-up failed, falling back to pattern matching: ${err instanceof Error ? err.message : String(err)}`
      );
      return null;
    }
  }

  /**
   * Generate a follow-up answer based on existing alert context
   * 根據現有告警上下文生成追問回答
   *
   * This is a rule-based fallback; in production with LLM integration,
   * this would send the context to the LLM with the system prompt.
   * 這是規則式的降級方案；正式環境會將上下文帶著系統提示詞送給 LLM。
   */
  private generateFollowUpAnswer(
    alert: ThreatAlert,
    question: string,
    lang: MessageLanguage
  ): string {
    const q = question.toLowerCase();
    const maxTokens = this.config.maxFollowUpTokens ?? MAX_FOLLOWUP_TOKENS;

    // Pattern-match common follow-up questions (most specific first)
    // 模式匹配常見追問（最具體的優先）

    // "What did you do?" / "Actions taken?"
    if (q.includes('做了') || q.includes('動作') || q.includes('did you') || q.includes('action')) {
      if (alert.actionsTaken && alert.actionsTaken.length > 0) {
        const prefix =
          lang === 'zh-TW' ? '我已執行以下動作:' : 'I have taken the following actions:';
        return `${prefix}\n${alert.actionsTaken.map((a) => `- ${a}`).join('\n')}`;
      }
      return lang === 'zh-TW'
        ? '目前尚未執行任何自動動作。系統正在等待進一步確認。'
        : 'No automated actions have been taken yet. The system is waiting for further confirmation.';
    }

    // "What should I do?" / "Recommendation?"
    if (
      q.includes('建議') ||
      q.includes('怎麼辦') ||
      q.includes('should') ||
      q.includes('recommend')
    ) {
      return lang === 'zh-TW'
        ? `建議: ${alert.recommendedAction}`
        : `Recommendation: ${alert.recommendedAction}`;
    }

    // "Is it dangerous?" / "How serious?"
    if (q.includes('嚴重') || q.includes('危險') || q.includes('serious') || q.includes('danger')) {
      const severityExplain =
        lang === 'zh-TW'
          ? {
              critical: '非常嚴重，需要立即處理',
              high: '嚴重，建議盡快處理',
              medium: '中等風險，建議關注',
              low: '低風險，已記錄',
              info: '僅供參考',
            }
          : {
              critical: 'Very serious, immediate action needed',
              high: 'Serious, prompt attention recommended',
              medium: 'Moderate risk, worth monitoring',
              low: 'Low risk, logged for reference',
              info: 'Informational only',
            };
      return `${severityExplain[alert.severity] ?? (lang === 'zh-TW' ? '已記錄' : 'Logged')}\n\n${lang === 'zh-TW' ? '信心度' : 'Confidence'}: ${Math.round(alert.confidence * 100)}%`;
    }

    // "What is this?" / "This is what?"
    if (q.includes('什麼') || q.includes('what') || q.includes('explain')) {
      return lang === 'zh-TW'
        ? `這是關於: ${alert.eventDescription}\n\n${alert.reasoning}\n\n簡單來說: ${alert.humanSummary}`
        : `This is about: ${alert.eventDescription}\n\n${alert.reasoning}\n\nIn simple terms: ${alert.humanSummary}`;
    }

    // Default: provide a brief summary
    // Keep response within token budget
    const response =
      lang === 'zh-TW'
        ? `關於此事件:\n${alert.humanSummary}\n\n如需更多細節，請問具體想了解什麼？`
        : `About this event:\n${alert.humanSummary}\n\nFor more details, please ask a specific question.`;

    // Ensure we stay within token budget (rough estimate: 1 token ~ 4 chars for English, ~2 chars for CJK)
    const estimatedTokens = lang === 'zh-TW' ? response.length / 2 : response.length / 4;
    if (estimatedTokens > maxTokens) {
      return lang === 'zh-TW' ? alert.humanSummary : alert.humanSummary;
    }

    return response;
  }

  // -------------------------------------------------------------------------
  // Context Management
  // 上下文管理
  // -------------------------------------------------------------------------

  /**
   * Store follow-up context for a threat alert
   * 儲存威脅告警的追問上下文
   */
  private storeFollowUpContext(alert: ThreatAlert): void {
    // Clean expired contexts
    this.cleanExpiredContexts();

    // Create a simple verdictId from alert data
    const verdictId = `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    this.followUpContexts.set(verdictId, {
      verdictId,
      originalAlert: alert,
      conversationHistory: [],
      expiresAt: Date.now() + CONTEXT_EXPIRY_MS,
    });
  }

  /**
   * Find the most recent follow-up context
   * 找到最近的追問上下文
   */
  private findMostRecentContext(): (FollowUpContext & { expiresAt: number }) | null {
    this.cleanExpiredContexts();

    let latest: (FollowUpContext & { expiresAt: number }) | null = null;
    for (const ctx of this.followUpContexts.values()) {
      if (!latest || ctx.expiresAt > latest.expiresAt) {
        latest = ctx;
      }
    }
    return latest;
  }

  /**
   * Clean expired follow-up contexts
   * 清理過期的追問上下文
   */
  private cleanExpiredContexts(): void {
    const now = Date.now();
    for (const [key, ctx] of this.followUpContexts) {
      if (ctx.expiresAt < now) {
        this.followUpContexts.delete(key);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Message Sending
  // 訊息發送
  // -------------------------------------------------------------------------

  /**
   * Send a formatted message via the primary channel
   * 透過主要管道發送格式化訊息
   */
  private async sendMessage(userId: string, message: FormattedMessage): Promise<ChannelResult> {
    const channel = this.getPrimaryChannel();
    if (!channel) {
      const error = `No channel registered for ${this.config.userProfile.notificationChannel}`;
      logger.error(`${error} / 未註冊管道: ${this.config.userProfile.notificationChannel}`);
      return {
        success: false,
        channel: this.config.userProfile.notificationChannel,
        error,
      };
    }

    try {
      return await channel.sendMessage(userId, message);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to send message: ${msg} / 發送訊息失敗: ${msg}`);
      return {
        success: false,
        channel: channel.channelType,
        error: msg,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Getters / Accessors
  // 取得器
  // -------------------------------------------------------------------------

  /** Get the system prompt / 取得系統提示詞 */
  getSystemPrompt(): string {
    return this.systemPrompt;
  }

  /** Get current user profile / 取得目前用戶資料 */
  getUserProfile(): UserProfile {
    return this.config.userProfile;
  }

  /** Get registered channel types / 取得已註冊的管道類型 */
  getRegisteredChannels(): string[] {
    return [...this.channels.keys()];
  }

  /** Get count of active follow-up contexts / 取得活動追問上下文數量 */
  getActiveContextCount(): number {
    this.cleanExpiredContexts();
    return this.followUpContexts.size;
  }

  /** Get count of pending confirmations / 取得待確認數量 */
  getPendingConfirmationCount(): number {
    return this.pendingConfirmations.size;
  }
}
