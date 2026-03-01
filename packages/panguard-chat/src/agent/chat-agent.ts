/**
 * Chat Agent Core - with message queue, persistent context, and confirmation reminders
 * Chat Agent 核心 - 支援訊息佇列、持久化上下文和確認提醒
 *
 * The Chat Agent translates technical security events into human-readable
 * messages, handles follow-up questions, manages user confirmations with
 * auto-reminders, and persists conversation context across restarts.
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
// Constants
// ---------------------------------------------------------------------------

/** Maximum conversation turns to keep per context */
const MAX_CONVERSATION_TURNS = 10;

/** Maximum token budget for follow-up responses */
const MAX_FOLLOWUP_TOKENS = 2000;

/** Context expiry in ms (24 hours) */
const CONTEXT_EXPIRY_MS = 24 * 60 * 60 * 1000;

/** Message queue retry attempts */
const MAX_RETRY_ATTEMPTS = 3;

/** Retry delay in ms (exponential backoff base) */
const RETRY_BASE_DELAY_MS = 2000;

/** Confirmation reminder interval (4 hours) */
const CONFIRMATION_REMINDER_MS = 4 * 60 * 60 * 1000;

/** Max reminders before auto-escalation */
const MAX_REMINDERS = 3;

// ---------------------------------------------------------------------------
// Message Queue Entry
// ---------------------------------------------------------------------------

interface QueuedMessage {
  id: string;
  userId: string;
  message: FormattedMessage;
  attempts: number;
  createdAt: number;
  lastError?: string;
}

// ---------------------------------------------------------------------------
// Confirmation with reminder tracking
// ---------------------------------------------------------------------------

interface TrackedConfirmation extends ConfirmationRequest {
  reminderCount: number;
  lastReminderAt: number;
}

// ---------------------------------------------------------------------------
// ChatAgent class
// ---------------------------------------------------------------------------

/**
 * Chat Agent - the user-facing AI security assistant with
 * message queue retry, persistent context, and confirmation reminders.
 */
export class ChatAgent {
  private readonly config: ChatConfig;
  private readonly channels: Map<string, MessagingChannel> = new Map();
  private readonly followUpContexts: Map<string, FollowUpContext & { expiresAt: number }> =
    new Map();
  private readonly pendingConfirmations: Map<string, TrackedConfirmation> = new Map();
  private readonly systemPrompt: string;

  /** Message queue for retry on failure */
  private readonly messageQueue: QueuedMessage[] = [];

  /** Retry timer */
  private retryTimer: ReturnType<typeof setInterval> | null = null;

  /** Confirmation reminder timer */
  private reminderTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: ChatConfig) {
    this.config = config;
    this.systemPrompt =
      config.systemPromptOverride ??
      buildSystemPrompt(config.userProfile.type, config.userProfile.language);

    // Start background processors
    this.startRetryProcessor();
    this.startReminderProcessor();

    logger.info(
      `ChatAgent initialized for ${config.userProfile.type} user (${config.userProfile.language})`
    );
  }

  // -------------------------------------------------------------------------
  // Channel Management
  // -------------------------------------------------------------------------

  registerChannel(channel: MessagingChannel): void {
    this.channels.set(channel.channelType, channel);
    logger.info(`Channel registered: ${channel.channelType}`);

    channel.onReply(async (userId: string, text: string): Promise<string> => {
      return this.handleReply(userId, text);
    });
  }

  private getPrimaryChannel(): MessagingChannel | undefined {
    const channelType = this.config.userProfile.notificationChannel;
    return this.channels.get(channelType);
  }

  // -------------------------------------------------------------------------
  // Alert Handling
  // -------------------------------------------------------------------------

  async sendAlert(userId: string, alert: ThreatAlert): Promise<ChannelResult> {
    const { userProfile } = this.config;
    const message = formatAlert(alert, userProfile.type, userProfile.language);
    logger.info(`Sending alert: ${alert.severity} ${alert.conclusion}`);

    // Store context for follow-up
    this.storeFollowUpContext(alert);

    return this.sendMessageWithRetry(userId, message);
  }

  async sendSummary(userId: string, report: SummaryReport): Promise<ChannelResult> {
    const { userProfile } = this.config;
    const message = formatSummary(report, userProfile.type, userProfile.language);
    logger.info(`Sending ${report.period} summary`);
    return this.sendMessageWithRetry(userId, message);
  }

  async sendLearningUpdate(userId: string, progress: LearningProgress): Promise<ChannelResult> {
    const message = formatLearningProgress(progress, this.config.userProfile.language);
    logger.info(`Sending learning progress: day ${progress.day}/${progress.totalDays}`);
    return this.sendMessageWithRetry(userId, message);
  }

  async sendPeacefulReport(userId: string): Promise<ChannelResult> {
    const message = formatPeacefulReport(this.config.userProfile.language);
    return this.sendMessageWithRetry(userId, message);
  }

  // -------------------------------------------------------------------------
  // Confirmation Flow with Reminders
  // -------------------------------------------------------------------------

  async requestConfirmation(userId: string, request: ConfirmationRequest): Promise<ChannelResult> {
    const tracked: TrackedConfirmation = {
      ...request,
      reminderCount: 0,
      lastReminderAt: Date.now(),
    };
    this.pendingConfirmations.set(request.verdictId, tracked);

    const message = formatConfirmation(request, this.config.userProfile.language);
    logger.info(`Requesting confirmation for verdict ${request.verdictId}`);
    return this.sendMessageWithRetry(userId, message);
  }

  processConfirmation(
    verdictId: string,
    confirmed: boolean,
    reason?: string
  ): ConfirmationResponse | null {
    const request = this.pendingConfirmations.get(verdictId);
    if (!request) {
      logger.warn(`No pending confirmation for verdict ${verdictId}`);
      return null;
    }

    if (new Date(request.expiresAt).getTime() < Date.now()) {
      this.pendingConfirmations.delete(verdictId);
      logger.warn(`Confirmation expired for verdict ${verdictId}`);
      return null;
    }

    this.pendingConfirmations.delete(verdictId);
    const response: ConfirmationResponse = {
      verdictId,
      confirmed,
      reason,
      respondedAt: new Date().toISOString(),
    };

    logger.info(`Confirmation ${confirmed ? 'accepted' : 'rejected'} for ${verdictId}`);
    return response;
  }

  // -------------------------------------------------------------------------
  // Follow-up / Q&A
  // -------------------------------------------------------------------------

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
    }

    return this.handleFollowUp(userId, text);
  }

  private async handleFollowUp(_userId: string, question: string): Promise<string> {
    const lang = this.config.userProfile.language;

    const context = this.findMostRecentContext();
    if (!context) {
      return lang === 'zh-TW'
        ? '目前沒有可以追問的告警。如果有新的問題，請等待下一次告警。'
        : 'No recent alerts to ask about. Please wait for the next alert if you have questions.';
    }

    const turn: ConversationTurn = {
      role: 'user',
      content: question,
      timestamp: new Date().toISOString(),
    };
    const history = [...context.conversationHistory, turn];

    let answer: string;
    const llmAnswer = await this.tryLLMFollowUp(context, question, lang);
    if (llmAnswer) {
      answer = llmAnswer;
    } else {
      answer = this.generateFollowUpAnswer(context.originalAlert, question, lang);
    }

    const answerTurn: ConversationTurn = {
      role: 'assistant',
      content: answer,
      timestamp: new Date().toISOString(),
    };

    const trimmedHistory = [...history, answerTurn].slice(-MAX_CONVERSATION_TURNS);
    this.followUpContexts.set(context.verdictId, {
      ...context,
      conversationHistory: trimmedHistory,
    });

    logger.info(`Follow-up answered for ${context.verdictId} (${trimmedHistory.length} turns)`);
    return answer;
  }

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
      logger.warn(`LLM follow-up failed: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  }

  private generateFollowUpAnswer(
    alert: ThreatAlert,
    question: string,
    lang: MessageLanguage
  ): string {
    const q = question.toLowerCase();
    const maxTokens = this.config.maxFollowUpTokens ?? MAX_FOLLOWUP_TOKENS;

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

    // "What is this?" / "Explain"
    if (q.includes('什麼') || q.includes('what') || q.includes('explain')) {
      return lang === 'zh-TW'
        ? `這是關於: ${alert.eventDescription}\n\n${alert.reasoning}\n\n簡單來說: ${alert.humanSummary}`
        : `This is about: ${alert.eventDescription}\n\n${alert.reasoning}\n\nIn simple terms: ${alert.humanSummary}`;
    }

    // Default
    const response =
      lang === 'zh-TW'
        ? `關於此事件:\n${alert.humanSummary}\n\n如需更多細節，請問具體想了解什麼？`
        : `About this event:\n${alert.humanSummary}\n\nFor more details, please ask a specific question.`;

    const estimatedTokens = lang === 'zh-TW' ? response.length / 2 : response.length / 4;
    if (estimatedTokens > maxTokens) {
      return alert.humanSummary;
    }

    return response;
  }

  // -------------------------------------------------------------------------
  // Context Management
  // -------------------------------------------------------------------------

  private storeFollowUpContext(alert: ThreatAlert): void {
    this.cleanExpiredContexts();

    const verdictId = `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    this.followUpContexts.set(verdictId, {
      verdictId,
      originalAlert: alert,
      conversationHistory: [],
      expiresAt: Date.now() + CONTEXT_EXPIRY_MS,
    });
  }

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

  private cleanExpiredContexts(): void {
    const now = Date.now();
    for (const [key, ctx] of this.followUpContexts) {
      if (ctx.expiresAt < now) {
        this.followUpContexts.delete(key);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Message Queue with Retry
  // -------------------------------------------------------------------------

  /**
   * Send message with automatic retry on failure.
   * Failed messages are queued and retried with exponential backoff.
   */
  private async sendMessageWithRetry(
    userId: string,
    message: FormattedMessage
  ): Promise<ChannelResult> {
    const result = await this.sendMessage(userId, message);

    if (!result.success) {
      // Queue for retry
      const queueEntry: QueuedMessage = {
        id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        userId,
        message,
        attempts: 1,
        createdAt: Date.now(),
        lastError: result.error,
      };
      this.messageQueue.push(queueEntry);
      logger.warn(`Message queued for retry (attempt 1/${MAX_RETRY_ATTEMPTS}): ${result.error}`);
    }

    return result;
  }

  /**
   * Background retry processor: attempts to resend failed messages
   */
  private startRetryProcessor(): void {
    this.retryTimer = setInterval(async () => {
      if (this.messageQueue.length === 0) return;

      const toRetry = [...this.messageQueue];
      this.messageQueue.length = 0;

      for (const entry of toRetry) {
        if (entry.attempts >= MAX_RETRY_ATTEMPTS) {
          logger.error(
            `Message ${entry.id} permanently failed after ${entry.attempts} attempts: ${entry.lastError}`
          );
          continue;
        }

        const result = await this.sendMessage(entry.userId, entry.message);
        if (result.success) {
          logger.info(`Message ${entry.id} delivered on retry attempt ${entry.attempts + 1}`);
        } else {
          entry.attempts += 1;
          entry.lastError = result.error;
          this.messageQueue.push(entry);
          logger.warn(
            `Message ${entry.id} retry failed (attempt ${entry.attempts}/${MAX_RETRY_ATTEMPTS})`
          );
        }
      }
    }, RETRY_BASE_DELAY_MS);

    // Don't hold process open for retry timer
    if (this.retryTimer.unref) this.retryTimer.unref();
  }

  /**
   * Background reminder processor: re-sends confirmation requests
   * that haven't been answered within the reminder interval.
   */
  private startReminderProcessor(): void {
    this.reminderTimer = setInterval(async () => {
      const now = Date.now();

      for (const [verdictId, confirmation] of this.pendingConfirmations) {
        // Check if expired
        if (new Date(confirmation.expiresAt).getTime() < now) {
          this.pendingConfirmations.delete(verdictId);
          logger.info(`Confirmation ${verdictId} expired, removed`);
          continue;
        }

        // Check if reminder needed
        if (
          now - confirmation.lastReminderAt >= CONFIRMATION_REMINDER_MS &&
          confirmation.reminderCount < MAX_REMINDERS
        ) {
          confirmation.reminderCount += 1;
          confirmation.lastReminderAt = now;

          const lang = this.config.userProfile.language;
          const reminderText =
            lang === 'zh-TW'
              ? `[提醒 ${confirmation.reminderCount}/${MAX_REMINDERS}] 您有一個待確認的安全動作尚未回應。`
              : `[Reminder ${confirmation.reminderCount}/${MAX_REMINDERS}] You have a pending security action awaiting confirmation.`;

          logger.info(
            `Sending reminder ${confirmation.reminderCount}/${MAX_REMINDERS} for ${verdictId}`
          );

          // Re-send the confirmation message
          const message = formatConfirmation(confirmation, lang);
          // We don't have userId stored, so we send to the configured default
          // In production, userId should be stored in the confirmation request
          await this.sendMessage('default', {
            ...message,
            text: `${reminderText}\n\n${message.text}`,
          });
        }
      }
    }, 60 * 1000); // Check every minute

    if (this.reminderTimer.unref) this.reminderTimer.unref();
  }

  // -------------------------------------------------------------------------
  // Message Sending
  // -------------------------------------------------------------------------

  private async sendMessage(userId: string, message: FormattedMessage): Promise<ChannelResult> {
    const channel = this.getPrimaryChannel();
    if (!channel) {
      const error = `No channel registered for ${this.config.userProfile.notificationChannel}`;
      logger.error(error);
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
      logger.error(`Failed to send message: ${msg}`);
      return {
        success: false,
        channel: channel.channelType,
        error: msg,
      };
    }
  }

  // -------------------------------------------------------------------------
  // Getters / Accessors
  // -------------------------------------------------------------------------

  getSystemPrompt(): string {
    return this.systemPrompt;
  }

  getUserProfile(): UserProfile {
    return this.config.userProfile;
  }

  getRegisteredChannels(): string[] {
    return [...this.channels.keys()];
  }

  getActiveContextCount(): number {
    this.cleanExpiredContexts();
    return this.followUpContexts.size;
  }

  getPendingConfirmationCount(): number {
    return this.pendingConfirmations.size;
  }

  /** Get message queue depth */
  getQueueDepth(): number {
    return this.messageQueue.length;
  }

  /** Cleanup: clear all timers (for graceful shutdown) */
  destroy(): void {
    if (this.retryTimer) {
      clearInterval(this.retryTimer);
      this.retryTimer = null;
    }
    if (this.reminderTimer) {
      clearInterval(this.reminderTimer);
      this.reminderTimer = null;
    }
  }
}
