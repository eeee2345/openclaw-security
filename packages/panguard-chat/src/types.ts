/**
 * PanguardChat Type Definitions
 * PanguardChat 型別定義
 *
 * @module @panguard-ai/panguard-chat
 */

// ---------------------------------------------------------------------------
// User Profile & Preferences
// 用戶資料與偏好
// ---------------------------------------------------------------------------

/** User type determines the tone and detail level of messages.
 *  用戶類型決定訊息語氣和細節層級。 */
export type UserType = 'developer' | 'boss' | 'it_admin';

/** Supported notification channel.
 *  支援的通知管道。 */
export type ChannelType = 'telegram' | 'slack' | 'email' | 'webhook' | 'line';

/** Supported language for messages.
 *  訊息支援的語言。 */
export type MessageLanguage = 'zh-TW' | 'en';

/** Notification preferences for a user.
 *  用戶的通知偏好設定。 */
export interface NotificationPreferences {
  /** Push critical alerts immediately (default: true).
   *  即時推送高危告警（預設 true）。 */
  readonly criticalAlerts: boolean;
  /** Daily summary (default: true).
   *  每日摘要（預設 true）。 */
  readonly dailySummary: boolean;
  /** Weekly summary (default: true).
   *  每週摘要（預設 true）。 */
  readonly weeklySummary: boolean;
  /** Peaceful "all clear" report when nothing happened (default: true).
   *  無事報平安報告（預設 true）。 */
  readonly peacefulReport: boolean;
}

/** User profile for tone adaptation.
 *  用戶資料，用於語氣適配。 */
export interface UserProfile {
  readonly type: UserType;
  readonly language: MessageLanguage;
  readonly notificationChannel: ChannelType;
  readonly preferences: NotificationPreferences;
}

// ---------------------------------------------------------------------------
// Message Formatting
// 訊息格式
// ---------------------------------------------------------------------------

/** Severity level for alert display.
 *  告警顯示的嚴重等級。 */
export type AlertSeverity = 'critical' | 'warning' | 'info';

/** Quick reply option for interactive channels.
 *  互動管道的快速回覆選項。 */
export interface QuickReply {
  readonly label: string;
  readonly action: string;
}

/** Attachment for messages (PDF reports, screenshots).
 *  訊息附件（PDF 報告、截圖等）。 */
export interface MessageAttachment {
  readonly type: 'pdf' | 'image' | 'text';
  readonly filename: string;
  readonly data: Buffer;
}

/** Formatted message for sending via any channel.
 *  透過任何管道發送的格式化訊息。 */
export interface FormattedMessage {
  readonly text: string;
  readonly severity?: AlertSeverity;
  readonly quickReplies?: readonly QuickReply[];
  readonly attachments?: readonly MessageAttachment[];
}

// ---------------------------------------------------------------------------
// Alert Templates
// 告警模板
// ---------------------------------------------------------------------------

/** Threat alert payload for the Chat Agent.
 *  Chat Agent 的威脅告警資料。 */
export interface ThreatAlert {
  readonly conclusion: 'benign' | 'suspicious' | 'malicious';
  readonly confidence: number;
  readonly humanSummary: string;
  readonly reasoning: string;
  readonly recommendedAction: string;
  readonly mitreTechnique?: string;
  readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  readonly eventDescription: string;
  readonly actionsTaken?: readonly string[];
  readonly timestamp: string;
}

/** Daily or weekly summary payload.
 *  日報或週報摘要資料。 */
export interface SummaryReport {
  readonly period: 'daily' | 'weekly';
  readonly startDate: string;
  readonly endDate: string;
  readonly totalEvents: number;
  readonly threatsBlocked: number;
  readonly suspiciousEvents: number;
  readonly topAttackSources: readonly AttackSource[];
  readonly actionsTaken: readonly ActionSummary[];
  readonly estimatedDamageAvoided?: number;
  readonly trendComparison?: TrendComparison;
  readonly newThreatsDiscovered?: readonly string[];
  readonly recommendations?: readonly string[];
}

/** Attack source entry in summary.
 *  摘要中的攻擊來源條目。 */
export interface AttackSource {
  readonly ip: string;
  readonly count: number;
  readonly country?: string;
}

/** Action summary entry.
 *  動作摘要條目。 */
export interface ActionSummary {
  readonly action: string;
  readonly count: number;
}

/** Trend comparison data.
 *  趨勢比較資料。 */
export interface TrendComparison {
  readonly thisPeriod: number;
  readonly lastPeriod: number;
  readonly changePercent: number;
}

// ---------------------------------------------------------------------------
// Learning Progress
// 學習進度
// ---------------------------------------------------------------------------

/** Learning period progress notification.
 *  學習期進度通知。 */
export interface LearningProgress {
  readonly day: number;
  readonly totalDays: number;
  readonly patternsRecorded: number;
  readonly eventsAnalyzed: number;
  readonly notableFindings: number;
}

// ---------------------------------------------------------------------------
// User Confirmation Flow
// 用戶確認流程
// ---------------------------------------------------------------------------

/** User confirmation request (Respond Agent asks Chat Agent to confirm).
 *  用戶確認請求（Respond Agent 請 Chat Agent 確認）。 */
export interface ConfirmationRequest {
  readonly verdictId: string;
  readonly conclusion: 'suspicious' | 'malicious';
  readonly confidence: number;
  readonly humanSummary: string;
  readonly proposedAction: string;
  readonly expiresAt: string;
}

/** User confirmation response.
 *  用戶確認回應。 */
export interface ConfirmationResponse {
  readonly verdictId: string;
  readonly confirmed: boolean;
  readonly reason?: string;
  readonly respondedAt: string;
}

// ---------------------------------------------------------------------------
// Follow-up / Q&A
// 追問處理
// ---------------------------------------------------------------------------

/** Context for follow-up question (low token cost).
 *  追問的上下文（低 token 成本）。 */
export interface FollowUpContext {
  readonly verdictId: string;
  readonly originalAlert: ThreatAlert;
  readonly conversationHistory: readonly ConversationTurn[];
}

/** A single conversation turn.
 *  一輪對話。 */
export interface ConversationTurn {
  readonly role: 'user' | 'assistant';
  readonly content: string;
  readonly timestamp: string;
}

// ---------------------------------------------------------------------------
// Messaging Channel Interface
// 通訊管道介面
// ---------------------------------------------------------------------------

/** Unified messaging channel interface for all platforms.
 *  所有平台的統一通訊管道介面。 */
export interface MessagingChannel {
  /** Channel identifier.
   *  管道識別碼。 */
  readonly channelType: ChannelType;

  /** Send a formatted message.
   *  發送格式化訊息。 */
  sendMessage(userId: string, message: FormattedMessage): Promise<ChannelResult>;

  /** Send a threat alert.
   *  發送威脅告警。 */
  sendAlert(userId: string, alert: ThreatAlert): Promise<ChannelResult>;

  /** Send a file (PDF report etc).
   *  發送檔案（PDF 報告等）。 */
  sendFile(userId: string, file: Buffer, filename: string): Promise<ChannelResult>;

  /** Register a handler for incoming replies.
   *  註冊收到回覆的處理器。 */
  onReply(handler: ReplyHandler): void;
}

/** Reply handler callback type.
 *  回覆處理器的回呼型別。 */
export type ReplyHandler = (userId: string, text: string) => Promise<string>;

/** Result of a channel send operation.
 *  管道發送操作的結果。 */
export interface ChannelResult {
  readonly success: boolean;
  readonly channel: ChannelType;
  readonly error?: string;
  readonly messageId?: string;
}

// ---------------------------------------------------------------------------
// Webhook Channel (Enterprise)
// Webhook 管道（企業級）
// ---------------------------------------------------------------------------

/** Webhook authentication method.
 *  Webhook 認證方式。 */
export type WebhookAuthMethod = 'bearer_token' | 'mtls' | 'hmac_signature';

/** Webhook channel configuration.
 *  Webhook 管道配置。 */
export interface WebhookConfig {
  readonly endpoint: string;
  readonly authMethod: WebhookAuthMethod;
  readonly secret: string;
  readonly headers?: Readonly<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Chat Agent Configuration
// Chat Agent 配置
// ---------------------------------------------------------------------------

/** LLM provider interface for chat follow-up (optional). */
export interface ChatLLMProvider {
  analyze(prompt: string, context?: string): Promise<{ summary: string }>;
  isAvailable(): Promise<boolean>;
}

/** Full PanguardChat configuration.
 *  完整 PanguardChat 配置。 */
export interface ChatConfig {
  readonly userProfile: UserProfile;
  readonly channels: ChannelConfigs;
  readonly maxFollowUpTokens: number;
  readonly systemPromptOverride?: string;
  readonly llmProvider?: ChatLLMProvider;
}

/** Per-channel configuration.
 *  各管道配置。 */
export interface ChannelConfigs {
  readonly telegram?: TelegramChannelConfig;
  readonly slack?: SlackChannelConfig;
  readonly email?: EmailChannelConfig;
  readonly webhook?: WebhookConfig;
  readonly line?: LINEChannelConfig;
}

/** Telegram Bot configuration.
 *  Telegram Bot 配置。 */
export interface TelegramChannelConfig {
  readonly botToken: string;
  readonly chatId: string;
}

/** Slack App configuration.
 *  Slack App 配置。 */
export interface SlackChannelConfig {
  readonly botToken: string;
  readonly signingSecret: string;
  readonly defaultChannel: string;
}

/** LINE Messaging API configuration.
 *  LINE Messaging API 配置。 */
export interface LINEChannelConfig {
  readonly channelAccessToken: string;
  readonly destinationUserId: string;
}

/** Email channel configuration.
 *  Email 管道配置。 */
export interface EmailChannelConfig {
  readonly host: string;
  readonly port: number;
  readonly secure: boolean;
  readonly auth: { readonly user: string; readonly pass: string };
  readonly from: string;
  readonly to: readonly string[];
}
