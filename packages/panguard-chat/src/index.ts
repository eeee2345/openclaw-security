/**
 * PanguardChat - AI Security Communication Assistant
 * PanguardChat - AI 資安通訊助手
 *
 * Panguard Chat - the user-facing communication layer of Panguard AI.
 * Translates technical security events into human-readable messages
 * and manages bidirectional communication via messaging platforms.
 * Panguard Chat - Panguard AI 的用戶端通訊層。
 * 將技術安全事件翻譯為人話，並透過通訊平台管理雙向通訊。
 *
 * @module @panguard-ai/panguard-chat
 */

/** Package version / 套件版本 */
export const PANGUARD_CHAT_VERSION = '0.1.0';
export const CLAWCHAT_NAME = 'PanguardChat';

// ---------------------------------------------------------------------------
// Types / 型別
// ---------------------------------------------------------------------------

export type {
  UserType,
  ChannelType,
  MessageLanguage,
  AlertSeverity,
  NotificationPreferences,
  UserProfile,
  QuickReply,
  MessageAttachment,
  FormattedMessage,
  ThreatAlert,
  SummaryReport,
  AttackSource,
  ActionSummary,
  TrendComparison,
  LearningProgress,
  ConfirmationRequest,
  ConfirmationResponse,
  FollowUpContext,
  ConversationTurn,
  MessagingChannel,
  ReplyHandler,
  ChannelResult,
  WebhookAuthMethod,
  WebhookConfig,
  ChatConfig,
  ChannelConfigs,
  LineChannelConfig,
  TelegramChannelConfig,
  SlackChannelConfig,
  EmailChannelConfig,
} from './types.js';

// ---------------------------------------------------------------------------
// Chat Agent / Chat Agent
// ---------------------------------------------------------------------------

export { ChatAgent } from './agent/index.js';
export { buildSystemPrompt, getUserTypeInstructions } from './agent/index.js';
export {
  formatAlert,
  formatSummary,
  formatLearningProgress,
  formatConfirmation,
  formatPeacefulReport,
} from './agent/index.js';

// ---------------------------------------------------------------------------
// Messaging Channels / 通訊管道
// ---------------------------------------------------------------------------

export { LineChannel } from './channels/index.js';
export { TelegramChannel } from './channels/index.js';
export { SlackChannel } from './channels/index.js';
export { EmailChannel } from './channels/index.js';
export { WebhookChannel } from './channels/index.js';

// ---------------------------------------------------------------------------
// Templates / 模板
// ---------------------------------------------------------------------------

export { ALERT_TEMPLATES, findAlertTemplate, getHumanSummary } from './templates/index.js';
export type { AlertTemplate } from './templates/index.js';

// ---------------------------------------------------------------------------
// Onboarding / 安裝引導
// ---------------------------------------------------------------------------

export {
  SETUP_STEPS,
  getChannelConfigSteps,
  buildConfigFromAnswers,
  getWelcomeMessage,
  DEFAULT_PREFERENCES,
} from './onboarding/index.js';
export type { SetupStep, SetupOption, SetupAnswers } from './onboarding/index.js';

// ---------------------------------------------------------------------------
// CLI / 命令列
// ---------------------------------------------------------------------------

export { runCLI, CLI_VERSION } from './cli/index.js';
