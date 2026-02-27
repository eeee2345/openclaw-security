/**
 * Onboarding Setup Flow
 * 安裝引導流程
 *
 * Guides users through setting up Panguard AI:
 * 1. Choose notification channel (LINE / Telegram / Slack / Email)
 * 2. Configure channel credentials
 * 3. Set user type (developer / boss / IT admin)
 * 4. Set language preference
 * 5. Send test notification
 *
 * 引導用戶完成 Panguard AI 設定：
 * 1. 選擇通知管道
 * 2. 配置管道憑證
 * 3. 設定用戶類型
 * 4. 設定語言偏好
 * 5. 發送測試通知
 *
 * @module @panguard-ai/panguard-chat/onboarding/setup-flow
 */

import { createLogger } from '@panguard-ai/core';
import type {
  UserType,
  ChannelType,
  MessageLanguage,
  UserProfile,
  NotificationPreferences,
  ChatConfig,
} from '../types.js';

const logger = createLogger('panguard-chat:onboarding');

// ---------------------------------------------------------------------------
// Setup Step Types
// 設定步驟類型
// ---------------------------------------------------------------------------

/** A single setup step / 一個設定步驟 */
export interface SetupStep {
  readonly id: string;
  readonly title: Record<MessageLanguage, string>;
  readonly description: Record<MessageLanguage, string>;
  readonly options?: readonly SetupOption[];
  readonly inputType?: 'text' | 'select';
}

/** An option within a setup step / 設定步驟中的一個選項 */
export interface SetupOption {
  readonly value: string;
  readonly label: Record<MessageLanguage, string>;
  readonly description: Record<MessageLanguage, string>;
}

/** Collected setup answers / 收集的設定答案 */
export interface SetupAnswers {
  channel: ChannelType;
  userType: UserType;
  language: MessageLanguage;
  channelConfig: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Setup Steps Definition
// 設定步驟定義
// ---------------------------------------------------------------------------

/** All onboarding steps / 所有安裝引導步驟 */
export const SETUP_STEPS: readonly SetupStep[] = [
  {
    id: 'channel',
    title: {
      'zh-TW': '選擇通知管道',
      en: 'Choose Notification Channel',
    },
    description: {
      'zh-TW': '你想透過哪個管道接收安全通知？',
      en: 'Which channel would you like to receive security notifications through?',
    },
    inputType: 'select',
    options: [
      {
        value: 'line',
        label: { 'zh-TW': 'LINE', en: 'LINE' },
        description: {
          'zh-TW': '適合個人開發者，台灣最常用的通訊軟體',
          en: 'Best for individual developers, most popular messaging app in Taiwan',
        },
      },
      {
        value: 'telegram',
        label: { 'zh-TW': 'Telegram', en: 'Telegram' },
        description: {
          'zh-TW': '適合個人開發者，全球通用的通訊軟體',
          en: 'Best for individual developers, globally used messaging app',
        },
      },
      {
        value: 'slack',
        label: { 'zh-TW': 'Slack', en: 'Slack' },
        description: {
          'zh-TW': '適合企業團隊，可整合到工作流程',
          en: 'Best for business teams, integrates into workflows',
        },
      },
      {
        value: 'email',
        label: { 'zh-TW': 'Email', en: 'Email' },
        description: {
          'zh-TW': '傳統方式，適合需要存檔記錄的場景',
          en: 'Traditional approach, best when records need to be archived',
        },
      },
      {
        value: 'webhook',
        label: { 'zh-TW': 'Webhook（企業級）', en: 'Webhook (Enterprise)' },
        description: {
          'zh-TW': '整合到 SIEM / 工單系統，支援 mTLS',
          en: 'Integrate with SIEM / ticketing systems, supports mTLS',
        },
      },
    ],
  },
  {
    id: 'userType',
    title: {
      'zh-TW': '你的角色是？',
      en: 'What is your role?',
    },
    description: {
      'zh-TW': '這會影響通知的語氣和技術程度',
      en: 'This will affect the tone and technical depth of notifications',
    },
    inputType: 'select',
    options: [
      {
        value: 'developer',
        label: { 'zh-TW': '開發者', en: 'Developer' },
        description: {
          'zh-TW': '包含技術細節、CLI 指令、CVE 編號',
          en: 'Includes technical details, CLI commands, CVE numbers',
        },
      },
      {
        value: 'boss',
        label: { 'zh-TW': '老闆 / 管理者', en: 'Boss / Manager' },
        description: {
          'zh-TW': '只講結果和影響，不講技術細節',
          en: 'Focus on outcomes and impact, no technical jargon',
        },
      },
      {
        value: 'it_admin',
        label: { 'zh-TW': 'IT 管理者', en: 'IT Admin' },
        description: {
          'zh-TW': '技術細節 + 管理建議 + 合規參考',
          en: 'Technical details + management advice + compliance references',
        },
      },
    ],
  },
  {
    id: 'language',
    title: {
      'zh-TW': '通知語言',
      en: 'Notification Language',
    },
    description: {
      'zh-TW': '選擇通知訊息的語言',
      en: 'Choose the language for notification messages',
    },
    inputType: 'select',
    options: [
      {
        value: 'zh-TW',
        label: { 'zh-TW': '繁體中文', en: 'Traditional Chinese' },
        description: { 'zh-TW': '繁體中文通知', en: 'Notifications in Traditional Chinese' },
      },
      {
        value: 'en',
        label: { 'zh-TW': 'English', en: 'English' },
        description: { 'zh-TW': '英文通知', en: 'Notifications in English' },
      },
    ],
  },
];

// ---------------------------------------------------------------------------
// Channel Configuration Steps
// 管道配置步驟
// ---------------------------------------------------------------------------

/** Get channel-specific configuration prompts / 取得管道專屬配置提示 */
export function getChannelConfigSteps(channel: ChannelType): readonly SetupStep[] {
  switch (channel) {
    case 'line':
      return [
        {
          id: 'lineChannelAccessToken',
          title: { 'zh-TW': 'LINE Channel Access Token', en: 'LINE Channel Access Token' },
          description: {
            'zh-TW': '在 LINE Developers Console 取得 Channel Access Token',
            en: 'Get your Channel Access Token from LINE Developers Console',
          },
          inputType: 'text',
        },
        {
          id: 'lineChannelSecret',
          title: { 'zh-TW': 'LINE Channel Secret', en: 'LINE Channel Secret' },
          description: {
            'zh-TW': '在 LINE Developers Console 取得 Channel Secret',
            en: 'Get your Channel Secret from LINE Developers Console',
          },
          inputType: 'text',
        },
      ];
    case 'telegram':
      return [
        {
          id: 'telegramBotToken',
          title: { 'zh-TW': 'Telegram Bot Token', en: 'Telegram Bot Token' },
          description: {
            'zh-TW': '從 @BotFather 取得 Bot Token',
            en: 'Get your Bot Token from @BotFather',
          },
          inputType: 'text',
        },
        {
          id: 'telegramChatId',
          title: { 'zh-TW': 'Telegram Chat ID', en: 'Telegram Chat ID' },
          description: {
            'zh-TW': '你的 Telegram Chat ID（可用 @userinfobot 查詢）',
            en: 'Your Telegram Chat ID (use @userinfobot to find it)',
          },
          inputType: 'text',
        },
      ];
    case 'slack':
      return [
        {
          id: 'slackBotToken',
          title: { 'zh-TW': 'Slack Bot Token', en: 'Slack Bot Token' },
          description: {
            'zh-TW': '在 Slack API 建立 App 後取得 Bot Token (xoxb-...)',
            en: 'Get your Bot Token after creating a Slack App (xoxb-...)',
          },
          inputType: 'text',
        },
        {
          id: 'slackSigningSecret',
          title: { 'zh-TW': 'Slack Signing Secret', en: 'Slack Signing Secret' },
          description: {
            'zh-TW': '在 Slack App 設定頁取得 Signing Secret',
            en: 'Get your Signing Secret from the Slack App settings page',
          },
          inputType: 'text',
        },
        {
          id: 'slackDefaultChannel',
          title: { 'zh-TW': '預設頻道', en: 'Default Channel' },
          description: {
            'zh-TW': '安全通知要發送到哪個頻道？（例如 #security-alerts）',
            en: 'Which channel should security notifications be sent to? (e.g. #security-alerts)',
          },
          inputType: 'text',
        },
      ];
    case 'email':
      return [
        {
          id: 'emailHost',
          title: { 'zh-TW': 'SMTP 主機', en: 'SMTP Host' },
          description: { 'zh-TW': 'SMTP 伺服器地址', en: 'SMTP server address' },
          inputType: 'text',
        },
        {
          id: 'emailPort',
          title: { 'zh-TW': 'SMTP 端口', en: 'SMTP Port' },
          description: {
            'zh-TW': 'SMTP 端口（常用: 587, 465）',
            en: 'SMTP port (common: 587, 465)',
          },
          inputType: 'text',
        },
        {
          id: 'emailUser',
          title: { 'zh-TW': 'SMTP 帳號', en: 'SMTP Username' },
          description: { 'zh-TW': 'SMTP 登入帳號', en: 'SMTP login username' },
          inputType: 'text',
        },
        {
          id: 'emailPass',
          title: { 'zh-TW': 'SMTP 密碼', en: 'SMTP Password' },
          description: { 'zh-TW': 'SMTP 登入密碼', en: 'SMTP login password' },
          inputType: 'text',
        },
        {
          id: 'emailFrom',
          title: { 'zh-TW': '寄件人地址', en: 'From Address' },
          description: { 'zh-TW': '通知郵件的寄件人', en: 'Sender address for notifications' },
          inputType: 'text',
        },
        {
          id: 'emailTo',
          title: { 'zh-TW': '收件人地址', en: 'To Address' },
          description: {
            'zh-TW': '接收通知的郵件地址',
            en: 'Email address to receive notifications',
          },
          inputType: 'text',
        },
      ];
    case 'webhook':
      return [
        {
          id: 'webhookEndpoint',
          title: { 'zh-TW': 'Webhook URL', en: 'Webhook URL' },
          description: {
            'zh-TW': '接收安全事件的 Webhook 端點',
            en: 'Webhook endpoint to receive security events',
          },
          inputType: 'text',
        },
        {
          id: 'webhookAuthMethod',
          title: { 'zh-TW': '認證方式', en: 'Authentication Method' },
          description: { 'zh-TW': '選擇認證方式', en: 'Choose authentication method' },
          inputType: 'select',
          options: [
            {
              value: 'bearer_token',
              label: { 'zh-TW': 'Bearer Token', en: 'Bearer Token' },
              description: { 'zh-TW': '使用 Bearer Token', en: 'Use Bearer Token' },
            },
            {
              value: 'hmac_signature',
              label: { 'zh-TW': 'HMAC 簽名', en: 'HMAC Signature' },
              description: { 'zh-TW': '使用 HMAC 簽名', en: 'Use HMAC Signature' },
            },
            {
              value: 'mtls',
              label: { 'zh-TW': 'mTLS', en: 'mTLS' },
              description: { 'zh-TW': '雙向 TLS 認證', en: 'Mutual TLS authentication' },
            },
          ],
        },
        {
          id: 'webhookSecret',
          title: { 'zh-TW': '密鑰 / Token', en: 'Secret / Token' },
          description: {
            'zh-TW': 'Bearer Token 或 HMAC Secret',
            en: 'Bearer Token or HMAC Secret',
          },
          inputType: 'text',
        },
      ];
  }
}

// ---------------------------------------------------------------------------
// Setup Flow Logic
// 設定流程邏輯
// ---------------------------------------------------------------------------

/**
 * Build a ChatConfig from setup answers
 * 從設定答案建構 ChatConfig
 *
 * @param answers - Collected setup answers / 收集的設定答案
 * @returns Chat configuration / Chat 配置
 */
export function buildConfigFromAnswers(answers: SetupAnswers): ChatConfig {
  const userProfile: UserProfile = {
    type: answers.userType,
    language: answers.language,
    notificationChannel: answers.channel,
    preferences: DEFAULT_PREFERENCES,
  };

  const config: ChatConfig = {
    userProfile,
    channels: {},
    maxFollowUpTokens: 2000,
  };

  logger.info(
    `Config built: ${answers.userType}/${answers.language}/${answers.channel} / ` +
      `配置已建構: ${answers.userType}/${answers.language}/${answers.channel}`
  );

  return config;
}

/** Default notification preferences / 預設通知偏好 */
export const DEFAULT_PREFERENCES: NotificationPreferences = {
  criticalAlerts: true,
  dailySummary: true,
  weeklySummary: true,
  peacefulReport: true,
};

/**
 * Generate a welcome message for new users
 * 為新用戶產生歡迎訊息
 *
 * @param language - Target language / 目標語言
 * @returns Welcome message / 歡迎訊息
 */
export function getWelcomeMessage(language: MessageLanguage): string {
  if (language === 'zh-TW') {
    return [
      'Panguard AI 設定完成!',
      '',
      '你的 AI 保鑣已經開始工作了。以下是你會收到的通知：',
      '',
      '- 即時威脅告警（有攻擊時才通知）',
      '- 每日安全摘要',
      '- 每週安全報告',
      '- 平安報告（沒事的時候也會告訴你）',
      '',
      '你隨時可以回覆訊息來追問任何告警的細節。',
      '',
      '目前系統處於學習期（7天），學習你的環境正常行為。',
      '學習期間不會推送即時告警（已知攻擊除外），只在日報中彙報。',
    ].join('\n');
  }

  return [
    'Panguard AI setup complete!',
    '',
    "Your AI bodyguard is now on duty. Here's what you'll receive:",
    '',
    '- Real-time threat alerts (only when attacks are detected)',
    '- Daily security summaries',
    '- Weekly security reports',
    "- Peace reports (we'll let you know when everything's fine too)",
    '',
    'You can reply to any alert message to ask follow-up questions.',
    '',
    'The system is currently in learning mode (7 days), learning your normal environment behavior.',
    'During this period, real-time alerts are suppressed (except known attacks) and included in daily summaries only.',
  ].join('\n');
}
