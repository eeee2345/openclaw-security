#!/usr/bin/env node
/**
 * PanguardChat CLI
 * PanguardChat 命令列介面
 *
 * Commands:
 * - setup: Interactive notification setup / 互動式通知設定
 * - test: Send a test notification / 發送測試通知
 * - status: Show channel status / 顯示管道狀態
 * - config: Show current configuration / 顯示當前配置
 *
 * @module @openclaw/panguard-chat/cli
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { SETUP_STEPS, getWelcomeMessage } from '../onboarding/index.js';
import type { ChatConfig, MessageLanguage, ChannelType, UserType, WebhookConfig } from '../types.js';
import { ChatAgent } from '../agent/chat-agent.js';
import { WebhookChannel } from '../channels/webhook.js';

/** CLI version / CLI 版本 */
export const CLI_VERSION = '0.1.0';

/**
 * Parse and execute CLI commands / 解析並執行 CLI 命令
 *
 * @param args - Command line arguments (process.argv.slice(2)) / 命令列引數
 */
export async function runCLI(args: string[]): Promise<void> {
  const command = args[0] ?? 'help';

  switch (command) {
    case 'setup':
      await commandSetup(args);
      break;
    case 'test':
      await commandTest(args);
      break;
    case 'status':
      commandStatus();
      break;
    case 'config':
      commandConfig();
      break;
    case 'prefs':
      commandPrefs(args);
      break;
    case 'help':
    default:
      printHelp();
      break;
  }
}

// ---------------------------------------------------------------------------
// Commands
// 命令
// ---------------------------------------------------------------------------

/**
 * Interactive notification setup / 互動式通知設定
 */
async function commandSetup(args: string[]): Promise<void> {
  const lang: MessageLanguage = extractOption(args, '--lang') === 'en' ? 'en' : 'zh-TW';

  console.log('');
  console.log(lang === 'zh-TW'
    ? 'Panguard AI - 通知管道設定精靈'
    : 'Panguard AI - Notification Setup Wizard');
  console.log('='.repeat(40));

  // Display available steps
  for (const step of SETUP_STEPS) {
    console.log('');
    console.log(`[${step.id}] ${step.title[lang]}`);
    console.log(`  ${step.description[lang]}`);
    if (step.options) {
      for (const opt of step.options) {
        console.log(`    - ${opt.label[lang]}: ${opt.description[lang]}`);
      }
    }
  }

  console.log('');
  console.log(lang === 'zh-TW'
    ? '使用 --channel, --user-type, --language 選項進行非互動式設定'
    : 'Use --channel, --user-type, --language options for non-interactive setup');

  // Non-interactive mode
  const channel = extractOption(args, '--channel') as ChannelType | undefined;
  const userType = extractOption(args, '--user-type') as UserType | undefined;

  if (channel && userType) {
    console.log('');
    console.log(lang === 'zh-TW'
      ? `配置: 管道=${channel}, 用戶類型=${userType}, 語言=${lang}`
      : `Config: channel=${channel}, userType=${userType}, language=${lang}`);
    console.log('');
    console.log(getWelcomeMessage(lang));
  }
}

/**
 * Send a test notification / 發送測試通知
 */
async function commandTest(args: string[]): Promise<void> {
  const channelType = (extractOption(args, '--channel') ?? 'webhook') as ChannelType;
  const lang: MessageLanguage = extractOption(args, '--lang') === 'en' ? 'en' : 'zh-TW';
  const url = extractOption(args, '--url');

  console.log(`Sending test notification via ${channelType}... / 正在透過 ${channelType} 發送測試通知...`);

  if (channelType === 'webhook') {
    if (!url) {
      console.log('');
      console.log(lang === 'zh-TW'
        ? '使用 Webhook 需要指定 URL。範例:'
        : 'Webhook requires a URL. Example:');
      console.log('  panguard-chat test --channel webhook --url https://httpbin.org/post');
      console.log('');
      console.log(lang === 'zh-TW'
        ? '或使用其他管道 (需先設定):'
        : 'Or use other channels (setup required):');
      console.log('  panguard-chat test --channel slack');
      console.log('  panguard-chat test --channel telegram');
      console.log('  panguard-chat test --channel line');
      return;
    }

    const webhookConfig: WebhookConfig = {
      endpoint: url,
      secret: '',
      authMethod: 'bearer_token',
    };

    const agent = new ChatAgent({
      userProfile: {
        type: 'it_admin',
        language: lang,
        notificationChannel: 'webhook',
        preferences: {
          criticalAlerts: true,
          dailySummary: true,
          weeklySummary: true,
          peacefulReport: true,
        },
      },
      channels: {
        webhook: webhookConfig,
      },
      maxFollowUpTokens: 2000,
    });

    const webhook = new WebhookChannel(webhookConfig);
    agent.registerChannel(webhook);

    const result = await agent.sendAlert('cli-test', {
      severity: 'medium',
      conclusion: 'suspicious',
      confidence: 0.95,
      humanSummary: lang === 'zh-TW'
        ? 'This is a test alert from Panguard AI / 這是 Panguard AI 的測試告警'
        : 'This is a test alert from Panguard AI',
      reasoning: 'CLI test command invoked',
      recommendedAction: lang === 'zh-TW'
        ? 'No action required - this is a test / 無需動作 - 這是測試'
        : 'No action required - this is a test',
      eventDescription: 'Test notification',
      actionsTaken: [],
      timestamp: new Date().toISOString(),
    });

    if (result.success) {
      console.log(lang === 'zh-TW'
        ? `Test notification sent successfully to ${url}`
        : `Test notification sent successfully to ${url}`);
      console.log(lang === 'zh-TW'
        ? '測試通知已成功發送!'
        : 'Test notification sent!');
    } else {
      console.error(lang === 'zh-TW'
        ? `發送失敗: ${result.error}`
        : `Send failed: ${result.error}`);
    }
  } else {
    // For other channels, show setup instructions
    console.log('');
    console.log(lang === 'zh-TW'
      ? `管道 ${channelType} 需要先完成設定。請執行:`
      : `Channel ${channelType} requires setup first. Run:`);
    console.log(`  panguard-chat setup --channel ${channelType}`);
  }
}

/** Default config directory / 預設配置目錄 */
const CONFIG_DIR = join(homedir(), '.panguard-chat');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

/** Load saved config if it exists / 讀取已儲存的配置 */
function loadConfig(): ChatConfig | null {
  const configPath = process.env['PANGUARD_CHAT_CONFIG'] ?? CONFIG_FILE;
  if (!existsSync(configPath)) return null;
  try {
    const raw = readFileSync(configPath, 'utf-8');
    return JSON.parse(raw) as ChatConfig;
  } catch {
    return null;
  }
}

/**
 * Show channel status / 顯示管道狀態
 */
function commandStatus(): void {
  console.log('PanguardChat Status / PanguardChat 狀態');
  console.log('================================');

  const config = loadConfig();
  if (!config) {
    console.log('Configured channels: (none)');
    console.log('');
    console.log('Run "panguard-chat setup" to configure notification channels.');
    console.log('執行 "panguard-chat setup" 來配置通知管道。');
    return;
  }

  const channels = config.channels;
  const configuredChannels = Object.keys(channels).filter(
    (k) => channels[k as keyof typeof channels] != null,
  );

  console.log(`User type: ${config.userProfile.type}`);
  console.log(`Language: ${config.userProfile.language}`);
  console.log(`Notification channel: ${config.userProfile.notificationChannel}`);
  console.log(`Configured channels: ${configuredChannels.length > 0 ? configuredChannels.join(', ') : '(none)'}`);
  console.log(`Max follow-up tokens: ${config.maxFollowUpTokens}`);
}

/**
 * Show current configuration / 顯示當前配置
 */
function commandConfig(): void {
  console.log('PanguardChat Configuration / PanguardChat 配置');
  console.log('========================================');

  const config = loadConfig();
  if (!config) {
    console.log('No configuration found. Run "panguard-chat setup" first.');
    console.log('找不到配置。請先執行 "panguard-chat setup"。');
    return;
  }

  console.log(JSON.stringify(config, null, 2));
}

/**
 * Show and update notification preferences / 顯示及更新通知偏好
 */
function commandPrefs(args: string[]): void {
  const config = loadConfig();
  if (!config) {
    console.log('No configuration found. Run "panguard chat setup" first.');
    console.log('找不到配置。請先執行 "panguard chat setup"。');
    return;
  }

  const prefs = config.userProfile.preferences;
  const updates: Record<string, boolean> = {};
  let hasUpdates = false;

  // Parse --critical, --daily, --weekly, --peaceful flags
  for (const [flag, key] of [
    ['--critical', 'criticalAlerts'],
    ['--daily', 'dailySummary'],
    ['--weekly', 'weeklySummary'],
    ['--peaceful', 'peacefulReport'],
  ] as const) {
    const val = extractOption(args, flag);
    if (val === 'on' || val === 'true') {
      updates[key] = true;
      hasUpdates = true;
    } else if (val === 'off' || val === 'false') {
      updates[key] = false;
      hasUpdates = true;
    }
  }

  if (hasUpdates) {
    const newPrefs = { ...prefs, ...updates };
    const newConfig: ChatConfig = {
      ...config,
      userProfile: {
        ...config.userProfile,
        preferences: newPrefs,
      },
    };
    const configPath = process.env['PANGUARD_CHAT_CONFIG'] ?? CONFIG_FILE;
    mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(configPath, JSON.stringify(newConfig, null, 2), 'utf-8');
    console.log('Notification preferences updated / 通知偏好已更新');
    console.log('');
    showPrefs(newPrefs);
  } else {
    showPrefs(prefs);
  }
}

function showPrefs(prefs: { criticalAlerts: boolean; dailySummary: boolean; weeklySummary: boolean; peacefulReport: boolean }): void {
  const on = '\x1b[32mON\x1b[0m';
  const off = '\x1b[31mOFF\x1b[0m';
  console.log('Notification Preferences / 通知偏好');
  console.log('====================================');
  console.log(`  Critical Alerts  : ${prefs.criticalAlerts ? on : off}`);
  console.log(`  Daily Summary    : ${prefs.dailySummary ? on : off}`);
  console.log(`  Weekly Summary   : ${prefs.weeklySummary ? on : off}`);
  console.log(`  Peaceful Report  : ${prefs.peacefulReport ? on : off}`);
  console.log('');
  console.log('Update: panguard chat prefs --critical on --daily off');
  console.log('更新: panguard chat prefs --critical on --daily off');
  console.log('');
}

/**
 * Print help message / 列印幫助訊息
 */
function printHelp(): void {
  console.log(`
PanguardChat - AI Security Communication Assistant
PanguardChat - AI 資安通訊助手

Usage: panguard-chat <command> [options]

Commands:
  setup             Interactive notification setup / 互動式通知設定
  test              Send a test notification / 發送測試通知
  status            Show channel status / 顯示管道狀態
  config            Show current configuration / 顯示當前配置
  prefs             View/update notification preferences / 查看/更新通知偏好
  help              Show this help / 顯示此說明

Options:
  --channel <type>    Channel type (line, telegram, slack, email, webhook)
  --user-type <type>  User type (developer, boss, it_admin)
  --lang <lang>       Language (zh-TW, en) / 語言
  --data-dir <path>   Data directory / 資料目錄

Version: ${CLI_VERSION}
`);
}

// ---------------------------------------------------------------------------
// Helpers
// 輔助函式
// ---------------------------------------------------------------------------

/**
 * Extract option value from args / 從引數中提取選項值
 */
function extractOption(args: string[], option: string): string | undefined {
  const idx = args.indexOf(option);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// CLI entry point (when run directly)
// CLI 進入點（直接執行時）
// ---------------------------------------------------------------------------

const isDirectRun = process.argv[1] &&
  (process.argv[1].endsWith('/panguard-chat') ||
   process.argv[1].includes('panguard-chat/dist/cli'));

if (isDirectRun) {
  runCLI(process.argv.slice(2)).catch((err) => {
    console.error('Error:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
