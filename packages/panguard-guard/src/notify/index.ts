/**
 * Notification System
 * 通知系統
 *
 * Dispatches threat alerts to configured notification channels:
 * LINE Notify, Telegram Bot, Slack Webhook, Email SMTP.
 * 將威脅警報派發至已配置的通知通道：
 * LINE Notify、Telegram Bot、Slack Webhook、Email SMTP。
 *
 * @module @panguard-ai/panguard-guard/notify
 */

import { createLogger } from '@panguard-ai/core';
import type { NotificationConfig, NotificationResult, ThreatVerdict } from '../types.js';
import { sendLineNotify } from './line-notify.js';
import { sendTelegramNotify } from './telegram.js';
import { sendSlackNotify } from './slack.js';
import { sendEmailNotify } from './email.js';

const logger = createLogger('panguard-guard:notify');

export { sendLineNotify } from './line-notify.js';
export { sendTelegramNotify } from './telegram.js';
export { sendSlackNotify } from './slack.js';
export { sendEmailNotify } from './email.js';

/**
 * Send notifications to all configured channels
 * 向所有已配置的通道發送通知
 *
 * Dispatches alerts in parallel to all configured channels and
 * collects results. Never throws - all errors are captured in results.
 * 平行向所有已配置的通道派發警報並收集結果。
 * 永不拋出錯誤 - 所有錯誤都會被捕獲在結果中。
 *
 * @param config - Notification configuration / 通知配置
 * @param verdict - The threat verdict to notify about / 要通知的威脅判決
 * @param eventDescription - Human-readable event description / 人類可讀的事件描述
 * @returns Array of notification results for each channel / 各通道的通知結果陣列
 */
export async function sendNotifications(
  config: NotificationConfig,
  verdict: ThreatVerdict,
  eventDescription: string
): Promise<NotificationResult[]> {
  const promises: Promise<NotificationResult>[] = [];

  if (config.line) {
    promises.push(sendLineNotify(config.line, verdict, eventDescription));
  }
  if (config.telegram) {
    promises.push(sendTelegramNotify(config.telegram, verdict, eventDescription));
  }
  if (config.slack) {
    promises.push(sendSlackNotify(config.slack, verdict, eventDescription));
  }
  if (config.email) {
    promises.push(sendEmailNotify(config.email, verdict, eventDescription));
  }

  if (promises.length === 0) {
    logger.info('No notification channels configured / 未配置通知通道');
    return [];
  }

  const results = await Promise.allSettled(promises);
  const notificationResults: NotificationResult[] = [];

  for (const result of results) {
    if (result.status === 'fulfilled') {
      notificationResults.push(result.value);
    } else {
      const msg = result.reason instanceof Error ? result.reason.message : String(result.reason);
      logger.error(`Notification failed: ${msg} / 通知失敗: ${msg}`);
      notificationResults.push({
        channel: 'line', // fallback channel name
        success: false,
        error: msg,
      });
    }
  }

  const successCount = notificationResults.filter((r) => r.success).length;
  logger.info(
    `Notifications sent: ${successCount}/${notificationResults.length} successful / ` +
      `通知發送: ${successCount}/${notificationResults.length} 成功`
  );

  return notificationResults;
}
