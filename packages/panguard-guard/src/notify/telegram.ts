/**
 * Telegram Bot notification integration
 * Telegram Bot 通知整合
 *
 * Sends threat alerts to Telegram chats via Bot API.
 * 透過 Bot API 將威脅警報發送至 Telegram 聊天。
 *
 * @module @panguard-ai/panguard-guard/notify/telegram
 */

import { request } from 'node:https';
import { createLogger } from '@panguard-ai/core';
import type { TelegramConfig, NotificationResult, ThreatVerdict } from '../types.js';

const logger = createLogger('panguard-guard:notify:telegram');

/**
 * Send a threat alert via Telegram Bot
 * 透過 Telegram Bot 發送威脅警報
 *
 * @param config - Telegram Bot configuration / Telegram Bot 配置
 * @param verdict - The threat verdict / 威脅判決
 * @param eventDescription - Event description / 事件描述
 * @returns Notification result / 通知結果
 */
export async function sendTelegramNotify(
  config: TelegramConfig,
  verdict: ThreatVerdict,
  eventDescription: string
): Promise<NotificationResult> {
  const conclusionLabel =
    verdict.conclusion === 'malicious'
      ? 'MALICIOUS'
      : verdict.conclusion === 'suspicious'
        ? 'SUSPICIOUS'
        : 'BENIGN';

  const text =
    `*[PanguardGuard Alert]*\n\n` +
    `*Conclusion:* ${conclusionLabel}\n` +
    `*Confidence:* ${verdict.confidence}%\n` +
    `*Action:* ${verdict.recommendedAction}\n` +
    `*Event:* ${escapeMarkdown(eventDescription)}\n` +
    `${verdict.mitreTechnique ? `*MITRE:* ${verdict.mitreTechnique}\n` : ''}` +
    `*Time:* ${new Date().toISOString()}`;

  try {
    await postTelegram(config.botToken, config.chatId, text);
    logger.info('Telegram notification sent / Telegram 通知已發送');
    return { channel: 'telegram', success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Telegram notification failed: ${msg} / Telegram 通知失敗: ${msg}`);
    return { channel: 'telegram', success: false, error: msg };
  }
}

/**
 * POST to Telegram Bot API sendMessage
 * 向 Telegram Bot API sendMessage 發送 POST
 */
function postTelegram(botToken: string, chatId: string, text: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      chat_id: chatId,
      text,
      parse_mode: 'Markdown',
    });

    const req = request(
      {
        hostname: 'api.telegram.org',
        port: 443,
        path: `/bot${botToken}/sendMessage`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString();
        });
        res.on('end', () => {
          if (res.statusCode === 200) {
            resolve();
          } else {
            reject(new Error(`Telegram HTTP ${res.statusCode}: ${data}`));
          }
        });
      }
    );

    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

/** Escape Markdown special characters / 逸出 Markdown 特殊字元 */
function escapeMarkdown(text: string): string {
  return text.replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}
