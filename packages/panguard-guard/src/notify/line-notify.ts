/**
 * LINE Notify integration
 * LINE Notify 整合
 *
 * Sends threat alerts to LINE Notify service via HTTP POST.
 * 透過 HTTP POST 將威脅警報發送至 LINE Notify 服務。
 *
 * @module @panguard-ai/panguard-guard/notify/line-notify
 */

import { request } from 'node:https';
import { createLogger } from '@panguard-ai/core';
import type { LineNotifyConfig, NotificationResult, ThreatVerdict } from '../types.js';

const logger = createLogger('panguard-guard:notify:line');

const LINE_NOTIFY_URL = 'https://notify-api.line.me/api/notify';

/**
 * Send a threat alert via LINE Notify
 * 透過 LINE Notify 發送威脅警報
 *
 * @param config - LINE Notify configuration with access token / LINE Notify 配置
 * @param verdict - The threat verdict to notify about / 要通知的威脅判決
 * @param eventDescription - Human-readable event description / 人類可讀的事件描述
 * @returns Notification result / 通知結果
 */
export async function sendLineNotify(
  config: LineNotifyConfig,
  verdict: ThreatVerdict,
  eventDescription: string
): Promise<NotificationResult> {
  const message =
    `\n[PanguardGuard Alert]\n` +
    `Conclusion: ${verdict.conclusion}\n` +
    `Confidence: ${verdict.confidence}%\n` +
    `Action: ${verdict.recommendedAction}\n` +
    `Event: ${eventDescription}\n` +
    `${verdict.mitreTechnique ? `MITRE: ${verdict.mitreTechnique}\n` : ''}` +
    `Time: ${new Date().toISOString()}`;

  try {
    await postLineNotify(config.accessToken, message);
    logger.info('LINE Notify sent successfully / LINE Notify 發送成功');
    return { channel: 'line', success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`LINE Notify failed: ${msg} / LINE Notify 發送失敗: ${msg}`);
    return { channel: 'line', success: false, error: msg };
  }
}

/**
 * POST to LINE Notify API / 向 LINE Notify API 發送 POST
 */
function postLineNotify(token: string, message: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const body = `message=${encodeURIComponent(message)}`;
    const url = new URL(LINE_NOTIFY_URL);

    const req = request(
      {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
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
            reject(new Error(`LINE Notify HTTP ${res.statusCode}: ${data}`));
          }
        });
      }
    );

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
