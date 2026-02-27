/**
 * Slack Webhook notification integration
 * Slack Webhook 通知整合
 *
 * Sends threat alerts to Slack channels via Incoming Webhooks.
 * 透過 Incoming Webhooks 將威脅警報發送至 Slack 頻道。
 *
 * @module @panguard-ai/panguard-guard/notify/slack
 */

import { request } from 'node:https';
import { createLogger } from '@panguard-ai/core';
import type { SlackConfig, NotificationResult, ThreatVerdict } from '../types.js';

const logger = createLogger('panguard-guard:notify:slack');

/**
 * Send a threat alert via Slack Webhook
 * 透過 Slack Webhook 發送威脅警報
 *
 * @param config - Slack webhook configuration / Slack webhook 配置
 * @param verdict - The threat verdict / 威脅判決
 * @param eventDescription - Event description / 事件描述
 * @returns Notification result / 通知結果
 */
export async function sendSlackNotify(
  config: SlackConfig,
  verdict: ThreatVerdict,
  eventDescription: string
): Promise<NotificationResult> {
  const color =
    verdict.conclusion === 'malicious'
      ? '#dc3545'
      : verdict.conclusion === 'suspicious'
        ? '#ffc107'
        : '#28a745';

  const payload = {
    attachments: [
      {
        color,
        title: `PanguardGuard Alert: ${verdict.conclusion.toUpperCase()}`,
        fields: [
          { title: 'Confidence', value: `${verdict.confidence}%`, short: true },
          { title: 'Action', value: verdict.recommendedAction, short: true },
          { title: 'Event', value: eventDescription, short: false },
          ...(verdict.mitreTechnique
            ? [{ title: 'MITRE ATT&CK', value: verdict.mitreTechnique, short: true }]
            : []),
        ],
        footer: 'PanguardGuard Security',
        ts: Math.floor(Date.now() / 1000).toString(),
      },
    ],
  };

  try {
    await postSlack(config.webhookUrl, payload);
    logger.info('Slack notification sent / Slack 通知已發送');
    return { channel: 'slack', success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Slack notification failed: ${msg} / Slack 通知失敗: ${msg}`);
    return { channel: 'slack', success: false, error: msg };
  }
}

/**
 * POST to Slack Webhook URL / 向 Slack Webhook URL 發送 POST
 */
function postSlack(webhookUrl: string, payload: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const url = new URL(webhookUrl);

    const req = request(
      {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
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
            reject(new Error(`Slack HTTP ${res.statusCode}: ${data}`));
          }
        });
      }
    );

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
