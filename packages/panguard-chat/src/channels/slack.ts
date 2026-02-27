/**
 * Slack Channel
 * Slack 管道
 *
 * Bidirectional Slack messaging channel using Slack Web API.
 * Supports interactive messages with buttons and blocks.
 * 使用 Slack Web API 的雙向通訊管道。
 * 支援帶按鈕和 blocks 的互動訊息。
 *
 * Recommended for Pro/Business plans.
 * 推薦 Pro/Business 方案使用。
 *
 * @module @panguard-ai/panguard-chat/channels/slack
 */

import { createLogger } from '@panguard-ai/core';
import type {
  MessagingChannel,
  ChannelResult,
  FormattedMessage,
  ThreatAlert,
  ReplyHandler,
  SlackChannelConfig,
  AlertSeverity,
} from '../types.js';
import { formatAlert } from '../agent/formatter.js';

const logger = createLogger('panguard-chat:channel:slack');

// ---------------------------------------------------------------------------
// Slack Message Helpers
// Slack 訊息輔助函式
// ---------------------------------------------------------------------------

/** Map severity to Slack attachment color */
function severityToColor(severity?: AlertSeverity): string {
  switch (severity) {
    case 'critical':
      return '#FF0000';
    case 'warning':
      return '#FFA500';
    case 'info':
    default:
      return '#2196F3';
  }
}

/** Build Slack Block Kit blocks from a formatted message */
function buildBlocks(message: FormattedMessage): Record<string, unknown>[] {
  const blocks: Record<string, unknown>[] = [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: message.text,
      },
    },
  ];

  if (message.quickReplies && message.quickReplies.length > 0) {
    blocks.push({
      type: 'actions',
      elements: message.quickReplies.map((qr) => ({
        type: 'button',
        text: {
          type: 'plain_text',
          text: qr.label,
        },
        action_id: qr.action,
        value: qr.action,
      })),
    });
  }

  return blocks;
}

// ---------------------------------------------------------------------------
// Slack Channel Implementation
// Slack 管道實作
// ---------------------------------------------------------------------------

/**
 * Slack bidirectional messaging channel
 * Slack 雙向通訊管道
 */
export class SlackChannel implements MessagingChannel {
  readonly channelType = 'slack' as const;
  private readonly config: SlackChannelConfig;
  private replyHandler: ReplyHandler | null = null;

  constructor(config: SlackChannelConfig) {
    this.config = config;
    logger.info('Slack channel initialized / Slack 管道已初始化');
  }

  /**
   * Send a formatted message via Slack Web API
   * 透過 Slack Web API 發送格式化訊息
   */
  async sendMessage(userId: string, message: FormattedMessage): Promise<ChannelResult> {
    try {
      const channel = userId || this.config.defaultChannel;
      const blocks = buildBlocks(message);

      const payload = JSON.stringify({
        channel,
        text: message.text.slice(0, 150), // fallback text
        blocks,
        attachments: [
          {
            color: severityToColor(message.severity),
            fallback: message.text.slice(0, 150),
          },
        ],
      });

      const response = await this.httpPost('https://slack.com/api/chat.postMessage', payload);

      if (!response.ok) {
        throw new Error(response.error ?? 'Slack API error');
      }

      logger.info(`Slack message sent to ${channel} / Slack 訊息已發送`);

      return {
        success: true,
        channel: 'slack',
        messageId: response.ts,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Slack send failed: ${msg} / Slack 發送失敗: ${msg}`);
      return { success: false, channel: 'slack', error: msg };
    }
  }

  /**
   * Send a threat alert via Slack
   * 透過 Slack 發送威脅告警
   */
  async sendAlert(userId: string, alert: ThreatAlert): Promise<ChannelResult> {
    const message = formatAlert(alert, 'developer', 'zh-TW');
    return this.sendMessage(userId, message);
  }

  /**
   * Send a file via Slack
   * 透過 Slack 發送檔案
   */
  async sendFile(userId: string, file: Buffer, filename: string): Promise<ChannelResult> {
    try {
      const channel = userId || this.config.defaultChannel;

      // Use Slack files.upload API (v2)
      const boundary = `----FormBoundary${Date.now()}`;
      const parts: Buffer[] = [];

      // channels field
      parts.push(
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="channels"\r\n\r\n${channel}\r\n`
        )
      );

      // filename field
      parts.push(
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="filename"\r\n\r\n${filename}\r\n`
        )
      );

      // file field
      parts.push(
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`
        )
      );
      parts.push(file);
      parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));

      const body = Buffer.concat(parts);

      await this.httpPostRaw(
        'https://slack.com/api/files.upload',
        body,
        `multipart/form-data; boundary=${boundary}`
      );

      logger.info(`Slack file sent: ${filename} / Slack 檔案已發送: ${filename}`);
      return { success: true, channel: 'slack' };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Slack file send failed: ${msg} / 檔案發送失敗: ${msg}`);
      return { success: false, channel: 'slack', error: msg };
    }
  }

  /**
   * Register a reply handler
   * 註冊回覆處理器
   */
  onReply(handler: ReplyHandler): void {
    this.replyHandler = handler;
    logger.info('Slack reply handler registered / Slack 回覆處理器已註冊');
  }

  /**
   * Process a Slack event (message or interaction)
   * 處理 Slack 事件（訊息或互動）
   */
  async processEvent(event: {
    type: string;
    text?: string;
    user?: string;
    channel?: string;
    actions?: Array<{ action_id: string; value: string }>;
  }): Promise<string | null> {
    if (!this.replyHandler) {
      return null;
    }

    // Handle text messages
    if (event.type === 'message' && event.text && event.user) {
      return this.replyHandler(event.channel ?? event.user, event.text);
    }

    // Handle interactive button presses
    if (event.type === 'block_actions' && event.actions && event.actions.length > 0) {
      const action = event.actions[0]!;
      return this.replyHandler(event.channel ?? event.user ?? '', action.value);
    }

    return null;
  }

  /**
   * Verify Slack request signature
   * 驗證 Slack 請求簽名
   */
  async verifySignature(signature: string, timestamp: string, body: string): Promise<boolean> {
    try {
      const crypto = await import('node:crypto');
      const sigBasestring = `v0:${timestamp}:${body}`;
      const mySignature = `v0=${crypto
        .createHmac('sha256', this.config.signingSecret)
        .update(sigBasestring)
        .digest('hex')}`;
      return mySignature === signature;
    } catch {
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // HTTP Helpers
  // -------------------------------------------------------------------------

  private async httpPost(
    url: string,
    body: string
  ): Promise<{ ok: boolean; error?: string; ts?: string }> {
    const { hostname, pathname } = new URL(url);

    return new Promise((resolve, reject) => {
      import('node:https')
        .then(({ request }) => {
          const req = request(
            {
              hostname,
              path: pathname,
              method: 'POST',
              headers: {
                'Content-Type': 'application/json; charset=utf-8',
                Authorization: `Bearer ${this.config.botToken}`,
                'Content-Length': Buffer.byteLength(body),
              },
            },
            (res) => {
              let data = '';
              res.on('data', (chunk: Buffer) => {
                data += chunk.toString();
              });
              res.on('end', () => {
                try {
                  resolve(JSON.parse(data) as { ok: boolean; error?: string; ts?: string });
                } catch {
                  reject(new Error(`Invalid Slack response: ${data}`));
                }
              });
            }
          );
          req.on('error', reject);
          req.write(body);
          req.end();
        })
        .catch(reject);
    });
  }

  private async httpPostRaw(url: string, body: Buffer, contentType: string): Promise<void> {
    const { hostname, pathname } = new URL(url);

    return new Promise((resolve, reject) => {
      import('node:https')
        .then(({ request }) => {
          const req = request(
            {
              hostname,
              path: pathname,
              method: 'POST',
              headers: {
                'Content-Type': contentType,
                Authorization: `Bearer ${this.config.botToken}`,
                'Content-Length': body.length,
              },
            },
            (res) => {
              let data = '';
              res.on('data', (chunk: Buffer) => {
                data += chunk.toString();
              });
              res.on('end', () => {
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                  resolve();
                } else {
                  reject(new Error(`Slack API error ${res.statusCode}: ${data}`));
                }
              });
            }
          );
          req.on('error', reject);
          req.write(body);
          req.end();
        })
        .catch(reject);
    });
  }
}
