/**
 * LINE Messaging API Channel
 * LINE Messaging API 管道
 *
 * Bidirectional LINE messaging channel using the Messaging API.
 * LINE Notify was deprecated on 2025/3/31; this uses Push Message API.
 * 使用 LINE Messaging API 的雙向通訊管道。
 * LINE Notify 已於 2025/3/31 停用；本模組使用 Push Message API。
 *
 * @module @panguard-ai/panguard-chat/channels/line
 */

import { createLogger } from '@panguard-ai/core';
import type {
  MessagingChannel,
  ChannelResult,
  FormattedMessage,
  ThreatAlert,
  ReplyHandler,
  LINEChannelConfig,
  AlertSeverity,
} from '../types.js';
import { formatAlert } from '../agent/formatter.js';

const logger = createLogger('panguard-chat:channel:line');

// ---------------------------------------------------------------------------
// LINE Message Helpers
// LINE 訊息輔助函式
// ---------------------------------------------------------------------------

/** Map severity to status prefix (text-based, no emoji per project rules) */
function severityPrefix(severity?: AlertSeverity): string {
  switch (severity) {
    case 'critical':
      return '[!!]';
    case 'warning':
      return '[!]';
    case 'info':
    default:
      return '[i]';
  }
}

// ---------------------------------------------------------------------------
// LINE Channel Implementation
// LINE 管道實作
// ---------------------------------------------------------------------------

/**
 * LINE Messaging API bidirectional messaging channel
 * LINE Messaging API 雙向通訊管道
 */
export class LINEChannel implements MessagingChannel {
  readonly channelType = 'line' as const;
  private readonly config: LINEChannelConfig;
  private replyHandler: ReplyHandler | null = null;

  constructor(config: LINEChannelConfig) {
    this.config = config;
    logger.info('LINE channel initialized / LINE 管道已初始化');
  }

  /**
   * Send a formatted message via LINE Push Message API
   * 透過 LINE Push Message API 發送格式化訊息
   */
  async sendMessage(userId: string, message: FormattedMessage): Promise<ChannelResult> {
    try {
      const targetId = userId || this.config.destinationUserId;
      const prefix = severityPrefix(message.severity);
      const fullText = `${prefix} ${message.text}`;

      const payload = JSON.stringify({
        to: targetId,
        messages: [{ type: 'text', text: fullText }],
      });

      const response = await this.httpPost(
        'https://api.line.me/v2/bot/message/push',
        payload
      );

      logger.info(`LINE message sent to ${targetId} / LINE 訊息已發送`);

      return {
        success: true,
        channel: 'line',
        messageId: response.sentMessages?.[0]?.id ?? '',
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`LINE send failed: ${msg} / LINE 發送失敗: ${msg}`);
      return { success: false, channel: 'line', error: msg };
    }
  }

  /**
   * Send a threat alert via LINE
   * 透過 LINE 發送威脅告警
   */
  async sendAlert(userId: string, alert: ThreatAlert): Promise<ChannelResult> {
    const message = formatAlert(alert, 'developer', 'zh-TW');
    return this.sendMessage(userId, message);
  }

  /**
   * Send a file via LINE
   * 透過 LINE 發送檔案
   *
   * LINE Messaging API does not support direct file push for arbitrary files.
   * We send a text message with the filename as a notification instead.
   * LINE Messaging API 不支援直接推送任意檔案。
   * 改為發送包含檔名的文字通知。
   */
  async sendFile(userId: string, _file: Buffer, filename: string): Promise<ChannelResult> {
    try {
      const targetId = userId || this.config.destinationUserId;

      const payload = JSON.stringify({
        to: targetId,
        messages: [
          {
            type: 'text',
            text: `[i] Report ready: ${filename}\nPlease check the Panguard web dashboard to download.`,
          },
        ],
      });

      await this.httpPost('https://api.line.me/v2/bot/message/push', payload);

      logger.info(`LINE file notification sent: ${filename} / LINE 檔案通知已發送: ${filename}`);
      return { success: true, channel: 'line' };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`LINE file send failed: ${msg} / 檔案發送失敗: ${msg}`);
      return { success: false, channel: 'line', error: msg };
    }
  }

  /**
   * Register a reply handler
   * 註冊回覆處理器
   */
  onReply(handler: ReplyHandler): void {
    this.replyHandler = handler;
    logger.info('LINE reply handler registered / LINE 回覆處理器已註冊');
  }

  /**
   * Process an incoming LINE webhook event
   * 處理收到的 LINE webhook 事件
   *
   * LINE webhook sends events array with type 'message', 'postback', etc.
   * LINE webhook 發送事件陣列，包含 'message'、'postback' 等類型。
   */
  async processWebhook(event: {
    type: string;
    source?: { userId?: string };
    message?: { type: string; text?: string };
    postback?: { data: string };
    replyToken?: string;
  }): Promise<string | null> {
    if (!this.replyHandler) {
      return null;
    }

    const userId = event.source?.userId ?? '';

    // Handle text messages
    if (event.type === 'message' && event.message?.type === 'text' && event.message.text) {
      return this.replyHandler(userId, event.message.text);
    }

    // Handle postback actions (quick reply buttons)
    if (event.type === 'postback' && event.postback?.data) {
      return this.replyHandler(userId, event.postback.data);
    }

    return null;
  }

  // -------------------------------------------------------------------------
  // HTTP Helpers
  // -------------------------------------------------------------------------

  private async httpPost(
    url: string,
    body: string
  ): Promise<{ sentMessages?: readonly { id: string }[] }> {
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
                'Content-Type': 'application/json',
                Authorization: `Bearer ${this.config.channelAccessToken}`,
                'Content-Length': Buffer.byteLength(body),
              },
            },
            (res) => {
              let data = '';
              res.on('data', (chunk: Buffer) => {
                data += chunk.toString();
              });
              res.on('end', () => {
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                  try {
                    resolve(
                      JSON.parse(data) as {
                        sentMessages?: readonly { id: string }[];
                      }
                    );
                  } catch {
                    resolve({});
                  }
                } else {
                  reject(new Error(`LINE API error ${res.statusCode}: ${data}`));
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
