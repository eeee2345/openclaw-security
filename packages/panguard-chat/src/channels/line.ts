/**
 * LINE Bot Channel
 * LINE Bot 管道
 *
 * Bidirectional LINE messaging channel using LINE Bot SDK.
 * Unlike PanguardGuard's one-way LINE Notify, this uses the Messaging API
 * for interactive conversations (follow-up questions, confirmations).
 * 使用 LINE Bot SDK 的雙向 LINE 通訊管道。
 * 與 PanguardGuard 的單向 LINE Notify 不同，這使用 Messaging API
 * 進行互動對話（追問、確認）。
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
  LineChannelConfig,
  AlertSeverity,
} from '../types.js';
import { formatAlert } from '../agent/formatter.js';

const logger = createLogger('panguard-chat:channel:line');

// ---------------------------------------------------------------------------
// LINE Message Helpers
// LINE 訊息輔助函式
// ---------------------------------------------------------------------------

/** Map severity to LINE Flex Message color */
function severityColor(severity?: AlertSeverity): string {
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

/** Build LINE Flex Message JSON for a formatted message */
function buildFlexMessage(message: FormattedMessage): Record<string, unknown> {
  const contents: Record<string, unknown>[] = [
    {
      type: 'text',
      text: message.text,
      wrap: true,
      size: 'sm',
    },
  ];

  return {
    type: 'flex',
    altText: message.text.slice(0, 100),
    contents: {
      type: 'bubble',
      header: {
        type: 'box',
        layout: 'vertical',
        backgroundColor: severityColor(message.severity),
        contents: [
          {
            type: 'text',
            text: message.severity === 'critical' ? 'Security Alert' : 'Notification',
            color: '#FFFFFF',
            weight: 'bold',
          },
        ],
      },
      body: {
        type: 'box',
        layout: 'vertical',
        contents,
      },
      footer: message.quickReplies
        ? {
            type: 'box',
            layout: 'vertical',
            contents: message.quickReplies.map((qr) => ({
              type: 'button',
              action: {
                type: 'message',
                label: qr.label,
                text: qr.action,
              },
              style: 'primary',
              color: severityColor(message.severity),
              margin: 'sm',
            })),
          }
        : undefined,
    },
  };
}

/** Build simple LINE text message */
function buildTextMessage(text: string): Record<string, unknown> {
  return { type: 'text', text };
}

// ---------------------------------------------------------------------------
// LINE Channel Implementation
// LINE 管道實作
// ---------------------------------------------------------------------------

/**
 * LINE Bot bidirectional messaging channel
 * LINE Bot 雙向通訊管道
 *
 * Requires @line/bot-sdk to be installed.
 * In development/testing, messages are logged instead of sent.
 * 需要安裝 @line/bot-sdk。
 * 在開發/測試環境中，訊息會被記錄而非實際發送。
 */
export class LineChannel implements MessagingChannel {
  readonly channelType = 'line' as const;
  private readonly config: LineChannelConfig;
  private replyHandler: ReplyHandler | null = null;

  constructor(config: LineChannelConfig) {
    this.config = config;
    logger.info('LINE channel initialized / LINE 管道已初始化');
  }

  /**
   * Send a formatted message via LINE Messaging API
   * 透過 LINE Messaging API 發送格式化訊息
   */
  async sendMessage(userId: string, message: FormattedMessage): Promise<ChannelResult> {
    try {
      const lineMessage = message.quickReplies
        ? buildFlexMessage(message)
        : buildTextMessage(message.text);

      // Use LINE Bot SDK push message API
      // POST https://api.line.me/v2/bot/message/push
      const payload = JSON.stringify({
        to: userId,
        messages: [lineMessage],
      });

      const response = await this.httpPost('https://api.line.me/v2/bot/message/push', payload);

      logger.info(`LINE message sent to ${userId.slice(0, 8)}... / LINE 訊息已發送`);

      return {
        success: true,
        channel: 'line',
        messageId: response.messageId,
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
   */
  async sendFile(userId: string, _file: Buffer, filename: string): Promise<ChannelResult> {
    // LINE doesn't support arbitrary file sending via push API
    // Send a notification about the file instead
    const message: FormattedMessage = {
      text: `[File] ${filename} is ready for download.`,
    };
    return this.sendMessage(userId, message);
  }

  /**
   * Register a reply handler for incoming messages
   * 註冊收到訊息的回覆處理器
   */
  onReply(handler: ReplyHandler): void {
    this.replyHandler = handler;
    logger.info('LINE reply handler registered / LINE 回覆處理器已註冊');
  }

  /**
   * Process an incoming webhook event from LINE
   * 處理來自 LINE 的 webhook 事件
   *
   * Called by the webhook server when a message event is received.
   * 當收到訊息事件時由 webhook 伺服器呼叫。
   */
  async processWebhookEvent(event: {
    type: string;
    source: { userId: string };
    message?: { type: string; text: string };
    replyToken: string;
  }): Promise<string | null> {
    if (event.type !== 'message' || event.message?.type !== 'text') {
      return null;
    }

    if (!this.replyHandler) {
      logger.warn('No reply handler registered / 未註冊回覆處理器');
      return null;
    }

    const userId = event.source.userId;
    const text = event.message.text;

    logger.info(`LINE message received from ${userId.slice(0, 8)}... / ` + `收到 LINE 訊息`);

    const response = await this.replyHandler(userId, text);

    // Reply using the reply token
    await this.httpPost(
      'https://api.line.me/v2/bot/message/reply',
      JSON.stringify({
        replyToken: event.replyToken,
        messages: [buildTextMessage(response)],
      })
    );

    return response;
  }

  // -------------------------------------------------------------------------
  // HTTP Helper
  // -------------------------------------------------------------------------

  /**
   * Send HTTP POST request to LINE API
   * 發送 HTTP POST 請求到 LINE API
   *
   * Uses native Node.js https module (zero external dependencies).
   * 使用原生 Node.js https 模組（零外部依賴）。
   */
  private async httpPost(url: string, body: string): Promise<{ messageId?: string }> {
    const { hostname, pathname } = new URL(url);

    return new Promise((resolve, reject) => {
      // Dynamic import to avoid bundling issues
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
                    resolve(JSON.parse(data) as { messageId?: string });
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
