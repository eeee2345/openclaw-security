/**
 * Telegram Bot Channel
 * Telegram Bot 管道
 *
 * Bidirectional Telegram messaging channel.
 * Uses Telegram Bot API for interactive conversations.
 * 使用 Telegram Bot API 的雙向通訊管道。
 *
 * Note: For Business/compliance plans, Telegram is not recommended
 * because Telegram defaults to unencrypted chat and holds keys server-side,
 * which may not comply with ISO 27001 / local regulations.
 * 注意：企業/合規方案不建議使用 Telegram，因為 Telegram
 * 預設不加密、伺服器端持有金鑰，可能不符合 ISO 27001 / 資通安全管理法。
 *
 * @module @panguard-ai/panguard-chat/channels/telegram
 */

import { createLogger } from '@panguard-ai/core';
import type {
  MessagingChannel,
  ChannelResult,
  FormattedMessage,
  ThreatAlert,
  ReplyHandler,
  TelegramChannelConfig,
  AlertSeverity,
} from '../types.js';
import { formatAlert } from '../agent/formatter.js';

const logger = createLogger('panguard-chat:channel:telegram');

// ---------------------------------------------------------------------------
// Telegram Message Helpers
// Telegram 訊息輔助函式
// ---------------------------------------------------------------------------

/** Map severity to status icon (text-based, no emoji per project rules) */
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

/** Build Telegram inline keyboard from quick replies */
function buildInlineKeyboard(
  quickReplies?: readonly { label: string; action: string }[]
): Record<string, unknown> | undefined {
  if (!quickReplies || quickReplies.length === 0) return undefined;
  return {
    inline_keyboard: [
      quickReplies.map((qr) => ({
        text: qr.label,
        callback_data: qr.action,
      })),
    ],
  };
}

// ---------------------------------------------------------------------------
// Telegram Channel Implementation
// Telegram 管道實作
// ---------------------------------------------------------------------------

/**
 * Telegram Bot bidirectional messaging channel
 * Telegram Bot 雙向通訊管道
 */
export class TelegramChannel implements MessagingChannel {
  readonly channelType = 'telegram' as const;
  private readonly config: TelegramChannelConfig;
  private replyHandler: ReplyHandler | null = null;

  constructor(config: TelegramChannelConfig) {
    this.config = config;
    logger.info('Telegram channel initialized / Telegram 管道已初始化');
  }

  /**
   * Send a formatted message via Telegram Bot API
   * 透過 Telegram Bot API 發送格式化訊息
   */
  async sendMessage(userId: string, message: FormattedMessage): Promise<ChannelResult> {
    try {
      const chatId = userId || this.config.chatId;
      const prefix = severityPrefix(message.severity);
      const fullText = `${prefix} ${message.text}`;

      const payload: Record<string, unknown> = {
        chat_id: chatId,
        text: fullText,
        parse_mode: 'HTML',
      };

      const keyboard = buildInlineKeyboard(message.quickReplies);
      if (keyboard) {
        payload['reply_markup'] = keyboard;
      }

      const response = await this.httpPost('sendMessage', JSON.stringify(payload));

      logger.info(`Telegram message sent to ${chatId} / Telegram 訊息已發送`);

      return {
        success: true,
        channel: 'telegram',
        messageId: String(response.result?.message_id ?? ''),
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Telegram send failed: ${msg} / Telegram 發送失敗: ${msg}`);
      return { success: false, channel: 'telegram', error: msg };
    }
  }

  /**
   * Send a threat alert via Telegram
   * 透過 Telegram 發送威脅告警
   */
  async sendAlert(userId: string, alert: ThreatAlert): Promise<ChannelResult> {
    const message = formatAlert(alert, 'developer', 'zh-TW');
    return this.sendMessage(userId, message);
  }

  /**
   * Send a file via Telegram
   * 透過 Telegram 發送檔案
   */
  async sendFile(userId: string, file: Buffer, filename: string): Promise<ChannelResult> {
    try {
      const chatId = userId || this.config.chatId;

      // Use multipart/form-data for file upload
      const boundary = `----FormBoundary${Date.now()}`;
      const parts: Buffer[] = [];

      // chat_id field
      parts.push(
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${chatId}\r\n`
        )
      );

      // document field
      parts.push(
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`
        )
      );
      parts.push(file);
      parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));

      const body = Buffer.concat(parts);

      await this.httpPostRaw('sendDocument', body, `multipart/form-data; boundary=${boundary}`);

      logger.info(`Telegram file sent: ${filename} / Telegram 檔案已發送: ${filename}`);
      return { success: true, channel: 'telegram' };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Telegram file send failed: ${msg} / 檔案發送失敗: ${msg}`);
      return { success: false, channel: 'telegram', error: msg };
    }
  }

  /**
   * Register a reply handler
   * 註冊回覆處理器
   */
  onReply(handler: ReplyHandler): void {
    this.replyHandler = handler;
    logger.info('Telegram reply handler registered / Telegram 回覆處理器已註冊');
  }

  /**
   * Process an incoming Telegram update
   * 處理收到的 Telegram 更新
   */
  async processUpdate(update: {
    message?: { chat: { id: number }; text?: string };
    callback_query?: { from: { id: number }; data: string; id: string };
  }): Promise<string | null> {
    if (!this.replyHandler) {
      return null;
    }

    // Handle text messages
    if (update.message?.text) {
      const chatId = String(update.message.chat.id);
      return this.replyHandler(chatId, update.message.text);
    }

    // Handle callback queries (inline keyboard button presses)
    if (update.callback_query) {
      const userId = String(update.callback_query.from.id);
      const data = update.callback_query.data;

      // Answer the callback query
      await this.httpPost(
        'answerCallbackQuery',
        JSON.stringify({
          callback_query_id: update.callback_query.id,
        })
      );

      return this.replyHandler(userId, data);
    }

    return null;
  }

  // -------------------------------------------------------------------------
  // HTTP Helpers
  // -------------------------------------------------------------------------

  private async httpPost(
    method: string,
    body: string
  ): Promise<{ result?: { message_id?: number } }> {
    const url = `https://api.telegram.org/bot${this.config.botToken}/${method}`;
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
                    resolve(JSON.parse(data) as { result?: { message_id?: number } });
                  } catch {
                    resolve({});
                  }
                } else {
                  reject(new Error(`Telegram API error ${res.statusCode}: ${data}`));
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

  private async httpPostRaw(method: string, body: Buffer, contentType: string): Promise<void> {
    const url = `https://api.telegram.org/bot${this.config.botToken}/${method}`;
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
                  reject(new Error(`Telegram API error ${res.statusCode}: ${data}`));
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
