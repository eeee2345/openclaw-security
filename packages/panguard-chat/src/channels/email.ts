/**
 * Email Channel
 * Email 管道
 *
 * Email-based messaging channel using raw SMTP (zero external deps).
 * Supports sending alerts, summaries, and file attachments.
 * 使用原生 SMTP 的 Email 通訊管道（零外部依賴）。
 * 支援發送告警、摘要和檔案附件。
 *
 * Recommended for Pro/Business plans.
 * 推薦 Pro/Business 方案使用。
 *
 * @module @panguard-ai/panguard-chat/channels/email
 */

import { createLogger } from '@panguard-ai/core';
import type {
  MessagingChannel,
  ChannelResult,
  FormattedMessage,
  ThreatAlert,
  ReplyHandler,
  EmailChannelConfig,
  AlertSeverity,
} from '../types.js';
import { formatAlert } from '../agent/formatter.js';

const logger = createLogger('panguard-chat:channel:email');

// ---------------------------------------------------------------------------
// Email Helpers
// Email 輔助函式
// ---------------------------------------------------------------------------

/** Map severity to email subject prefix */
function subjectPrefix(severity?: AlertSeverity): string {
  switch (severity) {
    case 'critical':
      return '[CRITICAL]';
    case 'warning':
      return '[WARNING]';
    case 'info':
    default:
      return '[INFO]';
  }
}

/** Convert plain text to simple HTML */
function textToHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\n/g, '<br>\n');
}

/** Build MIME message with optional attachments */
function buildMimeMessage(options: {
  from: string;
  to: readonly string[];
  subject: string;
  text: string;
  html: string;
  attachments?: readonly { filename: string; data: Buffer }[];
}): string {
  const boundary = `----MIMEBoundary${Date.now()}`;
  const hasAttachments = options.attachments && options.attachments.length > 0;

  const headers = [
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subject}`,
    'MIME-Version: 1.0',
  ];

  if (hasAttachments) {
    headers.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
  } else {
    headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
  }

  const parts: string[] = [headers.join('\r\n'), '', `--${boundary}`];

  // Text part
  parts.push(
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(options.text).toString('base64'),
    `--${boundary}`
  );

  // HTML part
  parts.push(
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(options.html).toString('base64')
  );

  // Attachments
  if (hasAttachments && options.attachments) {
    for (const att of options.attachments) {
      parts.push(
        `--${boundary}`,
        `Content-Type: application/octet-stream; name="${att.filename}"`,
        `Content-Disposition: attachment; filename="${att.filename}"`,
        'Content-Transfer-Encoding: base64',
        '',
        att.data.toString('base64')
      );
    }
  }

  parts.push(`--${boundary}--`);
  return parts.join('\r\n');
}

// ---------------------------------------------------------------------------
// Email Channel Implementation
// Email 管道實作
// ---------------------------------------------------------------------------

/**
 * Email messaging channel (SMTP-based, zero external deps)
 * Email 通訊管道（SMTP 基礎，零外部依賴）
 */
export class EmailChannel implements MessagingChannel {
  readonly channelType = 'email' as const;
  private readonly config: EmailChannelConfig;
  private replyHandler: ReplyHandler | null = null;

  constructor(config: EmailChannelConfig) {
    this.config = config;
    logger.info(
      `Email channel initialized: ${config.host}:${config.port} / ` +
        `Email 管道已初始化: ${config.host}:${config.port}`
    );
  }

  /**
   * Send a formatted message via email
   * 透過 Email 發送格式化訊息
   */
  async sendMessage(_userId: string, message: FormattedMessage): Promise<ChannelResult> {
    try {
      const prefix = subjectPrefix(message.severity);
      const subject = `${prefix} Panguard AI Security Notification`;

      const htmlBody = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px;">
<div style="max-width: 600px; margin: 0 auto;">
  <div style="background: ${message.severity === 'critical' ? '#FF0000' : message.severity === 'warning' ? '#FFA500' : '#2196F3'}; color: white; padding: 12px 20px; border-radius: 4px 4px 0 0;">
    <strong>Panguard AI ${prefix}</strong>
  </div>
  <div style="border: 1px solid #e0e0e0; border-top: none; padding: 20px; border-radius: 0 0 4px 4px;">
    <pre style="white-space: pre-wrap; font-family: inherit; margin: 0;">${textToHtml(message.text)}</pre>
  </div>
  <div style="color: #888; font-size: 12px; margin-top: 16px; text-align: center;">
    Powered by Panguard AI Security
  </div>
</div>
</body>
</html>`;

      const mime = buildMimeMessage({
        from: this.config.from,
        to: this.config.to,
        subject,
        text: message.text,
        html: htmlBody,
      });

      await this.sendSmtp(mime);

      logger.info(`Email sent to ${this.config.to.join(', ')} / Email 已發送`);

      return { success: true, channel: 'email' };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Email send failed: ${msg} / Email 發送失敗: ${msg}`);
      return { success: false, channel: 'email', error: msg };
    }
  }

  /**
   * Send a threat alert via email
   * 透過 Email 發送威脅告警
   */
  async sendAlert(userId: string, alert: ThreatAlert): Promise<ChannelResult> {
    const message = formatAlert(alert, 'developer', 'zh-TW');
    return this.sendMessage(userId, message);
  }

  /**
   * Send a file via email (as attachment)
   * 透過 Email 發送檔案（作為附件）
   */
  async sendFile(_userId: string, file: Buffer, filename: string): Promise<ChannelResult> {
    try {
      const mime = buildMimeMessage({
        from: this.config.from,
        to: this.config.to,
        subject: '[Panguard AI] Security Report',
        text: `Please find the attached security report: ${filename}`,
        html: `<p>Please find the attached security report: <strong>${filename}</strong></p>`,
        attachments: [{ filename, data: file }],
      });

      await this.sendSmtp(mime);

      logger.info(`Email file sent: ${filename} / Email 檔案已發送: ${filename}`);
      return { success: true, channel: 'email' };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Email file send failed: ${msg} / 檔案發送失敗: ${msg}`);
      return { success: false, channel: 'email', error: msg };
    }
  }

  /**
   * Register a reply handler (email is primarily one-way)
   * 註冊回覆處理器（Email 主要是單向的）
   */
  onReply(handler: ReplyHandler): void {
    this.replyHandler = handler;
    logger.info(
      'Email reply handler registered (polling-based) / Email 回覆處理器已註冊（輪詢式）'
    );
  }

  // -------------------------------------------------------------------------
  // SMTP Implementation (zero deps - uses node:net / node:tls)
  // SMTP 實作（零依賴 - 使用 node:net / node:tls）
  // -------------------------------------------------------------------------

  private async sendSmtp(mime: string): Promise<void> {
    const { config } = this;

    return new Promise((resolve, reject) => {
      const smtpConversation = (socket: import('node:net').Socket) => {
        // SMTP conversation
        const commands = [
          `EHLO localhost`,
          `AUTH LOGIN`,
          Buffer.from(config.auth.user).toString('base64'),
          Buffer.from(config.auth.pass).toString('base64'),
          `MAIL FROM:<${config.from}>`,
          ...config.to.map((to) => `RCPT TO:<${to}>`),
          'DATA',
        ];

        let commandIndex = -1; // Start at -1 for the greeting
        let dataPhase = false;

        socket.on('data', (data: Buffer) => {
          const response = data.toString();
          const code = parseInt(response.slice(0, 3), 10);

          if (dataPhase) {
            if (code === 354 || response.includes('354')) {
              socket.write(`${mime}\r\n.\r\n`);
              dataPhase = false;
            }
            return;
          }

          if (code >= 400) {
            socket.destroy();
            reject(new Error(`SMTP error: ${response.trim()}`));
            return;
          }

          commandIndex++;
          if (commandIndex < commands.length) {
            const cmd = commands[commandIndex]!;
            if (cmd === 'DATA') {
              dataPhase = true;
            }
            socket.write(`${cmd}\r\n`);
          } else {
            socket.write('QUIT\r\n');
            socket.end();
            resolve();
          }
        });

        socket.on('error', reject);
        socket.setTimeout(30000, () => {
          socket.destroy();
          reject(new Error('SMTP connection timeout'));
        });
      };

      if (config.secure) {
        import('node:tls')
          .then((tls) => {
            const socket = tls.connect({ port: config.port, host: config.host }, () => {
              smtpConversation(socket);
            });
            socket.on('error', reject);
          })
          .catch(reject);
      } else {
        import('node:net')
          .then((net) => {
            const socket = net.connect(config.port, config.host, () => {
              smtpConversation(socket);
            });
            socket.on('error', reject);
          })
          .catch(reject);
      }
    });
  }
}
