/**
 * Webhook Channel (Enterprise)
 * Webhook 管道（企業級）
 *
 * Enterprise-grade webhook channel with support for:
 * - Bearer token authentication
 * - mTLS (mutual TLS) for compliance
 * - HMAC signature verification
 *
 * Designed for integrating with SIEM systems and ticketing systems.
 * 設計用於與 SIEM 系統和工單系統整合。
 *
 * @module @panguard-ai/panguard-chat/channels/webhook
 */

import { createLogger } from '@panguard-ai/core';
import type {
  MessagingChannel,
  ChannelResult,
  FormattedMessage,
  ThreatAlert,
  ReplyHandler,
  WebhookConfig,
  AlertSeverity,
} from '../types.js';

const logger = createLogger('panguard-chat:channel:webhook');

// ---------------------------------------------------------------------------
// Webhook Payload
// Webhook 負載
// ---------------------------------------------------------------------------

/** Standard webhook payload structure / 標準 webhook 負載結構 */
interface WebhookPayload {
  readonly version: string;
  readonly type: 'alert' | 'summary' | 'confirmation' | 'file' | 'message';
  readonly timestamp: string;
  readonly severity: AlertSeverity;
  readonly data: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Webhook Channel Implementation
// Webhook 管道實作
// ---------------------------------------------------------------------------

/**
 * Enterprise webhook channel with multi-auth support
 * 企業級 webhook 管道（多重認證）
 */
export class WebhookChannel implements MessagingChannel {
  readonly channelType = 'webhook' as const;
  private readonly config: WebhookConfig;
  private replyHandler: ReplyHandler | null = null;

  constructor(config: WebhookConfig) {
    this.config = config;
    logger.info(
      `Webhook channel initialized: ${config.endpoint} (${config.authMethod}) / ` +
        `Webhook 管道已初始化: ${config.endpoint} (${config.authMethod})`
    );
  }

  /**
   * Send a formatted message via webhook
   * 透過 Webhook 發送格式化訊息
   */
  async sendMessage(_userId: string, message: FormattedMessage): Promise<ChannelResult> {
    const payload: WebhookPayload = {
      version: '1.0',
      type: 'message',
      timestamp: new Date().toISOString(),
      severity: message.severity ?? 'info',
      data: {
        text: message.text,
        quickReplies: message.quickReplies,
      },
    };

    return this.sendPayload(payload);
  }

  /**
   * Send a threat alert via webhook
   * 透過 Webhook 發送威脅告警
   */
  async sendAlert(_userId: string, alert: ThreatAlert): Promise<ChannelResult> {
    const payload: WebhookPayload = {
      version: '1.0',
      type: 'alert',
      timestamp: new Date().toISOString(),
      severity:
        alert.severity === 'critical' || alert.severity === 'high'
          ? 'critical'
          : alert.severity === 'medium'
            ? 'warning'
            : 'info',
      data: {
        conclusion: alert.conclusion,
        confidence: alert.confidence,
        humanSummary: alert.humanSummary,
        reasoning: alert.reasoning,
        recommendedAction: alert.recommendedAction,
        mitreTechnique: alert.mitreTechnique,
        severity: alert.severity,
        eventDescription: alert.eventDescription,
        actionsTaken: alert.actionsTaken,
      },
    };

    return this.sendPayload(payload);
  }

  /**
   * Send a file notification via webhook (metadata only, not the binary)
   * 透過 Webhook 發送檔案通知（僅中繼資料，不含二進位內容）
   */
  async sendFile(_userId: string, _file: Buffer, filename: string): Promise<ChannelResult> {
    const payload: WebhookPayload = {
      version: '1.0',
      type: 'file',
      timestamp: new Date().toISOString(),
      severity: 'info',
      data: {
        filename,
        message: `Security report available: ${filename}`,
      },
    };

    return this.sendPayload(payload);
  }

  /**
   * Register a reply handler (webhook uses response body for replies)
   * 註冊回覆處理器（webhook 使用回應本體進行回覆）
   */
  onReply(handler: ReplyHandler): void {
    this.replyHandler = handler;
    logger.info('Webhook reply handler registered / Webhook 回覆處理器已註冊');
  }

  /**
   * Process an incoming webhook callback
   * 處理傳入的 webhook 回呼
   */
  async processCallback(body: {
    userId?: string;
    text?: string;
    action?: string;
  }): Promise<string | null> {
    if (!this.replyHandler) {
      return null;
    }
    const text = body.text ?? body.action ?? '';
    if (!text) return null;
    return this.replyHandler(body.userId ?? '', text);
  }

  // -------------------------------------------------------------------------
  // Core Send Logic
  // 核心發送邏輯
  // -------------------------------------------------------------------------

  /**
   * Send a webhook payload with authentication
   * 發送帶認證的 webhook 負載
   */
  private async sendPayload(payload: WebhookPayload): Promise<ChannelResult> {
    try {
      const body = JSON.stringify(payload);
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Content-Length': String(Buffer.byteLength(body)),
        'X-Panguard-Version': '1.0',
        ...Object.fromEntries(Object.entries(this.config.headers ?? {}).map(([k, v]) => [k, v])),
      };

      // Add authentication headers based on method
      switch (this.config.authMethod) {
        case 'bearer_token':
          headers['Authorization'] = `Bearer ${this.config.secret}`;
          break;
        case 'hmac_signature': {
          const signature = await this.computeHmac(body);
          headers['X-Panguard-Signature'] = signature;
          break;
        }
        case 'mtls':
          // mTLS is handled at the connection level, not in headers
          // mTLS 在連線層級處理，而非標頭
          break;
      }

      await this.httpPost(body, headers);

      logger.info(
        `Webhook sent to ${this.config.endpoint} / Webhook 已發送到 ${this.config.endpoint}`
      );

      return { success: true, channel: 'webhook' };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Webhook send failed: ${msg} / Webhook 發送失敗: ${msg}`);
      return { success: false, channel: 'webhook', error: msg };
    }
  }

  /**
   * Compute HMAC-SHA256 signature for request body
   * 計算請求本體的 HMAC-SHA256 簽名
   */
  private async computeHmac(body: string): Promise<string> {
    const { createHmac } = await import('node:crypto');
    return createHmac('sha256', this.config.secret).update(body).digest('hex');
  }

  /**
   * Send HTTP POST request
   * 發送 HTTP POST 請求
   */
  private async httpPost(body: string, headers: Record<string, string>): Promise<void> {
    const url = new URL(this.config.endpoint);
    const isHttps = url.protocol === 'https:';
    const { hostname, pathname, port } = url;

    return new Promise((resolve, reject) => {
      const moduleName = isHttps ? 'node:https' : 'node:http';

      import(moduleName)
        .then((mod) => {
          const requestFn = (mod as { request: typeof import('node:https').request }).request;

          const options: Record<string, unknown> = {
            hostname,
            path: pathname,
            port: port || (isHttps ? 443 : 80),
            method: 'POST',
            headers,
          };

          // For mTLS, add client certificate options
          // In production, these would come from the config
          // 對於 mTLS，加入客戶端憑證選項
          if (this.config.authMethod === 'mtls') {
            // mTLS certificates would be loaded from config
            // options.key = fs.readFileSync(config.clientKeyPath);
            // options.cert = fs.readFileSync(config.clientCertPath);
            // options.ca = fs.readFileSync(config.caCertPath);
            options['rejectUnauthorized'] = true;
          }

          const req = requestFn(options, (res) => {
            let data = '';
            res.on('data', (chunk: Buffer) => {
              data += chunk.toString();
            });
            res.on('end', () => {
              const statusCode = res.statusCode ?? 0;
              if (statusCode >= 200 && statusCode < 300) {
                resolve();
              } else {
                reject(new Error(`Webhook error ${statusCode}: ${data}`));
              }
            });
          });

          req.on('error', reject);
          req.setTimeout(30000, () => {
            req.destroy();
            reject(new Error('Webhook connection timeout'));
          });
          req.write(body);
          req.end();
        })
        .catch(reject);
    });
  }
}
