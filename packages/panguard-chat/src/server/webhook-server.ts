/**
 * Webhook Server for receiving messages from LINE/Telegram/Slack
 * Webhook 伺服器 - 接收來自 LINE/Telegram/Slack 的訊息
 *
 * Provides a single HTTP endpoint that routes incoming webhooks
 * to the appropriate channel handler.
 *
 * @module @panguard-ai/panguard-chat/server/webhook-server
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHmac } from 'node:crypto';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-chat:webhook-server');

/** Webhook handler function / Webhook 處理函數 */
export type WebhookHandler = (body: unknown, headers: Record<string, string>) => Promise<void>;

/** Webhook server configuration / Webhook 伺服器配置 */
export interface WebhookServerConfig {
  /** Listen port / 監聽埠 */
  port: number;
  /** Listen host (default: 127.0.0.1) / 監聽主機 */
  host?: string;
  /** Channel webhook handlers / 頻道 webhook 處理器 */
  handlers: Map<string, WebhookHandler>;
  /** Slack signing secret for verification / Slack 簽章密鑰 */
  slackSigningSecret?: string;
  /** LINE channel secret for verification / LINE 頻道密鑰 */
  lineChannelSecret?: string;
  /** Telegram bot secret for verification / Telegram 機器人密鑰 */
  telegramSecret?: string;
}

/**
 * Webhook server that receives and routes messages from messaging platforms
 * 接收並路由來自通訊平台訊息的 Webhook 伺服器
 */
export class WebhookServer {
  private server: ReturnType<typeof createServer> | null = null;
  private readonly config: WebhookServerConfig;

  constructor(config: WebhookServerConfig) {
    this.config = config;
  }

  /**
   * Start the webhook server / 啟動 webhook 伺服器
   */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      const host = this.config.host ?? '127.0.0.1';
      this.server.listen(this.config.port, host, () => {
        logger.info(`Webhook server started on ${host}:${this.config.port}`);
        resolve();
      });
    });
  }

  /**
   * Stop the webhook server / 停止 webhook 伺服器
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('Webhook server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }

    const url = req.url ?? '/';

    // Route: /webhook/line, /webhook/telegram, /webhook/slack
    const channelMatch = url.match(/^\/webhook\/(\w+)/);
    if (!channelMatch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    const channel = channelMatch[1] ?? '';

    try {
      const body = await this.readBody(req);
      const headers = this.flattenHeaders(req);

      // Verify webhook signature based on channel
      if (channel === 'slack' && this.config.slackSigningSecret) {
        if (!this.verifySlackSignature(body, headers, this.config.slackSigningSecret)) {
          logger.warn('Invalid Slack webhook signature');
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid signature' }));
          return;
        }
      }

      if (channel === 'line' && this.config.lineChannelSecret) {
        if (!this.verifyLineSignature(body, headers, this.config.lineChannelSecret)) {
          logger.warn('Invalid LINE webhook signature');
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid signature' }));
          return;
        }
      }

      const handler = this.config.handlers.get(channel);
      if (!handler) {
        logger.warn(`No handler registered for channel: ${channel}`);
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Channel '${channel}' not configured` }));
        return;
      }

      const parsed = JSON.parse(body);
      await handler(parsed, headers);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    } catch (err) {
      logger.error('Webhook processing failed', {
        channel,
        error: err instanceof Error ? err.message : String(err),
      });
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const MAX_BODY = 1_048_576; // 1MB

      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY) {
          req.destroy();
          reject(new Error('Request body too large'));
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      req.on('error', reject);
    });
  }

  private flattenHeaders(req: IncomingMessage): Record<string, string> {
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === 'string') {
        headers[key] = value;
      } else if (Array.isArray(value)) {
        headers[key] = value[0] ?? '';
      }
    }
    return headers;
  }

  private verifySlackSignature(
    body: string,
    headers: Record<string, string>,
    secret: string
  ): boolean {
    const timestamp = headers['x-slack-request-timestamp'];
    const signature = headers['x-slack-signature'];
    if (!timestamp || !signature) return false;

    // Reject requests older than 5 minutes (replay protection)
    const age = Math.abs(Date.now() / 1000 - Number(timestamp));
    if (age > 300) return false;

    const sigBase = `v0:${timestamp}:${body}`;
    const expected = 'v0=' + createHmac('sha256', secret).update(sigBase).digest('hex');
    return signature === expected;
  }

  private verifyLineSignature(
    body: string,
    headers: Record<string, string>,
    secret: string
  ): boolean {
    const signature = headers['x-line-signature'];
    if (!signature) return false;

    const expected = createHmac('sha256', secret).update(body).digest('base64');
    return signature === expected;
  }
}
