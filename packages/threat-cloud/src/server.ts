/**
 * Threat Cloud HTTP API Server
 * 威脅雲 HTTP API 伺服器
 *
 * Endpoints:
 * - POST /api/threats      Upload anonymized threat data
 * - GET  /api/rules        Fetch rules (optional ?since= filter)
 * - POST /api/rules        Publish a new community rule
 * - GET  /api/stats        Get threat statistics
 * - GET  /health           Health check
 *
 * @module @panguard-ai/threat-cloud/server
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { ThreatCloudDB } from './database.js';
import type { ServerConfig, ApiResponse, AnonymizedThreatData, ThreatCloudRule } from './types.js';

/** Rate limiter state / 速率限制狀態 */
interface RateLimitEntry {
  count: number;
  resetAt: number;
}

/**
 * Threat Cloud API Server
 * 威脅雲 API 伺服器
 */
export class ThreatCloudServer {
  private server: ReturnType<typeof createServer> | null = null;
  private readonly db: ThreatCloudDB;
  private readonly config: ServerConfig;
  private rateLimits: Map<string, RateLimitEntry> = new Map();

  constructor(config: ServerConfig) {
    this.config = config;
    this.db = new ThreatCloudDB(config.dbPath);
  }

  /** Start the server / 啟動伺服器 */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      this.server.listen(this.config.port, this.config.host, () => {
        console.log(`Threat Cloud server started on ${this.config.host}:${this.config.port}`);
        resolve();
      });
    });
  }

  /** Stop the server / 停止伺服器 */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.db.close();
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Type', 'application/json');

    const clientIP = req.socket.remoteAddress ?? 'unknown';

    // Rate limiting
    if (!this.checkRateLimit(clientIP)) {
      this.sendJson(res, 429, { ok: false, error: 'Rate limit exceeded' });
      return;
    }

    // API key verification (skip for health check)
    const url = req.url ?? '/';
    const pathname = url.split('?')[0];

    if (pathname !== '/health' && this.config.apiKeyRequired) {
      const authHeader = req.headers.authorization ?? '';
      const token = authHeader.replace('Bearer ', '');
      if (!this.config.apiKeys.includes(token)) {
        this.sendJson(res, 401, { ok: false, error: 'Invalid API key' });
        return;
      }
    }

    // CORS — restrict to known origins
    const allowedOrigins = (process.env['CORS_ALLOWED_ORIGINS'] ?? 'https://panguard.ai,https://www.panguard.ai').split(',');
    const origin = req.headers.origin ?? '';
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      switch (pathname) {
        case '/health':
          this.sendJson(res, 200, { ok: true, data: { status: 'healthy', uptime: process.uptime() } });
          break;

        case '/api/threats':
          if (req.method === 'POST') {
            await this.handlePostThreat(req, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/rules':
          if (req.method === 'GET') {
            this.handleGetRules(url, res);
          } else if (req.method === 'POST') {
            await this.handlePostRule(req, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/stats':
          if (req.method === 'GET') {
            this.handleGetStats(res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        default:
          this.sendJson(res, 404, { ok: false, error: 'Not found' });
      }
    } catch (err) {
      console.error('Request error:', err);
      this.sendJson(res, 500, { ok: false, error: 'Internal server error' });
    }
  }

  /** POST /api/threats - Upload anonymized threat data */
  private async handlePostThreat(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const data = JSON.parse(body) as AnonymizedThreatData;

    // Validate required fields
    if (!data.attackSourceIP || !data.attackType || !data.mitreTechnique || !data.sigmaRuleMatched || !data.timestamp || !data.region) {
      this.sendJson(res, 400, { ok: false, error: 'Missing required fields: attackSourceIP, attackType, mitreTechnique, sigmaRuleMatched, timestamp, region' });
      return;
    }

    // Anonymize IP further (zero last octet if not already)
    const anonIP = this.anonymizeIP(data.attackSourceIP);
    data.attackSourceIP = anonIP;

    this.db.insertThreat(data);
    this.sendJson(res, 201, { ok: true, data: { message: 'Threat data received' } });
  }

  /** GET /api/rules?since=<ISO timestamp> */
  private handleGetRules(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const since = params.get('since');

    const rules = since ? this.db.getRulesSince(since) : this.db.getAllRules();
    this.sendJson(res, 200, rules);
  }

  /** POST /api/rules - Publish a new community rule */
  private async handlePostRule(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const rule = JSON.parse(body) as ThreatCloudRule;

    if (!rule.ruleId || !rule.ruleContent || !rule.source) {
      this.sendJson(res, 400, { ok: false, error: 'Missing required fields: ruleId, ruleContent, source' });
      return;
    }

    rule.publishedAt = rule.publishedAt || new Date().toISOString();
    this.db.upsertRule(rule);
    this.sendJson(res, 201, { ok: true, data: { message: 'Rule published', ruleId: rule.ruleId } });
  }

  /** GET /api/stats */
  private handleGetStats(res: ServerResponse): void {
    const stats = this.db.getStats();
    this.sendJson(res, 200, { ok: true, data: stats });
  }

  /** Anonymize IP by zeroing last octet / 匿名化 IP */
  private anonymizeIP(ip: string): string {
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length === 4) {
        parts[3] = '0';
        return parts.join('.');
      }
    }
    // IPv6: truncate last segment
    if (ip.includes(':')) {
      const parts = ip.split(':');
      parts[parts.length - 1] = '0';
      return parts.join(':');
    }
    return ip;
  }

  /** Rate limit check / 速率限制檢查 */
  private checkRateLimit(ip: string): boolean {
    const now = Date.now();
    const entry = this.rateLimits.get(ip);
    if (!entry || now > entry.resetAt) {
      this.rateLimits.set(ip, { count: 1, resetAt: now + 60_000 });
      return true;
    }
    entry.count++;
    return entry.count <= this.config.rateLimitPerMinute;
  }

  /** Read request body with size limit / 讀取請求主體（含大小限制） */
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

  /** Send JSON response / 發送 JSON 回應 */
  private sendJson(res: ServerResponse, status: number, data: unknown): void {
    res.writeHead(status);
    res.end(JSON.stringify(data));
  }
}
