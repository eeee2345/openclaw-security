/**
 * Threat Cloud HTTP API Server
 * 威脅雲 HTTP API 伺服器
 *
 * Endpoints:
 * - POST /api/threats                Upload anonymized threat data (single or batch)
 * - GET  /api/rules                  Fetch rules (optional ?since= filter)
 * - POST /api/rules                  Publish a new community rule
 * - GET  /api/stats                  Get threat statistics
 * - POST /api/atr-proposals          Submit or confirm ATR rule proposal
 * - POST /api/atr-feedback           Submit feedback on ATR rule
 * - POST /api/skill-threats          Submit skill threat from audit
 * - GET  /api/atr-rules              Fetch confirmed ATR rules (?since= filter)
 * - GET  /api/yara-rules             Fetch YARA rules (?since= filter)
 * - GET  /api/feeds/ip-blocklist     IP blocklist feed (text/plain, ?minReputation=)
 * - GET  /api/feeds/domain-blocklist Domain blocklist feed (text/plain, ?minReputation=)
 * - GET  /api/skill-blacklist        Community skill blacklist (aggregated threats)
 * - GET  /health                     Health check
 *
 * @module @panguard-ai/threat-cloud/server
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, basename, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ThreatCloudDB } from './database.js';
import { LLMReviewer } from './llm-reviewer.js';
import { getAdminHTML } from './admin-dashboard.js';
import type {
  ServerConfig,
  AnonymizedThreatData,
  ThreatCloudRule,
  ATRProposal,
  SkillThreatSubmission,
} from './types.js';

/** Simple structured logger for threat-cloud (no core dependency) */
const log = {
  info: (msg: string) => {
    process.stdout.write(`[threat-cloud] ${msg}\n`);
  },
  error: (msg: string, err?: unknown) => {
    process.stderr.write(
      `[threat-cloud] ERROR ${msg}${err ? `: ${err instanceof Error ? err.message : String(err)}` : ''}\n`
    );
  },
};

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
  private readonly llmReviewer: LLMReviewer | null;
  private promotionTimer: ReturnType<typeof setInterval> | null = null;
  private rateLimits: Map<string, RateLimitEntry> = new Map();
  private rateLimitCleanupTimer: ReturnType<typeof setInterval> | null = null;
  private statsCache: { data: unknown; expiresAt: number } | null = null;

  /** Promotion interval: 15 minutes / 推廣間隔：15 分鐘 */
  private static readonly PROMOTION_INTERVAL_MS = 15 * 60 * 1000;
  /** Stats cache TTL: 60 seconds */
  private static readonly STATS_CACHE_TTL_MS = 60_000;

  constructor(config: ServerConfig) {
    this.config = config;
    this.db = new ThreatCloudDB(config.dbPath);
    this.llmReviewer = config.anthropicApiKey
      ? new LLMReviewer(config.anthropicApiKey, this.db)
      : null;
  }

  /** Start the server / 啟動伺服器 */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      this.server.listen(this.config.port, this.config.host, () => {
        log.info(`Server started on ${this.config.host}:${this.config.port}`);
        if (this.llmReviewer) {
          log.info('LLM reviewer enabled for ATR proposal review');
        }
        // Auto-seed rules from bundled config/ if DB is empty (first startup)
        const stats = this.db.getStats();
        if (stats.totalRules === 0) {
          log.info('First startup detected — seeding bundled rules...');
          try {
            const seeded = this.seedFromBundled();
            log.info(`Seeded ${seeded} rules into database`);
          } catch (err) {
            log.error('Rule seeding failed', err);
          }
        } else {
          log.info(`Database: ${stats.totalRules} rules, ${stats.totalThreats} threats`);
        }

        // Backfill classification for existing unclassified rules (one-time on startup)
        try {
          const backfilled = this.db.backfillClassification();
          if (backfilled > 0) {
            log.info(`Backfilled classification for ${backfilled} rules`);
          }
        } catch (err) {
          log.error('Classification backfill failed', err);
        }

        // Start promotion cron (every 15 minutes)
        this.promotionTimer = setInterval(() => {
          try {
            const promoted = this.db.promoteConfirmedProposals();
            if (promoted > 0) {
              log.info(`Promotion cycle: ${promoted} proposal(s) promoted to rules`);
            }
          } catch (err) {
            log.error('Promotion cycle failed', err);
          }
        }, ThreatCloudServer.PROMOTION_INTERVAL_MS);

        // Rate limiter cleanup (every 60s, purge expired entries)
        this.rateLimitCleanupTimer = setInterval(() => {
          const now = Date.now();
          for (const [ip, entry] of this.rateLimits) {
            if (now > entry.resetAt) this.rateLimits.delete(ip);
          }
        }, 60_000);

        resolve();
      });
    });
  }

  /** Stop the server / 停止伺服器 */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.promotionTimer) {
        clearInterval(this.promotionTimer);
        this.promotionTimer = null;
      }
      if (this.rateLimitCleanupTimer) {
        clearInterval(this.rateLimitCleanupTimer);
        this.rateLimitCleanupTimer = null;
      }
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
    const allowedOrigins = (
      process.env['CORS_ALLOWED_ORIGINS'] ??
      'https://panguard.ai,https://www.panguard.ai,https://tc.panguard.ai,https://get.panguard.ai,https://docs.panguard.ai'
    ).split(',');
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
          this.sendJson(res, 200, {
            ok: true,
            data: { status: 'healthy', uptime: process.uptime() },
          });
          break;

        case '/admin':
          this.serveAdminDashboard(req, res);
          break;

        case '/api/threats':
          if (req.method === 'GET') {
            if (!this.checkAdminAuth(req)) {
              this.sendJson(res, 403, { ok: false, error: 'Admin API key required' });
              break;
            }
            this.handleGetThreats(url, res);
          } else if (req.method === 'POST') {
            await this.handlePostThreat(req, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/rules':
          if (req.method === 'GET') {
            this.handleGetRules(url, res);
          } else if (req.method === 'POST') {
            if (!this.checkAdminAuth(req)) {
              this.sendJson(res, 403, {
                ok: false,
                error: 'Admin API key required for rule publishing',
              });
              break;
            }
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

        case '/api/atr-proposals':
          if (req.method === 'GET') {
            if (!this.checkAdminAuth(req)) {
              this.sendJson(res, 403, { ok: false, error: 'Admin API key required' });
              break;
            }
            this.handleGetATRProposals(url, res);
          } else if (req.method === 'POST') {
            await this.handlePostATRProposal(req, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/atr-feedback':
          if (req.method === 'POST') {
            await this.handlePostATRFeedback(req, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/skill-threats':
          if (req.method === 'GET') {
            if (!this.checkAdminAuth(req)) {
              this.sendJson(res, 403, { ok: false, error: 'Admin API key required' });
              break;
            }
            this.handleGetSkillThreats(url, res);
          } else if (req.method === 'POST') {
            await this.handlePostSkillThreat(req, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/atr-rules':
          if (req.method === 'GET') {
            this.handleGetATRRules(url, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/yara-rules':
          if (req.method === 'GET') {
            this.handleGetYaraRules(url, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/feeds/ip-blocklist':
          if (req.method === 'GET') {
            this.handleGetIPBlocklist(url, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/feeds/domain-blocklist':
          if (req.method === 'GET') {
            this.handleGetDomainBlocklist(url, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/skill-whitelist':
          if (req.method === 'GET') {
            this.handleGetSkillWhitelist(res);
          } else if (req.method === 'POST') {
            await this.handlePostSkillWhitelist(req, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        case '/api/skill-blacklist':
          if (req.method === 'GET') {
            this.handleGetSkillBlacklist(url, res);
          } else {
            this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
          }
          break;

        default:
          this.sendJson(res, 404, { ok: false, error: 'Not found' });
      }
    } catch (err) {
      log.error('Request failed', err);
      this.sendJson(res, 500, { ok: false, error: 'Internal server error' });
    }
  }

  /** POST /api/threats - Upload anonymized threat data (single or batch) */
  private async handlePostThreat(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const parsed = JSON.parse(body) as AnonymizedThreatData | { events: AnonymizedThreatData[] };

    // Support both single object and batch { events: [...] } format
    const events: AnonymizedThreatData[] =
      'events' in parsed && Array.isArray(parsed.events)
        ? parsed.events
        : [parsed as AnonymizedThreatData];

    for (const data of events) {
      // Validate required fields
      if (
        !data.attackSourceIP ||
        !data.attackType ||
        !data.mitreTechnique ||
        !data.sigmaRuleMatched ||
        !data.timestamp ||
        !data.region
      ) {
        this.sendJson(res, 400, {
          ok: false,
          error:
            'Missing required fields: attackSourceIP, attackType, mitreTechnique, sigmaRuleMatched, timestamp, region',
        });
        return;
      }

      // Anonymize IP further (zero last octet if not already)
      data.attackSourceIP = this.anonymizeIP(data.attackSourceIP);
      this.db.insertThreat(data);
    }

    this.sendJson(res, 201, {
      ok: true,
      data: { message: 'Threat data received', count: events.length },
    });
  }

  /** GET /api/rules?since=<ISO>&category=<cat>&severity=<sev>&source=<src> */
  private handleGetRules(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const since = params.get('since');
    const filters = {
      category: params.get('category') ?? undefined,
      severity: params.get('severity') ?? undefined,
      source: params.get('source') ?? undefined,
    };

    // Cache for 1 hour — rules rarely change, let CDN absorb traffic
    res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=3600');

    const rules = since
      ? this.db.getRulesSince(since, filters)
      : this.db.getAllRules(5000, filters);
    this.sendJson(res, 200, rules);
  }

  /** POST /api/rules - Publish rules (single or batch) */
  private async handlePostRule(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const parsed = JSON.parse(body) as ThreatCloudRule | { rules: ThreatCloudRule[] };

    // Support both single object and batch { rules: [...] } format
    const rules: ThreatCloudRule[] =
      'rules' in parsed && Array.isArray(parsed.rules) ? parsed.rules : [parsed as ThreatCloudRule];

    const now = new Date().toISOString();
    let count = 0;
    for (const rule of rules) {
      if (!rule.ruleId || !rule.ruleContent || !rule.source) continue;
      rule.publishedAt = rule.publishedAt || now;
      this.db.upsertRule(rule);
      count++;
    }

    this.sendJson(res, 201, { ok: true, data: { message: `${count} rule(s) published`, count } });
  }

  /** GET /api/stats (cached 60s) */
  private handleGetStats(res: ServerResponse): void {
    res.setHeader('Cache-Control', 'public, max-age=60, s-maxage=60');
    const now = Date.now();
    if (this.statsCache && now < this.statsCache.expiresAt) {
      this.sendJson(res, 200, { ok: true, data: this.statsCache.data });
      return;
    }
    const stats = this.db.getStats();
    this.statsCache = { data: stats, expiresAt: now + ThreatCloudServer.STATS_CACHE_TTL_MS };
    this.sendJson(res, 200, { ok: true, data: stats });
  }

  /** GET /api/threats?page=1&limit=50 (admin-only, paginated) */
  private handleGetThreats(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const page = Math.max(1, parseInt(params.get('page') ?? '1', 10));
    const limit = Math.min(200, Math.max(1, parseInt(params.get('limit') ?? '50', 10)));
    const offset = (page - 1) * limit;
    const threats = this.db.getThreats(limit, offset);
    const total = this.db.getThreatCount();
    this.sendJson(res, 200, {
      ok: true,
      data: threats,
      meta: { total, page, limit, pages: Math.ceil(total / limit) },
    });
  }

  /** GET /api/atr-proposals?status=pending (admin-only) */
  private handleGetATRProposals(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const status = params.get('status') ?? undefined;
    const proposals = this.db.getATRProposals(status);
    this.sendJson(res, 200, { ok: true, data: proposals });
  }

  /** GET /api/skill-threats?limit=50 (admin-only) */
  private handleGetSkillThreats(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const limit = Math.min(500, Math.max(1, parseInt(params.get('limit') ?? '50', 10)));
    const threats = this.db.getSkillThreats(limit);
    this.sendJson(res, 200, { ok: true, data: threats });
  }

  /** POST /api/atr-proposals - Submit or confirm an ATR rule proposal */
  private async handlePostATRProposal(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const data = JSON.parse(body) as ATRProposal;
    const clientId = (req.headers['x-panguard-client-id'] as string) ?? undefined;

    if (!data.patternHash || !data.ruleContent) {
      this.sendJson(res, 400, {
        ok: false,
        error: 'Missing required fields: patternHash, ruleContent',
      });
      return;
    }

    // Check if a proposal with the same patternHash already exists
    const proposals = this.db.getATRProposals() as Array<Record<string, unknown>>;
    const existing = proposals.find((p) => p['pattern_hash'] === data.patternHash);

    if (existing) {
      this.db.confirmATRProposal(data.patternHash);
      this.sendJson(res, 200, {
        ok: true,
        data: { message: 'Proposal confirmed', patternHash: data.patternHash },
      });
    } else {
      const proposal: ATRProposal = {
        ...data,
        clientId: clientId ?? data.clientId,
      };
      this.db.insertATRProposal(proposal);

      // Fire-and-forget LLM review on first submission only
      if (this.llmReviewer?.isAvailable()) {
        void this.llmReviewer.reviewProposal(data.patternHash, data.ruleContent).catch((err) => {
          log.error(`LLM review failed for ${data.patternHash}`, err);
        });
      }

      this.sendJson(res, 201, {
        ok: true,
        data: { message: 'Proposal submitted', patternHash: data.patternHash },
      });
    }
  }

  /** POST /api/atr-feedback - Submit feedback on an ATR rule */
  private async handlePostATRFeedback(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const data = JSON.parse(body) as { ruleId: string; isTruePositive: boolean };
    const clientId = (req.headers['x-panguard-client-id'] as string) ?? undefined;

    if (!data.ruleId || typeof data.isTruePositive !== 'boolean') {
      this.sendJson(res, 400, {
        ok: false,
        error: 'Missing required fields: ruleId (string), isTruePositive (boolean)',
      });
      return;
    }

    this.db.insertATRFeedback(data.ruleId, data.isTruePositive, clientId);
    this.sendJson(res, 201, { ok: true, data: { message: 'Feedback received' } });
  }

  /** POST /api/skill-threats - Submit skill threat from audit */
  private async handlePostSkillThreat(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const data = JSON.parse(body) as SkillThreatSubmission;
    const clientId = (req.headers['x-panguard-client-id'] as string) ?? undefined;

    if (!data.skillHash || !data.skillName) {
      this.sendJson(res, 400, {
        ok: false,
        error: 'Missing required fields: skillHash, skillName',
      });
      return;
    }

    if (typeof data.riskScore !== 'number' || data.riskScore < 0 || data.riskScore > 100) {
      this.sendJson(res, 400, { ok: false, error: 'riskScore must be a number between 0 and 100' });
      return;
    }

    if (!data.riskLevel || typeof data.riskLevel !== 'string') {
      this.sendJson(res, 400, { ok: false, error: 'riskLevel is required and must be a string' });
      return;
    }

    const submission: SkillThreatSubmission = {
      ...data,
      clientId: clientId ?? data.clientId,
    };
    this.db.insertSkillThreat(submission);
    this.sendJson(res, 201, { ok: true, data: { message: 'Skill threat received' } });
  }

  /** GET /api/atr-rules?since=<ISO> - Fetch confirmed/promoted ATR rules */
  private handleGetATRRules(url: string, res: ServerResponse): void {
    res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=3600');
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const since = params.get('since') ?? undefined;
    const rules = this.db.getConfirmedATRRules(since);
    this.sendJson(res, 200, rules);
  }

  /** GET /api/yara-rules?since=<ISO> - Fetch YARA rules */
  private handleGetYaraRules(url: string, res: ServerResponse): void {
    res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=3600');
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const since = params.get('since') ?? undefined;
    const rules = this.db.getRulesBySource('yara', since);
    this.sendJson(res, 200, rules);
  }

  /** GET /api/feeds/ip-blocklist?minReputation=70 - IP blocklist feed (plain text) */
  private handleGetIPBlocklist(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const minReputation = Number(params.get('minReputation') ?? '70');

    const ips = this.db.getIPBlocklist(minReputation);
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'public, max-age=1800, s-maxage=1800');
    res.writeHead(200);
    res.end(ips.join('\n'));
  }

  /** GET /api/feeds/domain-blocklist?minReputation=70 - Domain blocklist feed (plain text) */
  private handleGetDomainBlocklist(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const minReputation = Number(params.get('minReputation') ?? '70');

    const domains = this.db.getDomainBlocklist(minReputation);
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'public, max-age=1800, s-maxage=1800');
    res.writeHead(200);
    res.end(domains.join('\n'));
  }

  /** POST /api/skill-whitelist - Report a safe skill (audit passed) */
  private async handlePostSkillWhitelist(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const data = JSON.parse(body) as
      | { skillName: string; fingerprintHash?: string }
      | { skills: Array<{ skillName: string; fingerprintHash?: string }> };

    const skills =
      'skills' in data && Array.isArray(data.skills)
        ? data.skills
        : [data as { skillName: string; fingerprintHash?: string }];

    let count = 0;
    for (const skill of skills) {
      if (!skill.skillName || typeof skill.skillName !== 'string') continue;
      this.db.reportSafeSkill(skill.skillName, skill.fingerprintHash);
      count++;
    }

    this.sendJson(res, 201, { ok: true, data: { message: `${count} skill(s) reported`, count } });
  }

  /** GET /api/skill-whitelist - Fetch community-confirmed safe skills */
  private handleGetSkillWhitelist(res: ServerResponse): void {
    const whitelist = this.db.getSkillWhitelist();
    this.sendJson(res, 200, { ok: true, data: whitelist });
  }

  /**
   * GET /api/skill-blacklist?minReports=3&minAvgRisk=70
   * Fetch community skill blacklist (aggregated from skill threat reports)
   * 取得社群技能黑名單（從技能威脅回報聚合）
   */
  private handleGetSkillBlacklist(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const minReports = Number(params.get('minReports') ?? '3');
    const minAvgRisk = Number(params.get('minAvgRisk') ?? '70');

    res.setHeader('Cache-Control', 'public, max-age=1800, s-maxage=1800');
    const blacklist = this.db.getSkillBlacklist(minReports, minAvgRisk);
    this.sendJson(res, 200, { ok: true, data: blacklist });
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

  /** Serve admin dashboard HTML -- requires admin auth via query param or header */
  private serveAdminDashboard(req: IncomingMessage, res: ServerResponse): void {
    // Server-side auth: require admin key via ?key= param or Authorization header
    if (this.config.adminApiKey) {
      const url = new URL(req.url ?? '/', `http://localhost:${this.config.port}`);
      const queryKey = url.searchParams.get('key');
      const headerKey = (req.headers.authorization ?? '').replace('Bearer ', '');
      if (queryKey !== this.config.adminApiKey && headerKey !== this.config.adminApiKey) {
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        res.end('Unauthorized: admin API key required. Use ?key=YOUR_KEY or Authorization header.');
        return;
      }
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.writeHead(200);
    res.end(getAdminHTML());
  }

  /** Check admin API key for write-protected endpoints / 檢查管理員 API 金鑰 */
  private checkAdminAuth(req: IncomingMessage): boolean {
    if (!this.config.adminApiKey) return true; // no admin key configured = open
    const authHeader = req.headers.authorization ?? '';
    const token = authHeader.replace('Bearer ', '');
    return token === this.config.adminApiKey;
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
      const MAX_BODY = 5_242_880; // 5MB (reasonable limit for JSON payloads)

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

  /**
   * Seed rules from bundled config/ directory on first startup.
   * Looks for config/ in cwd, relative to this file, or common Docker paths.
   */
  private seedFromBundled(): number {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const candidates = [
      join(process.cwd(), 'config'),
      join(__dirname, '..', '..', '..', 'config'), // monorepo: packages/threat-cloud/dist -> config
      join(__dirname, '..', '..', '..', '..', 'config'), // deeper nesting
      '/app/config', // Docker standard
    ];
    const configDir = candidates.find((d) => {
      try {
        return statSync(d).isDirectory();
      } catch {
        return false;
      }
    });

    if (!configDir) {
      log.info(`No config/ directory found (searched: ${candidates.join(', ')})`);
      return 0;
    }

    log.info(`Using config directory: ${configDir}`);
    const now = new Date().toISOString();
    let seeded = 0;

    const collectFiles = (dir: string, extensions: string[]): string[] => {
      const results: string[] = [];
      try {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          const fullPath = join(dir, entry.name);
          if (entry.isDirectory()) {
            results.push(...collectFiles(fullPath, extensions));
          } else if (extensions.some((ext) => entry.name.endsWith(ext))) {
            results.push(fullPath);
          }
        }
      } catch (err: unknown) {
        log.error(`Cannot read directory ${dir}`, err);
      }
      return results;
    };

    // Sigma rules
    const sigmaDir = join(configDir, 'sigma-rules');
    try {
      const files = collectFiles(sigmaDir, ['.yml', '.yaml']);
      for (const file of files) {
        const content = readFileSync(file, 'utf-8');
        const ruleId = `sigma:${relative(sigmaDir, file).replace(/\//g, ':')}`;
        this.db.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'sigma' });
        seeded++;
      }
      log.info(`  Sigma: ${files.length} files`);
    } catch (err: unknown) {
      log.error('Sigma seeding failed', err);
    }

    // YARA rules (split multi-rule files)
    const yaraDir = join(configDir, 'yara-rules');
    try {
      const files = collectFiles(yaraDir, ['.yar', '.yara']);
      for (const file of files) {
        const content = readFileSync(file, 'utf-8');
        const ruleMatches = content.match(/rule\s+\w+/g);
        if (ruleMatches && ruleMatches.length > 1) {
          for (const match of ruleMatches) {
            const ruleName = match.replace('rule ', '');
            const ruleId = `yara:${basename(file, '.yar').replace('.yara', '')}:${ruleName}`;
            this.db.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'yara' });
            seeded++;
          }
        } else {
          const ruleId = `yara:${relative(yaraDir, file).replace(/\//g, ':')}`;
          this.db.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'yara' });
          seeded++;
        }
      }
      log.info(`  YARA: ${files.length} files`);
    } catch (err: unknown) {
      log.error('YARA seeding failed', err);
    }

    // ATR rules
    const atrCandidates = [
      join(process.cwd(), 'node_modules', 'agent-threat-rules', 'rules'),
      join(__dirname, '..', '..', 'atr', 'rules'),
      join(__dirname, '..', '..', '..', 'packages', 'atr', 'rules'),
    ];
    const atrDir = atrCandidates.find((d) => {
      try {
        return statSync(d).isDirectory();
      } catch {
        return false;
      }
    });
    if (atrDir) {
      try {
        const files = collectFiles(atrDir, ['.yaml', '.yml']);
        for (const file of files) {
          const content = readFileSync(file, 'utf-8');
          const ruleId = `atr:${relative(atrDir, file).replace(/\//g, ':')}`;
          this.db.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'atr' });
          seeded++;
        }
        log.info(`  ATR: ${files.length} files`);
      } catch (err: unknown) {
        log.error('ATR seeding failed', err);
      }
    }

    return seeded;
  }
}
