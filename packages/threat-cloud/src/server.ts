/**
 * Threat Cloud HTTP API Server
 * 威脅雲 HTTP API 伺服器
 *
 * Endpoints:
 * - POST /api/threats      Upload anonymized threat data
 * - POST /api/trap-intel   Upload trap intelligence data
 * - GET  /api/rules        Fetch rules (optional ?since= filter)
 * - POST /api/rules        Publish a new community rule
 * - GET  /api/stats        Get threat statistics
 * - GET  /api/iocs         Search/list IoCs
 * - GET  /api/iocs/:value  Lookup single IoC
 * - GET  /health           Health check
 *
 * @module @panguard-ai/threat-cloud/server
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { ThreatCloudDB } from './database.js';
import { IoCStore } from './ioc-store.js';
import { CorrelationEngine } from './correlation-engine.js';
import { QueryHandlers } from './query-handlers.js';
import { FeedDistributor } from './feed-distributor.js';
import { SightingStore } from './sighting-store.js';
import { AuditLogger } from './audit-logger.js';
import { Scheduler } from './scheduler.js';
import type {
  ServerConfig,
  AnonymizedThreatData,
  ThreatCloudRule,
  TrapIntelligencePayload,
  IoCType,
  IoCStatus,
  SightingInput,
  AuditLogQuery,
} from './types.js';

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
  private readonly iocStore: IoCStore;
  private readonly correlation: CorrelationEngine;
  private readonly queryHandlers: QueryHandlers;
  private readonly feedDistributor: FeedDistributor;
  private readonly sightingStore: SightingStore;
  private readonly auditLogger: AuditLogger;
  private readonly scheduler: Scheduler;
  private readonly config: ServerConfig;
  private rateLimits: Map<string, RateLimitEntry> = new Map();
  /** Pre-hashed API keys for constant-time comparison */
  private readonly hashedApiKeys: Buffer[];

  constructor(config: ServerConfig) {
    this.config = config;
    this.db = new ThreatCloudDB(config.dbPath);
    const rawDb = this.db.getDB();
    this.iocStore = new IoCStore(rawDb);
    this.correlation = new CorrelationEngine(rawDb);
    this.queryHandlers = new QueryHandlers(rawDb);
    this.feedDistributor = new FeedDistributor(rawDb);
    this.sightingStore = new SightingStore(rawDb);
    this.auditLogger = new AuditLogger(rawDb);
    this.scheduler = new Scheduler(rawDb);
    // Pre-hash API keys for constant-time comparison
    this.hashedApiKeys = config.apiKeys.map((k) => createHash('sha256').update(k).digest());
  }

  /** Start the server / 啟動伺服器 */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      this.server.listen(this.config.port, this.config.host, () => {
        console.log(`Threat Cloud server started on ${this.config.host}:${this.config.port}`);
        if (this.hashedApiKeys.length === 0) {
          console.warn(
            'WARNING: No API keys configured. Write endpoints and sensitive data will return 503.'
          );
          console.warn('Set TC_API_KEYS=key1,key2 or use --api-key to enable full access.');
        }
        this.scheduler.start();
        resolve();
      });
    });
  }

  /** Stop the server gracefully / 優雅停止伺服器 */
  async stop(): Promise<void> {
    this.scheduler.stop();
    return new Promise((resolve) => {
      if (this.server) {
        // Stop accepting new connections, wait for in-flight requests
        this.server.close(() => {
          this.db.close();
          resolve();
        });
        // Force close after 25s if requests haven't drained
        setTimeout(() => {
          this.db.close();
          resolve();
        }, 25_000);
      } else {
        this.db.close();
        resolve();
      }
    });
  }

  /** Expose DB for testing / 暴露 DB 供測試使用 */
  getDB(): ThreatCloudDB {
    return this.db;
  }

  /** Expose IoC store for testing / 暴露 IoCStore 供測試使用 */
  getIoCStore(): IoCStore {
    return this.iocStore;
  }

  /** Expose scheduler for backup management / 暴露排程器供備份管理 */
  getScheduler(): Scheduler {
    return this.scheduler;
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    if (process.env['NODE_ENV'] === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }
    res.setHeader('Content-Type', 'application/json');

    const clientIP = req.socket.remoteAddress ?? 'unknown';

    // Rate limiting (per client IP)
    if (!this.checkRateLimit(clientIP)) {
      this.sendJson(res, 429, { ok: false, error: 'Rate limit exceeded' });
      return;
    }

    // API key verification
    const url = req.url ?? '/';
    const pathname = url.split('?')[0] ?? '/';
    let apiKeyHash = '';

    // Determine if this endpoint requires authentication
    const isHealthCheck = pathname === '/health';
    const allowAnonymousUpload = process.env['ALLOW_ANONYMOUS_UPLOAD'] === 'true';
    const isAnonymousThreatUpload =
      allowAnonymousUpload && req.method === 'POST' && pathname === '/api/threats';
    const isWriteOrSensitive =
      req.method === 'POST' || pathname === '/api/audit-log' || pathname === '/api/sightings';
    // Write and sensitive endpoints ALWAYS require auth, except anonymous threat uploads
    const requiresAuth =
      !isHealthCheck &&
      !isAnonymousThreatUpload &&
      (this.config.apiKeyRequired || isWriteOrSensitive);

    if (requiresAuth) {
      if (this.hashedApiKeys.length === 0) {
        this.sendJson(res, 503, {
          ok: false,
          error: 'Server not configured with API keys. Set TC_API_KEYS environment variable.',
        });
        return;
      }

      const authHeader = req.headers.authorization ?? '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
      if (!token || !this.verifyApiKey(token)) {
        this.sendJson(res, 401, { ok: false, error: 'Unauthorized' });
        return;
      }
      apiKeyHash = AuditLogger.hashApiKey(token);

      // Per-API-key rate limiting (stricter for write ops)
      if (req.method === 'POST' && !this.checkRateLimit(`key:${apiKeyHash}`, 30)) {
        this.sendJson(res, 429, { ok: false, error: 'Rate limit exceeded' });
        return;
      }
    }

    // CORS
    const allowedOrigins = (
      process.env['CORS_ALLOWED_ORIGINS'] ?? 'https://panguard.ai,https://www.panguard.ai'
    ).split(',');
    const origin = req.headers.origin ?? '';
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Strict Content-Type for POST requests
    if (req.method === 'POST') {
      const contentType = req.headers['content-type'] ?? '';
      if (!contentType.includes('application/json')) {
        this.sendJson(res, 415, { ok: false, error: 'Content-Type must be application/json' });
        return;
      }
    }

    // Attach audit context to this request (anonymize client IP for privacy)
    const auditCtx = { actorHash: apiKeyHash, ipAddress: this.anonymizeIP(clientIP) };

    try {
      // Route matching
      if (pathname === '/health') {
        try {
          this.db.getDB().prepare('SELECT 1').get();
          this.sendJson(res, 200, {
            ok: true,
            data: { status: 'healthy', uptime: process.uptime(), db: 'connected' },
          });
        } catch {
          this.sendJson(res, 503, {
            ok: false,
            data: { status: 'unhealthy', uptime: process.uptime(), db: 'disconnected' },
          });
        }
        return;
      }

      if (pathname === '/api/threats' && req.method === 'POST') {
        await this.handlePostThreat(req, res, auditCtx);
        return;
      }

      if (pathname === '/api/trap-intel' && req.method === 'POST') {
        await this.handlePostTrapIntel(req, res, auditCtx);
        return;
      }

      // Sighting endpoints
      if (pathname === '/api/sightings' && req.method === 'POST') {
        await this.handlePostSighting(req, res, auditCtx);
        return;
      }
      if (pathname === '/api/sightings' && req.method === 'GET') {
        this.handleGetSightings(url, res);
        return;
      }

      // Audit log endpoint
      if (pathname === '/api/audit-log' && req.method === 'GET') {
        this.handleGetAuditLog(url, res);
        return;
      }

      if (pathname === '/api/rules') {
        if (req.method === 'GET') {
          this.handleGetRules(url, res);
        } else if (req.method === 'POST') {
          await this.handlePostRule(req, res, auditCtx);
        } else {
          this.sendJson(res, 405, { ok: false, error: 'Method not allowed' });
        }
        return;
      }

      if (pathname === '/api/stats' && req.method === 'GET') {
        this.handleGetStats(res);
        return;
      }

      // GET /api/iocs or GET /api/iocs/:value
      if (pathname === '/api/iocs' && req.method === 'GET') {
        this.handleSearchIoCs(url, res);
        return;
      }

      // /api/iocs/xxx path param routing
      if (pathname.startsWith('/api/iocs/') && req.method === 'GET') {
        const value = decodeURIComponent(pathname.slice('/api/iocs/'.length));
        this.handleLookupIoC(url, value, res);
        return;
      }

      // Campaign endpoints
      if (pathname === '/api/campaigns/stats' && req.method === 'GET') {
        this.handleCampaignStats(res);
        return;
      }
      if (pathname === '/api/campaigns' && req.method === 'GET') {
        this.handleListCampaigns(url, res);
        return;
      }
      if (pathname.startsWith('/api/campaigns/') && req.method === 'GET') {
        const id = decodeURIComponent(pathname.slice('/api/campaigns/'.length));
        this.handleGetCampaign(id, res);
        return;
      }

      // Query endpoints
      if (pathname === '/api/query/timeseries' && req.method === 'GET') {
        this.handleTimeSeries(url, res);
        return;
      }
      if (pathname === '/api/query/geo' && req.method === 'GET') {
        this.handleGeoDistribution(url, res);
        return;
      }
      if (pathname === '/api/query/trends' && req.method === 'GET') {
        this.handleTrends(url, res);
        return;
      }
      if (pathname === '/api/query/mitre-heatmap' && req.method === 'GET') {
        this.handleMitreHeatmap(url, res);
        return;
      }

      // Feed endpoints
      if (pathname === '/api/feeds/ip-blocklist' && req.method === 'GET') {
        this.handleIPBlocklist(url, res);
        return;
      }
      if (pathname === '/api/feeds/domain-blocklist' && req.method === 'GET') {
        this.handleDomainBlocklist(url, res);
        return;
      }
      if (pathname === '/api/feeds/iocs' && req.method === 'GET') {
        this.handleIoCFeed(url, res);
        return;
      }
      if (pathname === '/api/feeds/agent-update' && req.method === 'GET') {
        this.handleAgentUpdate(url, res);
        return;
      }

      this.sendJson(res, 404, { ok: false, error: 'Not found' });
    } catch (err) {
      // Never leak stack traces or internal details in production
      if (err instanceof SyntaxError) {
        this.sendJson(res, 400, { ok: false, error: 'Invalid JSON in request body' });
        return;
      }
      const isDev = process.env['NODE_ENV'] !== 'production';
      const message = isDev && err instanceof Error ? err.message : 'Internal server error';
      console.error('Request error:', err);
      this.sendJson(res, 500, { ok: false, error: message });
    }
  }

  // -------------------------------------------------------------------------
  // POST /api/threats - Upload anonymized threat data (enhanced: also creates IoC)
  // -------------------------------------------------------------------------
  private async handlePostThreat(
    req: IncomingMessage,
    res: ServerResponse,
    auditCtx: { actorHash: string; ipAddress: string }
  ): Promise<void> {
    const body = await this.readBody(req);
    const data = JSON.parse(body) as AnonymizedThreatData;

    // Input validation
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

    if (!this.isValidIP(data.attackSourceIP)) {
      this.sendJson(res, 400, { ok: false, error: 'Invalid IP address format' });
      return;
    }

    if (!this.isValidTimestamp(data.timestamp)) {
      this.sendJson(res, 400, { ok: false, error: 'Invalid timestamp format' });
      return;
    }

    // Sanitize string fields
    data.attackType = this.sanitizeString(data.attackType, 100);
    data.mitreTechnique = this.sanitizeString(data.mitreTechnique, 50);
    data.sigmaRuleMatched = this.sanitizeString(data.sigmaRuleMatched, 200);
    data.region = this.sanitizeString(data.region, 10);
    if (data.industry) data.industry = this.sanitizeString(data.industry, 50);

    // Anonymize IP
    data.attackSourceIP = this.anonymizeIP(data.attackSourceIP);

    // Insert into legacy threats table (backward compat)
    this.db.insertThreat(data);

    // Insert into enriched_threats
    const enriched = ThreatCloudDB.guardToEnriched(data);
    const enrichedId = this.db.insertEnrichedThreat(enriched);

    // Extract IP as IoC + auto-sighting (learning)
    if (data.attackSourceIP && data.attackSourceIP !== 'unknown') {
      const ioc = this.iocStore.upsertIoC({
        type: 'ip',
        value: data.attackSourceIP,
        threatType: data.attackType,
        source: 'guard',
        confidence: 50,
        tags: [data.mitreTechnique],
      });

      // Auto-sighting: agent reported this IP → positive sighting
      if (ioc.sightings > 1) {
        this.sightingStore.recordAgentMatch(ioc.id, 'guard', auditCtx.actorHash);
        // Check for cross-source correlation
        this.sightingStore.recordCrossSourceMatch(ioc.id, auditCtx.actorHash);
      }
    }

    // Audit log
    this.auditLogger.log('threat_upload', 'enriched_threat', String(enrichedId ?? 'dup'), {
      ...auditCtx,
      details: { attackType: data.attackType, region: data.region },
    });

    this.sendJson(res, 201, {
      ok: true,
      data: {
        message: 'Threat data received',
        enrichedId: enrichedId ?? 'duplicate',
      },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/trap-intel - Upload trap intelligence
  // -------------------------------------------------------------------------
  private async handlePostTrapIntel(
    req: IncomingMessage,
    res: ServerResponse,
    auditCtx: { actorHash: string; ipAddress: string }
  ): Promise<void> {
    const body = await this.readBody(req);
    const parsed = JSON.parse(body) as TrapIntelligencePayload | TrapIntelligencePayload[];
    const items = Array.isArray(parsed) ? parsed : [parsed];

    if (items.length > 100) {
      this.sendJson(res, 400, { ok: false, error: 'Batch size exceeds maximum of 100' });
      return;
    }

    let accepted = 0;
    let duplicates = 0;

    for (const data of items) {
      // Validate required fields
      if (!data.sourceIP || !data.attackType || !data.timestamp || !data.mitreTechniques) {
        continue;
      }

      if (!this.isValidIP(data.sourceIP)) continue;

      // Sanitize
      data.attackType = this.sanitizeString(data.attackType, 100);
      if (data.region) data.region = this.sanitizeString(data.region, 10);

      // Anonymize IP
      data.sourceIP = this.anonymizeIP(data.sourceIP);

      // Convert and insert enriched threat
      const enriched = ThreatCloudDB.trapToEnriched(data);
      const enrichedId = this.db.insertEnrichedThreat(enriched);

      if (enrichedId !== null) {
        accepted++;

        // Insert trap credentials (sanitize usernames)
        if (data.topCredentials && data.topCredentials.length > 0) {
          const safeCreds = data.topCredentials.slice(0, 50).map((c) => ({
            username: this.sanitizeString(c.username, 200),
            count: Math.max(0, Math.min(1_000_000, c.count)),
          }));
          this.db.insertTrapCredentials(enrichedId, safeCreds);
        }

        // Extract IP as IoC + auto-sighting (learning)
        if (data.sourceIP && data.sourceIP !== 'unknown') {
          const techniques = data.mitreTechniques ?? [];
          const ioc = this.iocStore.upsertIoC({
            type: 'ip',
            value: data.sourceIP,
            threatType: data.attackType,
            source: 'trap',
            confidence: 60,
            tags: techniques.map((t) => this.sanitizeString(t, 50)),
            metadata: {
              serviceType: data.serviceType,
              skillLevel: data.skillLevel,
              intent: data.intent,
            },
          });

          // Auto-sighting: trap agent confirmed this IP
          if (ioc.sightings > 1) {
            this.sightingStore.recordAgentMatch(ioc.id, 'trap', auditCtx.actorHash);
            this.sightingStore.recordCrossSourceMatch(ioc.id, auditCtx.actorHash);
          }
        }
      } else {
        duplicates++;
      }
    }

    // Audit log
    this.auditLogger.log('trap_intel_upload', 'trap_intel', 'batch', {
      ...auditCtx,
      details: { accepted, duplicates, batchSize: items.length },
    });

    this.sendJson(res, 201, {
      ok: true,
      data: { message: 'Trap intelligence received', accepted, duplicates },
    });
  }

  // -------------------------------------------------------------------------
  // GET /api/iocs - Search IoCs
  // -------------------------------------------------------------------------
  private handleSearchIoCs(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;

    const result = this.iocStore.searchIoCs(
      {
        type: (params.get('type') as IoCType) || undefined,
        source: params.get('source') || undefined,
        minReputation: params.get('minReputation')
          ? Number(params.get('minReputation'))
          : undefined,
        status: (params.get('status') as IoCStatus) || undefined,
        since: params.get('since') || undefined,
        search: params.get('search') || undefined,
      },
      {
        page: Number(params.get('page') ?? '1'),
        limit: Number(params.get('limit') ?? '50'),
      }
    );

    this.sendJson(res, 200, { ok: true, data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/iocs/:value - Lookup single IoC
  // -------------------------------------------------------------------------
  private handleLookupIoC(url: string, value: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const typeParam = params.get('type') as IoCType | null;
    const type = typeParam ?? this.iocStore.detectType(value);

    const result = this.iocStore.lookupIoCWithContext(type, value, (ip) =>
      this.db.countRelatedThreats(ip)
    );

    this.sendJson(res, 200, { ok: true, data: result });
  }

  // -------------------------------------------------------------------------
  // Existing handlers / 既有處理器
  // -------------------------------------------------------------------------

  /** GET /api/rules?since=<ISO timestamp> */
  private handleGetRules(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const since = params.get('since');
    const rules = since ? this.db.getRulesSince(since) : this.db.getAllRules();
    this.sendJson(res, 200, rules);
  }

  /** POST /api/rules */
  private async handlePostRule(
    req: IncomingMessage,
    res: ServerResponse,
    auditCtx: { actorHash: string; ipAddress: string }
  ): Promise<void> {
    const body = await this.readBody(req);
    const rule = JSON.parse(body) as ThreatCloudRule;

    if (!rule.ruleId || !rule.ruleContent || !rule.source) {
      this.sendJson(res, 400, {
        ok: false,
        error: 'Missing required fields: ruleId, ruleContent, source',
      });
      return;
    }

    // Validate ruleContent size and format
    const MAX_RULE_CONTENT_SIZE = 65_536; // 64KB max
    if (rule.ruleContent.length > MAX_RULE_CONTENT_SIZE) {
      this.sendJson(res, 400, {
        ok: false,
        error: `ruleContent exceeds maximum size of ${MAX_RULE_CONTENT_SIZE} bytes`,
      });
      return;
    }

    // Basic Sigma YAML validation: must look like YAML (has title: or detection:)
    const looksLikeYaml =
      rule.ruleContent.includes('title:') || rule.ruleContent.includes('detection:');
    if (!looksLikeYaml) {
      this.sendJson(res, 400, {
        ok: false,
        error: 'ruleContent must be valid Sigma YAML (missing title: or detection:)',
      });
      return;
    }

    rule.ruleId = this.sanitizeString(rule.ruleId, 200);
    rule.ruleContent = this.sanitizeString(rule.ruleContent, MAX_RULE_CONTENT_SIZE);
    rule.source = this.sanitizeString(rule.source, 100);
    rule.publishedAt = rule.publishedAt || new Date().toISOString();
    this.db.upsertRule(rule);

    this.auditLogger.log('rule_publish', 'rule', rule.ruleId, {
      ...auditCtx,
      details: { source: rule.source },
    });

    this.sendJson(res, 201, { ok: true, data: { message: 'Rule published', ruleId: rule.ruleId } });
  }

  /** GET /api/stats (enhanced) */
  private handleGetStats(res: ServerResponse): void {
    const stats = this.queryHandlers.getEnhancedStats();
    this.sendJson(res, 200, { ok: true, data: stats });
  }

  // -------------------------------------------------------------------------
  // Campaign handlers / Campaign 處理器
  // -------------------------------------------------------------------------

  private handleListCampaigns(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const result = this.correlation.listCampaigns(
      {
        page: Number(params.get('page') ?? '1'),
        limit: Number(params.get('limit') ?? '20'),
      },
      params.get('status') || undefined
    );
    this.sendJson(res, 200, { ok: true, data: result });
  }

  private handleCampaignStats(res: ServerResponse): void {
    const stats = this.correlation.getCampaignStats();
    this.sendJson(res, 200, { ok: true, data: stats });
  }

  private handleGetCampaign(id: string, res: ServerResponse): void {
    const campaign = this.correlation.getCampaign(id);
    if (!campaign) {
      this.sendJson(res, 404, { ok: false, error: 'Campaign not found' });
      return;
    }
    const events = this.correlation.getCampaignEvents(id);
    this.sendJson(res, 200, { ok: true, data: { campaign, events } });
  }

  // -------------------------------------------------------------------------
  // Query handlers / 查詢處理器
  // -------------------------------------------------------------------------

  private handleTimeSeries(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const rawGranularity = params.get('granularity') ?? 'day';
    const ALLOWED_GRANULARITIES = ['hour', 'day', 'week'] as const;
    if (!ALLOWED_GRANULARITIES.includes(rawGranularity as (typeof ALLOWED_GRANULARITIES)[number])) {
      this.sendJson(res, 400, { ok: false, error: 'granularity must be one of: hour, day, week' });
      return;
    }
    const granularity = rawGranularity as 'hour' | 'day' | 'week';
    const result = this.queryHandlers.getTimeSeries(
      granularity,
      params.get('since') || undefined,
      params.get('attackType') || undefined
    );
    this.sendJson(res, 200, { ok: true, data: result });
  }

  private handleGeoDistribution(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const result = this.queryHandlers.getGeoDistribution(params.get('since') || undefined);
    this.sendJson(res, 200, { ok: true, data: result });
  }

  private handleTrends(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const periodDays = Number(params.get('periodDays') ?? '7');
    const result = this.queryHandlers.getTrends(periodDays);
    this.sendJson(res, 200, { ok: true, data: result });
  }

  private handleMitreHeatmap(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const result = this.queryHandlers.getMitreHeatmap(params.get('since') || undefined);
    this.sendJson(res, 200, { ok: true, data: result });
  }

  // -------------------------------------------------------------------------
  // Feed handlers / Feed 處理器
  // -------------------------------------------------------------------------

  private handleIPBlocklist(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const minRep = Number(params.get('minReputation') ?? '70');
    const blocklist = this.feedDistributor.getIPBlocklist(minRep);
    res.setHeader('Content-Type', 'text/plain');
    res.writeHead(200);
    res.end(blocklist);
  }

  private handleDomainBlocklist(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const minRep = Number(params.get('minReputation') ?? '70');
    const blocklist = this.feedDistributor.getDomainBlocklist(minRep);
    res.setHeader('Content-Type', 'text/plain');
    res.writeHead(200);
    res.end(blocklist);
  }

  private handleIoCFeed(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const result = this.feedDistributor.getIoCFeed(
      Number(params.get('minReputation') ?? '50'),
      Number(params.get('limit') ?? '1000'),
      params.get('since') || undefined
    );
    this.sendJson(res, 200, { ok: true, data: result });
  }

  private handleAgentUpdate(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const result = this.feedDistributor.getAgentUpdate(params.get('since') || undefined);
    this.sendJson(res, 200, { ok: true, data: result });
  }

  // -------------------------------------------------------------------------
  // Utility methods / 工具方法
  // -------------------------------------------------------------------------

  // -------------------------------------------------------------------------
  // Sighting + Audit handlers
  // -------------------------------------------------------------------------

  private async handlePostSighting(
    req: IncomingMessage,
    res: ServerResponse,
    auditCtx: { actorHash: string; ipAddress: string }
  ): Promise<void> {
    const body = await this.readBody(req);
    const input = JSON.parse(body) as SightingInput;

    if (!input.iocId || !input.type || !input.source) {
      this.sendJson(res, 400, {
        ok: false,
        error: 'Missing required fields: iocId, type, source',
      });
      return;
    }

    if (!['positive', 'negative', 'false_positive'].includes(input.type)) {
      this.sendJson(res, 400, {
        ok: false,
        error: 'type must be one of: positive, negative, false_positive',
      });
      return;
    }

    // Verify IoC exists
    const ioc = this.iocStore.getIoCById(input.iocId);
    if (!ioc) {
      this.sendJson(res, 404, { ok: false, error: 'IoC not found' });
      return;
    }

    input.source = this.sanitizeString(input.source, 200);
    if (input.details) input.details = this.sanitizeString(input.details, 1000);

    const sighting = this.sightingStore.createSighting(input, auditCtx.actorHash);

    this.auditLogger.log('sighting_create', 'sighting', String(sighting.id), {
      ...auditCtx,
      details: { iocId: input.iocId, type: input.type, source: input.source },
    });

    this.sendJson(res, 201, { ok: true, data: sighting });
  }

  private handleGetSightings(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;
    const iocId = Number(params.get('iocId') ?? '0');

    if (!iocId) {
      this.sendJson(res, 400, { ok: false, error: 'iocId query parameter required' });
      return;
    }

    const result = this.sightingStore.getSightingsForIoC(iocId, {
      page: Number(params.get('page') ?? '1'),
      limit: Number(params.get('limit') ?? '50'),
    });

    const summary = this.sightingStore.getSightingSummary(iocId);

    this.sendJson(res, 200, { ok: true, data: { ...result, summary } });
  }

  private handleGetAuditLog(url: string, res: ServerResponse): void {
    const params = new URL(url, `http://localhost:${this.config.port}`).searchParams;

    const query: AuditLogQuery = {
      action: (params.get('action') as AuditLogQuery['action']) || undefined,
      entityType: params.get('entityType') || undefined,
      entityId: params.get('entityId') || undefined,
      since: params.get('since') || undefined,
      limit: Number(params.get('limit') ?? '50'),
    };

    const result = this.auditLogger.query(query);
    this.sendJson(res, 200, { ok: true, data: result });
  }

  // -------------------------------------------------------------------------
  // Utility methods / 工具方法
  // -------------------------------------------------------------------------

  /**
   * Anonymize IP by zeroing last two octets (/16 for IPv4).
   * GDPR-compliant: /16 masking prevents re-identification.
   * 匿名化 IP（IPv4 遮蔽最後兩個八位元組，符合 GDPR）
   */
  private anonymizeIP(ip: string): string {
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length === 4) {
        parts[2] = '0';
        parts[3] = '0';
        return parts.join('.');
      }
    }
    if (ip.includes(':')) {
      const parts = ip.split(':');
      // Zero last two groups for IPv6
      if (parts.length >= 2) {
        parts[parts.length - 1] = '0';
        parts[parts.length - 2] = '0';
        return parts.join(':');
      }
    }
    return ip;
  }

  /**
   * Verify API key using constant-time comparison to prevent timing attacks.
   * 使用常數時間比較驗證 API key 以防止計時攻擊
   */
  private verifyApiKey(token: string): boolean {
    const tokenHash = createHash('sha256').update(token).digest();
    for (const keyHash of this.hashedApiKeys) {
      if (tokenHash.length === keyHash.length && timingSafeEqual(tokenHash, keyHash)) {
        return true;
      }
    }
    return false;
  }

  /** Rate limit check (supports per-IP and per-key) / 速率限制檢查 */
  private checkRateLimit(key: string, maxPerMinute?: number): boolean {
    const limit = maxPerMinute ?? this.config.rateLimitPerMinute;
    const now = Date.now();
    const entry = this.rateLimits.get(key);
    if (!entry || now > entry.resetAt) {
      this.rateLimits.set(key, { count: 1, resetAt: now + 60_000 });
      // Periodic cleanup: remove expired entries every ~500 checks
      if (this.rateLimits.size > 500) {
        for (const [k, v] of this.rateLimits) {
          if (now > v.resetAt) this.rateLimits.delete(k);
        }
      }
      return true;
    }
    entry.count++;
    return entry.count <= limit;
  }

  /** Validate IPv4 or IPv6 format / 驗證 IP 格式 */
  private isValidIP(ip: string): boolean {
    // IPv4
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(ip)) {
      const parts = ip.replace(/:\d+$/, '').split('.');
      return parts.every((p) => {
        const n = Number(p);
        return n >= 0 && n <= 255;
      });
    }
    // IPv6
    if (ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip)) return true;
    return false;
  }

  /** Validate ISO timestamp with reasonable bounds / 驗證 ISO 時間戳格式 */
  private isValidTimestamp(ts: string): boolean {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return false;
    const now = Date.now();
    const oneHourAhead = now + 3_600_000;
    const oneYearAgo = now - 365 * 24 * 3_600_000;
    return d.getTime() >= oneYearAgo && d.getTime() <= oneHourAhead;
  }

  /** Sanitize string input: truncate and strip control characters / 清理字串輸入 */
  private sanitizeString(input: string, maxLength: number): string {
    // eslint-disable-next-line no-control-regex
    return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').slice(0, maxLength);
  }

  /** Read request body with size limit / 讀取請求主體 */
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
