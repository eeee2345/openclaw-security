/**
 * Manager HTTP API Server
 * Manager HTTP API 伺服器
 *
 * Exposes the Manager orchestrator as a REST API for Guard agents
 * and the Admin dashboard.
 *
 * Endpoints:
 * - POST   /api/agents/register         Register a new agent
 * - POST   /api/agents/:id/heartbeat    Agent heartbeat
 * - POST   /api/agents/:id/events       Submit threat report
 * - DELETE  /api/agents/:id              Deregister an agent
 * - GET    /api/agents                   List all agents
 * - GET    /api/agents/:id              Get single agent
 * - GET    /api/overview                 Dashboard overview
 * - GET    /api/threats                  Recent threats
 * - GET    /api/threats/summary          Threat summary
 * - POST   /api/policy                   Create policy
 * - GET    /api/policy/active            Get active policy
 * - GET    /api/policy/agent/:id         Get policy for agent
 * - GET    /api/events/stream            SSE stream for real-time updates
 * - GET    /health                       Health check
 *
 * @module @panguard-ai/manager/server
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { createLogger } from '@panguard-ai/core';
import { Manager } from './manager.js';
import type {
  ManagerConfig,
  AgentRegistrationRequest,
  AgentHeartbeat,
  ThreatReport,
  PolicyRule,
} from './types.js';

const logger = createLogger('panguard-manager:server');

/** Rate limiter state */
interface RateLimitEntry {
  count: number;
  resetAt: number;
}

/**
 * Manager HTTP API Server
 * Wraps the Manager class with a REST API using raw node:http.
 */
export class ManagerServer {
  private server: ReturnType<typeof createServer> | null = null;
  private readonly manager: Manager;
  private readonly config: ManagerConfig;
  private readonly rateLimits: Map<string, RateLimitEntry> = new Map();
  private readonly hashedAuthToken: Buffer;
  private readonly sseClients: Set<ServerResponse> = new Set();

  constructor(config: ManagerConfig) {
    this.config = config;
    this.manager = new Manager(config);

    // In production, require an auth token to prevent unauthenticated access
    if (process.env['NODE_ENV'] === 'production' && !config.authToken) {
      throw new Error(
        'MANAGER_AUTH_TOKEN is required in production. ' +
          'Generate one with: openssl rand -hex 32'
      );
    }

    // Pre-hash auth token for constant-time comparison
    this.hashedAuthToken = config.authToken
      ? createHash('sha256').update(config.authToken).digest()
      : Buffer.alloc(0);
  }

  /** Get the underlying Manager instance */
  getManager(): Manager {
    return this.manager;
  }

  /** Start the HTTP server and Manager service */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      this.server.listen(this.config.port, () => {
        this.manager.start();
        logger.info(
          `Manager server started on port ${this.config.port} / ` +
            `Manager 伺服器已啟動於埠 ${this.config.port}`
        );
        resolve();
      });
    });
  }

  /** Stop the server and Manager service gracefully */
  async stop(): Promise<void> {
    // Close all SSE connections / 關閉所有 SSE 連線
    for (const client of this.sseClients) {
      client.end();
    }
    this.sseClients.clear();

    this.manager.stop();
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
        setTimeout(() => resolve(), 10_000);
      } else {
        resolve();
      }
    });
  }

  // ===== Request Handling / 請求處理 =====

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Type', 'application/json');
    if (process.env['NODE_ENV'] === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }

    // CORS
    const corsEnv = process.env['CORS_ALLOWED_ORIGINS'] ?? '';
    const allowedOrigins = corsEnv ? corsEnv.split(',').map((o) => o.trim()) : [];
    const origin = req.headers.origin ?? '';
    if (allowedOrigins.includes('*') && process.env['NODE_ENV'] !== 'production') {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
    } else if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const clientIP = req.socket.remoteAddress ?? 'unknown';

    // Rate limiting
    if (!this.checkRateLimit(clientIP)) {
      this.sendJson(res, 429, { ok: false, error: 'Rate limit exceeded' });
      return;
    }

    const url = req.url ?? '/';
    const pathname = url.split('?')[0] ?? '/';

    // Health check (no auth required)
    if (pathname === '/health') {
      this.sendJson(res, 200, {
        ok: true,
        data: {
          status: 'healthy',
          uptime: process.uptime(),
          agents: this.manager.getAgentCount(),
          running: this.manager.isRunning(),
        },
      });
      return;
    }

    // Auth check for all other endpoints
    if (!this.verifyAuth(req)) {
      this.sendJson(res, 401, { ok: false, error: 'Unauthorized' });
      return;
    }

    // Content-Type check for POST requests
    if (req.method === 'POST') {
      const contentType = req.headers['content-type'] ?? '';
      if (!contentType.includes('application/json')) {
        this.sendJson(res, 415, { ok: false, error: 'Content-Type must be application/json' });
        return;
      }
    }

    try {
      await this.route(req, res, pathname);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Internal server error';
      logger.error(`Request error: ${message}`);
      this.sendJson(res, 500, { ok: false, error: message });
    }
  }

  /** Route requests to handlers */
  private async route(
    req: IncomingMessage,
    res: ServerResponse,
    pathname: string
  ): Promise<void> {
    const method = req.method ?? 'GET';

    // POST /api/agents/register
    if (pathname === '/api/agents/register' && method === 'POST') {
      await this.handleRegister(req, res);
      return;
    }

    // POST /api/agents/:id/heartbeat
    const heartbeatMatch = pathname.match(/^\/api\/agents\/([^/]+)\/heartbeat$/);
    if (heartbeatMatch && method === 'POST') {
      await this.handleHeartbeat(req, res, heartbeatMatch[1]!);
      return;
    }

    // POST /api/agents/:id/events
    const eventsMatch = pathname.match(/^\/api\/agents\/([^/]+)\/events$/);
    if (eventsMatch && method === 'POST') {
      await this.handleEvents(req, res, eventsMatch[1]!);
      return;
    }

    // DELETE /api/agents/:id
    const deleteMatch = pathname.match(/^\/api\/agents\/([^/]+)$/);
    if (deleteMatch && method === 'DELETE') {
      this.handleDeregister(res, deleteMatch[1]!);
      return;
    }

    // GET /api/agents/:id
    const agentMatch = pathname.match(/^\/api\/agents\/([^/]+)$/);
    if (agentMatch && method === 'GET') {
      this.handleGetAgent(res, agentMatch[1]!);
      return;
    }

    // GET /api/agents
    if (pathname === '/api/agents' && method === 'GET') {
      this.handleListAgents(req, res);
      return;
    }

    // GET /api/overview
    if (pathname === '/api/overview' && method === 'GET') {
      this.handleOverview(req, res);
      return;
    }

    // GET /api/threats/summary
    if (pathname === '/api/threats/summary' && method === 'GET') {
      this.handleThreatSummary(res);
      return;
    }

    // GET /api/threats
    if (pathname === '/api/threats' && method === 'GET') {
      this.handleRecentThreats(req, res);
      return;
    }

    // POST /api/policy
    if (pathname === '/api/policy' && method === 'POST') {
      await this.handleCreatePolicy(req, res);
      return;
    }

    // GET /api/policy/active
    if (pathname === '/api/policy/active' && method === 'GET') {
      this.handleActivePolicy(res);
      return;
    }

    // GET /api/policy/agent/:id
    const policyAgentMatch = pathname.match(/^\/api\/policy\/agent\/([^/]+)$/);
    if (policyAgentMatch && method === 'GET') {
      this.handlePolicyForAgent(res, policyAgentMatch[1]!);
      return;
    }

    // GET /api/events/stream (SSE)
    if (pathname === '/api/events/stream' && method === 'GET') {
      this.handleSSEStream(res);
      return;
    }

    // 404
    this.sendJson(res, 404, { ok: false, error: 'Not found' });
  }

  // ===== Route Handlers / 路由處理器 =====

  private async handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody<AgentRegistrationRequest>(req);
    if (!body || !body.hostname || !body.os || !body.arch || !body.version) {
      this.sendJson(res, 400, {
        ok: false,
        error: 'Missing required fields: hostname, os, arch, version',
      });
      return;
    }

    try {
      const registration = this.manager.handleRegistration(body);
      this.sendJson(res, 201, { ok: true, data: registration });
      this.broadcastSSE('agent_online', {
        agentId: registration.agentId,
        hostname: registration.hostname,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      this.sendJson(res, 409, { ok: false, error: message });
    }
  }

  private async handleHeartbeat(
    req: IncomingMessage,
    res: ServerResponse,
    agentId: string
  ): Promise<void> {
    const body = await this.readBody<Omit<AgentHeartbeat, 'agentId'>>(req);
    if (!body) {
      this.sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const heartbeat: AgentHeartbeat = { ...body, agentId };
    const updated = this.manager.handleHeartbeat(heartbeat);

    if (!updated) {
      this.sendJson(res, 404, { ok: false, error: `Agent ${agentId} not found` });
      return;
    }

    this.sendJson(res, 200, { ok: true, data: updated });
  }

  private async handleEvents(
    req: IncomingMessage,
    res: ServerResponse,
    agentId: string
  ): Promise<void> {
    const body = await this.readBody<Omit<ThreatReport, 'agentId'>>(req);
    if (!body || !Array.isArray(body.threats)) {
      this.sendJson(res, 400, { ok: false, error: 'Invalid body: threats array required' });
      return;
    }

    const report: ThreatReport = { ...body, agentId };
    const aggregated = this.manager.handleThreatReport(report);

    this.sendJson(res, 200, {
      ok: true,
      data: { accepted: aggregated.length, threats: aggregated },
    });

    if (aggregated.length > 0) {
      this.broadcastSSE('threats_reported', {
        agentId,
        count: aggregated.length,
        threats: aggregated.map((t) => ({
          id: t.id,
          severity: t.originalThreat.verdict.conclusion,
          sourceHostname: t.sourceHostname,
        })),
      });
    }
  }

  private handleDeregister(res: ServerResponse, agentId: string): void {
    const removed = this.manager.handleDeregistration(agentId);
    if (!removed) {
      this.sendJson(res, 404, { ok: false, error: `Agent ${agentId} not found` });
      return;
    }
    this.sendJson(res, 200, { ok: true, data: { agentId, removed: true } });
    this.broadcastSSE('agent_offline', { agentId });
  }

  private handleGetAgent(res: ServerResponse, agentId: string): void {
    const agent = this.manager.getAgent(agentId);
    if (!agent) {
      this.sendJson(res, 404, { ok: false, error: `Agent ${agentId} not found` });
      return;
    }
    this.sendJson(res, 200, { ok: true, data: agent });
  }

  private handleListAgents(_req: IncomingMessage, res: ServerResponse): void {
    const overview = this.manager.getOverview();
    this.sendJson(res, 200, { ok: true, data: overview.agents });
  }

  private handleOverview(_req: IncomingMessage, res: ServerResponse): void {
    const overview = this.manager.getOverview();
    this.sendJson(res, 200, { ok: true, data: overview });
  }

  private handleThreatSummary(res: ServerResponse): void {
    const summary = this.manager.getThreatSummary();
    this.sendJson(res, 200, { ok: true, data: summary });
  }

  private handleRecentThreats(req: IncomingMessage, res: ServerResponse): void {
    const url = req.url ?? '/';
    const params = new URL(url, 'http://localhost').searchParams;
    const sinceParam = params.get('since');
    const since = sinceParam ? new Date(sinceParam) : new Date(Date.now() - 3_600_000); // default 1h

    const threats = this.manager.getRecentThreats(since);
    this.sendJson(res, 200, { ok: true, data: threats });
  }

  private async handleCreatePolicy(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody<{ rules: PolicyRule[]; broadcast?: boolean }>(req);
    if (!body || !Array.isArray(body.rules)) {
      this.sendJson(res, 400, { ok: false, error: 'Invalid body: rules array required' });
      return;
    }

    const policy = await this.manager.createPolicy(body.rules, body.broadcast ?? true);
    this.sendJson(res, 201, { ok: true, data: policy });
    this.broadcastSSE('policy_created', {
      policyId: policy.policyId,
      version: policy.version,
    });
  }

  private handleActivePolicy(res: ServerResponse): void {
    const policy = this.manager.getActivePolicy();
    if (!policy) {
      this.sendJson(res, 200, { ok: true, data: null });
      return;
    }
    this.sendJson(res, 200, { ok: true, data: policy });
  }

  private handlePolicyForAgent(res: ServerResponse, agentId: string): void {
    const policy = this.manager.getPolicyForAgent(agentId);
    this.sendJson(res, 200, { ok: true, data: policy });
  }

  // ===== SSE / 伺服器推送事件 =====

  /** Handle a new SSE stream connection / 處理新的 SSE 串流連線 */
  private handleSSEStream(res: ServerResponse): void {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    // Send initial connection event / 發送初始連線事件
    this.sendSSE(res, 'connected', { timestamp: new Date().toISOString() });

    // Keep-alive every 30 seconds to prevent proxy timeouts / 每 30 秒保持連線
    const keepAlive = setInterval(() => {
      res.write(':keep-alive\n\n');
    }, 30_000);

    // Track client / 追蹤客戶端
    this.sseClients.add(res);

    // Clean up on disconnect / 斷線時清理
    res.on('close', () => {
      clearInterval(keepAlive);
      this.sseClients.delete(res);
    });
  }

  /** Broadcast an event to all connected SSE clients / 向所有已連線的 SSE 客戶端廣播事件 */
  broadcastSSE(eventType: string, data: unknown): void {
    const payload = `data: ${JSON.stringify({ type: eventType, data, timestamp: new Date().toISOString() })}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(payload);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  /** Send an SSE event to a single client / 向單個客戶端發送 SSE 事件 */
  private sendSSE(res: ServerResponse, event: string, data: unknown): void {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  // ===== Utilities / 工具方法 =====

  /** Read and parse JSON body from request */
  private readBody<T>(req: IncomingMessage): Promise<T | null> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const maxSize = 1_048_576; // 1 MB

      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxSize) {
          req.destroy();
          resolve(null);
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        try {
          const raw = Buffer.concat(chunks).toString('utf8');
          resolve(JSON.parse(raw) as T);
        } catch {
          resolve(null);
        }
      });

      req.on('error', () => resolve(null));
    });
  }

  /** Send JSON response */
  private sendJson(res: ServerResponse, status: number, body: unknown): void {
    const json = JSON.stringify(body);
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(json);
  }

  /** Verify Bearer token authentication */
  private verifyAuth(req: IncomingMessage): boolean {
    // If no auth token configured, allow all (dev mode)
    if (this.hashedAuthToken.length === 0) return true;

    const authHeader = req.headers.authorization ?? '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) return false;

    const tokenHash = createHash('sha256').update(token).digest();
    try {
      return timingSafeEqual(tokenHash, this.hashedAuthToken);
    } catch {
      return false;
    }
  }

  /** Simple in-memory rate limiter */
  private checkRateLimit(key: string, maxRequests = 60): boolean {
    const now = Date.now();
    const windowMs = 60_000;
    const entry = this.rateLimits.get(key);

    if (!entry || now > entry.resetAt) {
      this.rateLimits.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }

    const newCount = entry.count + 1;
    this.rateLimits.set(key, { ...entry, count: newCount });
    return newCount <= maxRequests;
  }
}
