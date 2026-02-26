/**
 * Panguard Dashboard Server
 * Panguard 儀表板伺服器
 *
 * Serves the React frontend + REST API endpoints.
 * 提供 React 前端 + REST API 端點。
 *
 * @module @openclaw/panguard/server
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join, extname, resolve } from 'node:path';
import { readFile, stat } from 'node:fs/promises';
import { handleStatus } from './api/status.js';
import { handleScanStart, handleScanLatest } from './api/scan.js';
import { handleReportFrameworks, handleReportGenerate } from './api/report.js';
import { handleThreatStats } from './api/threat.js';
import { handleGuardStatus } from './api/guard.js';
import { handleTrapStatus } from './api/trap.js';
import { handleChatStatus, handleChatTest } from './api/chat.js';
import { AuthDB, createAuthHandlers, authenticateRequest } from '@openclaw/panguard-auth';

/** MIME type mapping / MIME 類型映射 */
const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json',
};

/**
 * Panguard Dashboard Server
 *
 * HTTP server that serves:
 * 1. REST API at /api/*
 * 2. Static files from the React build at all other paths
 */
export class PanguardDashboardServer {
  private server: ReturnType<typeof createServer> | null = null;
  private sessionCleanupTimer: ReturnType<typeof setInterval> | null = null;
  private readonly port: number;
  private readonly webDistPath: string;
  private readonly resolvedWebDistPath: string;
  private readonly authDB: AuthDB;
  private readonly authHandlers: ReturnType<typeof createAuthHandlers>;
  private readonly allowedOrigins: Set<string>;

  constructor(port: number, webDistPath: string, dbPath?: string) {
    this.port = port;
    this.webDistPath = webDistPath;
    this.resolvedWebDistPath = resolve(webDistPath);
    const authDbPath = dbPath ?? join(webDistPath, '..', 'panguard-auth.db');
    this.authDB = new AuthDB(authDbPath);
    const baseUrl = process.env['PANGUARD_BASE_URL'] ?? `http://localhost:${port}`;
    this.authHandlers = createAuthHandlers({
      db: this.authDB,
      baseUrl,
      // SMTP (optional - only enabled if env vars are set)
      smtp: process.env['SMTP_HOST'] ? {
        host: process.env['SMTP_HOST'],
        port: parseInt(process.env['SMTP_PORT'] ?? '587', 10),
        secure: process.env['SMTP_SECURE'] === 'true',
        from: process.env['SMTP_FROM'] ?? 'noreply@panguard.ai',
        auth: {
          user: process.env['SMTP_USER'] ?? '',
          pass: process.env['SMTP_PASS'] ?? '',
        },
      } : undefined,
      // Google OAuth (optional - only enabled if env vars are set)
      google: process.env['GOOGLE_CLIENT_ID'] ? {
        clientId: process.env['GOOGLE_CLIENT_ID'],
        clientSecret: process.env['GOOGLE_CLIENT_SECRET'] ?? '',
        redirectUri: `${baseUrl}/api/auth/google/callback`,
      } : undefined,
      // Google Sheets sync (optional - only enabled if env vars are set)
      sheets: process.env['GOOGLE_SHEETS_ID'] ? {
        spreadsheetId: process.env['GOOGLE_SHEETS_ID'],
        serviceAccountEmail: process.env['GOOGLE_SERVICE_ACCOUNT_EMAIL'] ?? '',
        privateKey: (process.env['GOOGLE_SERVICE_ACCOUNT_KEY'] ?? '').replace(/\\n/g, '\n'),
      } : undefined,
    });

    // CORS whitelist: env var or default to localhost only
    const corsEnv = process.env['PANGUARD_CORS_ORIGINS'];
    const origins = corsEnv
      ? corsEnv.split(',').map(o => o.trim()).filter(Boolean)
      : [`http://localhost:${port}`, `http://127.0.0.1:${port}`];
    this.allowedOrigins = new Set(origins);
  }

  /** Start the server / 啟動伺服器 */
  async start(): Promise<void> {
    // Clean expired sessions on startup, then every hour
    this.authDB.cleanExpiredSessions();
    this.sessionCleanupTimer = setInterval(() => {
      this.authDB.cleanExpiredSessions();
    }, 60 * 60 * 1000);
    if (this.sessionCleanupTimer.unref) this.sessionCleanupTimer.unref();

    return new Promise((resolvePromise) => {
      this.server = createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      const host = process.env['NODE_ENV'] === 'production' ? '0.0.0.0' : '127.0.0.1';
      this.server.listen(this.port, host, () => {
        resolvePromise();
      });
    });
  }

  /** Stop the server / 停止伺服器 */
  async stop(): Promise<void> {
    if (this.sessionCleanupTimer) {
      clearInterval(this.sessionCleanupTimer);
      this.sessionCleanupTimer = null;
    }
    this.authDB.close();
    return new Promise((resolvePromise) => {
      if (this.server) {
        this.server.close(() => resolvePromise());
      } else {
        resolvePromise();
      }
    });
  }

  /** Handle incoming request / 處理傳入請求 */
  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? '/';
    const [pathname] = url.split('?');
    const path = pathname ?? '/';

    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    );
    if (process.env['NODE_ENV'] === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    // CORS whitelist
    const origin = req.headers.origin;
    if (origin && this.allowedOrigins.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Vary', 'Origin');
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(origin && this.allowedOrigins.has(origin) ? 204 : 403);
      res.end();
      return;
    }

    // API routes
    if (path.startsWith('/api/')) {
      await this.handleApi(path, req, res);
      return;
    }

    // Static file serving for React SPA
    await this.serveStatic(path, res);
  }

  /** Authenticate request and return user, or null. Supports Bearer header or ?token= query param (for SSE). */
  private getAuthUser(req: IncomingMessage): { id: number; email: string; name: string; role: string; tier: string } | null {
    let user = authenticateRequest(req, this.authDB);
    if (!user) {
      const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      const queryToken = urlObj.searchParams.get('token');
      if (queryToken) {
        const fakeReq = { headers: { authorization: `Bearer ${queryToken}` } } as IncomingMessage;
        user = authenticateRequest(fakeReq, this.authDB);
      }
    }
    return user;
  }

  /** Check if request has valid session. */
  private requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
    if (!this.getAuthUser(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Authentication required' }));
      return false;
    }
    return true;
  }

  /** Handle API routes / 處理 API 路由 */
  private async handleApi(path: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader('Content-Type', 'application/json');

    try {
      switch (path) {
        case '/api/health':
          // Unauthenticated healthcheck — returns only { ok: true }
          res.writeHead(200);
          res.end(JSON.stringify({ ok: true }));
          return;

        case '/api/status':
          if (!this.requireAuth(req, res)) return;
          await handleStatus(req, res);
          return;

        case '/api/scan/start':
          if (!this.requireAuth(req, res)) return;
          if (req.method === 'GET' || req.method === 'POST') {
            await handleScanStart(req, res);
          } else {
            this.methodNotAllowed(res);
          }
          return;

        case '/api/scan/latest':
          if (!this.requireAuth(req, res)) return;
          handleScanLatest(req, res);
          return;

        case '/api/report/frameworks':
          if (!this.requireAuth(req, res)) return;
          handleReportFrameworks(req, res);
          return;

        case '/api/report/generate':
          if (!this.requireAuth(req, res)) return;
          if (req.method === 'POST') {
            await handleReportGenerate(req, res);
          } else {
            this.methodNotAllowed(res);
          }
          return;

        case '/api/threat/stats':
          if (!this.requireAuth(req, res)) return;
          handleThreatStats(req, res);
          return;

        case '/api/guard/status':
          if (!this.requireAuth(req, res)) return;
          handleGuardStatus(req, res);
          return;

        case '/api/trap/status':
          if (!this.requireAuth(req, res)) return;
          await handleTrapStatus(req, res);
          return;

        case '/api/chat/status':
          if (!this.requireAuth(req, res)) return;
          handleChatStatus(req, res);
          return;

        case '/api/chat/test':
          if (!this.requireAuth(req, res)) return;
          if (req.method === 'POST') {
            await handleChatTest(req, res);
          } else {
            this.methodNotAllowed(res);
          }
          return;

        // ── Report Purchases ──────────────────────────────────────
        case '/api/report/purchases': {
          if (!this.requireAuth(req, res)) return;
          const rpUser = this.getAuthUser(req)!;
          if (req.method === 'GET') {
            const purchases = this.authDB.getUserReportPurchases(rpUser.id);
            res.writeHead(200);
            res.end(JSON.stringify({ ok: true, data: { purchases } }));
          } else if (req.method === 'POST') {
            const body = await this.readBody(req);
            const parsed = JSON.parse(body) as { addonId?: string };
            if (!parsed.addonId || typeof parsed.addonId !== 'string') {
              res.writeHead(400);
              res.end(JSON.stringify({ ok: false, error: 'addonId is required' }));
              return;
            }
            // Calculate expiration for subscription add-ons (1 month)
            const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            const purchase = this.authDB.createReportPurchase(
              rpUser.id,
              parsed.addonId,
              'per_report',
              expiresAt,
            );
            res.writeHead(201);
            res.end(JSON.stringify({ ok: true, data: { purchase } }));
          } else {
            this.methodNotAllowed(res);
          }
          return;
        }

        case '/api/report/access': {
          if (!this.requireAuth(req, res)) return;
          const raUser = this.getAuthUser(req)!;
          // Business/Enterprise tiers get basic compliance included
          const hasBusinessAccess = raUser.tier === 'business' || raUser.tier === 'enterprise';
          const purchases = this.authDB.getUserReportPurchases(raUser.id);
          const purchasedAddons = purchases.map(p => p.addonId);
          res.writeHead(200);
          res.end(JSON.stringify({
            ok: true,
            data: {
              tier: raUser.tier,
              hasBusinessAccess,
              purchasedAddons,
            },
          }));
          return;
        }

        // ── Auth & Waitlist routes ────────────────────────────────
        case '/api/waitlist':
          await this.authHandlers.handleWaitlistJoin(req, res);
          return;

        case '/api/waitlist/stats':
          this.authHandlers.handleWaitlistStats(req, res);
          return;

        case '/api/waitlist/list':
          this.authHandlers.handleWaitlistList(req, res);
          return;

        case '/api/auth/register':
          await this.authHandlers.handleRegister(req, res);
          return;

        case '/api/auth/login':
          await this.authHandlers.handleLogin(req, res);
          return;

        case '/api/auth/logout':
          this.authHandlers.handleLogout(req, res);
          return;

        case '/api/auth/me':
          this.authHandlers.handleMe(req, res);
          return;

        case '/api/auth/google':
          this.authHandlers.handleGoogleAuth(req, res);
          return;

        case '/api/auth/cli':
          this.authHandlers.handleCliAuth(req, res);
          return;

        case '/api/auth/cli/exchange':
          await this.authHandlers.handleCliExchange(req, res);
          return;

        default:
          // Handle /api/waitlist/verify/:token pattern
          if (path.startsWith('/api/waitlist/verify/')) {
            const token = path.slice('/api/waitlist/verify/'.length);
            this.authHandlers.handleWaitlistVerify(req, res, token);
            return;
          }
          // Handle /api/auth/google/callback?code=xxx&state=xxx pattern
          if (path === '/api/auth/google/callback') {
            const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
            const code = urlObj.searchParams.get('code');
            const state = urlObj.searchParams.get('state');
            if (code) {
              await this.authHandlers.handleGoogleCallback(req, res, code, state);
            } else {
              res.writeHead(400);
              res.end(JSON.stringify({ ok: false, error: 'Missing code parameter' }));
            }
            return;
          }
          res.writeHead(404);
          res.end(JSON.stringify({ ok: false, error: 'Not found' }));
      }
    } catch (err) {
      // SECURITY: Log error internally but never expose err.message to clients
      console.error(`[API Error] ${path}:`, err);
      res.writeHead(500);
      res.end(JSON.stringify({ ok: false, error: 'Internal server error' }));
    }
  }

  /** Serve static files with SPA fallback / 提供靜態檔案（含 SPA 回退） */
  private async serveStatic(pathname: string, res: ServerResponse): Promise<void> {
    // Path traversal protection
    const resolved = resolve(this.resolvedWebDistPath, '.' + pathname);
    if (!resolved.startsWith(this.resolvedWebDistPath)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    let filePath = join(this.webDistPath, pathname === '/' ? 'index.html' : pathname);

    try {
      const stats = await stat(filePath);
      if (stats.isDirectory()) {
        filePath = join(filePath, 'index.html');
      }
    } catch {
      // File not found -> serve index.html for SPA routing
      filePath = join(this.webDistPath, 'index.html');
    }

    const ext = extname(filePath);
    const contentType = MIME_TYPES[ext] ?? 'application/octet-stream';

    try {
      const content = await readFile(filePath);
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  }

  /** Send 405 Method Not Allowed */
  private methodNotAllowed(res: ServerResponse): void {
    res.writeHead(405);
    res.end(JSON.stringify({ ok: false, error: 'Method not allowed' }));
  }

  /** Read request body as string with size limit */
  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const MAX_BODY = 64 * 1024; // 64KB

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
}
