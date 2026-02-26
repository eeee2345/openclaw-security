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
import { join, extname } from 'node:path';
import { readFile, stat } from 'node:fs/promises';
import { handleStatus } from './api/status.js';
import { handleScanStart, handleScanLatest } from './api/scan.js';
import { handleReportFrameworks, handleReportGenerate } from './api/report.js';
import { handleThreatStats } from './api/threat.js';
import { handleGuardStatus } from './api/guard.js';
import { handleTrapStatus } from './api/trap.js';
import { AuthDB, createAuthHandlers } from '@openclaw/panguard-auth';

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
  private readonly port: number;
  private readonly webDistPath: string;
  private readonly authDB: AuthDB;
  private readonly authHandlers: ReturnType<typeof createAuthHandlers>;

  constructor(port: number, webDistPath: string, dbPath?: string) {
    this.port = port;
    this.webDistPath = webDistPath;
    const authDbPath = dbPath ?? join(webDistPath, '..', 'panguard-auth.db');
    this.authDB = new AuthDB(authDbPath);
    const baseUrl = process.env['PANGUARD_BASE_URL'] ?? `http://localhost:${port}`;
    this.authHandlers = createAuthHandlers({
      db: this.authDB,
      baseUrl,
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
  }

  /** Start the server / 啟動伺服器 */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      this.server.listen(this.port, '127.0.0.1', () => {
        resolve();
      });
    });
  }

  /** Stop the server / 停止伺服器 */
  async stop(): Promise<void> {
    this.authDB.close();
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
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
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');

    // CORS for development
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
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

  /** Handle API routes / 處理 API 路由 */
  private async handleApi(path: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader('Content-Type', 'application/json');

    try {
      switch (path) {
        case '/api/status':
          handleStatus(req, res);
          return;

        case '/api/scan/start':
          if (req.method === 'GET' || req.method === 'POST') {
            await handleScanStart(req, res);
          } else {
            this.methodNotAllowed(res);
          }
          return;

        case '/api/scan/latest':
          handleScanLatest(req, res);
          return;

        case '/api/report/frameworks':
          handleReportFrameworks(req, res);
          return;

        case '/api/report/generate':
          if (req.method === 'POST') {
            await handleReportGenerate(req, res);
          } else {
            this.methodNotAllowed(res);
          }
          return;

        case '/api/threat/stats':
          handleThreatStats(req, res);
          return;

        case '/api/guard/status':
          handleGuardStatus(req, res);
          return;

        case '/api/trap/status':
          await handleTrapStatus(req, res);
          return;

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

        default:
          // Handle /api/waitlist/verify/:token pattern
          if (path.startsWith('/api/waitlist/verify/')) {
            const token = path.slice('/api/waitlist/verify/'.length);
            this.authHandlers.handleWaitlistVerify(req, res, token);
            return;
          }
          // Handle /api/auth/google/callback?code=xxx pattern
          if (path === '/api/auth/google/callback') {
            const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
            const code = urlObj.searchParams.get('code');
            if (code) {
              await this.authHandlers.handleGoogleCallback(req, res, code);
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
      res.writeHead(500);
      res.end(JSON.stringify({
        ok: false,
        error: err instanceof Error ? err.message : 'Internal server error',
      }));
    }
  }

  /** Serve static files with SPA fallback / 提供靜態檔案（含 SPA 回退） */
  private async serveStatic(pathname: string, res: ServerResponse): Promise<void> {
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
}
