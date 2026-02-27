/**
 * panguard serve - Unified HTTP server gateway
 *
 * Serves auth API, admin API, admin dashboard UI, and health check.
 */

import { Command } from 'commander';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { c, banner } from '@openclaw/core';
import { AuthDB, createAuthHandlers } from '@openclaw/panguard-auth';
import type { AuthRouteConfig, SmtpConfig, GoogleOAuthConfig, GoogleSheetsConfig } from '@openclaw/panguard-auth';

export function serveCommand(): Command {
  return new Command('serve')
    .description('Start unified HTTP server / 啟動統一 HTTP 伺服器')
    .option('--port <port>', 'Port number', '3000')
    .option('--host <host>', 'Host to bind', '127.0.0.1')
    .option('--db <path>', 'Database path', join(homedir(), '.panguard', 'auth.db'))
    .action(async (options: { port: string; host: string; db: string }) => {
      const port = parseInt(options.port, 10);
      const host = options.host;

      console.log(banner());
      console.log(`  ${c.sage('Panguard Serve')} - Unified Server Gateway`);
      console.log('');

      // Initialize database
      const db = new AuthDB(options.db);

      // Build config from environment
      const smtp: SmtpConfig | undefined = process.env['SMTP_HOST'] ? {
        host: process.env['SMTP_HOST'],
        port: parseInt(process.env['SMTP_PORT'] ?? '587', 10),
        secure: process.env['SMTP_SECURE'] === 'true',
        from: process.env['SMTP_FROM'] ?? 'noreply@panguard.ai',
        auth: {
          user: process.env['SMTP_USER'] ?? '',
          pass: process.env['SMTP_PASS'] ?? '',
        },
      } : undefined;

      const google: GoogleOAuthConfig | undefined = process.env['GOOGLE_CLIENT_ID'] ? {
        clientId: process.env['GOOGLE_CLIENT_ID'],
        clientSecret: process.env['GOOGLE_CLIENT_SECRET'] ?? '',
        redirectUri: process.env['GOOGLE_REDIRECT_URI'] ?? `http://${host}:${port}/api/auth/google/callback`,
      } : undefined;

      const sheets: GoogleSheetsConfig | undefined = process.env['GOOGLE_SHEETS_ID'] ? {
        spreadsheetId: process.env['GOOGLE_SHEETS_ID'],
        serviceAccountEmail: process.env['GOOGLE_SHEETS_SA_EMAIL'] ?? '',
        privateKey: process.env['GOOGLE_SHEETS_PRIVATE_KEY'] ?? '',
      } : undefined;

      const baseUrl = process.env['PANGUARD_BASE_URL'] ?? `http://${host}:${port}`;

      const authConfig: AuthRouteConfig = { db, smtp, baseUrl, google, sheets };
      const handlers = createAuthHandlers(authConfig);

      // Resolve admin static directory
      // Try multiple locations: sibling package, or relative to CWD
      const adminDirs = [
        join(process.cwd(), 'packages', 'admin'),
        join(__dirname, '..', '..', '..', '..', 'admin'),
      ];
      const adminDir = adminDirs.find(d => existsSync(d));

      const server = createServer((req, res) => {
        void handleRequest(req, res, handlers, db, adminDir);
      });

      server.listen(port, host, () => {
        console.log(`  ${c.safe('Server started')} on ${c.bold(`http://${host}:${port}`)}`);
        console.log('');
        console.log(`  Routes:`);
        console.log(`    ${c.dim('/api/auth/*')}     Auth API`);
        console.log(`    ${c.dim('/api/admin/*')}    Admin API`);
        if (adminDir) {
          console.log(`    ${c.dim('/admin')}          Admin Dashboard`);
        } else {
          console.log(`    ${c.dim('/admin')}          ${c.caution('Not found')} (packages/admin/ missing)`);
        }
        console.log(`    ${c.dim('/health')}         Health check`);
        console.log('');
      });

      // Graceful shutdown
      const shutdown = () => {
        console.log('\n  Shutting down...');
        server.close(() => {
          db.close();
          process.exit(0);
        });
      };
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
    });
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  handlers: ReturnType<typeof createAuthHandlers>,
  _db: AuthDB,
  adminDir: string | undefined,
): Promise<void> {
  const url = req.url ?? '/';
  const pathname = url.split('?')[0] ?? '/';

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');

  // CORS
  const allowedOrigins = (process.env['CORS_ALLOWED_ORIGINS'] ?? '*').split(',');
  const origin = req.headers.origin ?? '';
  if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // Health check
    if (pathname === '/health') {
      sendJson(res, 200, { ok: true, data: { status: 'healthy', uptime: process.uptime() } });
      return;
    }

    // Auth API routes
    if (pathname === '/api/auth/register') {
      await handlers.handleRegister(req, res);
      return;
    }
    if (pathname === '/api/auth/login') {
      await handlers.handleLogin(req, res);
      return;
    }
    if (pathname === '/api/auth/logout') {
      handlers.handleLogout(req, res);
      return;
    }
    if (pathname === '/api/auth/me') {
      handlers.handleMe(req, res);
      return;
    }
    if (pathname === '/api/auth/google') {
      handlers.handleGoogleAuth(req, res);
      return;
    }
    if (pathname.startsWith('/api/auth/google/callback')) {
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const code = urlObj.searchParams.get('code') ?? '';
      const state = urlObj.searchParams.get('state');
      await handlers.handleGoogleCallback(req, res, code, state);
      return;
    }
    if (pathname === '/api/auth/cli') {
      handlers.handleCliAuth(req, res);
      return;
    }
    if (pathname === '/api/auth/cli/exchange') {
      await handlers.handleCliExchange(req, res);
      return;
    }

    // Waitlist API routes
    if (pathname === '/api/waitlist/join') {
      await handlers.handleWaitlistJoin(req, res);
      return;
    }
    if (pathname.startsWith('/api/waitlist/verify/')) {
      const token = pathname.split('/api/waitlist/verify/')[1];
      handlers.handleWaitlistVerify(req, res, token ?? '');
      return;
    }
    if (pathname === '/api/waitlist/stats') {
      handlers.handleWaitlistStats(req, res);
      return;
    }
    if (pathname === '/api/waitlist/list') {
      handlers.handleWaitlistList(req, res);
      return;
    }

    // Admin API routes
    if (pathname === '/api/admin/users') {
      handlers.handleAdminUsers(req, res);
      return;
    }
    if (pathname === '/api/admin/stats') {
      handlers.handleAdminStats(req, res);
      return;
    }

    // /api/admin/users/:id/tier
    const tierMatch = pathname.match(/^\/api\/admin\/users\/(\d+)\/tier$/);
    if (tierMatch) {
      await handlers.handleAdminUpdateTier(req, res, tierMatch[1]!);
      return;
    }

    // /api/admin/users/:id/role
    const roleMatch = pathname.match(/^\/api\/admin\/users\/(\d+)\/role$/);
    if (roleMatch) {
      await handlers.handleAdminUpdateRole(req, res, roleMatch[1]!);
      return;
    }

    // /api/admin/waitlist/:id/approve
    const approveMatch = pathname.match(/^\/api\/admin\/waitlist\/(\d+)\/approve$/);
    if (approveMatch) {
      await handlers.handleAdminWaitlistApprove(req, res, approveMatch[1]!);
      return;
    }

    // /api/admin/waitlist/:id/reject
    const rejectMatch = pathname.match(/^\/api\/admin\/waitlist\/(\d+)\/reject$/);
    if (rejectMatch) {
      await handlers.handleAdminWaitlistReject(req, res, rejectMatch[1]!);
      return;
    }

    // Admin static files
    if (adminDir && pathname.startsWith('/admin')) {
      serveStaticFile(req, res, adminDir, pathname);
      return;
    }

    sendJson(res, 404, { ok: false, error: 'Not found' });
  } catch (err) {
    console.error('Request error:', err);
    sendJson(res, 500, { ok: false, error: 'Internal server error' });
  }
}

function serveStaticFile(
  _req: IncomingMessage,
  res: ServerResponse,
  adminDir: string,
  pathname: string,
): void {
  // Map /admin -> /admin/index.html
  let filePath: string;
  if (pathname === '/admin' || pathname === '/admin/') {
    filePath = join(adminDir, 'index.html');
  } else {
    // Strip /admin prefix
    const relative = pathname.slice('/admin'.length);
    filePath = join(adminDir, relative);

    // If no extension, try .html
    if (!relative.includes('.')) {
      filePath = join(adminDir, relative + '.html');
      if (!existsSync(filePath)) {
        filePath = join(adminDir, relative, 'index.html');
      }
    }
  }

  if (!existsSync(filePath)) {
    sendJson(res, 404, { ok: false, error: 'Not found' });
    return;
  }

  const ext = filePath.split('.').pop() ?? '';
  const mimeTypes: Record<string, string> = {
    html: 'text/html',
    css: 'text/css',
    js: 'application/javascript',
    json: 'application/json',
    png: 'image/png',
    svg: 'image/svg+xml',
    ico: 'image/x-icon',
  };

  const contentType = mimeTypes[ext] ?? 'application/octet-stream';
  const content = readFileSync(filePath);
  res.writeHead(200, { 'Content-Type': contentType });
  res.end(content);
}

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}
