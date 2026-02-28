/**
 * panguard serve - Unified HTTP server gateway
 *
 * Serves auth API, admin API, admin dashboard UI, and health check.
 */

import { Command } from 'commander';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join, dirname, resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { c, banner } from '@panguard-ai/core';
import {
  AuthDB,
  createAuthHandlers,
  sendExpirationWarningEmail,
  initErrorTracking,
  captureRequestError,
} from '@panguard-ai/panguard-auth';
import type {
  AuthRouteConfig,
  SmtpConfig,
  GoogleOAuthConfig,
  GoogleSheetsConfig,
  LemonSqueezyConfig,
} from '@panguard-ai/panguard-auth';

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

      // Initialize error tracking (Sentry if configured, console fallback)
      await initErrorTracking();

      // Initialize database
      const db = new AuthDB(options.db);

      // Build config from environment
      const smtp: SmtpConfig | undefined = process.env['SMTP_HOST']
        ? {
            host: process.env['SMTP_HOST'],
            port: parseInt(process.env['SMTP_PORT'] ?? '587', 10),
            secure: process.env['SMTP_SECURE'] === 'true',
            from: process.env['SMTP_FROM'] ?? 'noreply@panguard.ai',
            auth: {
              user: process.env['SMTP_USER'] ?? '',
              pass: process.env['SMTP_PASS'] ?? '',
            },
          }
        : undefined;

      const google: GoogleOAuthConfig | undefined = process.env['GOOGLE_CLIENT_ID']
        ? {
            clientId: process.env['GOOGLE_CLIENT_ID'],
            clientSecret: process.env['GOOGLE_CLIENT_SECRET'] ?? '',
            redirectUri:
              process.env['GOOGLE_REDIRECT_URI'] ??
              `http://${host}:${port}/api/auth/google/callback`,
          }
        : undefined;

      const sheets: GoogleSheetsConfig | undefined = process.env['GOOGLE_SHEETS_ID']
        ? {
            spreadsheetId: process.env['GOOGLE_SHEETS_ID'],
            serviceAccountEmail: process.env['GOOGLE_SHEETS_SA_EMAIL'] ?? '',
            privateKey: process.env['GOOGLE_SHEETS_PRIVATE_KEY'] ?? '',
          }
        : undefined;

      const lemonsqueezy: LemonSqueezyConfig | undefined = process.env['LEMON_SQUEEZY_API_KEY']
        ? {
            apiKey: process.env['LEMON_SQUEEZY_API_KEY'],
            storeId: process.env['LEMON_SQUEEZY_STORE_ID'] ?? '',
            webhookSecret: process.env['LEMON_SQUEEZY_WEBHOOK_SECRET'] ?? '',
            variantTierMap: JSON.parse(process.env['LEMON_SQUEEZY_VARIANT_MAP'] ?? '{}') as Record<string, string>,
          }
        : undefined;

      const baseUrl = process.env['PANGUARD_BASE_URL'] ?? `http://${host}:${port}`;

      const authConfig: AuthRouteConfig = { db, smtp, baseUrl, google, sheets, lemonsqueezy };
      const handlers = createAuthHandlers(authConfig);

      // Resolve admin static directory
      // Try multiple locations: sibling package, or relative to CWD
      const thisDir = dirname(fileURLToPath(import.meta.url));
      const adminDirs = [
        join(process.cwd(), 'packages', 'admin'),
        join(thisDir, '..', '..', '..', '..', 'admin'),
      ];
      const adminDir = adminDirs.find((d) => existsSync(d));

      const server = createServer((req, res) => {
        void handleRequest(req, res, handlers, db, adminDir);
      });

      server.listen(port, host, () => {
        console.log(`  ${c.safe('Server started')} on ${c.bold(`http://${host}:${port}`)}`);
        console.log('');
        console.log(`  Routes:`);
        console.log(`    ${c.dim('/api/auth/*')}     Auth API`);
        console.log(`    ${c.dim('/api/admin/*')}    Admin API`);
        if (lemonsqueezy) {
          console.log(`    ${c.dim('/api/billing/*')}  Billing API (Lemon Squeezy)`);
        }
        console.log(`    ${c.dim('/api/usage/*')}    Usage & Quota API`);
        if (adminDir) {
          console.log(`    ${c.dim('/admin')}          Admin Dashboard`);
        } else {
          console.log(
            `    ${c.dim('/admin')}          ${c.caution('Not found')} (packages/admin/ missing)`
          );
        }
        console.log(`    ${c.dim('/health')}         Health check`);
        console.log('');
      });

      // Subscription lifecycle: check expired plans hourly
      const runPlanCheck = () => {
        const expired = db.checkExpiredPlans();
        if (expired.length > 0) {
          console.log(`  [Plan] Downgraded ${expired.length} expired plan(s) to free tier`);
        }

        // Send warning emails for plans expiring in 3 days
        if (smtp) {
          const expiring = db.getExpiringPlans(3);
          for (const user of expiring) {
            sendExpirationWarningEmail(
              smtp,
              user.email,
              user.name,
              user.tier,
              user.planExpiresAt,
              baseUrl
            ).catch(() => {
              // Best-effort email delivery
            });
          }
          if (expiring.length > 0) {
            console.log(`  [Plan] Sent ${expiring.length} expiration warning email(s)`);
          }
        }
      };

      // Run immediately on startup, then every hour
      runPlanCheck();
      const planCheckTimer = setInterval(runPlanCheck, 60 * 60 * 1000);
      if (planCheckTimer.unref) planCheckTimer.unref();

      // Graceful shutdown
      const shutdown = () => {
        console.log('\n  Shutting down...');
        clearInterval(planCheckTimer);
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
  adminDir: string | undefined
): Promise<void> {
  const url = req.url ?? '/';
  const pathname = url.split('?')[0] ?? '/';

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');

  // CORS — default to same-origin only; set CORS_ALLOWED_ORIGINS to allow cross-origin
  const corsEnv = process.env['CORS_ALLOWED_ORIGINS'] ?? '';
  const allowedOrigins = corsEnv ? corsEnv.split(',').map((o) => o.trim()) : [];
  const origin = req.headers.origin ?? '';
  if (allowedOrigins.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  } else if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
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
    if (pathname === '/api/auth/delete-account') {
      await handlers.handleDeleteAccount(req, res);
      return;
    }
    if (pathname === '/api/auth/export-data') {
      handlers.handleExportData(req, res);
      return;
    }
    if (pathname === '/api/auth/totp/setup') {
      handlers.handleTotpSetup(req, res);
      return;
    }
    if (pathname === '/api/auth/totp/verify') {
      await handlers.handleTotpVerify(req, res);
      return;
    }
    if (pathname === '/api/auth/totp/disable') {
      await handlers.handleTotpDisable(req, res);
      return;
    }
    if (pathname === '/api/auth/totp/status') {
      handlers.handleTotpStatus(req, res);
      return;
    }
    if (pathname === '/api/auth/forgot-password') {
      await handlers.handleForgotPassword(req, res);
      return;
    }
    if (pathname === '/api/auth/reset-password') {
      await handlers.handleResetPassword(req, res);
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

    // Billing API routes (Lemon Squeezy)
    if (pathname === '/api/billing/webhook') {
      await handlers.handleBillingWebhook(req, res);
      return;
    }
    if (pathname === '/api/billing/checkout') {
      await handlers.handleBillingCheckout(req, res);
      return;
    }
    if (pathname === '/api/billing/portal') {
      await handlers.handleBillingPortal(req, res);
      return;
    }
    if (pathname === '/api/billing/status') {
      handlers.handleBillingStatus(req, res);
      return;
    }

    // Usage / Quota API routes
    if (pathname === '/api/usage') {
      handlers.handleUsageSummary(req, res);
      return;
    }
    if (pathname === '/api/usage/limits') {
      handlers.handleUsageLimits(req, res);
      return;
    }
    if (pathname === '/api/usage/check') {
      await handlers.handleUsageCheck(req, res);
      return;
    }
    if (pathname === '/api/usage/record') {
      await handlers.handleUsageRecord(req, res);
      return;
    }

    // Admin API routes
    if (pathname === '/api/admin/dashboard') {
      handlers.handleAdminDashboard(req, res);
      return;
    }
    if (pathname === '/api/admin/users/search') {
      handlers.handleAdminUsersSearch(req, res);
      return;
    }
    if (pathname === '/api/admin/users') {
      handlers.handleAdminUsers(req, res);
      return;
    }
    if (pathname === '/api/admin/stats') {
      handlers.handleAdminStats(req, res);
      return;
    }
    if (pathname === '/api/admin/sessions') {
      if (req.method === 'GET') {
        handlers.handleAdminSessions(req, res);
      } else {
        sendJson(res, 405, { ok: false, error: 'Method not allowed' });
      }
      return;
    }
    if (pathname === '/api/admin/activity') {
      handlers.handleAdminActivity(req, res);
      return;
    }

    // /api/admin/sessions/:id (DELETE)
    const sessionRevokeMatch = pathname.match(/^\/api\/admin\/sessions\/(\d+)$/);
    if (sessionRevokeMatch) {
      handlers.handleAdminSessionRevoke(req, res, sessionRevokeMatch[1]!);
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
    captureRequestError(err, req.method ?? 'UNKNOWN', pathname);
    sendJson(res, 500, { ok: false, error: 'Internal server error' });
  }
}

function serveStaticFile(
  _req: IncomingMessage,
  res: ServerResponse,
  adminDir: string,
  pathname: string
): void {
  // Map /admin -> /admin/index.html
  const resolvedAdminDir = resolve(adminDir);
  let filePath: string;
  if (pathname === '/admin' || pathname === '/admin/') {
    filePath = join(resolvedAdminDir, 'index.html');
  } else {
    // Strip /admin prefix and leading slash
    const relative = pathname.slice('/admin'.length).replace(/^\//, '');
    filePath = join(resolvedAdminDir, relative);

    // If no extension, try .html
    if (!relative.includes('.')) {
      filePath = join(resolvedAdminDir, relative + '.html');
      if (!existsSync(filePath)) {
        filePath = join(resolvedAdminDir, relative, 'index.html');
      }
    }
  }

  // Prevent path traversal: resolved path must be within admin directory
  if (!filePath.startsWith(resolvedAdminDir)) {
    sendJson(res, 403, { ok: false, error: 'Forbidden' });
    return;
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
