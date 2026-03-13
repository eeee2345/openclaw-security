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
import { PANGUARD_VERSION } from '../../index.js';
import {
  AuthDB,
  createAuthHandlers,
  sendExpirationWarningEmail,
  initErrorTracking,
  captureRequestError,
  generateOpenApiSpec,
  generateSwaggerHtml,
  ManagerProxy,
  authenticateRequest,
  requireAdmin,
} from '@panguard-ai/panguard-auth';
import type {
  AuthRouteConfig,
  EmailConfig,
  GoogleOAuthConfig,
  GoogleSheetsConfig,
  LemonSqueezyConfig,
} from '@panguard-ai/panguard-auth';
import { ManagerServer, DEFAULT_MANAGER_CONFIG } from '@panguard-ai/manager';
import type { ManagerConfig } from '@panguard-ai/manager';

// Threat Cloud types (dynamically loaded — not published to npm)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ThreatCloudDBInstance = any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type LLMReviewerInstance = any;

export function serveCommand(): Command {
  return new Command('serve')
    .description('Start unified HTTP server / 啟動統一 HTTP 伺服器')
    .option('--port <port>', 'Port number', '3000')
    .option('--host <host>', 'Host to bind', '127.0.0.1')
    .option('--db <path>', 'Database path', join(homedir(), '.panguard', 'auth.db'))
    .option('--manager-port <port>', 'Manager server port / Manager 伺服器埠', '8443')
    .action(async (options: { port: string; host: string; db: string; managerPort: string }) => {
      const port = parseInt(options.port, 10);
      const host = options.host;

      console.log(banner(PANGUARD_VERSION));
      console.log(`  ${c.sage('Panguard Serve')} - Unified Server Gateway`);
      console.log('');

      // Startup environment validation
      const isProd = process.env['NODE_ENV'] === 'production';
      const errors: string[] = [];
      const warnings: string[] = [];

      // Critical in production
      if (isProd && !process.env['PANGUARD_BASE_URL']) {
        errors.push('PANGUARD_BASE_URL not set in production — OAuth and email links will break');
      }
      if (isProd && !process.env['CORS_ALLOWED_ORIGINS']) {
        errors.push(
          'CORS_ALLOWED_ORIGINS not set in production — API will reject cross-origin requests'
        );
      }

      // Warnings (non-fatal)
      if (!process.env['PANGUARD_BASE_URL']) {
        warnings.push('PANGUARD_BASE_URL not set — OAuth callbacks will use localhost');
      }
      if (!process.env['GOOGLE_CLIENT_ID']) {
        warnings.push('GOOGLE_CLIENT_ID not set — Google OAuth login disabled');
      }
      if (!process.env['RESEND_API_KEY'] && !process.env['SMTP_HOST']) {
        warnings.push(
          'No email config (RESEND_API_KEY or SMTP_HOST) — password reset and waitlist emails disabled'
        );
      }
      if (!process.env['SENTRY_DSN']) {
        warnings.push('SENTRY_DSN not set — error tracking disabled');
      }
      if (isProd && !process.env['MANAGER_AUTH_TOKEN']) {
        errors.push(
          'MANAGER_AUTH_TOKEN not set in production — Manager API would allow unauthenticated access'
        );
      }
      if (!isProd && !process.env['MANAGER_AUTH_TOKEN']) {
        warnings.push(
          'MANAGER_AUTH_TOKEN not set — Manager API allows unauthenticated access (OK for dev)'
        );
      }
      if (!process.env['TC_API_KEY']) {
        warnings.push(
          'TC_API_KEY not set — Threat Cloud write API disabled in production, open in dev'
        );
      }

      if (errors.length > 0) {
        console.error(`  ${c.critical('FATAL — Missing required environment variables:')}`);
        for (const e of errors) {
          console.error(`    ${c.critical('x')} ${e}`);
        }
        console.error('');
        console.error(`  Set the variables above and restart. Aborting.`);
        process.exit(1);
      }

      if (warnings.length > 0) {
        console.log(`  ${c.caution('Environment warnings:')}`);
        for (const w of warnings) {
          console.log(`    ${c.dim('-')} ${w}`);
        }
        console.log('');
      }

      // Initialize error tracking (Sentry if configured, console fallback)
      await initErrorTracking();

      // Initialize database
      const db = new AuthDB(options.db);

      // Initialize Threat Cloud database (optional — graceful if unavailable)
      let threatDb: ThreatCloudDBInstance = null;
      try {
        const tcMod = '@panguard-ai/threat-cloud';
        const tc = await import(/* webpackIgnore: true */ tcMod);
        const threatDbPath = join(dirname(options.db), 'threat-cloud.db');
        threatDb = new tc.ThreatCloudDB(threatDbPath);
        console.log(`  ${c.safe('Threat Cloud DB')} initialized at ${c.dim(threatDbPath)}`);

        // Auto-seed rules on first startup if rules table is empty
        const stats = threatDb.getStats();
        if (stats.totalRules === 0) {
          console.log(`  ${c.sage('Seeding rules...')} (first startup detected)`);
          const seeded = await seedRulesFromBundled(threatDb);
          console.log(`  ${c.safe(`Seeded ${seeded} rules`)} into Threat Cloud DB`);
        } else {
          console.log(
            `  ${c.dim(`Threat Cloud: ${stats.totalRules} rules, ${stats.totalThreats} threats`)}`
          );
        }
        console.log('');
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  [ERROR] Threat Cloud initialization failed: ${msg}`);
        if (err instanceof Error && err.stack) {
          console.error(`  ${err.stack}`);
        }
        console.log(`  ${c.dim('Threat Cloud API routes disabled due to error above')}`);
        console.log('');
      }

      // Initialize LLM Reviewer for ATR proposals (optional — needs ANTHROPIC_API_KEY)
      let llmReviewer: LLMReviewerInstance = null;
      if (threatDb && process.env['ANTHROPIC_API_KEY']) {
        try {
          const tcMod = '@panguard-ai/threat-cloud';
          const tc = await import(/* webpackIgnore: true */ tcMod);
          llmReviewer = new tc.LLMReviewer(process.env['ANTHROPIC_API_KEY'], threatDb);
          console.log(`  ${c.safe('LLM Reviewer')} enabled for ATR proposal review`);
        } catch {
          console.log(`  ${c.dim('LLM Reviewer not available')}`);
        }
      }

      // Promotion cron: every 15 minutes, promote confirmed + LLM-approved proposals to rules
      let promotionTimer: ReturnType<typeof setInterval> | null = null;
      if (threatDb) {
        promotionTimer = setInterval(
          () => {
            try {
              const promoted = threatDb.promoteConfirmedProposals();
              if (promoted > 0) {
                console.log(`  [Promotion] ${promoted} proposal(s) promoted to rules`);
              }
            } catch (err: unknown) {
              console.error(
                `  [Promotion] Error: ${err instanceof Error ? err.message : String(err)}`
              );
            }
          },
          15 * 60 * 1000
        );
      }

      // Periodic database backup (every 6 hours)
      let backupTimer: ReturnType<typeof setInterval> | null = null;
      if (threatDb) {
        try {
          const tcMod2 = '@panguard-ai/threat-cloud';
          const tc2 = await import(/* webpackIgnore: true */ tcMod2);
          const backupDir = join(dirname(options.db), 'backups');
          const threatBackup = new tc2.BackupManager(
            join(dirname(options.db), 'threat-cloud.db'),
            backupDir,
            7
          );
          const authBackup = new tc2.BackupManager(options.db, backupDir, 7);

          const runBackups = () => {
            try {
              const r1 = threatBackup.backup();
              const r2 = authBackup.backup();
              console.log(
                `  [Backup] threat-cloud.db (${tc2.BackupManager.formatSize(r1.sizeBytes)}), auth.db (${tc2.BackupManager.formatSize(r2.sizeBytes)})`
              );
            } catch (err: unknown) {
              console.error(
                `  [Backup] Failed: ${err instanceof Error ? err.message : String(err)}`
              );
            }
          };

          // Initial backup on startup
          runBackups();

          // Every 6 hours
          backupTimer = setInterval(runBackups, 6 * 60 * 60 * 1000);
          if (backupTimer.unref) backupTimer.unref();
        } catch {
          console.log(`  ${c.dim('Backup manager not available — auto-backups disabled')}`);
        }
      }

      // Build config from environment
      // Prefer Resend API when RESEND_API_KEY is set; fall back to raw SMTP
      const emailConfig: EmailConfig | undefined = process.env['RESEND_API_KEY']
        ? {
            apiKey: process.env['RESEND_API_KEY'],
            from:
              process.env['RESEND_FROM'] ??
              process.env['SMTP_FROM'] ??
              'Panguard AI <noreply@panguard.ai>',
          }
        : process.env['SMTP_HOST']
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
            variantTierMap: JSON.parse(process.env['LEMON_SQUEEZY_VARIANT_MAP'] ?? '{}') as Record<
              string,
              string
            >,
          }
        : undefined;

      const baseUrl = process.env['PANGUARD_BASE_URL'] ?? `http://${host}:${port}`;

      const authConfig: AuthRouteConfig = {
        db,
        smtp: emailConfig,
        baseUrl,
        google,
        sheets,
        lemonsqueezy,
      };
      const handlers = createAuthHandlers(authConfig);

      // Initialize Manager proxy for agent/event admin API routes
      const managerProxy = new ManagerProxy(
        process.env['MANAGER_URL'],
        process.env['MANAGER_AUTH_TOKEN']
      );

      // Resolve admin static directory
      // Try multiple locations: sibling package, or relative to CWD
      const thisDir = dirname(fileURLToPath(import.meta.url));
      const adminDirs = [
        join(process.cwd(), 'packages', 'admin'),
        join(thisDir, '..', '..', '..', '..', 'admin'),
      ];
      const adminDir = adminDirs.find((d) => existsSync(d));

      const server = createServer((req, res) => {
        void handleRequest(req, res, handlers, db, adminDir, managerProxy, threatDb, llmReviewer);
      });

      // Build Manager config from environment / 從環境變數建構 Manager 設定
      const managerPort = parseInt(options.managerPort, 10);
      const managerConfig: ManagerConfig = {
        ...DEFAULT_MANAGER_CONFIG,
        port: managerPort,
        authToken: process.env['MANAGER_AUTH_TOKEN'] ?? '',
      };
      const managerServer = new ManagerServer(managerConfig);

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
        console.log(`    ${c.dim('/docs/api')}        API Documentation (Swagger UI)`);
        console.log(`    ${c.dim('/openapi.json')}    OpenAPI 3.0 Spec`);
        console.log(`    ${c.dim('/health')}         Health check`);
        console.log(`    ${c.dim('/api/manager/*')}  Manager API (port ${managerPort})`);
        if (threatDb) {
          console.log(`    ${c.dim('/api/threats')}     Threat Cloud API (POST)`);
          console.log(`    ${c.dim('/api/rules')}       Rule Distribution (GET/POST)`);
          console.log(`    ${c.dim('/api/stats')}       Threat Statistics (GET)`);
        }
        console.log('');
        console.log(`  Services:`);
        console.log(
          `    Email:   ${emailConfig ? ('apiKey' in emailConfig ? c.safe('Resend API') : c.safe('SMTP')) : c.caution('Not configured')}`
        );
        console.log(`    OAuth:   ${google ? c.safe('Google') : c.dim('Not configured')}`);
        console.log(
          `    Billing: ${lemonsqueezy ? c.safe('Lemon Squeezy') : c.dim('Not configured')}`
        );
        console.log(`    Sheets:  ${sheets ? c.safe('Google Sheets') : c.dim('Not configured')}`);
        console.log(
          `    Manager: ${c.safe(`port ${managerPort}`)}${process.env['MANAGER_AUTH_TOKEN'] ? '' : c.dim(' (no auth)')}`
        );
        console.log('');

        // Start Manager server after auth server is listening / 在 Auth 伺服器啟動後啟動 Manager 伺服器
        managerServer
          .start()
          .then(() => {
            console.log(
              `  ${c.safe('Manager server started')} on ${c.bold(`http://${host}:${managerPort}`)}`
            );
            console.log('');
          })
          .catch((err: unknown) => {
            const message = err instanceof Error ? err.message : String(err);
            console.log(`  ${c.caution('Manager server failed to start:')} ${message}`);
            console.log(`  ${c.dim('Auth server continues running without Manager')}`);
            console.log('');
          });
      });

      // Subscription lifecycle: check expired plans hourly
      const runPlanCheck = () => {
        const expired = db.checkExpiredPlans();
        if (expired.length > 0) {
          console.log(`  [Plan] Downgraded ${expired.length} expired plan(s) to community tier`);
        }

        // Send warning emails for plans expiring in 3 days
        if (emailConfig) {
          const expiring = db.getExpiringPlans(3);
          for (const user of expiring) {
            sendExpirationWarningEmail(
              emailConfig,
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

      // Graceful shutdown / 優雅關閉
      const shutdown = () => {
        console.log('\n  Shutting down...');
        clearInterval(planCheckTimer);
        if (backupTimer) clearInterval(backupTimer);
        if (promotionTimer) clearInterval(promotionTimer);
        managerServer.stop().catch(() => {});
        server.close(() => {
          db.close();
          if (threatDb) threatDb.close();
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
  managerProxy: ManagerProxy,
  threatDb: ThreatCloudDBInstance,
  llmReviewer: LLMReviewerInstance
): Promise<void> {
  const url = req.url ?? '/';
  const pathname = url.split('?')[0] ?? '/';

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('X-XSS-Protection', '0');
  if (process.env['NODE_ENV'] === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  // CORS — default to same-origin only; set CORS_ALLOWED_ORIGINS to allow cross-origin
  const corsEnv = process.env['CORS_ALLOWED_ORIGINS'] ?? '';
  const allowedOrigins = corsEnv ? corsEnv.split(',').map((o) => o.trim()) : [];
  const origin = req.headers.origin ?? '';
  if (allowedOrigins.includes('*') && process.env['NODE_ENV'] !== 'production') {
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
    // OpenAPI spec (JSON)
    if (pathname === '/openapi.json') {
      const spec = generateOpenApiSpec(
        process.env['PANGUARD_BASE_URL'] ?? `http://${req.headers.host ?? 'localhost'}`
      );
      sendJson(res, 200, spec);
      return;
    }

    // Swagger UI
    if (pathname === '/docs/api' || pathname === '/docs/api/') {
      const specUrl = '/openapi.json';
      const html = generateSwaggerHtml(specUrl);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    // Health check (minimal public response — detailed status behind /api/admin/health)
    if (pathname === '/health') {
      try {
        _db.healthCheck();
        sendJson(res, 200, {
          ok: true,
          data: {
            status: 'healthy',
            uptime: Math.round(process.uptime()),
            db: 'connected',
            threatCloud: threatDb ? 'connected' : 'unavailable',
          },
        });
      } catch {
        sendJson(res, 503, {
          ok: false,
          data: { status: 'unhealthy', db: 'disconnected' },
        });
      }
      return;
    }

    // Detailed health (admin-only) — includes memory, services, threat stats
    if (pathname === '/api/admin/health' && req.method === 'GET') {
      const mem = process.memoryUsage();
      const services = {
        email: !!(process.env['RESEND_API_KEY'] || process.env['SMTP_HOST']),
        oauth: !!process.env['GOOGLE_CLIENT_ID'],
        billing: !!process.env['LEMON_SQUEEZY_API_KEY'],
        errorTracking: !!process.env['SENTRY_DSN'],
        threatCloud: !!threatDb,
        tcApiKey: !!process.env['TC_API_KEY'],
      };
      let threatStats = null;
      if (threatDb) {
        try {
          const s = threatDb.getStats();
          threatStats = { rules: s.totalRules, threats: s.totalThreats };
        } catch {
          /* ignore */
        }
      }
      sendJson(res, 200, {
        ok: true,
        data: {
          status: 'healthy',
          version: process.env['npm_package_version'] ?? '0.0.0',
          uptime: Math.round(process.uptime()),
          db: 'connected',
          threatStats,
          memory: {
            rss: Math.round(mem.rss / 1024 / 1024),
            heapUsed: Math.round(mem.heapUsed / 1024 / 1024),
          },
          services,
        },
      });
      return;
    }

    // ── Threat Cloud API Routes ────────────────────────────────────
    // Security: rate limiting, auth, input validation

    // Rate limit for Threat Cloud endpoints (per-IP, shared state)
    if (
      threatDb &&
      pathname.startsWith('/api/') &&
      [
        '/api/threats',
        '/api/rules',
        '/api/stats',
        '/api/atr-proposals',
        '/api/atr-feedback',
        '/api/skill-threats',
        '/api/atr-rules',
        '/api/yara-rules',
        '/api/feeds/ip-blocklist',
        '/api/feeds/domain-blocklist',
      ].some((p) => pathname === p)
    ) {
      const clientIP = req.socket.remoteAddress ?? 'unknown';
      if (!checkTCRateLimit(clientIP)) {
        sendJson(res, 429, { ok: false, error: 'Rate limit exceeded. Try again later.' });
        return;
      }
    }

    // POST /api/threats - Upload anonymized threat data
    if (pathname === '/api/threats' && req.method === 'POST') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      if (!requireTCWriteAuth(req, res)) return;
      if (!requireJsonContentType(req, res)) return;
      const body = await readRequestBody(req);
      let data: Record<string, unknown>;
      try {
        data = JSON.parse(body) as Record<string, unknown>;
      } catch {
        sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
        return;
      }
      if (
        !data['attackSourceIP'] ||
        !data['attackType'] ||
        !data['mitreTechnique'] ||
        !data['sigmaRuleMatched'] ||
        !data['timestamp'] ||
        !data['region']
      ) {
        sendJson(res, 400, { ok: false, error: 'Missing required fields' });
        return;
      }
      // Anonymize IP (zero last octet)
      const ip = String(data['attackSourceIP']);
      if (ip.includes('.')) {
        const parts = ip.split('.');
        if (parts.length === 4) {
          parts[3] = '0';
          data['attackSourceIP'] = parts.join('.');
        }
      }
      threatDb.insertThreat(data);
      sendJson(res, 201, { ok: true, data: { message: 'Threat data received' } });
      return;
    }

    // GET /api/rules - Fetch rules (optional ?since= filter, paginated)
    if (pathname === '/api/rules' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const since = urlObj.searchParams.get('since');
      // Validate since parameter format (ISO 8601)
      if (since && !/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?/.test(since)) {
        sendJson(res, 400, { ok: false, error: 'Invalid since parameter: must be ISO 8601' });
        return;
      }
      const rawLimit = parseInt(urlObj.searchParams.get('limit') ?? '1000', 10);
      const limit = isNaN(rawLimit) || rawLimit < 1 ? 1000 : Math.min(rawLimit, 5000);
      const rules = since ? threatDb.getRulesSince(since) : threatDb.getAllRules(limit);
      sendJson(res, 200, { ok: true, data: rules });
      return;
    }

    // POST /api/rules - Publish a new community rule
    if (pathname === '/api/rules' && req.method === 'POST') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      if (!requireTCWriteAuth(req, res)) return;
      if (!requireJsonContentType(req, res)) return;
      const body = await readRequestBody(req);
      let rule: Record<string, unknown>;
      try {
        rule = JSON.parse(body) as Record<string, unknown>;
      } catch {
        sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
        return;
      }
      if (!rule['ruleId'] || !rule['ruleContent'] || !rule['source']) {
        sendJson(res, 400, {
          ok: false,
          error: 'Missing required fields: ruleId, ruleContent, source',
        });
        return;
      }
      // Field-level size limits
      if (String(rule['ruleContent']).length > 65_536) {
        sendJson(res, 400, { ok: false, error: 'ruleContent exceeds maximum size of 64KB' });
        return;
      }
      if (String(rule['ruleId']).length > 256) {
        sendJson(res, 400, { ok: false, error: 'ruleId exceeds maximum length of 256' });
        return;
      }
      rule['publishedAt'] = rule['publishedAt'] || new Date().toISOString();
      threatDb.upsertRule(rule);
      sendJson(res, 201, { ok: true, data: { message: 'Rule published', ruleId: rule['ruleId'] } });
      return;
    }

    // GET /api/stats - Threat statistics
    if (pathname === '/api/stats' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      const stats = threatDb.getStats();
      sendJson(res, 200, { ok: true, data: stats });
      return;
    }

    // POST /api/atr-proposals - Submit ATR rule proposal
    if (pathname === '/api/atr-proposals' && req.method === 'POST') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      if (!requireTCWriteAuth(req, res)) return;
      if (!requireJsonContentType(req, res)) return;
      const body = await readRequestBody(req);
      let proposal: Record<string, unknown>;
      try {
        proposal = JSON.parse(body) as Record<string, unknown>;
      } catch {
        sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
        return;
      }
      if (
        !proposal['patternHash'] ||
        !proposal['ruleContent'] ||
        !proposal['llmProvider'] ||
        !proposal['llmModel'] ||
        !proposal['selfReviewVerdict']
      ) {
        sendJson(res, 400, { ok: false, error: 'Missing required fields' });
        return;
      }
      // Validate and sanitize client ID
      const rawClientId = req.headers['x-panguard-client-id'];
      const clientId =
        typeof rawClientId === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(rawClientId)
          ? rawClientId
          : null;
      proposal['clientId'] = clientId;

      // Check if this pattern already has a proposal - if so, increment confirmation
      const pHash = String(proposal['patternHash']);
      const existing = threatDb
        .getATRProposals()
        .find((p: Record<string, unknown>) => p['pattern_hash'] === pHash);
      if (existing) {
        threatDb.confirmATRProposal(pHash);
        sendJson(res, 200, {
          ok: true,
          data: { message: 'Confirmation recorded', patternHash: pHash },
        });
      } else {
        threatDb.insertATRProposal(proposal);
        // Fire-and-forget LLM review on first submission
        if (llmReviewer?.isAvailable()) {
          void llmReviewer
            .reviewProposal(pHash, String(proposal['ruleContent']))
            .catch((err: unknown) => {
              console.error(`LLM review error for ${pHash}:`, err);
            });
        }
        sendJson(res, 201, {
          ok: true,
          data: { message: 'Proposal submitted', patternHash: pHash },
        });
      }
      return;
    }

    // GET /api/atr-proposals - List proposals (admin-only)
    if (pathname === '/api/atr-proposals' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      if (!requireTCAdminAuth(req, res, _db)) return;
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const status = urlObj.searchParams.get('status') ?? undefined;
      const proposals = threatDb.getATRProposals(status);
      sendJson(res, 200, { ok: true, data: proposals });
      return;
    }

    // POST /api/atr-feedback - Report ATR rule match feedback
    if (pathname === '/api/atr-feedback' && req.method === 'POST') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      if (!requireTCWriteAuth(req, res)) return;
      if (!requireJsonContentType(req, res)) return;
      const body = await readRequestBody(req);
      let feedback: Record<string, unknown>;
      try {
        feedback = JSON.parse(body) as Record<string, unknown>;
      } catch {
        sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
        return;
      }
      if (!feedback['ruleId'] || typeof feedback['isTruePositive'] !== 'boolean') {
        sendJson(res, 400, {
          ok: false,
          error: 'Missing or invalid fields: ruleId (string), isTruePositive (boolean)',
        });
        return;
      }
      const rawCid = req.headers['x-panguard-client-id'];
      const cid =
        typeof rawCid === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(rawCid) ? rawCid : null;
      threatDb.insertATRFeedback(
        String(feedback['ruleId']),
        feedback['isTruePositive'] as boolean,
        cid
      );
      sendJson(res, 201, { ok: true, data: { message: 'Feedback recorded' } });
      return;
    }

    // POST /api/skill-threats - Submit skill audit result
    if (pathname === '/api/skill-threats' && req.method === 'POST') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      if (!requireTCWriteAuth(req, res)) return;
      if (!requireJsonContentType(req, res)) return;
      const body = await readRequestBody(req);
      let submission: Record<string, unknown>;
      try {
        submission = JSON.parse(body) as Record<string, unknown>;
      } catch {
        sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
        return;
      }
      const VALID_RISK_LEVELS = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
      if (!submission['skillHash'] || !submission['skillName']) {
        sendJson(res, 400, { ok: false, error: 'Missing required fields: skillHash, skillName' });
        return;
      }
      const riskScore = submission['riskScore'];
      if (
        typeof riskScore !== 'number' ||
        !isFinite(riskScore) ||
        riskScore < 0 ||
        riskScore > 100
      ) {
        sendJson(res, 400, { ok: false, error: 'riskScore must be a number between 0 and 100' });
        return;
      }
      if (!VALID_RISK_LEVELS.has(String(submission['riskLevel']))) {
        sendJson(res, 400, {
          ok: false,
          error: 'riskLevel must be one of: LOW, MEDIUM, HIGH, CRITICAL',
        });
        return;
      }
      const rawCid2 = req.headers['x-panguard-client-id'];
      submission['clientId'] =
        typeof rawCid2 === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(rawCid2) ? rawCid2 : null;
      threatDb.insertSkillThreat(submission);
      sendJson(res, 201, { ok: true, data: { message: 'Skill threat recorded' } });
      return;
    }

    // GET /api/skill-threats - List skill threats (admin-only)
    if (pathname === '/api/skill-threats' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      if (!requireTCAdminAuth(req, res, _db)) return;
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const rawLimit = parseInt(urlObj.searchParams.get('limit') ?? '50', 10);
      const limit = isNaN(rawLimit) || rawLimit < 1 ? 50 : Math.min(rawLimit, 500);
      const threats = threatDb.getSkillThreats(limit);
      sendJson(res, 200, { ok: true, data: threats });
      return;
    }

    // GET /api/atr-rules - Fetch confirmed ATR rules (for Guard sync)
    if (pathname === '/api/atr-rules' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const since = urlObj.searchParams.get('since') ?? undefined;
      const rules = threatDb.getConfirmedATRRules(since);
      sendJson(res, 200, { ok: true, data: rules });
      return;
    }

    // GET /api/yara-rules - Fetch YARA rules (for Guard sync)
    if (pathname === '/api/yara-rules' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const since = urlObj.searchParams.get('since') ?? undefined;
      const rules = threatDb.getRulesBySource('yara', since);
      sendJson(res, 200, { ok: true, data: rules });
      return;
    }

    // GET /api/feeds/ip-blocklist - IP blocklist feed (plain text)
    if (pathname === '/api/feeds/ip-blocklist' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const minReputation = Number(urlObj.searchParams.get('minReputation') ?? '70');
      const ips = threatDb.getIPBlocklist(minReputation);
      res.setHeader('Content-Type', 'text/plain');
      res.writeHead(200);
      res.end(ips.join('\n'));
      return;
    }

    // GET /api/feeds/domain-blocklist - Domain blocklist feed (plain text)
    if (pathname === '/api/feeds/domain-blocklist' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const minReputation = Number(urlObj.searchParams.get('minReputation') ?? '70');
      const domains = threatDb.getDomainBlocklist(minReputation);
      res.setHeader('Content-Type', 'text/plain');
      res.writeHead(200);
      res.end(domains.join('\n'));
      return;
    }

    // POST /api/skill-whitelist - Report safe skill (audit passed)
    if (pathname === '/api/skill-whitelist' && req.method === 'POST') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      if (!requireTCWriteAuth(req, res)) return;
      if (!requireJsonContentType(req, res)) return;
      const body = await readRequestBody(req);
      let data: Record<string, unknown>;
      try {
        data = JSON.parse(body) as Record<string, unknown>;
      } catch {
        sendJson(res, 400, { ok: false, error: 'Invalid JSON body' });
        return;
      }

      const skills =
        'skills' in data && Array.isArray(data['skills'])
          ? (data['skills'] as Array<Record<string, unknown>>)
          : [data];

      let count = 0;
      for (const skill of skills) {
        const name = skill['skillName'];
        if (!name || typeof name !== 'string') continue;
        threatDb.reportSafeSkill(
          name,
          typeof skill['fingerprintHash'] === 'string' ? skill['fingerprintHash'] : undefined
        );
        count++;
      }
      sendJson(res, 201, { ok: true, data: { message: `${count} skill(s) reported`, count } });
      return;
    }

    // GET /api/skill-whitelist - Fetch community whitelist
    if (pathname === '/api/skill-whitelist' && req.method === 'GET') {
      if (!threatDb) {
        sendJson(res, 503, { ok: false, error: 'Threat Cloud not available' });
        return;
      }
      const whitelist = threatDb.getSkillWhitelist();
      sendJson(res, 200, { ok: true, data: whitelist });
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
    if (pathname === '/api/auth/oauth/exchange') {
      await handlers.handleOAuthExchange(req, res);
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
    if (pathname === '/api/admin/audit/actions') {
      handlers.handleAdminAuditActions(req, res);
      return;
    }
    if (pathname === '/api/admin/audit') {
      handlers.handleAdminAuditLog(req, res);
      return;
    }
    if (pathname === '/api/admin/usage') {
      handlers.handleAdminUsageOverview(req, res);
      return;
    }
    if (pathname === '/api/admin/users/bulk-action') {
      await handlers.handleAdminBulkAction(req, res);
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

    // /api/admin/users/:id/suspend
    const suspendMatch = pathname.match(/^\/api\/admin\/users\/(\d+)\/suspend$/);
    if (suspendMatch) {
      await handlers.handleAdminUserSuspend(req, res, suspendMatch[1]!);
      return;
    }

    // /api/admin/usage/:userId
    const usageUserMatch = pathname.match(/^\/api\/admin\/usage\/(\d+)$/);
    if (usageUserMatch) {
      handlers.handleAdminUsageUser(req, res, usageUserMatch[1]!);
      return;
    }

    // /api/admin/users/:id (GET — user detail)
    const userDetailMatch = pathname.match(/^\/api\/admin\/users\/(\d+)$/);
    if (userDetailMatch && req.method === 'GET') {
      handlers.handleAdminUserDetail(req, res, userDetailMatch[1]!);
      return;
    }

    // /api/admin/settings (GET — environment config status)
    if (pathname === '/api/admin/settings' && req.method === 'GET') {
      sendJson(res, 200, {
        ok: true,
        data: {
          oauth: {
            google: !!process.env['GOOGLE_CLIENT_ID'],
          },
          email: {
            resend: !!process.env['RESEND_API_KEY'],
            smtp: !!process.env['SMTP_HOST'],
          },
          security: {
            totpEnabled: true,
          },
          threatCloud: {
            endpoint: process.env['THREAT_CLOUD_ENDPOINT'] || null,
            apiKey: !!process.env['TC_API_KEY'],
          },
          notifications: {
            telegram: !!process.env['TELEGRAM_BOT_TOKEN'],
            slack: !!process.env['SLACK_WEBHOOK_URL'],
            email: !!process.env['RESEND_API_KEY'] || !!process.env['SMTP_HOST'],
          },
          manager: {
            key: !!process.env['PANGUARD_MANAGER_KEY'],
            corsOrigins: process.env['MANAGER_CORS_ORIGINS'] || '',
          },
        },
      });
      return;
    }

    // ── Manager Proxy Routes ────────────────────────────────────────
    // The admin frontend calls PG.managerFetch('/api/agents') which maps
    // to /api/manager/api/agents when MANAGER_URL is not set. These routes
    // proxy the request to the Manager server and return the response.

    // GET /api/manager/api/overview
    if (pathname === '/api/manager/api/overview' && req.method === 'GET') {
      const result = await managerProxy.getOverview();
      if (result.ok) {
        sendJson(res, 200, result.data);
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/manager/api/agents
    if (pathname === '/api/manager/api/agents' && req.method === 'GET') {
      const result = await managerProxy.getAgents();
      if (result.ok) {
        sendJson(res, 200, result.data);
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/manager/api/agents/:id
    const managerAgentMatch = pathname.match(/^\/api\/manager\/api\/agents\/([^/]+)$/);
    if (managerAgentMatch && req.method === 'GET') {
      const result = await managerProxy.getAgent(managerAgentMatch[1]!);
      if (result.ok) {
        sendJson(res, 200, result.data);
      } else {
        const status = result.error === 'Manager service unavailable' ? 503 : 404;
        sendJson(res, status, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/manager/api/events
    if (pathname === '/api/manager/api/events' && req.method === 'GET') {
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const limit = parseInt(urlObj.searchParams.get('limit') ?? '50', 10) || 50;
      const offset = parseInt(urlObj.searchParams.get('offset') ?? '0', 10) || 0;
      const since = urlObj.searchParams.get('since') ?? undefined;

      const result = await managerProxy.getEvents({ limit, offset, since });
      if (result.ok) {
        sendJson(res, 200, result.data);
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/manager/api/threats/summary
    if (pathname === '/api/manager/api/threats/summary' && req.method === 'GET') {
      const result = await managerProxy.getThreatSummary();
      if (result.ok) {
        sendJson(res, 200, result.data);
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/manager/api/threats
    if (pathname === '/api/manager/api/threats' && req.method === 'GET') {
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const since = urlObj.searchParams.get('since') ?? undefined;

      const result = await managerProxy.getEvents({ since });
      if (result.ok) {
        sendJson(res, 200, result.data);
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
      return;
    }

    // ── Additional Admin Proxy Routes (without /api/manager prefix) ──
    // These support the routes listed in the task specification.

    // GET /api/admin/agents
    if (pathname === '/api/admin/agents' && req.method === 'GET') {
      const result = await managerProxy.getAgents();
      if (result.ok) {
        sendJson(res, 200, { ok: true, data: result.data });
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/admin/agents/:id
    const adminAgentMatch = pathname.match(/^\/api\/admin\/agents\/([^/]+)$/);
    if (adminAgentMatch && req.method === 'GET') {
      const result = await managerProxy.getAgent(adminAgentMatch[1]!);
      if (result.ok) {
        sendJson(res, 200, { ok: true, data: result.data });
      } else {
        const status = result.error === 'Manager service unavailable' ? 503 : 404;
        sendJson(res, status, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/admin/events
    if (pathname === '/api/admin/events' && req.method === 'GET') {
      const urlObj = new URL(url, `http://${req.headers.host ?? 'localhost'}`);
      const limit = parseInt(urlObj.searchParams.get('limit') ?? '50', 10) || 50;
      const offset = parseInt(urlObj.searchParams.get('offset') ?? '0', 10) || 0;
      const since = urlObj.searchParams.get('since') ?? undefined;

      const result = await managerProxy.getEvents({ limit, offset, since });
      if (result.ok) {
        sendJson(res, 200, { ok: true, data: result.data });
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/admin/threats
    if (pathname === '/api/admin/threats' && req.method === 'GET') {
      const result = await managerProxy.getThreatSummary();
      if (result.ok) {
        sendJson(res, 200, { ok: true, data: result.data });
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
      return;
    }

    // GET /api/admin/overview
    if (pathname === '/api/admin/overview' && req.method === 'GET') {
      const result = await managerProxy.getOverview();
      if (result.ok) {
        sendJson(res, 200, { ok: true, data: result.data });
      } else {
        sendJson(res, 503, { ok: false, error: result.error });
      }
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

// ── Threat Cloud Security Helpers ──────────────────────────────

/** Timing-safe string comparison to prevent side-channel attacks */
function timingSafeCompare(a: string, b: string): boolean {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { timingSafeEqual } = require('node:crypto') as typeof import('node:crypto');
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    // Compare against self to maintain constant time
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/**
 * Require TC_API_KEY auth for write endpoints.
 * In production: BLOCK if TC_API_KEY not set (refuse unauthenticated writes).
 * In dev: allow passthrough with warning.
 */
function requireTCWriteAuth(req: IncomingMessage, res: ServerResponse): boolean {
  const tcApiKey = process.env['TC_API_KEY'];
  if (!tcApiKey) {
    if (process.env['NODE_ENV'] === 'production') {
      sendJson(res, 503, {
        ok: false,
        error: 'Threat Cloud write API not configured (TC_API_KEY missing)',
      });
      return false;
    }
    return true; // dev passthrough
  }
  const authHeader = req.headers.authorization ?? '';
  const token = authHeader.replace('Bearer ', '');
  if (!timingSafeCompare(token, tcApiKey)) {
    sendJson(res, 401, { ok: false, error: 'Invalid API key' });
    return false;
  }
  return true;
}

/**
 * Require admin session auth for admin-only GET endpoints.
 * Verifies the Bearer token is a valid session with admin role.
 */
function requireTCAdminAuth(req: IncomingMessage, res: ServerResponse, db: AuthDB): boolean {
  const user = authenticateRequest(req, db);
  if (!user) {
    sendJson(res, 401, { ok: false, error: 'Authentication required' });
    return false;
  }
  if (!requireAdmin(user)) {
    sendJson(res, 403, { ok: false, error: 'Admin access required' });
    return false;
  }
  return true;
}

/** Validate Content-Type is application/json for POST requests */
function requireJsonContentType(req: IncomingMessage, res: ServerResponse): boolean {
  const ct = req.headers['content-type'] ?? '';
  if (!ct.includes('application/json')) {
    sendJson(res, 400, { ok: false, error: 'Content-Type must be application/json' });
    return false;
  }
  return true;
}

/** Per-IP rate limiter for Threat Cloud endpoints (120 req/min) */
const tcRateLimits = new Map<string, { count: number; resetAt: number }>();
function checkTCRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = tcRateLimits.get(ip);
  if (!entry || now > entry.resetAt) {
    tcRateLimits.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  entry.count++;
  return entry.count <= 120;
}

/** Read request body with 1MB size limit */
function readRequestBody(req: IncomingMessage): Promise<string> {
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

/**
 * Seed rules from bundled config/ directory into Threat Cloud DB.
 * Reads Sigma YAML, YARA, and ATR YAML files.
 * Returns count of rules seeded.
 */
async function seedRulesFromBundled(threatDb: ThreatCloudDBInstance): Promise<number> {
  const { readdirSync, readFileSync: readFs, statSync } = await import('node:fs');
  const { join: joinPath, basename, relative } = await import('node:path');

  let seeded = 0;
  const now = new Date().toISOString();

  // Resolve config directory (Docker: /app/config, monorepo: ../../config)
  const configDirs = [
    join(process.cwd(), 'config'),
    join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..', 'config'),
  ];
  const configDir = configDirs.find((d) => {
    try {
      return statSync(d).isDirectory();
    } catch {
      return false;
    }
  });

  if (!configDir) {
    console.log(`  ${c.dim('  No config/ directory found — skipping rule seeding')}`);
    console.log(`  ${c.dim(`  Searched: ${configDirs.join(', ')}`)}`);
    return 0;
  }

  console.log(`  ${c.dim(`  Using config directory: ${configDir}`)}`);

  /** Recursively collect files matching extensions */
  function collectFiles(dir: string, extensions: string[]): string[] {
    const results: string[] = [];
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const fullPath = joinPath(dir, entry.name);
        if (entry.isDirectory()) {
          results.push(...collectFiles(fullPath, extensions));
        } else if (extensions.some((ext) => entry.name.endsWith(ext))) {
          results.push(fullPath);
        }
      }
    } catch (err: unknown) {
      console.error(
        `  [WARN] Cannot read directory ${dir}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
    return results;
  }

  // 1. Sigma rules (.yml, .yaml)
  const sigmaDir = joinPath(configDir, 'sigma-rules');
  try {
    const sigmaFiles = collectFiles(sigmaDir, ['.yml', '.yaml']);
    for (const file of sigmaFiles) {
      const content = readFs(file, 'utf-8');
      const ruleId = `sigma:${relative(sigmaDir, file).replace(/\//g, ':')}`;
      threatDb.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'sigma' });
      seeded++;
    }
    console.log(`  ${c.dim(`  Sigma: ${sigmaFiles.length} files processed`)}`);
  } catch (err: unknown) {
    console.error(
      `  [WARN] Sigma rule seeding failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // 2. YARA rules (.yar, .yara)
  const yaraDir = joinPath(configDir, 'yara-rules');
  try {
    const yaraFiles = collectFiles(yaraDir, ['.yar', '.yara']);
    for (const file of yaraFiles) {
      const content = readFs(file, 'utf-8');
      // Split multi-rule YARA files
      const ruleMatches = content.match(/rule\s+\w+/g);
      if (ruleMatches && ruleMatches.length > 1) {
        // Multi-rule file: store each rule name as sub-ID
        for (const match of ruleMatches) {
          const ruleName = match.replace('rule ', '');
          const ruleId = `yara:${basename(file, '.yar').replace('.yara', '')}:${ruleName}`;
          threatDb.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'yara' });
          seeded++;
        }
      } else {
        const ruleId = `yara:${relative(yaraDir, file).replace(/\//g, ':')}`;
        threatDb.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'yara' });
        seeded++;
      }
    }
    console.log(`  ${c.dim(`  YARA: ${yaraFiles.length} files processed`)}`);
  } catch (err: unknown) {
    console.error(
      `  [WARN] YARA rule seeding failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // 3. ATR rules (.yaml, .yml) from atr package
  const atrDirs = [
    joinPath(process.cwd(), 'node_modules', 'agent-threat-rules', 'rules'),
    joinPath(
      dirname(fileURLToPath(import.meta.url)),
      '..',
      '..',
      '..',
      '..',
      '..',
      'packages',
      'atr',
      'rules'
    ),
  ];
  const atrDir = atrDirs.find((d) => {
    try {
      return statSync(d).isDirectory();
    } catch {
      return false;
    }
  });
  if (atrDir) {
    try {
      const atrFiles = collectFiles(atrDir, ['.yaml', '.yml']);
      for (const file of atrFiles) {
        const content = readFs(file, 'utf-8');
        const ruleId = `atr:${relative(atrDir, file).replace(/\//g, ':')}`;
        threatDb.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'atr' });
        seeded++;
      }
      console.log(`  ${c.dim(`  ATR: ${atrFiles.length} files processed`)}`);
    } catch (err: unknown) {
      console.error(
        `  [WARN] ATR rule seeding failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  return seeded;
}
