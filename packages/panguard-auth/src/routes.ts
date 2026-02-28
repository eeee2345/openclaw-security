/**
 * HTTP route handlers for auth and waitlist API.
 * Designed to plug into the existing raw node:http server.
 * @module @panguard-ai/panguard-auth/routes
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { AuthDB } from './database.js';
import {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  generateVerifyToken,
  hashToken,
  sessionExpiry,
} from './auth.js';
import { authenticateRequest, requireAdmin } from './middleware.js';
import type { SmtpConfig } from './email-verify.js';
import { sendVerificationEmail, sendResetEmail } from './email-verify.js';
import type { GoogleOAuthConfig } from './google-oauth.js';
import {
  getGoogleAuthUrl,
  exchangeCodeForTokens,
  getGoogleUserInfo,
  generateCodeVerifier,
  generateCodeChallenge,
  generateOAuthState,
} from './google-oauth.js';
import type { GoogleSheetsConfig } from './google-sheets.js';
import { syncWaitlistEntry, ensureSheetHeaders } from './google-sheets.js';
import { RateLimiter } from './rate-limiter.js';
import type { UserPublic } from './types.js';
import { logAuditEvent } from '@panguard-ai/security-hardening';
import {
  generateTotpSecret,
  generateBackupCodes,
  buildOtpauthUri,
  verifyTotp,
} from './totp.js';
import type { LemonSqueezyConfig } from './lemonsqueezy.js';
import {
  verifyWebhookSignature,
  handleWebhookEvent,
  createCheckoutUrl,
  getCustomerPortalUrl,
} from './lemonsqueezy.js';
import { checkQuota, recordUsage, getUsageSummary, getQuotaLimits, currentPeriod } from './usage-meter.js';
import type { MeterableResource } from './usage-meter.js';

// ── Helpers ─────────────────────────────────────────────────────────

const MAX_BODY_SIZE = 1024 * 1024; // 1 MB

type ReadBodyResult =
  | { ok: true; data: Record<string, unknown> }
  | { ok: false; status: 400 | 413 };

function readBody(req: IncomingMessage): Promise<ReadBodyResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    let aborted = false;

    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        aborted = true;
        req.destroy();
        resolve({ ok: false, status: 413 });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (aborted) return;
      try {
        const raw = Buffer.concat(chunks).toString('utf-8');
        resolve({ ok: true, data: JSON.parse(raw) as Record<string, unknown> });
      } catch {
        resolve({ ok: false, status: 400 });
      }
    });
    req.on('error', () => {
      if (!aborted) resolve({ ok: false, status: 400 });
    });
  });
}

type ReadRawBodyResult =
  | { ok: true; raw: string }
  | { ok: false; status: 400 | 413 };

function readRawBody(req: IncomingMessage): Promise<ReadRawBodyResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    let aborted = false;

    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        aborted = true;
        req.destroy();
        resolve({ ok: false, status: 413 });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (aborted) return;
      resolve({ ok: true, raw: Buffer.concat(chunks).toString('utf-8') });
    });
    req.on('error', () => {
      if (!aborted) resolve({ ok: false, status: 400 });
    });
  });
}

function getClientIP(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? '127.0.0.1';
}

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function toPublicUser(u: {
  id: number;
  email: string;
  name: string;
  role: string;
  tier: string;
  createdAt: string;
  planExpiresAt?: string | null;
}): UserPublic {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    tier: u.tier,
    createdAt: u.createdAt,
    planExpiresAt: u.planExpiresAt,
  };
}

function isValidEmail(email: unknown): email is string {
  if (typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ── Route handler factory ───────────────────────────────────────────

export interface AuthRouteConfig {
  db: AuthDB;
  smtp?: SmtpConfig;
  baseUrl?: string;
  google?: GoogleOAuthConfig;
  sheets?: GoogleSheetsConfig;
  lemonsqueezy?: LemonSqueezyConfig;
}

/**
 * Create all auth route handlers bound to a database instance.
 */
export function createAuthHandlers(config: AuthRouteConfig) {
  const { db } = config;

  // Rate limiters
  const loginLimiter = new RateLimiter({ windowMs: 15 * 60 * 1000, maxRequests: 10 });
  const registerLimiter = new RateLimiter({ windowMs: 60 * 60 * 1000, maxRequests: 5 });
  const resetLimiter = new RateLimiter({ windowMs: 15 * 60 * 1000, maxRequests: 5 });

  // Pending OAuth flows: state -> { codeVerifier, createdAt }
  const pendingOAuthFlows = new Map<string, { codeVerifier: string; createdAt: number }>();
  // Pending CLI auth flows: state -> { callbackUrl, createdAt }
  const pendingCliFlows = new Map<string, { callbackUrl: string; createdAt: number }>();

  // Cleanup stale flows every 5 minutes
  const oauthCleanupTimer = setInterval(
    () => {
      const cutoff = Date.now() - 10 * 60 * 1000; // 10 min TTL
      for (const [state, flow] of pendingOAuthFlows) {
        if (flow.createdAt < cutoff) pendingOAuthFlows.delete(state);
      }
      for (const [state, flow] of pendingCliFlows) {
        if (flow.createdAt < cutoff) pendingCliFlows.delete(state);
      }
    },
    5 * 60 * 1000
  );
  if (oauthCleanupTimer.unref) oauthCleanupTimer.unref();

  // ── Waitlist ─────────────────────────────────────────────────────

  async function handleWaitlistJoin(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, {
        ok: false,
        error: result.status === 413 ? 'Payload too large' : 'Invalid JSON body',
      });
      return;
    }
    const body = result.data;

    const { email, name, company, role, source } = body;
    if (!isValidEmail(email)) {
      json(res, 400, { ok: false, error: 'Valid email is required' });
      return;
    }

    // Check if already on waitlist
    const existing = db.getWaitlistByEmail(email);
    if (existing) {
      json(res, 409, { ok: false, error: 'Email already on waitlist' });
      return;
    }

    const verifyToken = generateVerifyToken();
    const entry = db.addToWaitlist(
      {
        email,
        name: typeof name === 'string' ? name : undefined,
        company: typeof company === 'string' ? company : undefined,
        role: typeof role === 'string' ? role : undefined,
        source: typeof source === 'string' ? source : undefined,
      },
      verifyToken
    );

    // Send verification email (non-blocking, don't fail the request)
    if (config.smtp && config.baseUrl) {
      sendVerificationEmail(config.smtp, email, verifyToken, config.baseUrl).catch(() => {
        // Log but don't fail - email delivery is best-effort
      });
    }

    // Sync to Google Sheets (non-blocking)
    if (config.sheets) {
      syncWaitlistEntry(config.sheets, entry).catch(() => {
        // Best-effort sync
      });
    }

    json(res, 201, {
      ok: true,
      data: {
        id: entry.id,
        email: entry.email,
        name: entry.name,
        status: entry.status,
        message: 'Added to waitlist. Check your email to verify.',
      },
    });
  }

  function handleWaitlistVerify(req: IncomingMessage, res: ServerResponse, token: string): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const entry = db.verifyWaitlistToken(token);
    if (!entry) {
      json(res, 404, { ok: false, error: 'Invalid or expired verification token' });
      return;
    }

    json(res, 200, {
      ok: true,
      data: { email: entry.email, verified: true, message: 'Email verified successfully' },
    });
  }

  function handleWaitlistStats(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    // Admin-only
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const stats = db.getWaitlistStats();
    json(res, 200, { ok: true, data: stats });
  }

  function handleWaitlistList(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const entries = db.getAllWaitlist();
    json(res, 200, { ok: true, data: entries });
  }

  // ── Auth ─────────────────────────────────────────────────────────

  async function handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    // Rate limit
    const ip = getClientIP(req);
    const rl = registerLimiter.check(ip);
    if (!rl.allowed) {
      res.setHeader('Retry-After', String(Math.ceil(rl.retryAfterMs / 1000)));
      json(res, 429, { ok: false, error: 'Too many requests. Try again later.' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, {
        ok: false,
        error: result.status === 413 ? 'Payload too large' : 'Invalid JSON body',
      });
      return;
    }
    const body = result.data;

    const { email, name, password } = body;
    if (!isValidEmail(email)) {
      json(res, 400, { ok: false, error: 'Valid email is required' });
      return;
    }
    if (typeof name !== 'string' || name.trim().length === 0) {
      json(res, 400, { ok: false, error: 'Name is required' });
      return;
    }
    if (typeof password !== 'string' || password.length < 8) {
      json(res, 400, { ok: false, error: 'Password must be at least 8 characters' });
      return;
    }

    // Check if email already registered
    const existing = db.getUserByEmail(email);
    if (existing) {
      json(res, 409, { ok: false, error: 'Email already registered' });
      return;
    }

    const passwordHash = await hashPassword(password);
    const user = db.createUser({ email, name: name.trim(), password }, passwordHash);
    const token = generateSessionToken();
    const session = db.createSession(user.id, token, sessionExpiry());

    logAuditEvent({
      level: 'info',
      action: 'credential_access',
      target: email,
      result: 'success',
      context: { details: 'User registered' },
    });

    json(res, 201, {
      ok: true,
      data: {
        user: toPublicUser(user),
        token: session.token,
        expiresAt: session.expiresAt,
      },
    });
  }

  async function handleLogin(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    // Rate limit
    const ip = getClientIP(req);
    const rl = loginLimiter.check(ip);
    if (!rl.allowed) {
      res.setHeader('Retry-After', String(Math.ceil(rl.retryAfterMs / 1000)));
      json(res, 429, { ok: false, error: 'Too many requests. Try again later.' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, {
        ok: false,
        error: result.status === 413 ? 'Payload too large' : 'Invalid JSON body',
      });
      return;
    }
    const body = result.data;

    const { email, password } = body;
    if (!isValidEmail(email) || typeof password !== 'string') {
      json(res, 400, { ok: false, error: 'Email and password are required' });
      return;
    }

    const user = db.getUserByEmail(email);
    if (!user) {
      json(res, 401, { ok: false, error: 'Invalid email or password' });
      return;
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      logAuditEvent({
        level: 'warn',
        action: 'credential_access',
        target: email,
        result: 'failure',
        context: { details: 'Invalid password' },
      });
      json(res, 401, { ok: false, error: 'Invalid email or password' });
      return;
    }

    // Check if account is suspended
    if (user.suspended) {
      json(res, 403, { ok: false, error: 'Account suspended. Contact support.' });
      return;
    }

    // Check 2FA requirement
    const totpSecret = db.getTotpSecret(user.id);
    if (totpSecret?.enabled) {
      const { totpCode, backupCode } = body;

      if (!totpCode && !backupCode) {
        // Password is correct but 2FA is needed — tell the client
        json(res, 200, {
          ok: true,
          data: {
            requiresTwoFactor: true,
            message: 'Two-factor authentication required. Send totpCode or backupCode.',
          },
        });
        return;
      }

      // Verify TOTP code
      if (typeof totpCode === 'string') {
        if (!verifyTotp(totpSecret.encryptedSecret, totpCode)) {
          logAuditEvent({
            level: 'warn',
            action: 'credential_access',
            target: email,
            result: 'failure',
            context: { details: 'Invalid TOTP code' },
          });
          json(res, 401, { ok: false, error: 'Invalid two-factor code' });
          return;
        }
      } else if (typeof backupCode === 'string') {
        // Verify backup code
        if (!db.consumeBackupCode(user.id, backupCode)) {
          json(res, 401, { ok: false, error: 'Invalid backup code' });
          return;
        }
      }
    }

    db.updateLastLogin(user.id);
    const token = generateSessionToken();
    const session = db.createSession(user.id, token, sessionExpiry());

    logAuditEvent({
      level: 'info',
      action: 'credential_access',
      target: email,
      result: 'success',
      context: { details: 'User logged in' },
    });

    json(res, 200, {
      ok: true,
      data: {
        user: toPublicUser(user),
        token: session.token,
        expiresAt: session.expiresAt,
      },
    });
  }

  function handleLogout(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      db.deleteSession(token);
    }

    json(res, 200, { ok: true, data: { message: 'Logged out' } });
  }

  function handleMe(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    json(res, 200, { ok: true, data: { user: toPublicUser(user) } });
  }

  // ── Password Reset ─────────────────────────────────────────────

  async function handleForgotPassword(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    // Rate limit
    const ip = getClientIP(req);
    const rl = resetLimiter.check(ip);
    if (!rl.allowed) {
      res.setHeader('Retry-After', String(Math.ceil(rl.retryAfterMs / 1000)));
      json(res, 429, { ok: false, error: 'Too many requests. Try again later.' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, {
        ok: false,
        error: result.status === 413 ? 'Payload too large' : 'Invalid JSON body',
      });
      return;
    }
    const body = result.data;

    const { email } = body;
    if (!isValidEmail(email)) {
      json(res, 400, { ok: false, error: 'Valid email is required' });
      return;
    }

    // Always return success to prevent email enumeration
    const successResponse = {
      ok: true,
      data: { message: 'If that email is registered, a reset link has been sent.' },
    };

    const user = db.getUserByEmail(email);
    if (!user) {
      json(res, 200, successResponse);
      return;
    }

    // Generate token (plaintext to user, hash in DB)
    const resetToken = generateSessionToken();
    const resetTokenHash = hashToken(resetToken);
    db.createResetToken(user.id, resetTokenHash);

    // Audit log
    db.addAuditLog('password_reset_request', null, user.id, JSON.stringify({ email }));
    logAuditEvent({
      level: 'info',
      action: 'credential_access',
      target: email,
      result: 'success',
      context: { details: 'Password reset requested' },
    });

    // Send reset email (non-blocking)
    if (config.smtp && config.baseUrl) {
      sendResetEmail(config.smtp, email, resetToken, config.baseUrl).catch(() => {
        // Best-effort email delivery
      });
    }

    json(res, 200, successResponse);
  }

  async function handleResetPassword(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    // Rate limit
    const ip = getClientIP(req);
    const rl = resetLimiter.check(ip);
    if (!rl.allowed) {
      res.setHeader('Retry-After', String(Math.ceil(rl.retryAfterMs / 1000)));
      json(res, 429, { ok: false, error: 'Too many requests. Try again later.' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, {
        ok: false,
        error: result.status === 413 ? 'Payload too large' : 'Invalid JSON body',
      });
      return;
    }
    const body = result.data;

    const { token, password } = body;
    if (typeof token !== 'string' || token.length === 0) {
      json(res, 400, { ok: false, error: 'Reset token is required' });
      return;
    }
    if (typeof password !== 'string' || password.length < 8) {
      json(res, 400, { ok: false, error: 'Password must be at least 8 characters' });
      return;
    }

    const tokenHash = hashToken(token);
    const userId = db.validateResetToken(tokenHash);
    if (!userId) {
      json(res, 400, { ok: false, error: 'Invalid or expired reset token' });
      return;
    }

    const passwordHash = await hashPassword(password);
    db.updateUserPassword(userId, passwordHash);

    // Invalidate all existing sessions (force re-login with new password)
    db.deleteSessionsByUserId(userId);

    // Audit log
    const user = db.getUserById(userId);
    db.addAuditLog('password_reset_complete', null, userId, undefined);
    logAuditEvent({
      level: 'info',
      action: 'credential_access',
      target: user?.email ?? `user:${userId}`,
      result: 'success',
      context: { details: 'Password reset completed' },
    });

    json(res, 200, {
      ok: true,
      data: { message: 'Password has been reset. Please log in with your new password.' },
    });
  }

  // ── Google OAuth ─────────────────────────────────────────────────

  function handleGoogleAuth(_req: IncomingMessage, res: ServerResponse): void {
    if (!config.google) {
      json(res, 501, { ok: false, error: 'Google OAuth not configured' });
      return;
    }
    const state = generateOAuthState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    pendingOAuthFlows.set(state, { codeVerifier, createdAt: Date.now() });
    const url = getGoogleAuthUrl(config.google, state, codeChallenge);
    res.writeHead(302, { Location: url });
    res.end();
  }

  async function handleGoogleCallback(
    req: IncomingMessage,
    res: ServerResponse,
    code: string,
    state: string | null
  ): Promise<void> {
    if (!config.google) {
      json(res, 501, { ok: false, error: 'Google OAuth not configured' });
      return;
    }

    // Validate state parameter (CSRF protection)
    if (!state) {
      json(res, 400, { ok: false, error: 'Missing state parameter' });
      return;
    }
    const flow = pendingOAuthFlows.get(state);
    if (!flow) {
      json(res, 403, { ok: false, error: 'Invalid or expired OAuth state' });
      return;
    }
    pendingOAuthFlows.delete(state);

    try {
      const tokens = await exchangeCodeForTokens(config.google, code, flow.codeVerifier);
      const googleUser = await getGoogleUserInfo(tokens.access_token);

      if (!googleUser.email) {
        json(res, 400, { ok: false, error: 'No email from Google account' });
        return;
      }

      // Find or create user
      let user = db.getUserByEmail(googleUser.email);
      if (!user) {
        // Auto-create user from Google profile (random password since they use OAuth)
        const randomPw = generateSessionToken(); // Not used for login, just to fill the field
        const pwHash = await hashPassword(randomPw);
        user = db.createUser(
          {
            email: googleUser.email,
            name: googleUser.name || googleUser.email,
            password: randomPw,
          },
          pwHash
        );
      }

      db.updateLastLogin(user.id);
      const sessionToken = generateSessionToken();
      const session = db.createSession(user.id, sessionToken, sessionExpiry());

      // Redirect to frontend with token
      const baseUrl = config.baseUrl ?? '';
      const redirectUrl = `${baseUrl}/login?token=${sessionToken}&expires=${encodeURIComponent(session.expiresAt)}`;
      res.writeHead(302, { Location: redirectUrl });
      res.end();
    } catch (err) {
      json(res, 500, {
        ok: false,
        error: err instanceof Error ? err.message : 'Google OAuth failed',
      });
    }
  }

  // ── CLI Auth ─────────────────────────────────────────────────────

  /**
   * GET /api/auth/cli
   * Initiates CLI auth flow: validates callback URL and redirects to web login.
   */
  function handleCliAuth(req: IncomingMessage, res: ServerResponse): void {
    const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const callbackUrl = urlObj.searchParams.get('callback');
    const state = urlObj.searchParams.get('state');

    if (!callbackUrl || !state) {
      json(res, 400, { ok: false, error: 'Missing callback or state parameter' });
      return;
    }

    // Security: callback must be localhost
    try {
      const callbackParsed = new URL(callbackUrl);
      if (!['localhost', '127.0.0.1', '[::1]'].includes(callbackParsed.hostname)) {
        json(res, 400, { ok: false, error: 'Callback must be localhost' });
        return;
      }
    } catch {
      json(res, 400, { ok: false, error: 'Invalid callback URL' });
      return;
    }

    pendingCliFlows.set(state, { callbackUrl, createdAt: Date.now() });

    // Redirect to web login page with cli_state
    const baseUrl = config.baseUrl ?? '';
    const loginUrl = `${baseUrl}/login?cli_state=${encodeURIComponent(state)}`;
    res.writeHead(302, { Location: loginUrl });
    res.end();
  }

  /**
   * POST /api/auth/cli/exchange
   * Exchanges a web session token for a long-lived CLI session.
   * Returns the CLI callback redirect URL.
   */
  async function handleCliExchange(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, {
        ok: false,
        error: result.status === 413 ? 'Payload too large' : 'Invalid JSON body',
      });
      return;
    }
    const body = result.data;

    const { token, state } = body;
    if (typeof token !== 'string' || typeof state !== 'string') {
      json(res, 400, { ok: false, error: 'Token and state are required' });
      return;
    }

    // Validate web session
    const user = authenticateRequest(
      { headers: { authorization: `Bearer ${token}` } } as IncomingMessage,
      db
    );
    if (!user) {
      json(res, 401, { ok: false, error: 'Invalid session token' });
      return;
    }

    // Look up pending CLI flow
    const flow = pendingCliFlows.get(state);
    if (!flow) {
      json(res, 403, { ok: false, error: 'Invalid or expired CLI state' });
      return;
    }
    pendingCliFlows.delete(state);

    // Create long-lived CLI session (30 days)
    const cliToken = generateSessionToken();
    const cliSession = db.createSession(user.id, cliToken, sessionExpiry(24 * 30));

    // Build redirect URL back to CLI callback
    const params = new URLSearchParams({
      token: cliSession.token,
      expires: cliSession.expiresAt,
      email: user.email,
      name: user.name,
      tier: user.tier,
      state,
    });
    const redirectUrl = `${flow.callbackUrl}?${params.toString()}`;

    json(res, 200, { ok: true, data: { redirectUrl } });
  }

  // ── GDPR: Account Deletion + Data Export ───────────────────────

  /**
   * DELETE /api/auth/delete-account
   * Permanently delete the authenticated user's account and all data.
   */
  async function handleDeleteAccount(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'DELETE') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    // Require password confirmation
    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid request body' });
      return;
    }

    const { password } = body.data;
    if (typeof password !== 'string') {
      json(res, 400, { ok: false, error: 'Password confirmation is required' });
      return;
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      json(res, 401, { ok: false, error: 'Invalid password' });
      return;
    }

    // Prevent admin self-deletion if they're the only admin
    if (user.role === 'admin') {
      const allUsers = db.getAllUsers();
      const adminCount = allUsers.filter((u) => u.role === 'admin').length;
      if (adminCount <= 1) {
        json(res, 409, { ok: false, error: 'Cannot delete the only admin account' });
        return;
      }
    }

    const result = db.deleteUser(user.id);

    logAuditEvent({
      level: 'info',
      action: 'credential_access',
      target: user.email,
      result: 'success',
      context: { details: `Account deleted (GDPR). Tables: ${result.tablesAffected.join(', ')}` },
    });

    json(res, 200, {
      ok: true,
      data: {
        message: 'Account permanently deleted.',
        tablesAffected: result.tablesAffected,
      },
    });
  }

  /**
   * GET /api/auth/export-data
   * Export all data belonging to the authenticated user (GDPR portability).
   */
  function handleExportData(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const data = db.exportUserData(user.id);
    if (!data) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    db.addAuditLog('data_export', user.id, user.id, undefined);

    // Return as downloadable JSON
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="panguard-data-export-${user.id}.json"`,
    });
    res.end(JSON.stringify(data, null, 2));
  }

  // ── TOTP (Two-Factor Authentication) ──────────────────────────

  /**
   * POST /api/auth/totp/setup
   * Generate a new TOTP secret and backup codes. Returns otpauth URI for QR code.
   */
  function handleTotpSetup(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    // Check if already enabled
    const existing = db.getTotpSecret(user.id);
    if (existing?.enabled) {
      json(res, 409, { ok: false, error: '2FA is already enabled. Disable it first to re-setup.' });
      return;
    }

    const secret = generateTotpSecret();
    const backupCodes = generateBackupCodes();
    const otpauthUri = buildOtpauthUri(secret, user.email);

    // Store (not yet enabled — user must verify first)
    db.saveTotpSecret(user.id, secret, JSON.stringify(backupCodes));

    json(res, 200, {
      ok: true,
      data: {
        secret,
        otpauthUri,
        backupCodes,
        message: 'Scan the QR code with your authenticator app, then verify with /api/auth/totp/verify.',
      },
    });
  }

  /**
   * POST /api/auth/totp/verify
   * Verify a TOTP code to enable 2FA. Body: { code: "123456" }
   */
  async function handleTotpVerify(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid request body' });
      return;
    }

    const { code } = body.data;
    if (typeof code !== 'string' || code.length !== 6) {
      json(res, 400, { ok: false, error: 'A 6-digit code is required' });
      return;
    }

    const totpSecret = db.getTotpSecret(user.id);
    if (!totpSecret) {
      json(res, 404, { ok: false, error: 'No TOTP setup found. Call /api/auth/totp/setup first.' });
      return;
    }

    if (!verifyTotp(totpSecret.encryptedSecret, code)) {
      json(res, 401, { ok: false, error: 'Invalid TOTP code' });
      return;
    }

    db.enableTotp(user.id);

    db.addAuditLog('totp_enabled', user.id, user.id, undefined);
    logAuditEvent({
      level: 'info',
      action: 'credential_access',
      target: user.email,
      result: 'success',
      context: { details: '2FA enabled' },
    });

    json(res, 200, { ok: true, data: { message: '2FA has been enabled.' } });
  }

  /**
   * POST /api/auth/totp/disable
   * Disable 2FA. Requires password confirmation. Body: { password: "..." }
   */
  async function handleTotpDisable(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid request body' });
      return;
    }

    const { password } = body.data;
    if (typeof password !== 'string') {
      json(res, 400, { ok: false, error: 'Password is required to disable 2FA' });
      return;
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      json(res, 401, { ok: false, error: 'Invalid password' });
      return;
    }

    db.disableTotp(user.id);

    db.addAuditLog('totp_disabled', user.id, user.id, undefined);
    logAuditEvent({
      level: 'info',
      action: 'credential_access',
      target: user.email,
      result: 'success',
      context: { details: '2FA disabled' },
    });

    json(res, 200, { ok: true, data: { message: '2FA has been disabled.' } });
  }

  /**
   * GET /api/auth/totp/status
   * Check if 2FA is enabled for the authenticated user.
   */
  function handleTotpStatus(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const totpSecret = db.getTotpSecret(user.id);
    json(res, 200, {
      ok: true,
      data: {
        enabled: totpSecret?.enabled === 1,
        backupCodesRemaining: totpSecret
          ? (JSON.parse(totpSecret.backupCodes) as string[]).length
          : 0,
      },
    });
  }

  // ── Lemon Squeezy (Billing) ─────────────────────────────────────

  /**
   * POST /api/billing/webhook
   * Receives Lemon Squeezy webhook events. Verifies HMAC signature.
   */
  async function handleBillingWebhook(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    if (!config.lemonsqueezy) {
      json(res, 501, { ok: false, error: 'Billing not configured' });
      return;
    }

    const rawResult = await readRawBody(req);
    if (!rawResult.ok) {
      json(res, rawResult.status, { ok: false, error: 'Invalid request body' });
      return;
    }

    // Verify HMAC signature
    const signature = req.headers['x-signature'] as string | undefined;
    if (!signature || !verifyWebhookSignature(rawResult.raw, signature, config.lemonsqueezy.webhookSecret)) {
      json(res, 401, { ok: false, error: 'Invalid webhook signature' });
      return;
    }

    let payload: { meta: { event_name: string; custom_data?: Record<string, string> }; data: { type: string; id: string; attributes: Record<string, unknown> } };
    try {
      payload = JSON.parse(rawResult.raw);
    } catch {
      json(res, 400, { ok: false, error: 'Invalid JSON' });
      return;
    }

    const result = handleWebhookEvent(payload, config.lemonsqueezy, db);

    // Always return 200 to prevent Lemon Squeezy from retrying
    json(res, 200, { ok: true, data: result });
  }

  /**
   * POST /api/billing/checkout
   * Creates a checkout URL for the authenticated user.
   * Body: { variantId: string } or { tier: string }
   * When `tier` is provided, the server resolves it to a variant ID via variantTierMap.
   */
  async function handleBillingCheckout(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    if (!config.lemonsqueezy) {
      json(res, 501, { ok: false, error: 'Billing not configured' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid request body' });
      return;
    }

    let resolvedVariantId: string | undefined;

    // Accept variantId directly
    if (typeof body.data['variantId'] === 'string' && (body.data['variantId'] as string).length > 0) {
      resolvedVariantId = body.data['variantId'] as string;
    }
    // Or resolve from tier name
    else if (typeof body.data['tier'] === 'string' && (body.data['tier'] as string).length > 0) {
      const tierMap = config.lemonsqueezy.variantTierMap;
      // Reverse lookup: find variant ID for this tier
      const entry = Object.entries(tierMap).find(([, t]) => t === body.data['tier']);
      if (!entry) {
        json(res, 400, { ok: false, error: `No variant configured for tier: ${body.data['tier']}` });
        return;
      }
      resolvedVariantId = entry[0];
    }

    if (!resolvedVariantId) {
      json(res, 400, { ok: false, error: 'variantId or tier is required' });
      return;
    }

    const checkoutUrl = await createCheckoutUrl(config.lemonsqueezy, resolvedVariantId, {
      id: user.id,
      email: user.email,
      name: user.name,
    });

    if (!checkoutUrl) {
      json(res, 502, { ok: false, error: 'Failed to create checkout session' });
      return;
    }

    json(res, 200, { ok: true, data: { url: checkoutUrl } });
  }

  /**
   * GET /api/billing/portal
   * Returns the customer portal URL for the authenticated user.
   */
  async function handleBillingPortal(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    if (!config.lemonsqueezy) {
      json(res, 501, { ok: false, error: 'Billing not configured' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const subscription = db.getActiveSubscription(user.id);
    if (!subscription?.lsSubscriptionId) {
      json(res, 404, { ok: false, error: 'No active subscription found' });
      return;
    }

    const portalUrl = await getCustomerPortalUrl(config.lemonsqueezy, subscription.lsSubscriptionId);
    if (!portalUrl) {
      json(res, 502, { ok: false, error: 'Failed to get portal URL' });
      return;
    }

    json(res, 200, { ok: true, data: { url: portalUrl } });
  }

  /**
   * GET /api/billing/status
   * Returns the current subscription status for the authenticated user.
   */
  function handleBillingStatus(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const subscription = db.getActiveSubscription(user.id);
    json(res, 200, {
      ok: true,
      data: {
        tier: user.tier,
        planExpiresAt: user.planExpiresAt,
        subscription: subscription
          ? {
              status: subscription.status,
              tier: subscription.tier,
              renewsAt: subscription.renewsAt,
              endsAt: subscription.endsAt,
            }
          : null,
      },
    });
  }

  // ── Admin: User Management ──────────────────────────────────────

  function handleAdminUsers(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const users = db.getAllUsersAdmin();
    json(res, 200, { ok: true, data: users });
  }

  async function handleAdminUpdateTier(
    req: IncomingMessage,
    res: ServerResponse,
    userId: string
  ): Promise<void> {
    if (req.method !== 'PATCH') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const { tier } = result.data;
    const validTiers = ['free', 'solo', 'starter', 'pro', 'team', 'business', 'enterprise'];
    if (typeof tier !== 'string' || !validTiers.includes(tier)) {
      json(res, 400, {
        ok: false,
        error: `Invalid tier. Must be one of: ${validTiers.join(', ')}`,
      });
      return;
    }

    const target = db.getUserById(Number(userId));
    if (!target) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    const oldTier = target.tier;
    db.updateUserTier(target.id, tier);

    // Audit log
    db.addAuditLog('tier_change', user!.id, target.id, JSON.stringify({ from: oldTier, to: tier }));
    logAuditEvent({
      level: 'info',
      action: 'policy_check',
      target: `user:${target.id}`,
      result: 'success',
      context: { details: `Tier changed: ${oldTier} -> ${tier}` },
    });

    // Invalidate all sessions for this user so they pick up the new tier
    db.deleteSessionsByUserId(target.id);

    const updated = db.getUserById(target.id)!;
    json(res, 200, { ok: true, data: toPublicUser(updated) });
  }

  async function handleAdminUpdateRole(
    req: IncomingMessage,
    res: ServerResponse,
    userId: string
  ): Promise<void> {
    if (req.method !== 'PATCH') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const { role } = result.data;
    if (typeof role !== 'string' || !['user', 'admin'].includes(role)) {
      json(res, 400, { ok: false, error: 'Invalid role. Must be "user" or "admin"' });
      return;
    }

    const target = db.getUserById(Number(userId));
    if (!target) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    const oldRole = target.role;
    db.updateUserRole(target.id, role);

    // Audit log
    db.addAuditLog('role_change', user!.id, target.id, JSON.stringify({ from: oldRole, to: role }));
    logAuditEvent({
      level: 'info',
      action: 'policy_check',
      target: `user:${target.id}`,
      result: 'success',
      context: { details: `Role changed: ${oldRole} -> ${role}` },
    });

    const updated = db.getUserById(target.id)!;
    json(res, 200, { ok: true, data: toPublicUser(updated) });
  }

  function handleAdminStats(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const userStats = db.getUserStats();
    const waitlistStats = db.getWaitlistStats();
    json(res, 200, { ok: true, data: { users: userStats, waitlist: waitlistStats } });
  }

  async function handleAdminWaitlistApprove(
    req: IncomingMessage,
    res: ServerResponse,
    entryId: string
  ): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const entry = db.getWaitlistById(Number(entryId));
    if (!entry) {
      json(res, 404, { ok: false, error: 'Waitlist entry not found' });
      return;
    }

    db.approveWaitlistEntry(entry.id);
    json(res, 200, { ok: true, data: { id: entry.id, status: 'approved' } });
  }

  async function handleAdminWaitlistReject(
    req: IncomingMessage,
    res: ServerResponse,
    entryId: string
  ): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const entry = db.getWaitlistById(Number(entryId));
    if (!entry) {
      json(res, 404, { ok: false, error: 'Waitlist entry not found' });
      return;
    }

    db.rejectWaitlistEntry(entry.id);
    json(res, 200, { ok: true, data: { id: entry.id, status: 'rejected' } });
  }

  // ── Admin: Enhanced Endpoints ───────────────────────────────────

  function handleAdminDashboard(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const stats = db.getAdminDashboardStats();
    json(res, 200, { ok: true, data: stats });
  }

  function handleAdminUsersSearch(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const q = urlObj.searchParams.get('q') ?? '';
    const users = q ? db.searchUsers(q) : db.getAllUsersAdmin();
    json(res, 200, { ok: true, data: users });
  }

  function handleAdminSessions(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const sessions = db.getActiveSessions();
    json(res, 200, { ok: true, data: sessions });
  }

  function handleAdminSessionRevoke(
    req: IncomingMessage,
    res: ServerResponse,
    sessionId: string
  ): void {
    if (req.method !== 'DELETE') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const deleted = db.deleteSessionById(Number(sessionId));
    if (!deleted) {
      json(res, 404, { ok: false, error: 'Session not found' });
      return;
    }
    json(res, 200, { ok: true, data: { revoked: true } });
  }

  function handleAdminActivity(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const limit = Math.min(parseInt(urlObj.searchParams.get('limit') ?? '20', 10) || 20, 50);
    const activity = db.getRecentActivity(limit);
    json(res, 200, { ok: true, data: activity });
  }

  // ── Admin: Audit Log (paginated + filtered) ──────────────────────

  function handleAdminAuditLog(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const filter = {
      action: urlObj.searchParams.get('action') || undefined,
      actorId: urlObj.searchParams.has('actorId')
        ? parseInt(urlObj.searchParams.get('actorId')!, 10)
        : undefined,
      dateFrom: urlObj.searchParams.get('dateFrom') || undefined,
      dateTo: urlObj.searchParams.get('dateTo') || undefined,
      page: parseInt(urlObj.searchParams.get('page') ?? '1', 10) || 1,
      perPage: parseInt(urlObj.searchParams.get('perPage') ?? '50', 10) || 50,
    };

    const result = db.getAuditLogFiltered(filter);
    const actions = db.getDistinctAuditActions();
    json(res, 200, {
      ok: true,
      data: { ...result, page: filter.page, perPage: filter.perPage, actions },
    });
  }

  function handleAdminAuditActions(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    json(res, 200, { ok: true, data: db.getDistinctAuditActions() });
  }

  // ── Admin: Usage Overview ─────────────────────────────────────

  function handleAdminUsageOverview(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const allUsers = db.getAllUsersAdmin();
    const period = currentPeriod();
    const byUser: Array<{
      userId: number;
      email: string;
      name: string;
      tier: string;
      suspended: number;
      usage: Array<{ resource: string; current: number; limit: number; percentage: number }>;
    }> = [];
    const nearQuota: Array<{
      userId: number;
      email: string;
      tier: string;
      resource: string;
      current: number;
      limit: number;
      percentage: number;
    }> = [];

    for (const u of allUsers) {
      const summary = getUsageSummary(db, u.id, u.tier);
      byUser.push({
        userId: u.id,
        email: u.email,
        name: u.name,
        tier: u.tier,
        suspended: u.suspended,
        usage: summary,
      });
      for (const s of summary) {
        if (s.limit > 0 && s.percentage >= 80) {
          nearQuota.push({
            userId: u.id,
            email: u.email,
            tier: u.tier,
            resource: s.resource,
            current: s.current,
            limit: s.limit,
            percentage: s.percentage,
          });
        }
      }
    }

    // Aggregate by tier
    const byTier: Record<string, { userCount: number; resources: Record<string, number> }> = {};
    for (const u of byUser) {
      if (!byTier[u.tier]) {
        byTier[u.tier] = { userCount: 0, resources: {} };
      }
      const tierEntry = byTier[u.tier]!;
      tierEntry.userCount++;
      for (const s of u.usage) {
        tierEntry.resources[s.resource] =
          (tierEntry.resources[s.resource] ?? 0) + s.current;
      }
    }

    json(res, 200, {
      ok: true,
      data: { byUser, nearQuota, byTier, period },
    });
  }

  function handleAdminUsageUser(
    req: IncomingMessage,
    res: ServerResponse,
    userId: string
  ): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const admin = authenticateRequest(req, db);
    if (!requireAdmin(admin)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const targetUser = db.getUserById(parseInt(userId, 10));
    if (!targetUser) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    const summary = getUsageSummary(db, targetUser.id, targetUser.tier);
    const history = db.getUserUsage(targetUser.id);

    json(res, 200, {
      ok: true,
      data: {
        user: { id: targetUser.id, email: targetUser.email, name: targetUser.name, tier: targetUser.tier },
        usage: summary,
        history,
      },
    });
  }

  // ── Admin: User Detail ────────────────────────────────────────

  function handleAdminUserDetail(
    req: IncomingMessage,
    res: ServerResponse,
    userId: string
  ): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const admin = authenticateRequest(req, db);
    if (!requireAdmin(admin)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const detail = db.getUserDetailById(parseInt(userId, 10));
    if (!detail) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    // Enrich usage with quota limits
    const limits = getQuotaLimits(detail.user.tier);
    const usage = detail.usage.map((u) => {
      const limit = limits[u.resource as MeterableResource] ?? -1;
      const current = u.count;
      return {
        resource: u.resource,
        current,
        limit,
        percentage: limit > 0 ? Math.round((current / limit) * 100) : 0,
      };
    });

    json(res, 200, {
      ok: true,
      data: {
        user: detail.user,
        subscription: detail.subscription,
        usage,
        sessions: detail.sessions,
        recentAudit: detail.recentAudit,
        twoFactor: { enabled: detail.totpEnabled },
      },
    });
  }

  // ── Admin: Suspend / Unsuspend ────────────────────────────────

  async function handleAdminUserSuspend(
    req: IncomingMessage,
    res: ServerResponse,
    userId: string
  ): Promise<void> {
    if (req.method !== 'PATCH') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const admin = authenticateRequest(req, db);
    if (!requireAdmin(admin)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const targetId = parseInt(userId, 10);
    if (targetId === admin!.id) {
      json(res, 400, { ok: false, error: 'Cannot suspend your own account' });
      return;
    }

    const suspended = body.data['suspended'] === true;

    if (suspended) {
      db.suspendUser(targetId);
    } else {
      db.unsuspendUser(targetId);
    }

    db.addAuditLog(
      suspended ? 'user_suspended' : 'user_unsuspended',
      admin!.id,
      targetId,
      JSON.stringify({ suspended })
    );

    json(res, 200, { ok: true, data: { id: targetId, suspended } });
  }

  // ── Admin: Bulk Action ────────────────────────────────────────

  async function handleAdminBulkAction(
    req: IncomingMessage,
    res: ServerResponse
  ): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const admin = authenticateRequest(req, db);
    if (!requireAdmin(admin)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const { userIds, action, value } = body.data as {
      userIds?: number[];
      action?: string;
      value?: string;
    };

    if (!Array.isArray(userIds) || userIds.length === 0) {
      json(res, 400, { ok: false, error: 'userIds array is required' });
      return;
    }
    if (userIds.length > 100) {
      json(res, 400, { ok: false, error: 'Maximum 100 users per bulk action' });
      return;
    }
    const validActions = ['change_tier', 'change_role', 'suspend', 'unsuspend'];
    if (!action || !validActions.includes(action)) {
      json(res, 400, { ok: false, error: `action must be one of: ${validActions.join(', ')}` });
      return;
    }

    const validTiers = ['free', 'solo', 'starter', 'team', 'business', 'enterprise'];
    const validRoles = ['user', 'admin'];

    if (action === 'change_tier' && (!value || !validTiers.includes(value))) {
      json(res, 400, { ok: false, error: `value must be one of: ${validTiers.join(', ')}` });
      return;
    }
    if (action === 'change_role' && (!value || !validRoles.includes(value))) {
      json(res, 400, { ok: false, error: `value must be one of: ${validRoles.join(', ')}` });
      return;
    }

    const results: Array<{ userId: number; success: boolean; error?: string }> = [];
    let processed = 0;
    let failed = 0;

    for (const uid of userIds) {
      try {
        if (uid === admin!.id && (action === 'suspend' || action === 'change_role')) {
          results.push({ userId: uid, success: false, error: 'Cannot modify own account' });
          failed++;
          continue;
        }

        switch (action) {
          case 'change_tier':
            db.updateUserTier(uid, value!);
            db.deleteSessionsByUserId(uid);
            break;
          case 'change_role':
            db.updateUserRole(uid, value!);
            break;
          case 'suspend':
            db.suspendUser(uid);
            break;
          case 'unsuspend':
            db.unsuspendUser(uid);
            break;
        }

        db.addAuditLog(
          `bulk_${action}`,
          admin!.id,
          uid,
          JSON.stringify({ action, value })
        );
        results.push({ userId: uid, success: true });
        processed++;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        results.push({ userId: uid, success: false, error: msg });
        failed++;
      }
    }

    json(res, 200, { ok: true, data: { processed, failed, results } });
  }

  // ── Init Google Sheets headers ──────────────────────────────────

  if (config.sheets) {
    ensureSheetHeaders(config.sheets).catch(() => {
      // Best-effort header initialization
    });
  }

  // ── Usage / Quota ─────────────────────────────────────────────────

  /**
   * GET /api/usage
   * Returns current usage and quota for the authenticated user.
   */
  function handleUsageSummary(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const summary = getUsageSummary(db, user.id, user.tier);
    json(res, 200, { ok: true, data: { usage: summary, tier: user.tier } });
  }

  /**
   * GET /api/usage/limits
   * Returns quota limits for the authenticated user's tier.
   */
  function handleUsageLimits(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const limits = getQuotaLimits(user.tier);
    json(res, 200, { ok: true, data: { limits, tier: user.tier } });
  }

  /**
   * POST /api/usage/check
   * Checks if the user has quota for a specific resource.
   * Body: { resource: string }
   */
  async function handleUsageCheck(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid request body' });
      return;
    }

    const resource = body.data['resource'] as MeterableResource;
    if (!resource) {
      json(res, 400, { ok: false, error: 'resource is required' });
      return;
    }

    const check = checkQuota(db, user.id, user.tier, resource);
    json(res, 200, { ok: true, data: check });
  }

  /**
   * POST /api/usage/record
   * Records usage for a resource. Intended for internal/trusted callers.
   * Body: { resource: string, count?: number }
   */
  async function handleUsageRecord(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!user) {
      json(res, 401, { ok: false, error: 'Not authenticated' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid request body' });
      return;
    }

    const resource = body.data['resource'] as MeterableResource;
    const count = typeof body.data['count'] === 'number' ? body.data['count'] : 1;

    if (!resource) {
      json(res, 400, { ok: false, error: 'resource is required' });
      return;
    }

    // Check quota before recording
    const check = checkQuota(db, user.id, user.tier, resource);
    if (!check.allowed) {
      json(res, 429, {
        ok: false,
        error: 'Quota exceeded',
        data: { current: check.current, limit: check.limit, resource },
      });
      return;
    }

    recordUsage(db, user.id, resource, count);
    json(res, 200, { ok: true, data: { recorded: count, resource } });
  }

  return {
    handleWaitlistJoin,
    handleWaitlistVerify,
    handleWaitlistStats,
    handleWaitlistList,
    handleRegister,
    handleLogin,
    handleLogout,
    handleMe,
    handleForgotPassword,
    handleResetPassword,
    handleGoogleAuth,
    handleGoogleCallback,
    handleCliAuth,
    handleCliExchange,
    // Admin
    handleAdminUsers,
    handleAdminUpdateTier,
    handleAdminUpdateRole,
    handleAdminStats,
    handleAdminWaitlistApprove,
    handleAdminWaitlistReject,
    handleAdminDashboard,
    handleAdminUsersSearch,
    handleAdminSessions,
    handleAdminSessionRevoke,
    handleAdminActivity,
    handleAdminAuditLog,
    handleAdminAuditActions,
    handleAdminUsageOverview,
    handleAdminUsageUser,
    handleAdminUserDetail,
    handleAdminUserSuspend,
    handleAdminBulkAction,
    // GDPR
    handleDeleteAccount,
    handleExportData,
    // TOTP (2FA)
    handleTotpSetup,
    handleTotpVerify,
    handleTotpDisable,
    handleTotpStatus,
    // Billing (Lemon Squeezy)
    handleBillingWebhook,
    handleBillingCheckout,
    handleBillingPortal,
    handleBillingStatus,
    // Usage / Quota
    handleUsageSummary,
    handleUsageLimits,
    handleUsageCheck,
    handleUsageRecord,
  };
}
