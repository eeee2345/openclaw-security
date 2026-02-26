/**
 * HTTP route handlers for auth and waitlist API.
 * Designed to plug into the existing raw node:http server.
 * @module @openclaw/panguard-auth/routes
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { AuthDB } from './database.js';
import { hashPassword, verifyPassword, generateSessionToken, generateVerifyToken, sessionExpiry } from './auth.js';
import { authenticateRequest, requireAdmin } from './middleware.js';
import type { SmtpConfig } from './email-verify.js';
import { sendVerificationEmail } from './email-verify.js';
import type { GoogleOAuthConfig } from './google-oauth.js';
import { getGoogleAuthUrl, exchangeCodeForTokens, getGoogleUserInfo } from './google-oauth.js';
import type { GoogleSheetsConfig } from './google-sheets.js';
import { syncWaitlistEntry, ensureSheetHeaders } from './google-sheets.js';
import type { UserPublic } from './types.js';

// ── Helpers ─────────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf-8');
        resolve(JSON.parse(raw) as Record<string, unknown>);
      } catch {
        resolve(null);
      }
    });
    req.on('error', () => resolve(null));
  });
}

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function toPublicUser(u: { id: number; email: string; name: string; role: string; tier: string; createdAt: string }): UserPublic {
  return { id: u.id, email: u.email, name: u.name, role: u.role, tier: u.tier, createdAt: u.createdAt };
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
}

/**
 * Create all auth route handlers bound to a database instance.
 */
export function createAuthHandlers(config: AuthRouteConfig) {
  const { db } = config;

  // ── Waitlist ─────────────────────────────────────────────────────

  async function handleWaitlistJoin(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const body = await readBody(req);
    if (!body) {
      json(res, 400, { ok: false, error: 'Invalid JSON body' });
      return;
    }

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
      verifyToken,
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

    const body = await readBody(req);
    if (!body) {
      json(res, 400, { ok: false, error: 'Invalid JSON body' });
      return;
    }

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

    const body = await readBody(req);
    if (!body) {
      json(res, 400, { ok: false, error: 'Invalid JSON body' });
      return;
    }

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
      json(res, 401, { ok: false, error: 'Invalid email or password' });
      return;
    }

    db.updateLastLogin(user.id);
    const token = generateSessionToken();
    const session = db.createSession(user.id, token, sessionExpiry());

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

  // ── Google OAuth ─────────────────────────────────────────────────

  function handleGoogleAuth(_req: IncomingMessage, res: ServerResponse): void {
    if (!config.google) {
      json(res, 501, { ok: false, error: 'Google OAuth not configured' });
      return;
    }
    const url = getGoogleAuthUrl(config.google);
    res.writeHead(302, { Location: url });
    res.end();
  }

  async function handleGoogleCallback(req: IncomingMessage, res: ServerResponse, code: string): Promise<void> {
    if (!config.google) {
      json(res, 501, { ok: false, error: 'Google OAuth not configured' });
      return;
    }

    try {
      const tokens = await exchangeCodeForTokens(config.google, code);
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
          { email: googleUser.email, name: googleUser.name || googleUser.email, password: randomPw },
          pwHash,
        );
      }

      db.updateLastLogin(user.id);
      const sessionToken = generateSessionToken();
      const session = db.createSession(user.id, sessionToken, sessionExpiry());

      // Redirect to frontend with token
      const baseUrl = config.baseUrl ?? '';
      const redirectUrl = `${baseUrl}/login?token=${session.token}&expires=${encodeURIComponent(session.expiresAt)}`;
      res.writeHead(302, { Location: redirectUrl });
      res.end();
    } catch (err) {
      json(res, 500, {
        ok: false,
        error: err instanceof Error ? err.message : 'Google OAuth failed',
      });
    }
  }

  // ── Init Google Sheets headers ──────────────────────────────────

  if (config.sheets) {
    ensureSheetHeaders(config.sheets).catch(() => {
      // Best-effort header initialization
    });
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
    handleGoogleAuth,
    handleGoogleCallback,
  };
}
