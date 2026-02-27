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
  sessionExpiry,
} from './auth.js';
import { authenticateRequest, requireAdmin } from './middleware.js';
import type { SmtpConfig } from './email-verify.js';
import { sendVerificationEmail } from './email-verify.js';
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
}

/**
 * Create all auth route handlers bound to a database instance.
 */
export function createAuthHandlers(config: AuthRouteConfig) {
  const { db } = config;

  // Rate limiters
  const loginLimiter = new RateLimiter({ windowMs: 15 * 60 * 1000, maxRequests: 10 });
  const registerLimiter = new RateLimiter({ windowMs: 60 * 60 * 1000, maxRequests: 5 });

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
  };
}
