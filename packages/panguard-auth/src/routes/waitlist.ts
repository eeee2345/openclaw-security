/**
 * Waitlist route handlers:
 * handleWaitlistJoin, handleWaitlistVerify, handleWaitlistStats, handleWaitlistList.
 * @module @panguard-ai/panguard-auth/routes/waitlist
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { generateVerifyToken } from '../auth.js';
import { authenticateRequest, requireAdmin } from '../middleware.js';
import { sendVerificationEmail, sendWelcomeEmail, detectLocale } from '../email-verify.js';
import { syncWaitlistEntry } from '../google-sheets.js';
import type { RouteContext } from './shared.js';
import { readBody, json, getClientIP, isValidEmail } from './shared.js';

export function createWaitlistRoutes(ctx: RouteContext) {
  const { db, config, waitlistLimiter } = ctx;

  async function handleWaitlistJoin(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const ip = getClientIP(req);
    const rl = waitlistLimiter.check(ip);
    if (!rl.allowed) {
      res.setHeader('Retry-After', String(Math.ceil((rl.retryAfterMs ?? 60000) / 1000)));
      json(res, 429, { ok: false, error: 'Too many requests. Please try again later.' });
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
        name: typeof name === 'string' ? name.slice(0, 200) : undefined,
        company: typeof company === 'string' ? company.slice(0, 200) : undefined,
        role: typeof role === 'string' ? role.slice(0, 200) : undefined,
        source: typeof source === 'string' ? source.slice(0, 200) : undefined,
      },
      verifyToken
    );

    // Send verification email (non-blocking, don't fail the request)
    if (config.smtp && config.baseUrl) {
      const locale = detectLocale(req.headers['accept-language']);
      sendVerificationEmail(config.smtp, email, verifyToken, config.baseUrl, locale).catch(() => {
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

    // Send welcome email with registration link
    if (config.smtp && config.baseUrl) {
      const locale = detectLocale(req.headers['accept-language']);
      sendWelcomeEmail(
        config.smtp,
        entry.email,
        entry.name || 'there',
        config.baseUrl,
        locale
      ).catch(() => {
        // Best-effort delivery
      });
    }

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

  return {
    handleWaitlistJoin,
    handleWaitlistVerify,
    handleWaitlistStats,
    handleWaitlistList,
    handleAdminWaitlistApprove,
    handleAdminWaitlistReject,
  };
}
