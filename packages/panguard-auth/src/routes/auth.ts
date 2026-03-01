/**
 * Core authentication route handlers:
 * register, login, logout, me, forgot-password, reset-password, delete-account, export-data.
 * @module @panguard-ai/panguard-auth/routes/auth
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  sessionExpiry,
  hashToken,
} from '../auth.js';
import { authenticateRequest } from '../middleware.js';
import { sendResetEmail, detectLocale } from '../email-verify.js';
import { logAuditEvent } from '@panguard-ai/security-hardening';
import { verifyTotp } from '../totp.js';
import type { RouteContext } from './shared.js';
import { readBody, json, getClientIP, isValidEmail, toPublicUser } from './shared.js';

export function createAuthRoutes(ctx: RouteContext) {
  const { db, config, registerLimiter, resetLimiter, loginLimiter } = ctx;

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
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      json(res, 400, { ok: false, error: 'Password must be between 8 and 128 characters' });
      return;
    }

    // Check if email already registered (prevent account enumeration)
    const existing = db.getUserByEmail(email);
    if (existing) {
      // Match timing of password hashing to prevent timing-based enumeration
      await hashPassword('timing-safe-dummy');
      json(res, 200, {
        ok: true,
        message: 'If this email is not already registered, your account has been created.',
      });
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
        const matchedStep = verifyTotp(
          totpSecret.encryptedSecret,
          totpCode,
          totpSecret.lastUsedStep
        );
        if (matchedStep < 0) {
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
        db.updateLastUsedStep(user.id, matchedStep);
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
      const locale = detectLocale(req.headers['accept-language']);
      sendResetEmail(config.smtp, email, resetToken, config.baseUrl, locale).catch(() => {
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
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      json(res, 400, { ok: false, error: 'Password must be between 8 and 128 characters' });
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

  return {
    handleRegister,
    handleLogin,
    handleLogout,
    handleMe,
    handleForgotPassword,
    handleResetPassword,
    handleDeleteAccount,
    handleExportData,
  };
}
