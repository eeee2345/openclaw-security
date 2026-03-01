/**
 * TOTP (Two-Factor Authentication) route handlers:
 * handleTotpSetup, handleTotpVerify, handleTotpDisable, handleTotpStatus.
 * @module @panguard-ai/panguard-auth/routes/totp
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { verifyPassword } from '../auth.js';
import { authenticateRequest } from '../middleware.js';
import { logAuditEvent } from '@panguard-ai/security-hardening';
import { generateTotpSecret, generateBackupCodes, buildOtpauthUri, verifyTotp } from '../totp.js';
import type { RouteContext } from './shared.js';
import { readBody, json } from './shared.js';

export function createTotpRoutes(ctx: RouteContext) {
  const { db } = ctx;

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
        message:
          'Scan the QR code with your authenticator app, then verify with /api/auth/totp/verify.',
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

    const matchedStep = verifyTotp(totpSecret.encryptedSecret, code, totpSecret.lastUsedStep);
    if (matchedStep < 0) {
      json(res, 401, { ok: false, error: 'Invalid TOTP code' });
      return;
    }
    db.updateLastUsedStep(user.id, matchedStep);

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

  return {
    handleTotpSetup,
    handleTotpVerify,
    handleTotpDisable,
    handleTotpStatus,
  };
}
