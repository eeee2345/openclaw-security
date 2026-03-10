/**
 * Billing (Lemon Squeezy) route handlers:
 * handleBillingWebhook, handleBillingCheckout, handleBillingPortal, handleBillingStatus.
 * @module @panguard-ai/panguard-auth/routes/billing
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { authenticateRequest } from '../middleware.js';
import type { RouteContext } from './shared.js';
import { json } from './shared.js';

export function createBillingRoutes(ctx: RouteContext) {
  const { db } = ctx;

  /**
   * POST /api/billing/webhook
   * Receives Lemon Squeezy webhook events. Verifies HMAC signature.
   */
  async function handleBillingWebhook(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    json(res, 501, { ok: false, error: 'Billing disabled. All features are free.' });
  }

  /**
   * POST /api/billing/checkout
   * Billing disabled — all features are free and open source.
   */
  async function handleBillingCheckout(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    json(res, 501, { ok: false, error: 'Billing disabled. All features are free and open source.' });
  }

  /**
   * GET /api/billing/portal
   * Billing disabled — all features are free and open source.
   */
  async function handleBillingPortal(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    json(res, 501, { ok: false, error: 'Billing disabled. All features are free and open source.' });
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

  return {
    handleBillingWebhook,
    handleBillingCheckout,
    handleBillingPortal,
    handleBillingStatus,
  };
}
