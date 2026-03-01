/**
 * Billing (Lemon Squeezy) route handlers:
 * handleBillingWebhook, handleBillingCheckout, handleBillingPortal, handleBillingStatus.
 * @module @panguard-ai/panguard-auth/routes/billing
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { authenticateRequest } from '../middleware.js';
import {
  verifyWebhookSignature,
  handleWebhookEvent,
  createCheckoutUrl,
  getCustomerPortalUrl,
} from '../lemonsqueezy.js';
import type { RouteContext } from './shared.js';
import { readBody, readRawBody, json } from './shared.js';

export function createBillingRoutes(ctx: RouteContext) {
  const { db, config } = ctx;

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
    if (
      !signature ||
      !verifyWebhookSignature(rawResult.raw, signature, config.lemonsqueezy.webhookSecret)
    ) {
      json(res, 401, { ok: false, error: 'Invalid webhook signature' });
      return;
    }

    let payload: {
      meta: { event_name: string; custom_data?: Record<string, string> };
      data: { type: string; id: string; attributes: Record<string, unknown> };
    };
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
    if (
      typeof body.data['variantId'] === 'string' &&
      (body.data['variantId'] as string).length > 0
    ) {
      resolvedVariantId = body.data['variantId'] as string;
    }
    // Or resolve from tier name
    else if (typeof body.data['tier'] === 'string' && (body.data['tier'] as string).length > 0) {
      const tierMap = config.lemonsqueezy.variantTierMap;
      // Reverse lookup: find variant ID for this tier
      const entry = Object.entries(tierMap).find(([, t]) => t === body.data['tier']);
      if (!entry) {
        json(res, 400, {
          ok: false,
          error: `No variant configured for tier: ${body.data['tier']}`,
        });
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

    const portalUrl = await getCustomerPortalUrl(
      config.lemonsqueezy,
      subscription.lsSubscriptionId
    );
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

  return {
    handleBillingWebhook,
    handleBillingCheckout,
    handleBillingPortal,
    handleBillingStatus,
  };
}
