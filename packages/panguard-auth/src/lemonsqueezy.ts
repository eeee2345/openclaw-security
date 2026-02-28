/**
 * Lemon Squeezy integration for subscription management.
 * Handles webhook verification, event processing, and checkout URL generation.
 *
 * @module @panguard-ai/panguard-auth/lemonsqueezy
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { AuthDB } from './database.js';
import { logAuditEvent } from '@panguard-ai/security-hardening';

// ── Types ───────────────────────────────────────────────────────

export interface LemonSqueezyConfig {
  /** API key from LS dashboard (for creating checkouts) */
  apiKey: string;
  /** Store numeric ID */
  storeId: string;
  /** Webhook signing secret (set when creating webhook in LS dashboard) */
  webhookSecret: string;
  /** Variant ID -> tier mapping (e.g. { "123456": "solo", "123457": "pro" }) */
  variantTierMap: Record<string, string>;
}

interface WebhookPayload {
  meta: {
    event_name: string;
    custom_data?: Record<string, string>;
  };
  data: {
    type: string;
    id: string;
    attributes: Record<string, unknown>;
  };
}

export interface WebhookResult {
  handled: boolean;
  event: string;
  userId?: number;
  tier?: string;
  error?: string;
}

// ── Webhook Signature Verification ─────────────────────────────

/**
 * Verify that a webhook request comes from Lemon Squeezy.
 * Uses HMAC SHA-256 with timing-safe comparison.
 */
export function verifyWebhookSignature(
  rawBody: string,
  signature: string,
  secret: string
): boolean {
  if (!signature || !rawBody || !secret) return false;

  try {
    const expected = Buffer.from(
      createHmac('sha256', secret).update(rawBody).digest('hex'),
      'hex'
    );
    const received = Buffer.from(signature, 'hex');

    if (expected.length !== received.length) return false;
    return timingSafeEqual(expected, received);
  } catch {
    return false;
  }
}

// ── Webhook Event Handler ──────────────────────────────────────

/**
 * Process a verified Lemon Squeezy webhook event.
 * Updates subscription status and user tier in the database.
 */
export function handleWebhookEvent(
  payload: WebhookPayload,
  config: LemonSqueezyConfig,
  db: AuthDB
): WebhookResult {
  const eventName = payload.meta.event_name;
  const customData = payload.meta.custom_data ?? {};
  const attrs = payload.data.attributes;
  const lsSubscriptionId = payload.data.id;

  // Resolve user from custom_data.user_id
  const userIdStr = customData['user_id'];
  if (!userIdStr) {
    return { handled: false, event: eventName, error: 'Missing user_id in custom_data' };
  }
  const userId = Number(userIdStr);
  const user = db.getUserById(userId);
  if (!user) {
    return { handled: false, event: eventName, error: `User ${userId} not found` };
  }

  const variantId = String(attrs['variant_id'] ?? '');
  const status = String(attrs['status'] ?? 'active');
  const renewsAt = attrs['renews_at'] ? String(attrs['renews_at']) : null;
  const endsAt = attrs['ends_at'] ? String(attrs['ends_at']) : null;
  const lsCustomerId = String(attrs['customer_id'] ?? '');

  // Resolve tier from variant ID
  const tier = config.variantTierMap[variantId] ?? 'solo';

  switch (eventName) {
    case 'subscription_created': {
      // New subscription: upgrade user
      db.upsertSubscription({
        userId,
        lsSubscriptionId,
        lsCustomerId,
        lsVariantId: variantId,
        tier,
        status,
        renewsAt,
        endsAt,
      });

      // Set plan_expires_at based on renews_at (subscription auto-renews)
      db.updateUserTier(userId, tier, renewsAt ?? undefined);

      // Invalidate sessions so next login picks up new tier
      db.deleteSessionsByUserId(userId);

      db.addAuditLog('subscription_created', null, userId, JSON.stringify({
        tier,
        lsSubscriptionId,
        variantId,
      }));

      logAuditEvent({
        level: 'info',
        action: 'policy_check',
        target: user.email,
        result: 'success',
        context: { details: `Subscription created: ${tier}` },
      });

      return { handled: true, event: eventName, userId, tier };
    }

    case 'subscription_updated':
    case 'subscription_resumed':
    case 'subscription_unpaused': {
      // Plan change or resumption
      db.upsertSubscription({
        userId,
        lsSubscriptionId,
        lsCustomerId,
        lsVariantId: variantId,
        tier,
        status,
        renewsAt,
        endsAt,
      });

      // Only upgrade tier if subscription is active
      if (status === 'active' || status === 'on_trial') {
        db.updateUserTier(userId, tier, renewsAt ?? undefined);
      }

      db.addAuditLog('subscription_updated', null, userId, JSON.stringify({
        tier,
        status,
        lsSubscriptionId,
      }));

      return { handled: true, event: eventName, userId, tier };
    }

    case 'subscription_cancelled': {
      // Cancelled but still active until period end
      db.updateSubscriptionStatus(lsSubscriptionId, 'cancelled', endsAt);

      db.addAuditLog('subscription_cancelled', null, userId, JSON.stringify({
        tier,
        endsAt,
        lsSubscriptionId,
      }));

      logAuditEvent({
        level: 'info',
        action: 'policy_check',
        target: user.email,
        result: 'success',
        context: { details: `Subscription cancelled, active until ${endsAt}` },
      });

      return { handled: true, event: eventName, userId, tier };
    }

    case 'subscription_expired': {
      // Subscription fully ended: downgrade to free
      db.updateSubscriptionStatus(lsSubscriptionId, 'expired', endsAt);
      db.updateUserTier(userId, 'free');

      // Invalidate sessions
      db.deleteSessionsByUserId(userId);

      db.addAuditLog('subscription_expired', null, userId, JSON.stringify({
        previousTier: tier,
        lsSubscriptionId,
      }));

      logAuditEvent({
        level: 'info',
        action: 'policy_check',
        target: user.email,
        result: 'success',
        context: { details: `Subscription expired, downgraded to free` },
      });

      return { handled: true, event: eventName, userId, tier: 'free' };
    }

    case 'subscription_paused': {
      db.updateSubscriptionStatus(lsSubscriptionId, 'paused', endsAt);

      db.addAuditLog('subscription_paused', null, userId, JSON.stringify({ lsSubscriptionId }));

      return { handled: true, event: eventName, userId, tier };
    }

    case 'subscription_payment_success': {
      // Renewal success: ensure tier is current
      db.upsertSubscription({
        userId,
        lsSubscriptionId,
        lsCustomerId,
        lsVariantId: variantId,
        tier,
        status: 'active',
        renewsAt,
        endsAt,
      });
      db.updateUserTier(userId, tier, renewsAt ?? undefined);

      return { handled: true, event: eventName, userId, tier };
    }

    case 'subscription_payment_failed': {
      db.updateSubscriptionStatus(lsSubscriptionId, 'past_due', endsAt);

      db.addAuditLog('payment_failed', null, userId, JSON.stringify({ lsSubscriptionId }));

      logAuditEvent({
        level: 'warn',
        action: 'policy_check',
        target: user.email,
        result: 'failure',
        context: { details: 'Subscription payment failed' },
      });

      return { handled: true, event: eventName, userId, tier };
    }

    default: {
      // Unknown event — acknowledge but don't process
      return { handled: false, event: eventName };
    }
  }
}

// ── Checkout URL Creation ──────────────────────────────────────

/**
 * Create a Lemon Squeezy checkout session via API.
 * Returns the checkout URL for the user.
 */
export async function createCheckoutUrl(
  config: LemonSqueezyConfig,
  variantId: string,
  user: { id: number; email: string; name: string }
): Promise<string | null> {
  try {
    const response = await fetch('https://api.lemonsqueezy.com/v1/checkouts', {
      method: 'POST',
      headers: {
        Accept: 'application/vnd.api+json',
        'Content-Type': 'application/vnd.api+json',
        Authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        data: {
          type: 'checkouts',
          attributes: {
            checkout_data: {
              email: user.email,
              name: user.name,
              custom: {
                user_id: String(user.id),
              },
            },
          },
          relationships: {
            store: {
              data: { type: 'stores', id: config.storeId },
            },
            variant: {
              data: { type: 'variants', id: variantId },
            },
          },
        },
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) return null;

    const body = (await response.json()) as {
      data?: { attributes?: { url?: string } };
    };
    return body.data?.attributes?.url ?? null;
  } catch {
    return null;
  }
}

/**
 * Retrieve the customer portal URL for managing a subscription.
 * The URL is ephemeral (24hr) — always fetch fresh.
 */
export async function getCustomerPortalUrl(
  config: LemonSqueezyConfig,
  lsSubscriptionId: string
): Promise<string | null> {
  try {
    const response = await fetch(
      `https://api.lemonsqueezy.com/v1/subscriptions/${lsSubscriptionId}`,
      {
        headers: {
          Accept: 'application/vnd.api+json',
          Authorization: `Bearer ${config.apiKey}`,
        },
        signal: AbortSignal.timeout(10000),
      }
    );

    if (!response.ok) return null;

    const body = (await response.json()) as {
      data?: { attributes?: { urls?: { customer_portal?: string } } };
    };
    return body.data?.attributes?.urls?.customer_portal ?? null;
  } catch {
    return null;
  }
}
