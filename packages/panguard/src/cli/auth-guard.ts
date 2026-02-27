/**
 * CLI feature gating based on authenticated user tier.
 * CLI 功能控制 - 基於已驗證用戶的訂閱等級
 *
 * @module @openclaw/panguard/cli/auth-guard
 */

import { c, symbols, box } from '@openclaw/core';
import { loadCredentials, isTokenExpired, tierDisplayName, TIER_LEVEL } from './credentials.js';
import type { StoredCredentials, Tier } from './credentials.js';

export type RequiredTier = Tier;

export interface AuthCheckResult {
  authenticated: boolean;
  authorized: boolean;
  credentials: StoredCredentials | null;
}

/**
 * Check if the current CLI user is authenticated and has the required tier.
 */
export function requireAuth(requiredTier: RequiredTier = 'free'): AuthCheckResult {
  // Free tier requires no authentication — allow anonymous usage
  if (requiredTier === 'free') {
    return { authenticated: true, authorized: true, credentials: null };
  }

  const creds = loadCredentials();

  if (!creds || isTokenExpired(creds)) {
    return { authenticated: false, authorized: false, credentials: null };
  }

  const userLevel = TIER_LEVEL[creds.tier] ?? 0;
  const requiredLevel = TIER_LEVEL[requiredTier] ?? 0;

  return {
    authenticated: true,
    authorized: userLevel >= requiredLevel,
    credentials: creds,
  };
}

/**
 * Decorator for Commander actions that require authentication.
 *
 * Usage:
 *   .action(withAuth('pro', async (opts, creds) => { ... }))
 */
export function withAuth<T>(
  requiredTier: RequiredTier,
  handler: (options: T, credentials: StoredCredentials) => Promise<void>,
): (options: T) => Promise<void> {
  return async (options: T) => {
    // In server/production mode (e.g. Railway), skip CLI auth check.
    // The server has its own session-based auth for API routes.
    if (process.env['PANGUARD_SERVER_MODE'] === '1' || process.env['NODE_ENV'] === 'production') {
      const creds = loadCredentials();
      await handler(options, creds ?? {
        token: 'server-mode',
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
        email: 'server@panguard.ai',
        tier: 'enterprise' as Tier,
        name: 'Panguard Server',
        savedAt: new Date().toISOString(),
        apiUrl: process.env['PANGUARD_BASE_URL'] ?? 'http://localhost:3000',
      });
      return;
    }

    const check = requireAuth(requiredTier);

    if (!check.authenticated) {
      console.log('');
      console.log(box(
        [
          `${symbols.warn} \u9700\u8981\u767B\u5165 / Authentication required`,
          '',
          `  \u8ACB\u57F7\u884C ${c.sage('panguard login')} \u4F86\u9A57\u8B49\u3002`,
          `  Run ${c.sage('panguard login')} to authenticate.`,
        ].join('\n'),
        { borderColor: c.caution, title: 'Panguard AI' },
      ));
      console.log('');
      process.exitCode = 1;
      return;
    }

    if (!check.authorized) {
      const tierName = tierDisplayName(requiredTier);
      console.log('');
      console.log(box(
        [
          `${symbols.fail} \u9700\u8981 ${tierName} \u7B49\u7D1A / ${tierName} tier required`,
          '',
          `  \u76EE\u524D\u7B49\u7D1A: ${c.sage(tierDisplayName(check.credentials!.tier))}`,
          `  Current tier: ${c.sage(tierDisplayName(check.credentials!.tier))}`,
          '',
          `  \u5347\u7D1A\u8ACB\u898B ${c.underline('https://panguard.ai/pricing')}`,
        ].join('\n'),
        { borderColor: c.critical, title: '\u9700\u8981\u5347\u7D1A / Upgrade Required' },
      ));
      console.log('');
      process.exitCode = 1;
      return;
    }

    await handler(options, check.credentials!);
  };
}

/**
 * Tier badge string for display in menus.
 */
export function tierBadge(tier: RequiredTier): string {
  if (tier === 'free') return '';
  const names: Record<string, string> = {
    solo: '[SOLO]',
    starter: '[STARTER]',
    team: '[TEAM]',
    business: '[BIZ]',
    enterprise: '[ENT]',
  };
  return c.dim(names[tier] ?? '');
}

/**
 * Get current license/tier from stored credentials.
 */
export function getLicense(): { tier: Tier; email?: string } {
  const creds = loadCredentials();
  if (!creds || isTokenExpired(creds)) return { tier: 'free' };
  return { tier: creds.tier, email: creds.email };
}

/**
 * Check if current user has access to a given tier level.
 */
export function checkAccess(requiredTier: Tier): boolean {
  const { tier } = getLicense();
  return (TIER_LEVEL[tier] ?? 0) >= (TIER_LEVEL[requiredTier] ?? 0);
}

/**
 * Display a branded upgrade prompt for a locked feature.
 */
export function showUpgradePrompt(feature: string, requiredTier: Tier): void {
  const { tier } = getLicense();
  const price = PRICING_TIERS[requiredTier]?.price ?? 'custom';
  console.log('');
  console.log(box(
    [
      `${symbols.warn} "${feature}" ${tierDisplayName(requiredTier)} tier required`,
      '',
      `  Current: ${c.sage(tierDisplayName(tier))}`,
      `  Required: ${c.sage(tierDisplayName(requiredTier))}${price !== 'custom' ? ` ($${price}/mo)` : ''}`,
      '',
      `  Upgrade: ${c.underline('https://panguard.ai/pricing')}`,
      `  Or run: ${c.sage('panguard login')}`,
    ].join('\n'),
    { borderColor: c.caution, title: 'Upgrade Required' },
  ));
  console.log('');
}

/* ── Pricing Constants ── */

export const PRICING_TIERS: Record<string, { price: number | 'custom'; unit: string; endpoints: string }> = {
  free: { price: 0, unit: '', endpoints: '1 endpoint' },
  solo: { price: 9, unit: '/mo', endpoints: '1 endpoint' },
  pro: { price: 19, unit: '/endpoint/mo', endpoints: 'Up to 50 endpoints' },
  enterprise: { price: 'custom', unit: '', endpoints: 'Unlimited' },
};

export const COMPLIANCE_PRICING = {
  assessment: { price: 499, originalPrice: 999, unit: 'one-time' },
  monitoring: { price: 99, originalPrice: 199, unit: '/mo' },
} as const;
