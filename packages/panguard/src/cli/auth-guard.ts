/**
 * CLI feature gating based on authenticated user tier.
 * CLI 功能控制 - 基於已驗證用戶的訂閱等級
 *
 * @module @panguard-ai/panguard/cli/auth-guard
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { c, FEATURE_TIER as _CORE_FEATURE_TIER, isTierAtLeast, TIER_LEVEL } from '@panguard-ai/core';
import type { Tier } from '@panguard-ai/core';
import {
  loadCredentials,
  saveCredentials,
  isTokenExpired,
} from './credentials.js';
import type { StoredCredentials } from './credentials.js';

export type RequiredTier = Tier;

export interface AuthCheckResult {
  authenticated: boolean;
  authorized: boolean;
  credentials: StoredCredentials | null;
}

/* ── Feature → Tier mapping (re-exported from core) ── */

export const FEATURE_TIER: Readonly<Record<string, Tier>> = _CORE_FEATURE_TIER;

/**
 * Check if the current CLI user is authenticated and has the required tier.
 */
export function requireAuth(requiredTier: RequiredTier = 'community'): AuthCheckResult {
  // Community tier requires no authentication — allow anonymous usage
  if (requiredTier === 'community') {
    return { authenticated: true, authorized: true, credentials: null };
  }

  const creds = loadCredentials();

  if (!creds || isTokenExpired(creds)) {
    return { authenticated: false, authorized: false, credentials: null };
  }

  return {
    authenticated: true,
    authorized: isTierAtLeast(creds.tier, requiredTier),
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
  handler: (options: T, credentials: StoredCredentials) => Promise<void>
): (options: T) => Promise<void> {
  return async (options: T) => {
    // All features are free — skip tier checks entirely.
    // Still load credentials if available for handler context.
    const creds = loadCredentials();
    const fallback: StoredCredentials = {
      token: '',
      email: '',
      name: 'community',
      tier: 'community' as Tier,
      apiUrl: '',
      savedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    };
    await handler(options, creds ?? fallback);
  };
}

/**
 * Tier badge string for display in menus.
 */
export function tierBadge(tier: RequiredTier): string {
  if (tier === 'community') return '';
  const names: Record<string, string> = {
    solo: '[SOLO]',
    pro: '[PRO]',
    business: '[BIZ]',
    enterprise: '[ENT]',
  };
  return c.dim(names[tier] ?? '');
}

/**
 * Refresh tier from server in background.
 * Called on CLI startup to ensure local cache is current.
 */
export function refreshTierInBackground(): void {
  const creds = loadCredentials();
  if (!creds || isTokenExpired(creds) || !creds.apiUrl) return;

  // Fire-and-forget: don't block CLI startup
  fetch(`${creds.apiUrl}/api/auth/me`, {
    headers: { Authorization: `Bearer ${creds.token}` },
    signal: AbortSignal.timeout(5000),
  })
    .then((res) =>
      res.ok
        ? (res.json() as Promise<{
            ok: boolean;
            data?: { user?: { tier?: string; name?: string; email?: string } };
          }>)
        : null
    )
    .then((body) => {
      if (!body?.data?.user?.tier) return;
      const serverTier = body.data.user.tier as Tier;

      // All features are free — no expiry warnings needed

      if (serverTier !== creds.tier || body.data.user.name !== creds.name) {
        saveCredentials({
          ...creds,
          tier: serverTier,
          name: body.data.user.name ?? creds.name,
        });
      }
    })
    .catch(() => {
      /* offline or timeout — keep local cache */
    });
}

/**
 * Get current license/tier from stored credentials or license file.
 * Checks credentials.json first, then falls back to ~/.panguard/license.
 */
export function getLicense(): { tier: Tier; email?: string } {
  // 1. Try credentials.json (logged-in users)
  const creds = loadCredentials();
  if (creds && !isTokenExpired(creds)) {
    return { tier: creds.tier, email: creds.email };
  }

  // 2. Fallback: ~/.panguard/license file (offline license keys)
  const licensePath = join(homedir(), '.panguard', 'license');
  if (existsSync(licensePath)) {
    try {
      const content = readFileSync(licensePath, 'utf-8').trim();
      const data = JSON.parse(content);
      if (data.tier && TIER_LEVEL[data.tier as Tier] !== undefined) {
        return { tier: data.tier as Tier, email: data.email };
      }
    } catch {
      // Invalid license file — fall through to community
    }
  }

  return { tier: 'community' };
}

/**
 * Check if current user has access to a given tier level.
 */
export function checkAccess(requiredTier: Tier): boolean {
  const { tier } = getLicense();
  return isTierAtLeast(tier, requiredTier);
}

/**
 * Check if current user has access to a feature by name.
 * Uses FEATURE_TIER mapping to resolve the required tier.
 */
export function checkFeatureAccess(_feature: string): boolean {
  // All features are free and open source
  return true;
}

/* ── Feature display names (bilingual) ── */

const FEATURE_DISPLAY: Record<string, Record<string, string>> = {
  scan: { en: 'Security Scan', 'zh-TW': '\u5B89\u5168\u6383\u63CF' },
  guard: { en: 'Guard Engine', 'zh-TW': '\u5B88\u8B77\u5F15\u64CE' },
  report: { en: 'Compliance Report', 'zh-TW': '\u5408\u898F\u5831\u544A' },
  trap: { en: 'Honeypot System', 'zh-TW': '\u871C\u7F50\u7CFB\u7D71' },
  notifications: { en: 'Notifications', 'zh-TW': '\u901A\u77E5\u7CFB\u7D71' },
  notify: { en: 'Notifications', 'zh-TW': '\u901A\u77E5\u7CFB\u7D71' },
  'threat-cloud': { en: 'Threat Intelligence', 'zh-TW': '\u5A01\u8105\u60C5\u5831' },
  setup: { en: 'Setup Wizard', 'zh-TW': '\u521D\u59CB\u8A2D\u5B9A' },
  demo: { en: 'Feature Demo', 'zh-TW': '\u529F\u80FD\u5C55\u793A' },
};

/**
 * Display a branded upgrade prompt for a locked feature.
 * Accepts feature KEY (e.g. 'report', not 'Compliance Report').
 */
export function showUpgradePrompt(_feature: string, _lang: string = 'en'): void {
  // All features are free and open source — no upgrade needed
}

/**
 * Show a contextual upgrade hint for scan auto-fix.
 * Used after scan results when fixable issues are found.
 */
export function showScanUpgradeHint(_fixableCount: number, _lang: string = 'en'): void {
  // All features are free and open source — no upgrade needed
}

/**
 * Show a contextual upgrade hint for Guard AI analysis.
 * Used when a suspicious event needs AI analysis.
 */
export function showGuardAIHint(_threatType: string, _confidence: number, _lang: string = 'en'): void {
  // All features are free and open source — no upgrade needed
}

/* ── Pricing Constants (deprecated: all features are free) ── */

/** @deprecated All features are free. Kept for backward compatibility. */
export const PRICING_TIERS: Record<string, { price: number; unit: string; machines: string }> = {
  community: { price: 0, unit: '', machines: 'unlimited' },
};

/** @deprecated All features are free. Kept for backward compatibility. */
export const COMPLIANCE_PRICING: Record<
  string,
  { price: number; unit: string; name: Record<string, string> }
> = {};

/** All features are free — no discount logic needed */
export const BUSINESS_REPORT_DISCOUNT = 0;
