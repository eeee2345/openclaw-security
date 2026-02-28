/**
 * CLI feature gating based on authenticated user tier.
 * CLI 功能控制 - 基於已驗證用戶的訂閱等級
 *
 * @module @panguard-ai/panguard/cli/auth-guard
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { c, symbols, box } from '@panguard-ai/core';
import {
  loadCredentials,
  saveCredentials,
  isTokenExpired,
  tierDisplayName,
  TIER_LEVEL,
} from './credentials.js';
import type { StoredCredentials, Tier } from './credentials.js';

export type RequiredTier = Tier;

export interface AuthCheckResult {
  authenticated: boolean;
  authorized: boolean;
  credentials: StoredCredentials | null;
}

/* ── Feature → Tier mapping ── */

export const FEATURE_TIER: Record<string, Tier> = {
  setup: 'free',
  scan: 'free',
  guard: 'free',
  'threat-cloud': 'free',
  demo: 'free',
  notifications: 'solo',
  notify: 'solo',
  trap: 'solo',
  report: 'business',
};

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
  handler: (options: T, credentials: StoredCredentials) => Promise<void>
): (options: T) => Promise<void> {
  return async (options: T) => {
    // In server mode, require a valid service token from environment.
    // The server has its own session-based auth for API routes.
    if (process.env['PANGUARD_SERVER_MODE'] === '1') {
      const creds = loadCredentials();
      if (!creds || isTokenExpired(creds)) {
        console.error('Server mode requires valid credentials. Run `panguard login` first.');
        process.exitCode = 1;
        return;
      }
      await handler(options, creds);
      return;
    }

    const check = requireAuth(requiredTier);

    if (!check.authenticated) {
      console.log('');
      console.log(
        box(
          [
            `${symbols.warn} \u9700\u8981\u767B\u5165 / Authentication required`,
            '',
            `  \u8ACB\u57F7\u884C ${c.sage('panguard login')} \u4F86\u9A57\u8B49\u3002`,
            `  Run ${c.sage('panguard login')} to authenticate.`,
          ].join('\n'),
          { borderColor: c.caution, title: 'Panguard AI' }
        )
      );
      console.log('');
      process.exitCode = 1;
      return;
    }

    if (!check.authorized) {
      const tierName = tierDisplayName(requiredTier);
      console.log('');
      console.log(
        box(
          [
            `${symbols.fail} \u9700\u8981 ${tierName} \u7B49\u7D1A / ${tierName} tier required`,
            '',
            `  \u76EE\u524D\u7B49\u7D1A: ${c.sage(tierDisplayName(check.credentials!.tier))}`,
            `  Current tier: ${c.sage(tierDisplayName(check.credentials!.tier))}`,
            '',
            `  \u5347\u7D1A\u8ACB\u898B ${c.underline('https://panguard.ai/pricing')}`,
          ].join('\n'),
          { borderColor: c.critical, title: '\u9700\u8981\u5347\u7D1A / Upgrade Required' }
        )
      );
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
  if (tier === 'free' || tier === 'community') return '';
  const names: Record<string, string> = {
    solo: '[SOLO]',
    pro: '[PRO]',
    business: '[BIZ]',
    // legacy
    enterprise: '[BIZ]',
    starter: '[SOLO]',
    team: '[PRO]',
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
      const serverPlanExpires = (body.data.user as Record<string, unknown>).planExpiresAt as
        | string
        | null
        | undefined;

      // Check if plan has expired server-side (tier got downgraded to free)
      if (serverTier === 'free' && creds.tier !== 'free') {
        console.log('');
        console.log(
          c.caution(
            `  [!] Your ${tierDisplayName(creds.tier)} plan has expired. Account downgraded to free tier.`
          )
        );
        console.log(c.dim(`      Renew at https://panguard.ai/pricing`));
        console.log('');
      }

      // Warn if plan expiring soon (within 3 days)
      if (serverPlanExpires) {
        const expiresDate = new Date(serverPlanExpires);
        const daysLeft = Math.ceil((expiresDate.getTime() - Date.now()) / (24 * 60 * 60 * 1000));
        if (daysLeft > 0 && daysLeft <= 3) {
          console.log('');
          console.log(
            c.caution(
              `  [!] Your ${tierDisplayName(serverTier)} plan expires in ${daysLeft} day(s).`
            )
          );
          console.log(c.dim(`      Renew at https://panguard.ai/pricing`));
          console.log('');
        }
      }

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
      // Invalid license file — fall through to free
    }
  }

  return { tier: 'free' };
}

/**
 * Check if current user has access to a given tier level.
 */
export function checkAccess(requiredTier: Tier): boolean {
  const { tier } = getLicense();
  return (TIER_LEVEL[tier] ?? 0) >= (TIER_LEVEL[requiredTier] ?? 0);
}

/**
 * Check if current user has access to a feature by name.
 * Uses FEATURE_TIER mapping to resolve the required tier.
 */
export function checkFeatureAccess(feature: string): boolean {
  const requiredTier = FEATURE_TIER[feature] ?? 'free';
  return checkAccess(requiredTier);
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
export function showUpgradePrompt(feature: string, lang: string = 'en'): void {
  const tier = FEATURE_TIER[feature] ?? 'free';
  const { tier: userTier } = getLicense();
  const tierName = tierDisplayName(tier);
  const userTierName = tierDisplayName(userTier);
  const pricing = PRICING_TIERS[tier];
  const priceStr = pricing && pricing.price > 0 ? `$${pricing.price}${pricing.unit}` : '';
  const machinesStr = pricing ? pricing.machines : '';
  const featureName =
    FEATURE_DISPLAY[feature]?.[lang] ?? FEATURE_DISPLAY[feature]?.['en'] ?? feature;

  const lines: string[] =
    lang === 'zh-TW'
      ? [
          `\u300C${featureName}\u300D\u9700\u8981 ${tierName} \u65B9\u6848`,
          priceStr ? `${priceStr} | ${machinesStr} \u53F0\u6A5F\u5668` : '',
          '',
          `\u76EE\u524D\u65B9\u6848:  ${c.sage(userTierName)}`,
          `\u9700\u8981\u65B9\u6848:  ${c.sage(tierName)}`,
          '',
          `\u2192 ${c.underline('https://panguard.ai/pricing')}`,
          `\u2192 ${c.sage('panguard activate <license-key>')}`,
          '',
          c.dim(
            '\u6240\u6709\u4ED8\u8CBB\u65B9\u6848\u4EAB 30 \u5929\u514D\u8CBB\u8A66\u7528\u3002'
          ),
        ]
      : [
          `${featureName} requires ${tierName} plan`,
          priceStr ? `${priceStr} | ${machinesStr} machine(s)` : '',
          '',
          `Current:   ${c.sage(userTierName)}`,
          `Required:  ${c.sage(tierName)}`,
          '',
          `\u2192 ${c.underline('https://panguard.ai/pricing')}`,
          `\u2192 ${c.sage('panguard activate <license-key>')}`,
          '',
          c.dim('All paid plans include 30-day free trial.'),
        ];

  const content = lines.filter((l) => l !== '');

  console.log('');
  console.log(
    box(content.join('\n'), {
      borderColor: c.sage,
      title: lang === 'zh-TW' ? '\u9700\u8981\u5347\u7D1A' : 'Upgrade Required',
    })
  );
  console.log('');
}

/**
 * Show a contextual upgrade hint for scan auto-fix.
 * Used after scan results when fixable issues are found.
 */
export function showScanUpgradeHint(fixableCount: number, lang: string = 'en'): void {
  const lines =
    lang === 'zh-TW'
      ? [
          `\u767C\u73FE ${fixableCount} \u500B\u53EF\u81EA\u52D5\u4FEE\u5FA9\u7684\u554F\u984C\u3002`,
          `\u5347\u7D1A\u5230 Solo ($9/\u6708) \u5373\u53EF\u4E00\u9375\u4FEE\u5FA9\uFF1A`,
          `$ panguard scan --fix`,
        ]
      : [
          `${fixableCount} issue(s) can be auto-fixed.`,
          `Upgrade to Solo ($9/mo) for one-click fix:`,
          `$ panguard scan --fix`,
        ];
  console.log('');
  console.log(box(lines.join('\n'), { borderColor: c.sage }));
}

/**
 * Show a contextual upgrade hint for Guard AI analysis.
 * Used when a suspicious event needs AI analysis.
 */
export function showGuardAIHint(threatType: string, confidence: number, lang: string = 'en'): void {
  console.log('');
  if (lang === 'zh-TW') {
    console.log(
      `  ${c.caution('[?]')} \u5075\u6E2C\u5230\u53EF\u7591\u6D3B\u52D5\uFF08\u4FE1\u5FC3\u5EA6 ${confidence}%\uFF09`
    );
    console.log(`      \u985E\u578B: ${threatType}`);
    console.log('');
    console.log(
      c.dim(
        `      \u9700\u8981 AI \u5206\u6790\u624D\u80FD\u5224\u65B7\u662F\u5426\u70BA\u5A01\u8105\u3002`
      )
    );
    console.log(
      c.dim(
        `      \u5347\u7D1A\u5230 Solo ($9/\u6708) \u89E3\u9396 AI \u6DF1\u5EA6\u5206\u6790\u3002`
      )
    );
  } else {
    console.log(`  ${c.caution('[?]')} Suspicious activity detected (confidence ${confidence}%)`);
    console.log(`      Type: ${threatType}`);
    console.log('');
    console.log(c.dim(`      AI analysis required to determine if this is a threat.`));
    console.log(c.dim(`      Upgrade to Solo ($9/mo) for AI-powered analysis.`));
  }
  console.log('');
}

/* ── Pricing Constants ── */

export const PRICING_TIERS: Record<string, { price: number; unit: string; machines: string }> = {
  free: { price: 0, unit: '', machines: '1' },
  community: { price: 0, unit: '', machines: '1' },
  solo: { price: 9, unit: '/mo', machines: '3' },
  pro: { price: 29, unit: '/mo', machines: '10' },
  business: { price: 79, unit: '/mo', machines: '25' },
};

export const COMPLIANCE_PRICING: Record<
  string,
  { price: number; unit: string; name: Record<string, string> }
> = {
  tw_cyber_security: {
    price: 299,
    unit: 'one-time',
    name: {
      en: 'TW Cyber Security Act',
      'zh-TW': '\u8CC7\u5B89\u6CD5\u6E96\u5099\u5EA6\u8A55\u4F30',
    },
  },
  iso27001: {
    price: 499,
    unit: 'one-time',
    name: { en: 'ISO 27001 Readiness', 'zh-TW': 'ISO 27001 \u6E96\u5099\u5EA6\u8A55\u4F30' },
  },
  soc2: {
    price: 699,
    unit: 'one-time',
    name: { en: 'SOC 2 Readiness', 'zh-TW': 'SOC 2 \u6E96\u5099\u5EA6\u8A55\u4F30' },
  },
  bundle: {
    price: 999,
    unit: 'one-time',
    name: {
      en: 'Compliance Bundle (All 3)',
      'zh-TW': '\u5408\u898F\u7D44\u5408\u5305 (3 \u9805\u5168\u542B)',
    },
  },
};

/** Business subscribers get 50% off additional reports */
export const BUSINESS_REPORT_DISCOUNT = 0.5;
