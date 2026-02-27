/**
 * Panguard CLI Theme — Minimalist brand styling system
 *
 * Wraps @openclaw/core color system with semantic theme API.
 * Brand color: Sage Green #8B9878
 *
 * @module @openclaw/panguard/cli/theme
 */

import { c, stripAnsi, visLen } from '@openclaw/core';
import type { Tier } from './credentials.js';

// ── Brand ASCII Block Letter Logo ─────────────────────────────────────
// Exact characters from brand spec. Do not modify.

export const BRAND_LOGO = [
  ' \u2554\u2550\u2557 \u2554\u2550\u2557 \u2554\u2557\u2554 \u2554\u2550\u2557 \u2566 \u2566 \u2554\u2550\u2557 \u2566\u2550\u2557 \u2554\u2566\u2557   \u2554\u2550\u2557 \u2566',
  ' \u2560\u2550\u2563 \u2560\u2550\u2563 \u2551\u2551\u2551 \u2551 \u2566 \u2551 \u2551 \u2560\u2550\u2563 \u2560\u2566\u255d  \u2551\u2551   \u2560\u2550\u2563 \u2551',
  ' \u2569   \u2569 \u2569 \u255d\u255a\u255d \u255a\u2550\u255d \u255a\u2550\u255d \u2569 \u2569 \u2569\u255a\u2550 \u2550\u2569\u255d   \u2569 \u2569 \u2569',
];

// ── Theme Colors ──────────────────────────────────────────────────────

export const theme = {
  // Brand
  brand: c.sage,
  brandBold: (s: string) => c.bold(c.sage(s)),

  // Text hierarchy
  title: (s: string) => c.bold(s),
  subtitle: c.dim,
  dim: c.dim,
  link: (s: string) => c.underline(c.sage(s)),

  // Status
  success: c.safe,
  warning: c.caution,
  error: c.critical,

  // Severity
  critical: (s: string) => c.bold(c.critical(s)),
  high: c.critical,
  medium: c.caution,
  low: c.dim,
};

// ── Tier Badges ───────────────────────────────────────────────────────

const TIER_COLORS: Record<string, (s: string) => string> = {
  free: c.safe,
  solo: c.caution,
  starter: c.caution,
  pro: c.alert,
  team: c.alert,
  business: c.alert,
  enterprise: c.critical,
};

/** Tier badge for menu display (e.g. "Free", "Solo 🔒", "Pro 🔒") */
export function tierLabel(tier: Tier | string): string {
  const colorFn = TIER_COLORS[tier] ?? c.dim;
  const names: Record<string, string> = {
    free: 'Free',
    solo: 'Solo',
    starter: 'Solo',
    pro: 'Pro',
    team: 'Pro',
    business: 'Pro',
    enterprise: 'Ent',
  };
  const name = names[tier] ?? tier;
  if (tier === 'free') return colorFn(name);
  return colorFn(name) + ' ' + c.dim('\uD83D\uDD12');
}

/** Render the brand logo in sage green */
export function renderLogo(): void {
  for (const line of BRAND_LOGO) {
    console.log(c.sage(line));
  }
}

// Re-export for convenience
export { c, stripAnsi, visLen };
