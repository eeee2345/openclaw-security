/**
 * Centralized tier definitions for the Panguard AI platform.
 * All packages should import tier types and constants from here.
 *
 * @module @panguard-ai/core/tiers
 */

/** Subscription tier levels */
export type Tier = 'community' | 'solo' | 'pro' | 'business' | 'enterprise';

/** All valid tiers as a const tuple (useful for validation) */
export const TIERS = ['community', 'solo', 'pro', 'business', 'enterprise'] as const;

/** Numeric tier hierarchy for access control comparisons */
export const TIER_LEVEL: Record<Tier, number> = {
  community: 0,
  solo: 1,
  pro: 2,
  business: 3,
  enterprise: 5,
};

/** Maps CLI feature names to their minimum required tier */
export const FEATURE_TIER: Readonly<Record<string, Tier>> = {
  setup: 'community',
  scan: 'community',
  guard: 'community',
  'threat-cloud': 'community',
  demo: 'community',
  notifications: 'solo',
  notify: 'solo',
  trap: 'pro',
  report: 'pro',
};

/** Check if current tier meets or exceeds the required tier */
export function isTierAtLeast(current: Tier, required: Tier): boolean {
  return TIER_LEVEL[current] >= TIER_LEVEL[required];
}

/** Type guard: check if a string is a valid Tier */
export function isValidTier(value: string): value is Tier {
  return (TIERS as readonly string[]).includes(value);
}
