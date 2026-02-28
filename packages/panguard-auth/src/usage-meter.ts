/**
 * Usage metering and quota enforcement for tier-based limits.
 * Tracks monthly usage per resource per user.
 *
 * @module @panguard-ai/panguard-auth/usage-meter
 */

import type { AuthDB } from './database.js';

/**
 * Resource types that can be metered.
 * - Monthly resources reset each calendar month.
 * - Count resources are persistent (e.g. active endpoints).
 */
export type MeterableResource =
  | 'scan'
  | 'guard_endpoints'
  | 'reports'
  | 'api_calls'
  | 'notifications'
  | 'trap_instances';

export interface QuotaCheck {
  allowed: boolean;
  current: number;
  limit: number; // -1 = unlimited
  remaining: number; // -1 = unlimited
  resource: MeterableResource;
}

export interface UsageSummary {
  resource: MeterableResource;
  current: number;
  limit: number;
  percentage: number; // 0-100, capped at 100
}

/** Quota limits per tier. -1 means unlimited. */
const TIER_QUOTAS: Record<string, Record<MeterableResource, number>> = {
  free: {
    scan: 100,
    guard_endpoints: 1,
    reports: 0,
    api_calls: 1000,
    notifications: 0,
    trap_instances: 0,
  },
  community: {
    scan: 100,
    guard_endpoints: 1,
    reports: 0,
    api_calls: 1000,
    notifications: 0,
    trap_instances: 0,
  },
  solo: {
    scan: -1,
    guard_endpoints: 3,
    reports: 0,
    api_calls: 10000,
    notifications: 1,
    trap_instances: 1,
  },
  starter: {
    scan: -1,
    guard_endpoints: 5,
    reports: 0,
    api_calls: 10000,
    notifications: 3,
    trap_instances: 1,
  },
  pro: {
    scan: -1,
    guard_endpoints: 10,
    reports: 5,
    api_calls: 50000,
    notifications: 3,
    trap_instances: 3,
  },
  team: {
    scan: -1,
    guard_endpoints: 10,
    reports: 5,
    api_calls: 50000,
    notifications: -1,
    trap_instances: 3,
  },
  business: {
    scan: -1,
    guard_endpoints: 25,
    reports: 20,
    api_calls: -1,
    notifications: -1,
    trap_instances: 8,
  },
  enterprise: {
    scan: -1,
    guard_endpoints: -1,
    reports: -1,
    api_calls: -1,
    notifications: -1,
    trap_instances: -1,
  },
};

/** Monthly resources that reset each calendar month. */
const MONTHLY_RESOURCES: Set<MeterableResource> = new Set(['scan', 'reports', 'api_calls']);

/** Get the current month period string, e.g. '2026-02'. */
export function currentPeriod(): string {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

/** Get the period string for a resource (monthly vs lifetime). */
function getPeriod(resource: MeterableResource): string {
  return MONTHLY_RESOURCES.has(resource) ? currentPeriod() : 'lifetime';
}

/**
 * Check if a user has quota remaining for a given resource.
 */
export function checkQuota(
  db: AuthDB,
  userId: number,
  tier: string,
  resource: MeterableResource
): QuotaCheck {
  const quotas = TIER_QUOTAS[tier] ?? TIER_QUOTAS['free']!;
  const limit = quotas[resource] ?? 0;
  const period = getPeriod(resource);
  const current = db.getUsage(userId, resource, period);

  if (limit === -1) {
    return { allowed: true, current, limit: -1, remaining: -1, resource };
  }

  const remaining = Math.max(0, limit - current);
  return {
    allowed: current < limit,
    current,
    limit,
    remaining,
    resource,
  };
}

/**
 * Record usage for a resource. Call after the operation succeeds.
 */
export function recordUsage(
  db: AuthDB,
  userId: number,
  resource: MeterableResource,
  count: number = 1
): void {
  const period = getPeriod(resource);
  db.incrementUsage(userId, resource, period, count);
}

/**
 * Set absolute usage for count-based resources (e.g. guard_endpoints).
 */
export function setUsage(
  db: AuthDB,
  userId: number,
  resource: MeterableResource,
  count: number
): void {
  const period = getPeriod(resource);
  db.setUsage(userId, resource, period, count);
}

/**
 * Get usage summary for all resources for a user.
 */
export function getUsageSummary(db: AuthDB, userId: number, tier: string): UsageSummary[] {
  const quotas = TIER_QUOTAS[tier] ?? TIER_QUOTAS['free']!;
  const resources = Object.keys(quotas) as MeterableResource[];

  return resources.map((resource) => {
    const limit = quotas[resource] ?? 0;
    const period = getPeriod(resource);
    const current = db.getUsage(userId, resource, period);
    const percentage =
      limit === -1
        ? 0
        : limit === 0
          ? current > 0
            ? 100
            : 0
          : Math.min(100, Math.round((current / limit) * 100));

    return { resource, current, limit, percentage };
  });
}

/**
 * Get quota limits for a tier (for display purposes).
 */
export function getQuotaLimits(tier: string): Record<MeterableResource, number> {
  return { ...(TIER_QUOTAS[tier] ?? TIER_QUOTAS['free']!) };
}
