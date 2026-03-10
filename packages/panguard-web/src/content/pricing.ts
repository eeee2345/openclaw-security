/**
 * Pricing plan definitions
 * 定價方案定義
 *
 * Based on competitive analysis: Panguard fills the gap between
 * self-serve EDR ($2-8/ep) and enterprise AI SOC ($36K+/yr).
 * "AI watches for you, at self-serve prices."
 *
 * @module @panguard-ai/panguard-web/content/pricing
 */

import type { PricingPlanDetails, PricingPlan, PlanFeature, ReportAddon } from '../types.js';

// ---------------------------------------------------------------------------
// Shared features
// 共享功能
// ---------------------------------------------------------------------------

function feature(nameEn: string, nameZh: string, included: boolean, limit?: string): PlanFeature {
  return { nameEn, nameZh, included, limit };
}

// ---------------------------------------------------------------------------
// Plan definitions — Community plan (all features free)
// 方案定義 — 社群方案（所有功能免費）
// ---------------------------------------------------------------------------

export const PRICING_PLANS: PricingPlanDetails[] = [
  {
    plan: 'community',
    nameEn: 'Community',
    nameZh: '社群版',
    taglineEn: 'All features included. Free and open source.',
    taglineZh: '所有功能免費開源',
    priceUsd: 0,
    priceDisplayEn: 'Free',
    priceDisplayZh: '免費',
    targetPersona: 'developer',
    highlighted: true,
    features: [
      feature('Panguard Scan (full scan)', 'Panguard Scan（完整掃描）', true),
      feature('Guard detection (all layers)', 'Guard 偵測（全部層級）', true),
      feature('Auto-block known patterns', '自動封鎖已知攻擊模式', true),
      feature('AI analysis', 'AI 分析', true),
      feature('Panguard Chat', 'Panguard Chat', true),
      feature('Panguard Report', 'Panguard Report（完整報告）', true),
      feature('Panguard Trap (honeypot)', 'Panguard Trap（蜜罐系統）', true),
      feature('Notification channels', '通知管道', true),
      feature('Compliance reports', '合規報告', true),
      feature('Webhook / API integration', 'Webhook / API 整合', true),
      feature('Community support', '社群支援', true),
    ],
  },
];

// ---------------------------------------------------------------------------
// Report add-on products (independent of subscription tier)
// 報告加購產品（獨立於訂閱方案）
// ---------------------------------------------------------------------------

export const REPORT_ADDONS: ReportAddon[] = [];

/**
 * Get pricing plan by type
 * 根據類型取得方案
 */
export function getPricingPlan(plan: PricingPlan): PricingPlanDetails | undefined {
  return PRICING_PLANS.find((p) => p.plan === plan);
}

/**
 * Get all pricing plans
 * 取得所有方案
 */
export function getAllPricingPlans(): PricingPlanDetails[] {
  return PRICING_PLANS;
}

/**
 * Get recommended plan for a persona
 * 根據角色取得推薦方案
 */
export function getRecommendedPlan(persona: string): PricingPlanDetails | undefined {
  return (
    PRICING_PLANS.find((p) => p.targetPersona === persona && p.highlighted) ??
    PRICING_PLANS.find((p) => p.targetPersona === persona)
  );
}

/**
 * Get all report add-on products
 * 取得所有報告加購產品
 */
export function getAllReportAddons(): ReportAddon[] {
  return REPORT_ADDONS;
}

/**
 * Get report add-on by ID
 * 根據 ID 取得報告加購產品
 */
export function getReportAddon(id: string): ReportAddon | undefined {
  return REPORT_ADDONS.find((r) => r.id === id);
}
