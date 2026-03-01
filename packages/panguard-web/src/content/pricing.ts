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
// Plan definitions (3 paid tiers + Community free)
// 方案定義（3 個付費方案 + 社群免費版）
// ---------------------------------------------------------------------------

export const PRICING_PLANS: PricingPlanDetails[] = [
  {
    plan: 'community',
    nameEn: 'Community',
    nameZh: '社群版',
    taglineEn: '60-second security health check',
    taglineZh: '60 秒資安健檢',
    priceUsd: 0,
    priceDisplayEn: 'Free',
    priceDisplayZh: '免費',
    targetPersona: 'developer',
    highlighted: false,
    features: [
      feature('Panguard Scan (full scan)', 'Panguard Scan（完整掃描）', true),
      feature('Guard detection (Layer 1)', 'Guard 偵測（第一層）', true),
      feature('Auto-block known patterns', '自動封鎖已知攻擊模式', true),
      feature('Manual remediation guide', '手動修復指南', true),
      feature('Community support', '社群支援', true),
      feature('AI analysis', 'AI 分析', false),
      feature('Notification channels', '通知管道', false),
      feature('Compliance reports', '合規報告', false),
    ],
  },
  {
    plan: 'solo',
    nameEn: 'Solo',
    nameZh: '個人版',
    taglineEn: 'Full protection for individual developers',
    taglineZh: '個人開發者的完整防護',
    priceUsd: 9,
    priceDisplayEn: '$9/mo',
    priceDisplayZh: 'US$9/月',
    targetPersona: 'developer',
    highlighted: false,
    features: [
      feature('Everything in Community', '社群版所有功能', true),
      feature('Guard detection (Layer 1+2+3)', 'Guard 偵測（全部三層）', true),
      feature('Up to 3 machines', '最多 3 台機器', true, '3 machines'),
      feature('AI analysis', 'AI 分析', true),
      feature('Panguard Chat (basic)', 'Panguard Chat（基礎版）', true),
      feature('Email + Telegram alerts', 'Email + Telegram 通知', true),
      feature('One-click auto-fix', '一鍵自動修復', true),
      feature('7-day log retention', '7 天日誌保留', true),
    ],
  },
  {
    plan: 'pro',
    nameEn: 'Pro',
    nameZh: '專業版',
    taglineEn: 'AI-powered protection for teams',
    taglineZh: 'AI 驅動的團隊防護',
    priceUsd: 29,
    priceDisplayEn: '$29/mo',
    priceDisplayZh: 'US$29/月',
    targetPersona: 'small_business',
    highlighted: true,
    features: [
      feature('Everything in Solo', '個人版所有功能', true),
      feature('Up to 10 machines', '最多 10 台機器', true, '10 machines'),
      feature('Panguard Chat (advanced)', 'Panguard Chat（進階版）', true),
      feature('Panguard Report (full)', 'Panguard Report（完整報告）', true),
      feature('Panguard Trap (honeypot)', 'Panguard Trap（蜜罐系統）', true),
      feature('Slack integration', 'Slack 整合', true),
      feature('Priority support', '優先技術支援', true),
      feature('30-day log retention', '30 天日誌保留', true),
    ],
  },
  {
    plan: 'business',
    nameEn: 'Business',
    nameZh: '企業版',
    taglineEn: 'Compliance-ready, audit-proof',
    taglineZh: '合規就緒，稽核免煩惱',
    priceUsd: 79,
    priceDisplayEn: '$79/mo',
    priceDisplayZh: 'US$79/月',
    targetPersona: 'mid_enterprise',
    highlighted: false,
    features: [
      feature('Everything in Pro', '專業版所有功能', true),
      feature('Up to 25 machines', '最多 25 台機器', true, '25 machines'),
      feature('Custom AI models', '自訂 AI 模型', true),
      feature('Panguard Chat (advanced + API)', 'Panguard Chat（進階 + API）', true),
      feature('Webhook / API integration', 'Webhook / API 整合', true),
      feature('Panguard Report (full + custom)', 'Panguard Report（完整 + 客製）', true),
      feature('90-day+ log retention', '90 天以上日誌保留', true),
      feature('SSO / SAML (roadmap)', 'SSO / SAML（規劃中）', true),
    ],
  },
];

// ---------------------------------------------------------------------------
// Report add-on products (independent of subscription tier)
// 報告加購產品（獨立於訂閱方案）
// ---------------------------------------------------------------------------

export const REPORT_ADDONS: ReportAddon[] = [
  {
    id: 'tw_cyber_security_act',
    nameEn: 'Taiwan Cyber Security Act',
    nameZh: '台灣資通安全管理法',
    descriptionEn:
      'Automated compliance assessment against Taiwan Cyber Security Management Act. Monthly monitoring and reporting.',
    descriptionZh: '自動化台灣資通安全管理法合規評估。每月監控與報告。',
    pricingModel: 'subscription',
    priceUsd: 149,
    priceDisplayEn: '$149/mo',
    priceDisplayZh: 'US$149/月',
    annualPriceUsd: 1499,
    annualPriceDisplayEn: '$1,499/yr',
    annualPriceDisplayZh: 'US$1,499/年',
    framework: 'tw_cyber_security_act',
  },
  {
    id: 'iso27001',
    nameEn: 'ISO 27001 Readiness Report',
    nameZh: 'ISO 27001 準備報告',
    descriptionEn:
      'Gap analysis report for ISO/IEC 27001:2022 certification readiness. Includes control mapping and remediation plan.',
    descriptionZh: 'ISO/IEC 27001:2022 認證準備差距分析報告。含控制項對照與改善計畫。',
    pricingModel: 'per_report',
    priceUsd: 499,
    priceDisplayEn: '$499/report',
    priceDisplayZh: 'US$499/份',
    framework: 'iso27001',
  },
  {
    id: 'soc2',
    nameEn: 'SOC 2 Readiness Report',
    nameZh: 'SOC 2 準備報告',
    descriptionEn:
      'Trust Services Criteria assessment for SOC 2 audit preparation. Covers all 5 trust categories.',
    descriptionZh: 'SOC 2 稽核準備的信任服務準則評估。涵蓋全部 5 大信任類別。',
    pricingModel: 'per_report',
    priceUsd: 499,
    priceDisplayEn: '$499/report',
    priceDisplayZh: 'US$499/份',
    framework: 'soc2',
  },
  {
    id: 'incident_report',
    nameEn: 'Security Incident Report',
    nameZh: '資安事件報告',
    descriptionEn:
      'Formal security incident documentation required by regulators. Includes timeline, impact analysis, and remediation.',
    descriptionZh: '監管機關要求的正式資安事件文件。含時間線、影響分析及改善措施。',
    pricingModel: 'per_report',
    priceUsd: 299,
    priceDisplayEn: '$299/report',
    priceDisplayZh: 'US$299/份',
    framework: 'incident',
  },
];

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
