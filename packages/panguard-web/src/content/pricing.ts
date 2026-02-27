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
// Plan definitions (5 tiers + Enterprise contact)
// 方案定義（5 層 + 企業聯繫）
// ---------------------------------------------------------------------------

export const PRICING_PLANS: PricingPlanDetails[] = [
  {
    plan: 'free',
    nameEn: 'Scan',
    nameZh: '免費掃描',
    taglineEn: '60-second security health check',
    taglineZh: '60 秒資安健檢',
    priceUsd: 0,
    priceDisplayEn: 'Free',
    priceDisplayZh: '免費',
    targetPersona: 'developer',
    highlighted: false,
    features: [
      feature('Panguard Scan (60-sec scan)', 'Panguard Scan（60 秒掃描）', true),
      feature('PDF security report', 'PDF 資安報告', true),
      feature('Basic risk scoring', '基礎風險評分', true),
      feature('Remediation suggestions', '修復建議', true),
      feature('Real-time monitoring', '即時監控（Panguard Guard）', false),
      feature('Chat notifications', '聊天通知（Panguard Chat）', false),
      feature('Honeypot system', '蜜罐系統（Panguard Trap）', false),
      feature('Compliance reports', '合規報告（加購）', false),
    ],
  },
  {
    plan: 'solo',
    nameEn: 'Solo',
    nameZh: '個人版',
    taglineEn: 'One endpoint, full protection',
    taglineZh: '一台端點，全面保護',
    priceUsd: 9,
    priceDisplayEn: '$9/mo',
    priceDisplayZh: 'US$9/月',
    targetPersona: 'developer',
    highlighted: false,
    features: [
      feature('Panguard Scan (unlimited)', 'Panguard Scan（無限制）', true),
      feature('Panguard Guard (1 endpoint)', 'Panguard Guard（1 台端點）', true, '1 endpoint'),
      feature('1 notification channel', '1 個通知管道', true, '1 channel'),
      feature('Monthly security summary', '月度資安摘要', true),
      feature('Auto-block malicious IPs', '自動封鎖惡意 IP', true),
      feature('7-day learning period', '7 天學習期', true),
      feature('Multiple notification channels', '多通知管道', false),
      feature('Honeypot system', '蜜罐系統（Panguard Trap）', false),
      feature('Compliance reports', '合規報告（加購）', false),
    ],
  },
  {
    plan: 'starter',
    nameEn: 'Starter',
    nameZh: '入門版',
    taglineEn: 'For freelancers and small teams',
    taglineZh: '給 Freelancer 和小團隊',
    priceUsd: 19,
    priceDisplayEn: '$19/mo',
    priceDisplayZh: 'US$19/月',
    targetPersona: 'developer',
    highlighted: false,
    features: [
      feature('Everything in Solo', '個人版所有功能', true),
      feature(
        'Panguard Guard (up to 5 endpoints)',
        'Panguard Guard（最多 5 台端點）',
        true,
        '5 endpoints'
      ),
      feature('3 notification channels', '3 個通知管道', true, '3 channels'),
      feature('Monthly security summary', '月度資安摘要', true),
      feature('Auto-block malicious IPs', '自動封鎖惡意 IP', true),
      feature('7-day learning period', '7 天學習期', true),
      feature('Honeypot system', '蜜罐系統（Panguard Trap）', false),
      feature('Compliance reports', '合規報告（加購）', false),
    ],
  },
  {
    plan: 'team',
    nameEn: 'Team',
    nameZh: '團隊版',
    taglineEn: 'AI-powered protection for your business',
    taglineZh: 'AI 驅動的企業防護',
    priceUsd: 14,
    priceDisplayEn: '$14/mo per endpoint',
    priceDisplayZh: 'US$14/月/端點',
    targetPersona: 'small_business',
    highlighted: true,
    features: [
      feature('Everything in Starter', '入門版所有功能', true),
      feature(
        'Panguard Guard (5-50 endpoints)',
        'Panguard Guard（5-50 台端點）',
        true,
        '50 endpoints'
      ),
      feature('Unlimited notification channels', '不限通知管道', true),
      feature('Weekly + monthly reports', '週報 + 月報', true),
      feature('AI auto-response', 'AI 自動回應', true),
      feature('Panguard Trap (honeypot)', 'Panguard Trap（蜜罐系統）', true),
      feature('Compliance reports', '合規報告（加購）', false),
      feature('SSO / SAML', 'SSO / SAML', false),
    ],
  },
  {
    plan: 'business',
    nameEn: 'Business',
    nameZh: '企業版',
    taglineEn: 'Compliance-ready, audit-proof',
    taglineZh: '合規就緒，稽核免煩惱',
    priceUsd: 10,
    priceDisplayEn: '$10/mo per endpoint',
    priceDisplayZh: 'US$10/月/端點',
    targetPersona: 'mid_enterprise',
    highlighted: false,
    features: [
      feature('Everything in Team', '團隊版所有功能', true),
      feature(
        'Panguard Guard (50-500 endpoints)',
        'Panguard Guard（50-500 台端點）',
        true,
        '500 endpoints'
      ),
      feature('Unlimited notification channels', '不限通知管道', true),
      feature('Daily + weekly + monthly reports', '日報 + 週報 + 月報', true),
      feature('Panguard Report (compliance)', 'Panguard Report（合規報告）', true),
      feature('Panguard Trap (advanced honeypot)', 'Panguard Trap（進階蜜罐）', true),
      feature('SSO / SAML', 'SSO / SAML', true),
      feature('Priority support', '優先技術支援', true),
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
