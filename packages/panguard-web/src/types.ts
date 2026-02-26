/**
 * Panguard Web type definitions
 * Panguard Web 型別定義
 * @module @openclaw/panguard-web/types
 */

// ---------------------------------------------------------------------------
// Language & Locale
// 語言與地區
// ---------------------------------------------------------------------------

/** Supported website languages / 支援的網站語言 */
export type WebLanguage = 'zh-TW' | 'en';

// ---------------------------------------------------------------------------
// Target Audience (TA) Personas
// 目標用戶角色
// ---------------------------------------------------------------------------

/** User persona types matching README TA / 用戶角色（符合 README TA 定義） */
export type PersonaType = 'developer' | 'small_business' | 'mid_enterprise';

/** Persona profile for scenario-based content / 場景化內容的用戶 profile */
export interface PersonaProfile {
  /** Persona type / 角色類型 */
  type: PersonaType;
  /** Display name / 顯示名稱 */
  nameEn: string;
  /** Display name in Chinese / 中文顯示名稱 */
  nameZh: string;
  /** Short description / 簡短描述 */
  descriptionEn: string;
  /** Short description in Chinese / 中文簡短描述 */
  descriptionZh: string;
  /** Pain points / 痛點 */
  painPointsEn: string[];
  /** Pain points in Chinese / 中文痛點 */
  painPointsZh: string[];
  /** Recommended plan / 推薦方案 */
  recommendedPlan: PricingPlan;
  /** Scenario stories / 場景故事 */
  scenarios: ScenarioStory[];
}

// ---------------------------------------------------------------------------
// Scenario Stories (場景化文案)
// ---------------------------------------------------------------------------

/** A scenario-based story for the website / 場景化故事 */
export interface ScenarioStory {
  /** Scenario ID / 場景 ID */
  id: string;
  /** Threat type / 威脅類型 */
  threatType: string;
  /** Before: What the user sees (without Panguard) / 使用前：用戶看到什麼 */
  beforeEn: string;
  beforeZh: string;
  /** After: What Panguard does (human language) / 使用後：Panguard 做了什麼 */
  afterEn: string;
  afterZh: string;
  /** Notification the user would receive / 用戶會收到的通知 */
  notificationEn: string;
  notificationZh: string;
}

// ---------------------------------------------------------------------------
// Pricing
// 定價
// ---------------------------------------------------------------------------

/** Pricing plan names / 方案名稱 */
export type PricingPlan = 'free' | 'solo' | 'starter' | 'team' | 'business';

/** Report add-on product / 報告加購產品 */
export interface ReportAddon {
  /** Report type ID / 報告類型 ID */
  id: string;
  /** Display name / 顯示名稱 */
  nameEn: string;
  nameZh: string;
  /** Description / 描述 */
  descriptionEn: string;
  descriptionZh: string;
  /** Pricing model / 計費模式 */
  pricingModel: 'per_report' | 'subscription';
  /** Price in USD / 美元價格 */
  priceUsd: number;
  /** Price display / 價格顯示 */
  priceDisplayEn: string;
  priceDisplayZh: string;
  /** Annual price (for subscription model) / 年費（訂閱模式用） */
  annualPriceUsd?: number;
  annualPriceDisplayEn?: string;
  annualPriceDisplayZh?: string;
  /** Compliance framework ID / 合規框架 ID */
  framework: string;
}

/** Feature entry in a pricing plan / 方案中的功能項 */
export interface PlanFeature {
  /** Feature name / 功能名稱 */
  nameEn: string;
  nameZh: string;
  /** Included in this plan / 此方案是否包含 */
  included: boolean;
  /** Limit (if any) / 限制（如有） */
  limit?: string;
}

/** Pricing plan details / 方案詳情 */
export interface PricingPlanDetails {
  /** Plan type / 方案類型 */
  plan: PricingPlan;
  /** Display name / 顯示名稱 */
  nameEn: string;
  nameZh: string;
  /** Tagline / 標語 */
  taglineEn: string;
  taglineZh: string;
  /** Monthly price (USD) / 月費 (USD) */
  priceUsd: number;
  /** Price display text / 價格顯示文字 */
  priceDisplayEn: string;
  priceDisplayZh: string;
  /** Features / 功能列表 */
  features: PlanFeature[];
  /** Target audience / 目標用戶 */
  targetPersona: PersonaType;
  /** Is highlighted / 是否突出顯示 */
  highlighted: boolean;
}

// ---------------------------------------------------------------------------
// Website Pages
// 網站頁面
// ---------------------------------------------------------------------------

/** Page identifier / 頁面識別碼 */
export type PageId = 'home' | 'features' | 'pricing' | 'docs' | 'guide' | 'about';

/** Page metadata / 頁面元資料 */
export interface PageMeta {
  id: PageId;
  titleEn: string;
  titleZh: string;
  descriptionEn: string;
  descriptionZh: string;
  path: string;
}

// ---------------------------------------------------------------------------
// Online Guidance (線上引導)
// ---------------------------------------------------------------------------

/** Guidance step type / 引導步驟類型 */
export type GuidanceStepType =
  | 'welcome'
  | 'persona_select'
  | 'threat_assessment'
  | 'product_recommendation'
  | 'installation'
  | 'notification_setup'
  | 'complete';

/** A single guidance step / 單一引導步驟 */
export interface GuidanceStep {
  /** Step type / 步驟類型 */
  type: GuidanceStepType;
  /** Step number / 步驟編號 */
  stepNumber: number;
  /** Title / 標題 */
  titleEn: string;
  titleZh: string;
  /** Description / 描述 */
  descriptionEn: string;
  descriptionZh: string;
  /** Options (if selection step) / 選項（如果是選擇步驟） */
  options?: GuidanceOption[];
}

/** An option within a guidance step / 引導步驟中的選項 */
export interface GuidanceOption {
  /** Option ID / 選項 ID */
  id: string;
  /** Label / 標籤 */
  labelEn: string;
  labelZh: string;
  /** Description / 描述 */
  descriptionEn: string;
  descriptionZh: string;
}

/** User's guidance answers / 用戶的引導回答 */
export interface GuidanceAnswers {
  persona?: PersonaType;
  hasServer?: boolean;
  hasWebApp?: boolean;
  hasDatabase?: boolean;
  notificationChannel?: 'line' | 'telegram' | 'slack' | 'email';
  language?: WebLanguage;
}

/** Guidance result / 引導結果 */
export interface GuidanceResult {
  /** Recommended plan / 推薦方案 */
  recommendedPlan: PricingPlan;
  /** Recommended products / 推薦產品 */
  recommendedProducts: string[];
  /** Installation command / 安裝指令 */
  installCommand: string;
  /** Configuration steps / 配置步驟 */
  configSteps: string[];
  /** Estimated setup time / 預估設定時間 */
  estimatedSetupTime: string;
}

// ---------------------------------------------------------------------------
// Website Configuration
// 網站配置
// ---------------------------------------------------------------------------

/** Website config / 網站配置 */
export interface WebConfig {
  /** Default language / 預設語言 */
  language: WebLanguage;
  /** Base URL / 基礎 URL */
  baseUrl: string;
  /** Brand name / 品牌名稱 */
  brandName: string;
  /** Brand tagline / 品牌標語 */
  taglineEn: string;
  taglineZh: string;
}

/** Default website config / 預設網站配置 */
export const DEFAULT_WEB_CONFIG: WebConfig = {
  language: 'zh-TW',
  baseUrl: 'https://panguard.ai',
  brandName: 'Panguard AI',
  taglineEn: 'AI-Driven Adaptive Endpoint Protection',
  taglineZh: 'AI 驅動的自適應端點防護平台',
};
