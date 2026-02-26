/**
 * Panguard Web - Official Website Engine
 * Panguard Web - 官網引擎
 *
 * Provides scenario-based content, online guidance wizard,
 * pricing plans, and HTML template generation for the
 * Panguard AI marketing website.
 *
 * 提供場景化文案、線上引導精靈、定價方案和 HTML 範本產生器，
 * 用於 Panguard AI 行銷官網。
 *
 * @module @openclaw/panguard-web
 */

export const PANGUARD_WEB_VERSION = '0.1.0';
export const PANGUARD_WEB_NAME = 'Panguard Web';

// Types
export type {
  WebLanguage,
  PersonaType,
  PersonaProfile,
  ScenarioStory,
  PricingPlan,
  PlanFeature,
  PricingPlanDetails,
  ReportAddon,
  PageId,
  PageMeta,
  GuidanceStepType,
  GuidanceStep,
  GuidanceOption,
  GuidanceAnswers,
  GuidanceResult,
  WebConfig,
} from './types.js';
export { DEFAULT_WEB_CONFIG } from './types.js';

// Content - Personas
export {
  PERSONAS,
  getPersona,
  getAllPersonas,
} from './content/index.js';

// Content - Pricing
export {
  PRICING_PLANS,
  REPORT_ADDONS,
  getPricingPlan,
  getAllPricingPlans,
  getRecommendedPlan,
  getAllReportAddons,
  getReportAddon,
} from './content/index.js';

// Pages
export {
  PAGES,
  getPage,
  getPageTitle,
  getAllPages,
  getNavItems,
  PRODUCT_FEATURES,
  getProductFeature,
} from './pages/index.js';
export type { ProductFeature } from './pages/index.js';

// Guidance
export {
  GUIDANCE_STEPS,
  getGuidanceStep,
  getNextStep,
  getPreviousStep,
  getTotalSteps,
  generateGuidanceResult,
} from './guidance/index.js';

// Templates
export {
  generateHead,
  generateNav,
  generateHero,
  generateFeatureCard,
  generatePricingCard,
  generateFooter,
} from './templates/index.js';
