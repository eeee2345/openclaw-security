/**
 * HTML Template Engine for static site generation
 * 靜態網站產生的 HTML 範本引擎
 *
 * Generates complete HTML pages for the Panguard AI website.
 * 為 Panguard AI 官網產生完整的 HTML 頁面。
 *
 * @module @panguard-ai/panguard-web/templates
 */

import type { WebLanguage, WebConfig, PageMeta } from '../types.js';
import type { ProductFeature } from '../pages/index.js';
import type { PricingPlanDetails } from '../types.js';
import { DEFAULT_WEB_CONFIG } from '../types.js';

// ---------------------------------------------------------------------------
// HTML head template
// HTML 頭部範本
// ---------------------------------------------------------------------------

/**
 * Generate HTML head section
 * 產生 HTML 頭部區段
 */
export function generateHead(
  page: PageMeta,
  language: WebLanguage,
  config: WebConfig = DEFAULT_WEB_CONFIG
): string {
  const title = language === 'zh-TW' ? page.titleZh : page.titleEn;
  const description = language === 'zh-TW' ? page.descriptionZh : page.descriptionEn;
  const lang = language === 'zh-TW' ? 'zh-Hant-TW' : 'en';

  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <meta name="description" content="${description}">
  <meta property="og:title" content="${title}">
  <meta property="og:description" content="${description}">
  <meta property="og:type" content="website">
  <meta property="og:url" content="${config.baseUrl}${page.path}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${title}">
  <meta name="twitter:description" content="${description}">
  <link rel="canonical" href="${config.baseUrl}${page.path}">
</head>`;
}

// ---------------------------------------------------------------------------
// Navigation template
// 導覽範本
// ---------------------------------------------------------------------------

/**
 * Generate navigation bar HTML
 * 產生導覽列 HTML
 */
export function generateNav(
  pages: PageMeta[],
  language: WebLanguage,
  config: WebConfig = DEFAULT_WEB_CONFIG
): string {
  const items = pages
    .map((p) => {
      const label =
        language === 'zh-TW'
          ? (p.titleZh.split(' - ')[0] ?? p.titleZh)
          : (p.titleEn.split(' - ')[0] ?? p.titleEn);
      return `    <a href="${p.path}">${label}</a>`;
    })
    .join('\n');

  return `<nav>
  <div class="nav-brand">${config.brandName}</div>
  <div class="nav-links">
${items}
  </div>
</nav>`;
}

// ---------------------------------------------------------------------------
// Hero section template
// 首頁英雄區段範本
// ---------------------------------------------------------------------------

/**
 * Generate hero section for homepage
 * 產生首頁英雄區段
 */
export function generateHero(
  language: WebLanguage,
  config: WebConfig = DEFAULT_WEB_CONFIG
): string {
  const isZh = language === 'zh-TW';

  const headline = isZh ? config.taglineZh : config.taglineEn;
  const subheadline = isZh
    ? '一行指令安裝，AI 全自動保護你的機器。有事它會告訴你，沒事你什麼都不用做。'
    : 'One command to install. AI protects your machines automatically. It tells you when something happens. You do nothing when all is well.';
  const ctaText = isZh ? '免費掃描你的系統' : 'Scan Your System Free';
  const installCmd = 'curl -fsSL https://get.panguard.ai | sh';

  return `<section class="hero">
  <h1>${headline}</h1>
  <p class="hero-sub">${subheadline}</p>
  <div class="hero-install">
    <code>${installCmd}</code>
  </div>
  <a href="/guide" class="cta-button">${ctaText}</a>
</section>`;
}

// ---------------------------------------------------------------------------
// Feature card template
// 功能卡片範本
// ---------------------------------------------------------------------------

/**
 * Generate a product feature card
 * 產生產品功能卡片
 */
export function generateFeatureCard(feature: ProductFeature, language: WebLanguage): string {
  const isZh = language === 'zh-TW';
  const tag = isZh ? feature.tagZh : feature.tagEn;
  const headline = isZh ? feature.headlineZh : feature.headlineEn;
  const description = isZh ? feature.descriptionZh : feature.descriptionEn;
  const highlights = isZh ? feature.highlightsZh : feature.highlightsEn;

  const highlightItems = highlights.map((h) => `      <li>${h}</li>`).join('\n');

  return `<div class="feature-card">
  <span class="feature-tag">${tag}</span>
  <h3>${feature.product}</h3>
  <h4>${headline}</h4>
  <p>${description}</p>
  <ul class="feature-highlights">
${highlightItems}
  </ul>
</div>`;
}

// ---------------------------------------------------------------------------
// Pricing card template
// 定價卡片範本
// ---------------------------------------------------------------------------

/**
 * Generate a pricing plan card
 * 產生定價方案卡片
 */
export function generatePricingCard(plan: PricingPlanDetails, language: WebLanguage): string {
  const isZh = language === 'zh-TW';
  const name = isZh ? plan.nameZh : plan.nameEn;
  const tagline = isZh ? plan.taglineZh : plan.taglineEn;
  const price = isZh ? plan.priceDisplayZh : plan.priceDisplayEn;
  const highlightClass = plan.highlighted ? ' pricing-highlighted' : '';

  const featureList = plan.features
    .map((f) => {
      const label = isZh ? f.nameZh : f.nameEn;
      const icon = f.included ? 'V' : '-';
      const limit = f.limit ? ` (${f.limit})` : '';
      return `      <li class="${f.included ? 'included' : 'not-included'}">${icon} ${label}${limit}</li>`;
    })
    .join('\n');

  return `<div class="pricing-card${highlightClass}">
  <h3>${name}</h3>
  <p class="pricing-tagline">${tagline}</p>
  <div class="pricing-price">${price}</div>
  <ul class="pricing-features">
${featureList}
  </ul>
</div>`;
}

// ---------------------------------------------------------------------------
// Footer template
// 頁尾範本
// ---------------------------------------------------------------------------

/**
 * Generate footer HTML
 * 產生頁尾 HTML
 */
export function generateFooter(
  language: WebLanguage,
  config: WebConfig = DEFAULT_WEB_CONFIG
): string {
  const isZh = language === 'zh-TW';
  const copyright = isZh
    ? `${config.brandName} - ${config.taglineZh}`
    : `${config.brandName} - ${config.taglineEn}`;
  const builtWith = isZh ? '由 Panguard AI 團隊打造' : 'Built by the Panguard AI team';

  return `<footer>
  <p>${copyright}</p>
  <p>${builtWith}</p>
</footer>`;
}
