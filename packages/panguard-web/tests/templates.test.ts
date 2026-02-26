/**
 * HTML Templates tests
 * HTML 範本測試
 */

import { describe, it, expect } from 'vitest';
import {
  generateHead,
  generateNav,
  generateHero,
  generateFeatureCard,
  generatePricingCard,
  generateFooter,
} from '../src/templates/index.js';
import { getPage, getAllPages, PRODUCT_FEATURES } from '../src/pages/index.js';
import { getAllPricingPlans } from '../src/content/pricing.js';

describe('HTML Templates', () => {
  describe('generateHead', () => {
    it('should generate valid HTML head for English', () => {
      const page = getPage('home')!;
      const html = generateHead(page, 'en');
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('lang="en"');
      expect(html).toContain('<title>');
      expect(html).toContain('Panguard AI');
    });

    it('should generate valid HTML head for Chinese', () => {
      const page = getPage('home')!;
      const html = generateHead(page, 'zh-TW');
      expect(html).toContain('lang="zh-Hant-TW"');
      expect(html).toContain('Panguard AI');
    });

    it('should include meta description', () => {
      const page = getPage('home')!;
      const html = generateHead(page, 'en');
      expect(html).toContain('meta name="description"');
    });

    it('should include Open Graph tags', () => {
      const page = getPage('features')!;
      const html = generateHead(page, 'en');
      expect(html).toContain('og:title');
      expect(html).toContain('og:description');
      expect(html).toContain('og:type');
    });

    it('should include canonical URL', () => {
      const page = getPage('pricing')!;
      const html = generateHead(page, 'en');
      expect(html).toContain('link rel="canonical"');
      expect(html).toContain('https://panguard.ai/pricing');
    });

    it('should include Twitter card meta', () => {
      const page = getPage('home')!;
      const html = generateHead(page, 'en');
      expect(html).toContain('twitter:card');
    });
  });

  describe('generateNav', () => {
    it('should generate navigation with brand name', () => {
      const pages = getAllPages();
      const html = generateNav(pages, 'en');
      expect(html).toContain('<nav>');
      expect(html).toContain('Panguard AI');
    });

    it('should include page links', () => {
      const pages = getAllPages();
      const html = generateNav(pages, 'en');
      expect(html).toContain('href="/"');
      expect(html).toContain('href="/features"');
      expect(html).toContain('href="/pricing"');
    });

    it('should use Chinese labels for zh-TW', () => {
      const pages = getAllPages();
      const html = generateNav(pages, 'zh-TW');
      expect(html).toContain('Panguard AI');
    });
  });

  describe('generateHero', () => {
    it('should generate hero section in English', () => {
      const html = generateHero('en');
      expect(html).toContain('<section class="hero">');
      expect(html).toContain('<h1>');
      expect(html).toContain('curl -fsSL https://get.panguard.ai');
      expect(html).toContain('cta-button');
    });

    it('should generate hero section in Chinese', () => {
      const html = generateHero('zh-TW');
      expect(html).toContain('<section class="hero">');
      expect(html).toContain('curl -fsSL https://get.panguard.ai');
    });

    it('should include install command', () => {
      const html = generateHero('en');
      expect(html).toContain('<code>');
      expect(html).toContain('get.panguard.ai');
    });

    it('should include CTA button', () => {
      const html = generateHero('en');
      expect(html).toContain('href="/guide"');
    });
  });

  describe('generateFeatureCard', () => {
    it('should generate feature card in English', () => {
      const feature = PRODUCT_FEATURES[0]!;
      const html = generateFeatureCard(feature, 'en');
      expect(html).toContain('feature-card');
      expect(html).toContain(feature.product);
      expect(html).toContain(feature.headlineEn);
    });

    it('should generate feature card in Chinese', () => {
      const feature = PRODUCT_FEATURES[0]!;
      const html = generateFeatureCard(feature, 'zh-TW');
      expect(html).toContain(feature.headlineZh);
    });

    it('should include highlights as list items', () => {
      const feature = PRODUCT_FEATURES[0]!;
      const html = generateFeatureCard(feature, 'en');
      expect(html).toContain('<li>');
      expect(html).toContain('feature-highlights');
    });

    it('should generate cards for all products', () => {
      for (const feature of PRODUCT_FEATURES) {
        const html = generateFeatureCard(feature, 'en');
        expect(html).toContain(feature.product);
      }
    });
  });

  describe('generatePricingCard', () => {
    it('should generate pricing card', () => {
      const plan = getAllPricingPlans()[0]!;
      const html = generatePricingCard(plan, 'en');
      expect(html).toContain('pricing-card');
      expect(html).toContain(plan.nameEn);
    });

    it('should highlight team plan', () => {
      const pro = getAllPricingPlans().find((p) => p.highlighted)!;
      const html = generatePricingCard(pro, 'en');
      expect(html).toContain('pricing-highlighted');
    });

    it('should not highlight non-highlighted plans', () => {
      const free = getAllPricingPlans()[0]!;
      const html = generatePricingCard(free, 'en');
      expect(html).not.toContain('pricing-highlighted');
    });

    it('should include features list', () => {
      const plan = getAllPricingPlans()[0]!;
      const html = generatePricingCard(plan, 'en');
      expect(html).toContain('pricing-features');
      expect(html).toContain('<li');
    });

    it('should mark included/not-included features', () => {
      const plan = getAllPricingPlans()[0]!;
      const html = generatePricingCard(plan, 'en');
      expect(html).toContain('included');
      expect(html).toContain('not-included');
    });

    it('should generate cards for all plans', () => {
      for (const plan of getAllPricingPlans()) {
        const html = generatePricingCard(plan, 'en');
        expect(html).toContain(plan.nameEn);
      }
    });

    it('should use Chinese names for zh-TW', () => {
      const plan = getAllPricingPlans()[0]!;
      const html = generatePricingCard(plan, 'zh-TW');
      expect(html).toContain(plan.nameZh);
    });
  });

  describe('generateFooter', () => {
    it('should generate footer with brand name', () => {
      const html = generateFooter('en');
      expect(html).toContain('<footer>');
      expect(html).toContain('Panguard AI');
    });

    it('should include built-by text', () => {
      const html = generateFooter('en');
      expect(html).toContain('OpenClaw Security');
    });

    it('should use Chinese text for zh-TW', () => {
      const html = generateFooter('zh-TW');
      expect(html).toContain('Panguard AI');
    });
  });
});
