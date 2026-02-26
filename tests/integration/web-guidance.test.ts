/**
 * Integration Test: Panguard Web Guidance -> Product Recommendations
 * 整合測試：Panguard Web 線上引導 -> 產品推薦
 *
 * Tests the end-to-end guidance wizard flow from persona selection
 * to product/plan recommendations and install command generation.
 * Verifies consistency with pricing plans and product features.
 * 測試從角色選擇到產品/方案推薦和安裝指令產生的完整引導流程。
 * 驗證與定價方案和產品特色的一致性。
 */

import { describe, it, expect } from 'vitest';
import type { PersonaType, PricingPlan, GuidanceAnswers } from '@openclaw/panguard-web';
import {
  getPersona,
  getAllPersonas,
  getAllPricingPlans,
  getRecommendedPlan,
  getPage,
  getAllPages,
  getNavItems,
  getProductFeature,
  PRODUCT_FEATURES,
  generateGuidanceResult,
  getGuidanceStep,
  getNextStep,
  getPreviousStep,
  getTotalSteps,
  GUIDANCE_STEPS,
  generateHead,
  generateNav,
  generateHero,
  generateFeatureCard,
  generatePricingCard,
  generateFooter,
} from '@openclaw/panguard-web';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Panguard Web Guidance -> Product Recommendation Pipeline', () => {
  describe('Persona to Plan Mapping Consistency', () => {
    const personaPlanMap: Record<PersonaType, PricingPlan> = {
      developer: 'solo',
      small_business: 'team',
      mid_enterprise: 'business',
    };

    for (const [personaType, expectedPlan] of Object.entries(personaPlanMap)) {
      it(`should recommend ${expectedPlan} plan for ${personaType} via guidance`, () => {
        const persona = getPersona(personaType as PersonaType);
        expect(persona).toBeDefined();
        expect(persona!.recommendedPlan).toBe(expectedPlan);

        // Guidance wizard should map persona to expected plan
        const result = generateGuidanceResult({ persona: personaType as PersonaType });
        expect(result.recommendedPlan).toBe(expectedPlan);
      });
    }

    it('should recommend free plan when no persona selected', () => {
      const result = generateGuidanceResult({});
      expect(result.recommendedPlan).toBe('free');
    });
  });

  describe('Product Recommendations Consistency', () => {
    it('should always include Panguard Scan in recommendations', () => {
      const personas: (PersonaType | undefined)[] = [
        'developer',
        'small_business',
        'mid_enterprise',
        undefined,
      ];

      for (const persona of personas) {
        const answers: GuidanceAnswers = persona ? { persona } : {};
        const result = generateGuidanceResult(answers);
        expect(result.recommendedProducts).toContain('Panguard Scan');
      }
    });

    it('should recommend Guard and Chat for all persona types', () => {
      const personas: PersonaType[] = ['developer', 'small_business', 'mid_enterprise'];

      for (const persona of personas) {
        const result = generateGuidanceResult({ persona });
        expect(result.recommendedProducts).toContain('Panguard Guard');
        expect(result.recommendedProducts).toContain('Panguard Chat');
      }
    });

    it('should recommend Panguard Trap only for server users', () => {
      const withServer = generateGuidanceResult({ persona: 'developer', hasServer: true });
      const withoutServer = generateGuidanceResult({ persona: 'developer' });

      expect(withServer.recommendedProducts).toContain('Panguard Trap');
      expect(withoutServer.recommendedProducts).not.toContain('Panguard Trap');
    });

    it('should recommend Panguard Report for enterprise', () => {
      const enterprise = generateGuidanceResult({ persona: 'mid_enterprise' });
      expect(enterprise.recommendedProducts).toContain('Panguard Report');
    });

    it('should verify all recommended products have feature cards', () => {
      const personas: PersonaType[] = ['developer', 'small_business', 'mid_enterprise'];

      for (const persona of personas) {
        const result = generateGuidanceResult({
          persona,
          hasServer: true, // Include all products
        });

        for (const product of result.recommendedProducts) {
          const feature = getProductFeature(product);
          expect(feature).toBeDefined();
          expect(feature!.product).toBe(product);
        }
      }
    });
  });

  describe('Install Command Generation', () => {
    it('should generate basic curl command for free plan', () => {
      const result = generateGuidanceResult({});
      expect(result.installCommand).toContain('curl -fsSL https://get.panguard.ai');
      expect(result.installCommand).not.toContain('--plan');
    });

    it('should include plan flag for paid plans', () => {
      const plans: [PersonaType, string][] = [
        ['developer', 'solo'],
        ['small_business', 'team'],
        ['mid_enterprise', 'business'],
      ];

      for (const [persona, plan] of plans) {
        const result = generateGuidanceResult({ persona });
        expect(result.installCommand).toContain(`--plan ${plan}`);
      }
    });

    it('should include notification channel in command', () => {
      const channels = ['line', 'telegram', 'slack', 'email'];

      for (const channel of channels) {
        const result = generateGuidanceResult({
          persona: 'developer',
          notificationChannel: channel,
        });
        expect(result.installCommand).toContain(`--notify ${channel}`);
      }
    });
  });

  describe('Configuration Steps Generation', () => {
    it('should generate bilingual config steps for developer', () => {
      const enResult = generateGuidanceResult({ persona: 'developer' }, 'en');
      const zhResult = generateGuidanceResult({ persona: 'developer' }, 'zh-TW');

      expect(enResult.configSteps.length).toBeGreaterThan(0);
      expect(zhResult.configSteps.length).toBeGreaterThan(0);
    });

    it('should include compliance step for enterprise', () => {
      const result = generateGuidanceResult({ persona: 'mid_enterprise' }, 'en');
      const hasComplianceStep = result.configSteps.some((s) => s.includes('compliance'));
      expect(hasComplianceStep).toBe(true);
    });

    it('should include honeypot step for server users', () => {
      const result = generateGuidanceResult({ persona: 'developer', hasServer: true }, 'en');
      const hasTrapStep = result.configSteps.some(
        (s) => s.includes('honeypot') || s.includes('Panguard Trap')
      );
      expect(hasTrapStep).toBe(true);
    });

    it('should estimate setup time based on plan', () => {
      const free = generateGuidanceResult({});
      const starter = generateGuidanceResult({ persona: 'developer' });
      const business = generateGuidanceResult({ persona: 'mid_enterprise' });

      expect(free.estimatedSetupTime).toContain('60');
      expect(starter.estimatedSetupTime).toContain('5');
      expect(business.estimatedSetupTime).toContain('10');
    });
  });

  describe('Wizard Step Navigation', () => {
    it('should navigate through all 7 steps', () => {
      expect(getTotalSteps()).toBe(7);

      let current = GUIDANCE_STEPS[0]!;
      const visited: string[] = [current.type];

      while (true) {
        const next = getNextStep(current.type);
        if (!next) break;
        current = next;
        visited.push(current.type);
      }

      expect(visited).toHaveLength(7);
      expect(visited[0]).toBe('welcome');
      expect(visited[visited.length - 1]).toBe('complete');
    });

    it('should support backward navigation', () => {
      const personaStep = getGuidanceStep('persona_select')!;
      const prev = getPreviousStep(personaStep.type);
      expect(prev).toBeDefined();
      expect(prev!.type).toBe('welcome');
    });

    it('should have persona selection options matching personas', () => {
      const step = getGuidanceStep('persona_select')!;
      const optionIds = step.options!.map((o) => o.id);
      const personaTypes = getAllPersonas().map((p) => p.type);

      for (const persona of personaTypes) {
        expect(optionIds).toContain(persona);
      }
    });

    it('should have notification setup options matching channels', () => {
      const step = getGuidanceStep('notification_setup')!;
      expect(step.options!.length).toBe(4); // LINE, Telegram, Slack, Email
    });
  });

  describe('Pricing Plan Consistency', () => {
    it('should have free plan at $0 and all paid plans above $0', () => {
      const plans = getAllPricingPlans();
      const freePlan = plans.find((p) => p.plan === 'free');
      expect(freePlan!.priceUsd).toBe(0);
      const paidPlans = plans.filter((p) => p.plan !== 'free');
      for (const plan of paidPlans) {
        expect(plan.priceUsd).toBeGreaterThan(0);
      }
    });

    it('should have highlighted plan matching small_business recommendation', () => {
      const highlighted = getAllPricingPlans().find((p) => p.highlighted);
      expect(highlighted).toBeDefined();
      expect(highlighted!.plan).toBe('team');

      const sbRec = getRecommendedPlan('small_business');
      expect(sbRec!.plan).toBe(highlighted!.plan);
    });

    it('should have bilingual content for all plans', () => {
      for (const plan of getAllPricingPlans()) {
        expect(plan.nameEn.length).toBeGreaterThan(0);
        expect(plan.nameZh.length).toBeGreaterThan(0);
        expect(plan.taglineEn.length).toBeGreaterThan(0);
        expect(plan.taglineZh.length).toBeGreaterThan(0);
        expect(plan.features.length).toBeGreaterThan(0);
      }
    });
  });

  describe('HTML Template Generation Consistency', () => {
    it('should generate consistent nav for all pages', () => {
      const pages = getAllPages();
      const enNav = generateNav(pages, 'en');
      const zhNav = generateNav(pages, 'zh-TW');

      expect(enNav).toContain('Panguard AI');
      expect(zhNav).toContain('Panguard AI');
      expect(enNav).toContain('href="/"');
    });

    it('should generate feature cards for all products', () => {
      for (const feature of PRODUCT_FEATURES) {
        const enCard = generateFeatureCard(feature, 'en');
        const zhCard = generateFeatureCard(feature, 'zh-TW');

        expect(enCard).toContain(feature.product);
        expect(zhCard).toContain(feature.product);
        expect(enCard).toContain('feature-card');
      }
    });

    it('should generate pricing cards for all plans', () => {
      for (const plan of getAllPricingPlans()) {
        const enCard = generatePricingCard(plan, 'en');
        const zhCard = generatePricingCard(plan, 'zh-TW');

        expect(enCard).toContain('pricing-card');
        expect(zhCard).toContain('pricing-card');
      }
    });

    it('should generate hero with install command', () => {
      const hero = generateHero('en');
      expect(hero).toContain('curl -fsSL https://get.panguard.ai');
      expect(hero).toContain('cta-button');
    });

    it('should generate head with SEO metadata', () => {
      const page = getPage('home')!;
      const head = generateHead(page, 'en');

      expect(head).toContain('<!DOCTYPE html>');
      expect(head).toContain('og:title');
      expect(head).toContain('twitter:card');
      expect(head).toContain('Panguard AI');
    });

    it('should generate consistent footer', () => {
      const enFooter = generateFooter('en');
      const zhFooter = generateFooter('zh-TW');

      expect(enFooter).toContain('Panguard AI');
      expect(zhFooter).toContain('Panguard AI');
      expect(enFooter).toContain('OpenClaw Security');
    });
  });

  describe('Page Navigation Consistency', () => {
    it('should have all pages accessible', () => {
      const pageIds = ['home', 'features', 'pricing', 'docs', 'guide', 'about'] as const;
      for (const id of pageIds) {
        const page = getPage(id);
        expect(page).toBeDefined();
      }
    });

    it('should exclude guide from navigation', () => {
      const navItems = getNavItems();
      expect(navItems.find((p) => p.id === 'guide')).toBeUndefined();
      expect(navItems).toHaveLength(5);
    });

    it('should have unique paths for all pages', () => {
      const paths = getAllPages().map((p) => p.path);
      const uniquePaths = new Set(paths);
      expect(uniquePaths.size).toBe(paths.length);
    });
  });
});
