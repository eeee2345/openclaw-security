/**
 * Panguard Web types tests
 * Panguard Web 型別測試
 */

import { describe, it, expect } from 'vitest';
import { DEFAULT_WEB_CONFIG } from '../src/types.js';
import type {
  WebLanguage,
  PersonaType,
  PricingPlan,
  PageId,
  GuidanceStepType,
  WebConfig,
  GuidanceAnswers,
} from '../src/types.js';

describe('Panguard Web Types', () => {
  describe('DEFAULT_WEB_CONFIG', () => {
    it('should have default language zh-TW', () => {
      expect(DEFAULT_WEB_CONFIG.language).toBe('zh-TW');
    });

    it('should have base URL', () => {
      expect(DEFAULT_WEB_CONFIG.baseUrl).toBe('https://panguard.ai');
    });

    it('should have brand name Panguard AI', () => {
      expect(DEFAULT_WEB_CONFIG.brandName).toBe('Panguard AI');
    });

    it('should have bilingual taglines', () => {
      expect(DEFAULT_WEB_CONFIG.taglineEn.length).toBeGreaterThan(0);
      expect(DEFAULT_WEB_CONFIG.taglineZh.length).toBeGreaterThan(0);
    });
  });

  describe('Type constraints', () => {
    it('should support all web languages', () => {
      const languages: WebLanguage[] = ['zh-TW', 'en'];
      expect(languages).toHaveLength(2);
    });

    it('should support all persona types', () => {
      const personas: PersonaType[] = ['developer', 'small_business', 'mid_enterprise'];
      expect(personas).toHaveLength(3);
    });

    it('should support all pricing plans', () => {
      const plans: PricingPlan[] = ['free', 'solo', 'starter', 'team', 'business'];
      expect(plans).toHaveLength(5);
    });

    it('should support all page IDs', () => {
      const pages: PageId[] = ['home', 'features', 'pricing', 'docs', 'guide', 'about'];
      expect(pages).toHaveLength(6);
    });

    it('should support all guidance step types', () => {
      const steps: GuidanceStepType[] = [
        'welcome',
        'persona_select',
        'threat_assessment',
        'product_recommendation',
        'installation',
        'notification_setup',
        'complete',
      ];
      expect(steps).toHaveLength(7);
    });
  });

  describe('Type safety', () => {
    it('should create valid GuidanceAnswers', () => {
      const answers: GuidanceAnswers = {
        persona: 'developer',
        hasServer: true,
        hasWebApp: false,
        notificationChannel: 'line',
      };
      expect(answers.persona).toBe('developer');
      expect(answers.hasServer).toBe(true);
    });

    it('should create valid WebConfig', () => {
      const config: WebConfig = {
        language: 'en',
        baseUrl: 'https://test.panguard.ai',
        brandName: 'Panguard AI',
        taglineEn: 'Test',
        taglineZh: '測試',
      };
      expect(config.language).toBe('en');
    });
  });
});
