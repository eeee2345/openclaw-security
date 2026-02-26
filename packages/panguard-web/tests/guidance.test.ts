/**
 * Guidance wizard tests
 * 引導精靈測試
 */

import { describe, it, expect } from 'vitest';
import {
  GUIDANCE_STEPS,
  getGuidanceStep,
  getNextStep,
  getPreviousStep,
  getTotalSteps,
  generateGuidanceResult,
} from '../src/guidance/index.js';
import type { GuidanceAnswers } from '../src/types.js';

describe('Guidance Wizard', () => {
  describe('Step definitions', () => {
    it('should have 7 guidance steps', () => {
      expect(getTotalSteps()).toBe(7);
    });

    it('should start with welcome step', () => {
      expect(GUIDANCE_STEPS[0]!.type).toBe('welcome');
      expect(GUIDANCE_STEPS[0]!.stepNumber).toBe(1);
    });

    it('should end with complete step', () => {
      const lastStep = GUIDANCE_STEPS[GUIDANCE_STEPS.length - 1]!;
      expect(lastStep.type).toBe('complete');
    });

    it('should have sequential step numbers', () => {
      for (let i = 0; i < GUIDANCE_STEPS.length; i++) {
        expect(GUIDANCE_STEPS[i]!.stepNumber).toBe(i + 1);
      }
    });

    it('should have bilingual titles for all steps', () => {
      for (const step of GUIDANCE_STEPS) {
        expect(step.titleEn.length).toBeGreaterThan(0);
        expect(step.titleZh.length).toBeGreaterThan(0);
        expect(step.descriptionEn.length).toBeGreaterThan(0);
        expect(step.descriptionZh.length).toBeGreaterThan(0);
      }
    });
  });

  describe('getGuidanceStep', () => {
    it('should get welcome step', () => {
      const step = getGuidanceStep('welcome');
      expect(step).toBeDefined();
      expect(step!.type).toBe('welcome');
    });

    it('should get persona_select step with options', () => {
      const step = getGuidanceStep('persona_select');
      expect(step).toBeDefined();
      expect(step!.options).toBeDefined();
      expect(step!.options!.length).toBe(3);
    });

    it('should get notification_setup step with options', () => {
      const step = getGuidanceStep('notification_setup');
      expect(step).toBeDefined();
      expect(step!.options).toBeDefined();
      expect(step!.options!.length).toBe(4);
    });

    it('should return undefined for unknown type', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(getGuidanceStep('unknown' as any)).toBeUndefined();
    });
  });

  describe('Step navigation', () => {
    it('should get next step from welcome', () => {
      const next = getNextStep('welcome');
      expect(next).toBeDefined();
      expect(next!.type).toBe('persona_select');
    });

    it('should return undefined for next after complete', () => {
      const next = getNextStep('complete');
      expect(next).toBeUndefined();
    });

    it('should get previous step from persona_select', () => {
      const prev = getPreviousStep('persona_select');
      expect(prev).toBeDefined();
      expect(prev!.type).toBe('welcome');
    });

    it('should return undefined for previous before welcome', () => {
      const prev = getPreviousStep('welcome');
      expect(prev).toBeUndefined();
    });

    it('should navigate through all steps sequentially', () => {
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
  });

  describe('Persona select options', () => {
    it('should have developer, small_business, mid_enterprise options', () => {
      const step = getGuidanceStep('persona_select')!;
      const optionIds = step.options!.map((o) => o.id);
      expect(optionIds).toContain('developer');
      expect(optionIds).toContain('small_business');
      expect(optionIds).toContain('mid_enterprise');
    });

    it('should have bilingual labels for all options', () => {
      const step = getGuidanceStep('persona_select')!;
      for (const option of step.options!) {
        expect(option.labelEn.length).toBeGreaterThan(0);
        expect(option.labelZh.length).toBeGreaterThan(0);
        expect(option.descriptionEn.length).toBeGreaterThan(0);
        expect(option.descriptionZh.length).toBeGreaterThan(0);
      }
    });
  });

  describe('generateGuidanceResult', () => {
    it('should recommend solo plan for developer', () => {
      const answers: GuidanceAnswers = { persona: 'developer' };
      const result = generateGuidanceResult(answers);
      expect(result.recommendedPlan).toBe('solo');
    });

    it('should recommend team plan for small_business', () => {
      const answers: GuidanceAnswers = { persona: 'small_business' };
      const result = generateGuidanceResult(answers);
      expect(result.recommendedPlan).toBe('team');
    });

    it('should recommend business plan for mid_enterprise', () => {
      const answers: GuidanceAnswers = { persona: 'mid_enterprise' };
      const result = generateGuidanceResult(answers);
      expect(result.recommendedPlan).toBe('business');
    });

    it('should recommend free plan when no persona', () => {
      const answers: GuidanceAnswers = {};
      const result = generateGuidanceResult(answers);
      expect(result.recommendedPlan).toBe('free');
    });

    it('should always recommend Panguard Scan', () => {
      const result = generateGuidanceResult({});
      expect(result.recommendedProducts).toContain('Panguard Scan');
    });

    it('should recommend Guard and Chat when persona is set', () => {
      const result = generateGuidanceResult({ persona: 'developer' });
      expect(result.recommendedProducts).toContain('Panguard Guard');
      expect(result.recommendedProducts).toContain('Panguard Chat');
    });

    it('should recommend Trap for server users', () => {
      const result = generateGuidanceResult({
        persona: 'developer',
        hasServer: true,
      });
      expect(result.recommendedProducts).toContain('Panguard Trap');
    });

    it('should recommend Report for mid_enterprise', () => {
      const result = generateGuidanceResult({ persona: 'mid_enterprise' });
      expect(result.recommendedProducts).toContain('Panguard Report');
    });

    it('should generate install command with plan', () => {
      const result = generateGuidanceResult({ persona: 'developer' });
      expect(result.installCommand).toContain('--plan solo');
    });

    it('should generate simple install command for free', () => {
      const result = generateGuidanceResult({});
      expect(result.installCommand).toContain('curl -fsSL https://get.panguard.ai');
      expect(result.installCommand).not.toContain('--plan');
    });

    it('should include notification channel in command', () => {
      const result = generateGuidanceResult({
        persona: 'developer',
        notificationChannel: 'line',
      });
      expect(result.installCommand).toContain('--notify line');
    });

    it('should generate configuration steps', () => {
      const result = generateGuidanceResult({
        persona: 'developer',
        notificationChannel: 'telegram',
      });
      expect(result.configSteps.length).toBeGreaterThan(0);
    });

    it('should include compliance step for enterprise', () => {
      const result = generateGuidanceResult({
        persona: 'mid_enterprise',
      }, 'en');
      const hasComplianceStep = result.configSteps.some((s) => s.includes('compliance'));
      expect(hasComplianceStep).toBe(true);
    });

    it('should include honeypot step for server users', () => {
      const result = generateGuidanceResult({
        persona: 'developer',
        hasServer: true,
      }, 'en');
      const hasTrapStep = result.configSteps.some((s) => s.includes('honeypot') || s.includes('Panguard Trap'));
      expect(hasTrapStep).toBe(true);
    });

    it('should estimate setup time', () => {
      const free = generateGuidanceResult({});
      expect(free.estimatedSetupTime).toContain('60');

      const starter = generateGuidanceResult({ persona: 'developer' });
      expect(starter.estimatedSetupTime).toContain('5');

      const business = generateGuidanceResult({ persona: 'mid_enterprise' });
      expect(business.estimatedSetupTime).toContain('10');
    });

    it('should generate Chinese config steps', () => {
      const result = generateGuidanceResult({ persona: 'developer' }, 'zh-TW');
      const hasChineseStep = result.configSteps.some((s) => /[\u4e00-\u9fff]/.test(s));
      expect(hasChineseStep).toBe(true);
    });

    it('should generate English config steps', () => {
      const result = generateGuidanceResult({ persona: 'developer' }, 'en');
      expect(result.configSteps[0]).toContain('Run');
    });
  });
});
