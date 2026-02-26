/**
 * Content module tests (personas + pricing)
 * 內容模組測試（角色 + 定價）
 */

import { describe, it, expect } from 'vitest';
import {
  getPersona,
  getAllPersonas,
  getPricingPlan,
  getAllPricingPlans,
  getRecommendedPlan,
} from '../src/content/index.js';

describe('Personas', () => {
  it('should have 3 persona types', () => {
    const all = getAllPersonas();
    expect(all).toHaveLength(3);
  });

  it('should have developer persona', () => {
    const dev = getPersona('developer');
    expect(dev).toBeDefined();
    expect(dev!.type).toBe('developer');
    expect(dev!.nameEn.length).toBeGreaterThan(0);
    expect(dev!.nameZh.length).toBeGreaterThan(0);
  });

  it('should have small_business persona', () => {
    const biz = getPersona('small_business');
    expect(biz).toBeDefined();
    expect(biz!.type).toBe('small_business');
    expect(biz!.recommendedPlan).toBe('team');
  });

  it('should have mid_enterprise persona', () => {
    const ent = getPersona('mid_enterprise');
    expect(ent).toBeDefined();
    expect(ent!.type).toBe('mid_enterprise');
    expect(ent!.recommendedPlan).toBe('business');
  });

  it('should return undefined for unknown persona', () => {
    const unknown = getPersona('unknown');
    expect(unknown).toBeUndefined();
  });

  it('should have pain points for all personas', () => {
    for (const persona of getAllPersonas()) {
      expect(persona.painPointsEn.length).toBeGreaterThan(0);
      expect(persona.painPointsZh.length).toBeGreaterThan(0);
      expect(persona.painPointsEn.length).toBe(persona.painPointsZh.length);
    }
  });

  it('should have scenarios for all personas', () => {
    for (const persona of getAllPersonas()) {
      expect(persona.scenarios.length).toBeGreaterThan(0);
      for (const scenario of persona.scenarios) {
        expect(scenario.id.length).toBeGreaterThan(0);
        expect(scenario.beforeEn.length).toBeGreaterThan(0);
        expect(scenario.beforeZh.length).toBeGreaterThan(0);
        expect(scenario.afterEn.length).toBeGreaterThan(0);
        expect(scenario.afterZh.length).toBeGreaterThan(0);
        expect(scenario.notificationEn.length).toBeGreaterThan(0);
        expect(scenario.notificationZh.length).toBeGreaterThan(0);
      }
    }
  });

  it('should have bilingual names and descriptions', () => {
    for (const persona of getAllPersonas()) {
      expect(persona.nameEn.length).toBeGreaterThan(0);
      expect(persona.nameZh.length).toBeGreaterThan(0);
      expect(persona.descriptionEn.length).toBeGreaterThan(0);
      expect(persona.descriptionZh.length).toBeGreaterThan(0);
    }
  });

  it('should use human-language notifications (no jargon)', () => {
    for (const persona of getAllPersonas()) {
      for (const scenario of persona.scenarios) {
        // Notifications should NOT contain technical jargon
        const jargonTerms = ['Sigma Rule', 'YARA', 'IOC', 'MITRE ATT&CK'];
        for (const term of jargonTerms) {
          expect(scenario.notificationEn).not.toContain(term);
          expect(scenario.notificationZh).not.toContain(term);
        }
      }
    }
  });
});

describe('Pricing Plans', () => {
  it('should have 5 pricing plans', () => {
    const all = getAllPricingPlans();
    expect(all).toHaveLength(5);
  });

  it('should have free plan at $0', () => {
    const free = getPricingPlan('free');
    expect(free).toBeDefined();
    expect(free!.priceUsd).toBe(0);
  });

  it('should have starter plan', () => {
    const starter = getPricingPlan('starter');
    expect(starter).toBeDefined();
    expect(starter!.priceUsd).toBeGreaterThan(0);
    expect(starter!.targetPersona).toBe('developer');
  });

  it('should have team plan highlighted', () => {
    const team = getPricingPlan('team');
    expect(team).toBeDefined();
    expect(team!.highlighted).toBe(true);
  });

  it('should have business plan', () => {
    const biz = getPricingPlan('business');
    expect(biz).toBeDefined();
    expect(biz!.targetPersona).toBe('mid_enterprise');
  });

  it('should return undefined for unknown plan', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const unknown = getPricingPlan('unknown' as any);
    expect(unknown).toBeUndefined();
  });

  it('should have bilingual names and taglines', () => {
    for (const plan of getAllPricingPlans()) {
      expect(plan.nameEn.length).toBeGreaterThan(0);
      expect(plan.nameZh.length).toBeGreaterThan(0);
      expect(plan.taglineEn.length).toBeGreaterThan(0);
      expect(plan.taglineZh.length).toBeGreaterThan(0);
    }
  });

  it('should have features for all plans', () => {
    for (const plan of getAllPricingPlans()) {
      expect(plan.features.length).toBeGreaterThan(0);
      for (const feature of plan.features) {
        expect(feature.nameEn.length).toBeGreaterThan(0);
        expect(feature.nameZh.length).toBeGreaterThan(0);
      }
    }
  });

  it('should have free plan at $0 and paid plans above $0', () => {
    const plans = getAllPricingPlans();
    expect(plans[0]!.priceUsd).toBe(0);
    for (let i = 1; i < plans.length; i++) {
      expect(plans[i]!.priceUsd).toBeGreaterThan(0);
    }
  });

  it('should recommend plan for personas', () => {
    expect(getRecommendedPlan('developer')).toBeDefined();
    expect(getRecommendedPlan('small_business')).toBeDefined();
    expect(getRecommendedPlan('mid_enterprise')).toBeDefined();
  });

  it('should recommend team plan for small_business (highlighted)', () => {
    const rec = getRecommendedPlan('small_business');
    expect(rec).toBeDefined();
    expect(rec!.plan).toBe('team');
  });
});
