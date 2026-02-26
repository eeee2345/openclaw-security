/**
 * Compliance Frameworks tests
 * 合規框架測試
 */

import { describe, it, expect } from 'vitest';
import {
  getFrameworkControls,
  getFrameworkName,
  getSupportedFrameworks,
  TW_CYBER_SECURITY_CONTROLS,
  ISO27001_CONTROLS,
  SOC2_CONTROLS,
} from '../src/frameworks/index.js';
import type { ComplianceFramework } from '../src/types.js';

describe('Compliance Frameworks', () => {
  describe('getSupportedFrameworks', () => {
    it('should return 3 supported frameworks', () => {
      const frameworks = getSupportedFrameworks();
      expect(frameworks).toHaveLength(3);
      expect(frameworks).toContain('tw_cyber_security_act');
      expect(frameworks).toContain('iso27001');
      expect(frameworks).toContain('soc2');
    });
  });

  describe('getFrameworkControls', () => {
    it('should return Taiwan Cyber Security Act controls', () => {
      const controls = getFrameworkControls('tw_cyber_security_act');
      expect(controls.length).toBeGreaterThan(0);
      expect(controls[0]!.controlId).toMatch(/^TWCS-/);
    });

    it('should return ISO 27001 controls', () => {
      const controls = getFrameworkControls('iso27001');
      expect(controls.length).toBeGreaterThan(0);
      expect(controls[0]!.controlId).toMatch(/^A\./);
    });

    it('should return SOC 2 controls', () => {
      const controls = getFrameworkControls('soc2');
      expect(controls.length).toBeGreaterThan(0);
      expect(controls[0]!.controlId).toMatch(/^CC/);
    });

    it('should return empty array for unknown framework', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const controls = getFrameworkControls('unknown' as any);
      expect(controls).toHaveLength(0);
    });
  });

  describe('getFrameworkName', () => {
    it('should return English name for tw_cyber_security_act', () => {
      const name = getFrameworkName('tw_cyber_security_act', 'en');
      expect(name).toBe('Taiwan Cyber Security Management Act');
    });

    it('should return Chinese name for tw_cyber_security_act', () => {
      const name = getFrameworkName('tw_cyber_security_act', 'zh-TW');
      expect(name).toBe('資通安全管理法');
    });

    it('should return English name for iso27001', () => {
      const name = getFrameworkName('iso27001', 'en');
      expect(name).toBe('ISO/IEC 27001:2022');
    });

    it('should return Chinese name for iso27001', () => {
      const name = getFrameworkName('iso27001', 'zh-TW');
      expect(name).toBe('ISO/IEC 27001:2022');
    });

    it('should return English name for soc2', () => {
      const name = getFrameworkName('soc2', 'en');
      expect(name).toBe('SOC 2 Trust Services Criteria');
    });

    it('should return Chinese name for soc2', () => {
      const name = getFrameworkName('soc2', 'zh-TW');
      expect(name).toBe('SOC 2 信任服務準則');
    });

    it('should fallback to framework ID for unknown', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const name = getFrameworkName('unknown' as any, 'en');
      expect(name).toBe('unknown');
    });
  });

  describe('Taiwan Cyber Security Act controls', () => {
    it('should have 10 controls', () => {
      expect(TW_CYBER_SECURITY_CONTROLS).toHaveLength(10);
    });

    it('should have bilingual titles for all controls', () => {
      for (const control of TW_CYBER_SECURITY_CONTROLS) {
        expect(control.titleEn.length).toBeGreaterThan(0);
        expect(control.titleZh.length).toBeGreaterThan(0);
        expect(control.descriptionEn.length).toBeGreaterThan(0);
        expect(control.descriptionZh.length).toBeGreaterThan(0);
      }
    });

    it('should have related categories for all controls', () => {
      for (const control of TW_CYBER_SECURITY_CONTROLS) {
        expect(control.relatedCategories.length).toBeGreaterThan(0);
      }
    });

    it('should have unique control IDs', () => {
      const ids = TW_CYBER_SECURITY_CONTROLS.map((c) => c.controlId);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe('ISO 27001 controls', () => {
    it('should have 30 controls', () => {
      expect(ISO27001_CONTROLS).toHaveLength(30);
    });

    it('should have bilingual titles for all controls', () => {
      for (const control of ISO27001_CONTROLS) {
        expect(control.titleEn.length).toBeGreaterThan(0);
        expect(control.titleZh.length).toBeGreaterThan(0);
      }
    });

    it('should have unique control IDs', () => {
      const ids = ISO27001_CONTROLS.map((c) => c.controlId);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe('SOC 2 controls', () => {
    it('should have 10 controls', () => {
      expect(SOC2_CONTROLS).toHaveLength(10);
    });

    it('should have bilingual titles for all controls', () => {
      for (const control of SOC2_CONTROLS) {
        expect(control.titleEn.length).toBeGreaterThan(0);
        expect(control.titleZh.length).toBeGreaterThan(0);
      }
    });

    it('should have unique control IDs', () => {
      const ids = SOC2_CONTROLS.map((c) => c.controlId);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe('Cross-framework consistency', () => {
    it('all frameworks should have controls with required fields', () => {
      const frameworks: ComplianceFramework[] = ['tw_cyber_security_act', 'iso27001', 'soc2'];
      for (const fw of frameworks) {
        const controls = getFrameworkControls(fw);
        for (const control of controls) {
          expect(control.controlId).toBeDefined();
          expect(control.category).toBeDefined();
          expect(control.titleEn).toBeDefined();
          expect(control.titleZh).toBeDefined();
          expect(control.descriptionEn).toBeDefined();
          expect(control.descriptionZh).toBeDefined();
          expect(control.relatedCategories).toBeDefined();
          expect(Array.isArray(control.relatedCategories)).toBe(true);
        }
      }
    });
  });
});
