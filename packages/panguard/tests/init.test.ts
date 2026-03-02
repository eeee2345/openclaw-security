import { describe, it, expect } from 'vitest';
import {
  getWizardSteps,
  getQuickSteps,
  buildQuickConfig,
  buildPanguardConfig,
  validateConfigSchema,
} from '../src/init/index.js';
import type { EnhancedEnvironment, WizardAnswers } from '../src/init/types.js';

describe('Init Wizard', () => {
  describe('getQuickSteps', () => {
    it('should return exactly 3 steps', () => {
      const steps = getQuickSteps();
      expect(steps).toHaveLength(3);
    });

    it('should have language as step 1', () => {
      const steps = getQuickSteps();
      expect(steps[0]!.id).toBe('language');
      expect(steps[0]!.inputType).toBe('select');
    });

    it('should have usageProfile as step 2', () => {
      const steps = getQuickSteps();
      expect(steps[1]!.id).toBe('usageProfile');
      expect(steps[1]!.inputType).toBe('select');
      expect(steps[1]!.options).toHaveLength(3);
    });

    it('should have environment auto-detect as step 3', () => {
      const steps = getQuickSteps();
      expect(steps[2]!.id).toBe('environment_os');
      expect(steps[2]!.inputType).toBe('auto');
      expect(steps[2]!.autoDetect).toBeTypeOf('function');
    });

    it('should have bilingual titles', () => {
      const steps = getQuickSteps();
      for (const step of steps) {
        expect(step.title).toHaveProperty('en');
        expect(step.title).toHaveProperty('zh-TW');
      }
    });
  });

  describe('getWizardSteps (advanced)', () => {
    it('should return 11 steps', () => {
      const steps = getWizardSteps();
      expect(steps.length).toBe(11);
    });

    it('should start with language step', () => {
      const steps = getWizardSteps();
      expect(steps[0]!.id).toBe('language');
    });
  });

  describe('buildQuickConfig', () => {
    const mockEnv: EnhancedEnvironment = {
      os: 'darwin 24.3.0',
      hostname: 'test-machine',
      arch: 'arm64',
      platform: 'darwin',
      totalMemGB: 16,
      openPorts: [22, 80],
      securityTools: ['ufw'],
      hasDocker: true,
    };

    it('should produce a valid config for personal profile', () => {
      const config = buildQuickConfig('personal', 'en', mockEnv);
      expect(config.version).toBe('1.0.0');
      expect(config.organization.name).toBe('test-machine');
      expect(config.organization.size).toBe('individual');
      expect(config.security.protectionLevel).toBe('balanced');
      expect(config.ai.preference).toBe('cloud_ai');
      expect(config.security.compliance).toEqual([]);
    });

    it('should use hostname as org name for personal profile', () => {
      const config = buildQuickConfig('personal', 'zh-TW', mockEnv);
      expect(config.organization.name).toBe('test-machine');
      expect(config.meta.language).toBe('zh-TW');
    });

    it('should produce team config correctly', () => {
      const config = buildQuickConfig('team', 'en', mockEnv);
      expect(config.organization.name).toBe('My Team');
      expect(config.organization.size).toBe('small');
      expect(config.environment.deployType).toBe('cloud');
    });

    it('should produce enterprise config with compliance', () => {
      const config = buildQuickConfig('enterprise', 'en', mockEnv);
      expect(config.organization.name).toBe('Enterprise');
      expect(config.organization.size).toBe('large');
      expect(config.security.protectionLevel).toBe('learning');
      expect(config.security.compliance).toEqual(['iso27001', 'soc2']);
      expect(config.environment.deployType).toBe('hybrid');
      expect(config.environment.serverCount).toBe(10);
    });

    it('should enable all modules', () => {
      const config = buildQuickConfig('personal', 'en', mockEnv);
      expect(config.modules.guard).toBe(true);
      expect(config.modules.scan).toBe(true);
      expect(config.modules.chat).toBe(true);
      expect(config.modules.dashboard).toBe(true);
    });

    it('should enable all security goals', () => {
      const config = buildQuickConfig('personal', 'en', mockEnv);
      expect(config.security.goals).toContain('realtime');
      expect(config.security.goals).toContain('compliance');
      expect(config.security.goals).toContain('vulnerability');
      expect(config.security.goals).toContain('honeypot');
    });

    it('should set balanced guard policy for personal', () => {
      const config = buildQuickConfig('personal', 'en', mockEnv);
      expect(config.guard.mode).toBe('learning');
      expect(config.guard.learningDays).toBe(7);
    });

    it('should set learning guard policy for enterprise', () => {
      const config = buildQuickConfig('enterprise', 'en', mockEnv);
      expect(config.guard.mode).toBe('learning');
      expect(config.guard.learningDays).toBe(14);
    });

    it('should sanitize hostname in personal quick config', () => {
      const envWithBadHostname: EnhancedEnvironment = {
        ...mockEnv,
        hostname: '<script>alert(1)</script>',
      };
      const config = buildQuickConfig('personal', 'en', envWithBadHostname);
      expect(config.organization.name).not.toContain('<');
      expect(config.organization.name).not.toContain('>');
    });
  });

  describe('validateConfigSchema', () => {
    it('should accept a valid config', () => {
      const valid = {
        version: '1.0.0',
        meta: { createdAt: '2026-01-01', language: 'en' },
        organization: { name: 'Test', size: 'individual', industry: 'tech' },
        environment: { os: 'linux', hostname: 'h', arch: 'x64', deployType: 'cloud', serverCount: 1 },
        security: { goals: [], compliance: [], protectionLevel: 'balanced' },
      };
      expect(validateConfigSchema(valid)).toBe(true);
    });

    it('should reject null', () => {
      expect(validateConfigSchema(null)).toBe(false);
    });

    it('should reject non-object', () => {
      expect(validateConfigSchema('string')).toBe(false);
      expect(validateConfigSchema(42)).toBe(false);
    });

    it('should reject missing version', () => {
      expect(
        validateConfigSchema({
          meta: {},
          organization: {},
          environment: {},
          security: {},
        })
      ).toBe(false);
    });

    it('should reject missing organization', () => {
      expect(
        validateConfigSchema({
          version: '1.0.0',
          meta: {},
          environment: {},
          security: {},
        })
      ).toBe(false);
    });

    it('should reject missing meta', () => {
      expect(
        validateConfigSchema({
          version: '1.0.0',
          organization: { name: 'Test' },
          environment: {},
          security: {},
        })
      ).toBe(false);
    });

    it('should reject missing environment', () => {
      expect(
        validateConfigSchema({
          version: '1.0.0',
          meta: {},
          organization: { name: 'Test' },
          security: {},
        })
      ).toBe(false);
    });

    it('should reject missing security', () => {
      expect(
        validateConfigSchema({
          version: '1.0.0',
          meta: {},
          organization: { name: 'Test' },
          environment: {},
        })
      ).toBe(false);
    });

    it('should reject if version is not a string', () => {
      expect(
        validateConfigSchema({
          version: 1,
          meta: {},
          organization: { name: 'Test' },
          environment: {},
          security: {},
        })
      ).toBe(false);
    });

    it('should reject organization without name', () => {
      expect(
        validateConfigSchema({
          version: '1.0.0',
          meta: {},
          organization: { size: 'small' },
          environment: {},
          security: {},
        })
      ).toBe(false);
    });

    it('should reject invalid deployType', () => {
      expect(
        validateConfigSchema({
          version: '1.0.0',
          meta: {},
          organization: { name: 'Test' },
          environment: { deployType: 'invalid' },
          security: {},
        })
      ).toBe(false);
    });

    it('should reject invalid protectionLevel', () => {
      expect(
        validateConfigSchema({
          version: '1.0.0',
          meta: {},
          organization: { name: 'Test' },
          environment: {},
          security: { protectionLevel: 'invalid' },
        })
      ).toBe(false);
    });

  });

  describe('buildPanguardConfig (full wizard)', () => {
    it('should build config from full wizard answers', () => {
      const answers: WizardAnswers = {
        language: 'en',
        orgName: 'Test Corp',
        orgSize: 'small',
        industry: 'tech',
        environment: {
          os: 'linux 6.1.0',
          hostname: 'server1',
          deployType: 'cloud',
          serverCount: 2,
        },
        securityGoals: 'all',
        compliance: 'iso27001',
        notification: { channel: 'telegram', config: {} },
        aiPreference: 'cloud_ai',
        protectionLevel: 'balanced',
      };

      const config = buildPanguardConfig(answers);
      expect(config.version).toBe('1.0.0');
      expect(config.organization.name).toBe('Test Corp');
      expect(config.security.goals).toHaveLength(4);
      expect(config.ai.provider).toBe('claude');
      expect(config.notifications.channel).toBe('telegram');
    });
  });
});
