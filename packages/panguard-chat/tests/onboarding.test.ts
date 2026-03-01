/**
 * Onboarding tests
 * 安裝引導測試
 */

import { describe, it, expect } from 'vitest';
import {
  SETUP_STEPS,
  getChannelConfigSteps,
  buildConfigFromAnswers,
  getWelcomeMessage,
  DEFAULT_PREFERENCES,
} from '../src/onboarding/setup-flow.js';
import type { SetupAnswers } from '../src/onboarding/setup-flow.js';

describe('SETUP_STEPS', () => {
  it('should have 3 main setup steps', () => {
    expect(SETUP_STEPS.length).toBe(3);
  });

  it('should have channel selection step', () => {
    const step = SETUP_STEPS.find((s) => s.id === 'channel');
    expect(step).toBeDefined();
    expect(step!.options!.length).toBe(5);
  });

  it('should have user type step', () => {
    const step = SETUP_STEPS.find((s) => s.id === 'userType');
    expect(step).toBeDefined();
    expect(step!.options!.length).toBe(3);
  });

  it('should have language step', () => {
    const step = SETUP_STEPS.find((s) => s.id === 'language');
    expect(step).toBeDefined();
    expect(step!.options!.length).toBe(2);
  });

  it('should have bilingual labels for all options', () => {
    for (const step of SETUP_STEPS) {
      expect(step.title['zh-TW']).toBeTruthy();
      expect(step.title['en']).toBeTruthy();
      if (step.options) {
        for (const opt of step.options) {
          expect(opt.label['zh-TW']).toBeTruthy();
          expect(opt.label['en']).toBeTruthy();
        }
      }
    }
  });
});

describe('getChannelConfigSteps', () => {
  it('should return Telegram config steps', () => {
    const steps = getChannelConfigSteps('telegram');
    expect(steps.length).toBe(2);
    expect(steps[0]!.id).toContain('telegram');
  });

  it('should return Slack config steps', () => {
    const steps = getChannelConfigSteps('slack');
    expect(steps.length).toBe(3);
  });

  it('should return Email config steps', () => {
    const steps = getChannelConfigSteps('email');
    expect(steps.length).toBe(6);
  });

  it('should return Webhook config steps', () => {
    const steps = getChannelConfigSteps('webhook');
    expect(steps.length).toBe(3);
    const authStep = steps.find((s) => s.id === 'webhookAuthMethod');
    expect(authStep).toBeDefined();
    expect(authStep!.options!.length).toBe(3);
  });
});

describe('buildConfigFromAnswers', () => {
  it('should build config from developer/line/en answers', () => {
    const answers: SetupAnswers = {
      channel: 'line',
      userType: 'developer',
      language: 'en',
      channelConfig: {},
    };

    const config = buildConfigFromAnswers(answers);
    expect(config.userProfile.type).toBe('developer');
    expect(config.userProfile.language).toBe('en');
    expect(config.userProfile.notificationChannel).toBe('line');
    expect(config.maxFollowUpTokens).toBe(2000);
  });

  it('should build config from boss/slack/zh-TW answers', () => {
    const answers: SetupAnswers = {
      channel: 'slack',
      userType: 'boss',
      language: 'zh-TW',
      channelConfig: {},
    };

    const config = buildConfigFromAnswers(answers);
    expect(config.userProfile.type).toBe('boss');
    expect(config.userProfile.language).toBe('zh-TW');
    expect(config.userProfile.notificationChannel).toBe('slack');
  });

  it('should apply default preferences', () => {
    const answers: SetupAnswers = {
      channel: 'line',
      userType: 'developer',
      language: 'en',
      channelConfig: {},
    };

    const config = buildConfigFromAnswers(answers);
    expect(config.userProfile.preferences.criticalAlerts).toBe(true);
    expect(config.userProfile.preferences.dailySummary).toBe(true);
    expect(config.userProfile.preferences.weeklySummary).toBe(true);
    expect(config.userProfile.preferences.peacefulReport).toBe(true);
  });
});

describe('getWelcomeMessage', () => {
  it('should return zh-TW welcome message', () => {
    const msg = getWelcomeMessage('zh-TW');
    expect(msg).toContain('Panguard AI');
    expect(msg).toContain('AI 保鑣');
    expect(msg).toContain('學習期');
    expect(msg).toContain('7');
  });

  it('should return en welcome message', () => {
    const msg = getWelcomeMessage('en');
    expect(msg).toContain('Panguard AI');
    expect(msg).toContain('AI bodyguard');
    expect(msg).toContain('learning mode');
    expect(msg).toContain('7 days');
  });

  it('should mention notification types', () => {
    const msg = getWelcomeMessage('en');
    expect(msg).toContain('threat alerts');
    expect(msg).toContain('Daily security summaries');
    expect(msg).toContain('Weekly security reports');
    expect(msg).toContain('Peace reports');
  });
});

describe('DEFAULT_PREFERENCES', () => {
  it('should have all preferences enabled by default', () => {
    expect(DEFAULT_PREFERENCES.criticalAlerts).toBe(true);
    expect(DEFAULT_PREFERENCES.dailySummary).toBe(true);
    expect(DEFAULT_PREFERENCES.weeklySummary).toBe(true);
    expect(DEFAULT_PREFERENCES.peacefulReport).toBe(true);
  });
});
