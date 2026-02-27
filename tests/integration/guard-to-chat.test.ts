/**
 * Integration Test: PanguardGuard -> PanguardChat Notification Pipeline
 * 整合測試：PanguardGuard -> PanguardChat 通知管線
 *
 * Tests the pipeline from threat detection to user notification
 * via chat channels with tone adaptation.
 * 測試從威脅偵測到透過聊天管道通知用戶（含語氣適配）的管線。
 */

import { describe, it, expect } from 'vitest';
import type { ThreatVerdict } from '@panguard-ai/panguard-guard';
import {
  DEFAULT_ACTION_POLICY,
  createEmptyBaseline,
  checkDeviation,
  updateBaseline,
  getLearningProgress,
  getBaselineSummary,
  validateLicense,
  hasFeature,
  generateTestLicenseKey,
} from '@panguard-ai/panguard-guard';
import type { ThreatAlert, UserProfile, UserType } from '@panguard-ai/panguard-chat';
import {
  formatAlert,
  formatConfirmation,
  formatPeacefulReport,
  buildSystemPrompt,
  findAlertTemplate,
  getHumanSummary,
  ALERT_TEMPLATES,
  DEFAULT_PREFERENCES,
} from '@panguard-ai/panguard-chat';

// ---------------------------------------------------------------------------
// Helpers: Convert ThreatVerdict to ThreatAlert
// 輔助函式：將 ThreatVerdict 轉換為 ThreatAlert
// ---------------------------------------------------------------------------

function verdictToAlert(verdict: ThreatVerdict, eventDescription: string): ThreatAlert {
  const severityMap: Record<string, ThreatAlert['severity']> = {
    malicious: verdict.confidence >= 90 ? 'critical' : 'high',
    suspicious: 'medium',
    benign: 'info',
  };

  return {
    conclusion: verdict.conclusion,
    confidence: verdict.confidence / 100,
    humanSummary: `Detected ${verdict.conclusion} activity with ${verdict.confidence}% confidence`,
    reasoning: verdict.reasoning,
    recommendedAction: verdict.recommendedAction,
    mitreTechnique: verdict.mitreTechnique,
    severity: severityMap[verdict.conclusion] ?? 'info',
    eventDescription,
    actionsTaken:
      verdict.recommendedAction !== 'log_only' ? [`Executed: ${verdict.recommendedAction}`] : [],
    timestamp: new Date().toISOString(),
  };
}

function createMockUserProfile(type: UserType, language: 'zh-TW' | 'en' = 'en'): UserProfile {
  return {
    type,
    language,
    notificationChannel: 'slack',
    preferences: { ...DEFAULT_PREFERENCES },
  };
}

// ---------------------------------------------------------------------------
// Test Data
// ---------------------------------------------------------------------------

function createMockMaliciousVerdict(): ThreatVerdict {
  return {
    conclusion: 'malicious',
    confidence: 92,
    reasoning: 'Multiple SSH brute force attempts from known malicious IP',
    evidence: [
      { source: 'rule_match', description: 'Sigma rule: SSH brute force', confidence: 90 },
      { source: 'threat_intel', description: 'IP in AbuseIPDB blacklist', confidence: 95 },
    ],
    recommendedAction: 'block_ip',
    mitreTechnique: 'T1110',
  };
}

function createMockSuspiciousVerdict(): ThreatVerdict {
  return {
    conclusion: 'suspicious',
    confidence: 65,
    reasoning: 'Unusual outbound connection to unknown destination',
    evidence: [
      { source: 'baseline_deviation', description: 'New outbound destination', confidence: 60 },
    ],
    recommendedAction: 'notify',
  };
}

function createMockBenignVerdict(): ThreatVerdict {
  return {
    conclusion: 'benign',
    confidence: 88,
    reasoning: 'Normal system update check',
    evidence: [
      { source: 'baseline_deviation', description: 'Within normal range', confidence: 85 },
    ],
    recommendedAction: 'log_only',
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PanguardGuard -> PanguardChat Pipeline Integration', () => {
  describe('Verdict to Alert Conversion', () => {
    it('should convert malicious verdict to critical alert', () => {
      const verdict = createMockMaliciousVerdict();
      const alert = verdictToAlert(verdict, 'SSH brute force from 103.x.x.x');

      expect(alert.conclusion).toBe('malicious');
      expect(alert.severity).toBe('critical');
      expect(alert.confidence).toBeCloseTo(0.92);
      expect(alert.mitreTechnique).toBe('T1110');
      expect(alert.actionsTaken).toHaveLength(1);
    });

    it('should convert suspicious verdict to medium alert', () => {
      const verdict = createMockSuspiciousVerdict();
      const alert = verdictToAlert(verdict, 'Outbound to unknown IP');

      expect(alert.conclusion).toBe('suspicious');
      expect(alert.severity).toBe('medium');
      expect(alert.confidence).toBeCloseTo(0.65);
    });

    it('should convert benign verdict to info alert', () => {
      const verdict = createMockBenignVerdict();
      const alert = verdictToAlert(verdict, 'System update check');

      expect(alert.conclusion).toBe('benign');
      expect(alert.severity).toBe('info');
      expect(alert.actionsTaken).toHaveLength(0);
    });
  });

  describe('Tone Adaptation per User Type', () => {
    const userTypes: UserType[] = ['developer', 'boss', 'it_admin'];
    const verdict = createMockMaliciousVerdict();
    const alert = verdictToAlert(verdict, 'SSH brute force from 103.x.x.x');

    for (const userType of userTypes) {
      it(`should format alert for ${userType}`, () => {
        const profile = createMockUserProfile(userType);
        const message = formatAlert(alert, profile.type, profile.language);

        expect(message.text.length).toBeGreaterThan(0);
        expect(message.severity).toBeDefined();
      });

      it(`should format alert in Chinese for ${userType}`, () => {
        const profile = createMockUserProfile(userType, 'zh-TW');
        const message = formatAlert(alert, profile.type, profile.language);

        expect(message.text.length).toBeGreaterThan(0);
      });
    }
  });

  describe('Confidence-Based Action Decisions', () => {
    it('should auto-respond for high confidence malicious', () => {
      const verdict = createMockMaliciousVerdict();
      const policy = DEFAULT_ACTION_POLICY;

      if (verdict.confidence >= policy.autoRespond) {
        const alert = verdictToAlert(verdict, 'Auto-blocked threat');
        expect(alert.actionsTaken!.length).toBeGreaterThan(0);
      }
    });

    it('should notify for medium confidence suspicious', () => {
      const verdict = createMockSuspiciousVerdict();
      const policy = DEFAULT_ACTION_POLICY;

      expect(verdict.confidence).toBeGreaterThanOrEqual(policy.notifyAndWait);
      expect(verdict.confidence).toBeLessThan(policy.autoRespond);
    });

    it('should log only for low confidence', () => {
      const verdict: ThreatVerdict = {
        conclusion: 'benign',
        confidence: 30,
        reasoning: 'Routine activity',
        evidence: [],
        recommendedAction: 'log_only',
      };

      const policy = DEFAULT_ACTION_POLICY;
      expect(verdict.confidence).toBeLessThan(policy.notifyAndWait);
    });
  });

  describe('Alert Templates Integration', () => {
    it('should have templates that cover common attack types', () => {
      expect(ALERT_TEMPLATES.length).toBeGreaterThan(0);

      const attackTypes = ALERT_TEMPLATES.map((t) => t.attackType);
      expect(attackTypes).toContain('ssh_brute_force');
      expect(attackTypes).toContain('ransomware_detected');
      expect(attackTypes).toContain('sql_injection');
    });

    it('should get human summary with parameter interpolation', () => {
      const template = findAlertTemplate('ssh_brute_force');
      expect(template).toBeDefined();

      const summary = getHumanSummary('ssh_brute_force', 'en', {
        count: '2847',
      });
      expect(summary).toContain('2847');
    });

    it('should get bilingual human summaries', () => {
      const enSummary = getHumanSummary('ssh_brute_force', 'en', { count: '100' });
      const zhSummary = getHumanSummary('ssh_brute_force', 'zh-TW', { count: '100' });

      expect(enSummary.length).toBeGreaterThan(0);
      expect(zhSummary.length).toBeGreaterThan(0);
    });
  });

  describe('System Prompt per User Type', () => {
    it('should build system prompt for developer in English', () => {
      const prompt = buildSystemPrompt('developer', 'en');
      expect(prompt.length).toBeGreaterThan(0);
    });

    it('should build system prompt for boss in Chinese', () => {
      const prompt = buildSystemPrompt('boss', 'zh-TW');
      expect(prompt.length).toBeGreaterThan(0);
    });

    it('should build system prompt for it_admin', () => {
      const prompt = buildSystemPrompt('it_admin', 'en');
      expect(prompt.length).toBeGreaterThan(0);
    });
  });

  describe('License Gating for Notifications', () => {
    it('should allow notifications for Pro license', () => {
      const key = generateTestLicenseKey('pro');
      const license = validateLicense(key);

      expect(license).not.toBeNull();
      expect(hasFeature(license!, 'notifications')).toBe(true);
    });

    it('should not allow notifications for Free license', () => {
      const key = generateTestLicenseKey('free');
      const license = validateLicense(key);

      expect(license).not.toBeNull();
      expect(hasFeature(license!, 'notifications')).toBe(false);
    });

    it('should allow full features for Enterprise license', () => {
      const key = generateTestLicenseKey('enterprise');
      const license = validateLicense(key);

      expect(license).not.toBeNull();
      expect(hasFeature(license!, 'notifications')).toBe(true);
      expect(hasFeature(license!, 'auto_respond')).toBe(true);
    });
  });

  describe('Baseline Integration with Alert Context', () => {
    it('should provide baseline summary for alert context', () => {
      const baseline = createEmptyBaseline();
      const summary = getBaselineSummary(baseline);

      expect(summary).toBeDefined();
      expect(summary.processCount).toBeGreaterThanOrEqual(0);
      expect(summary.confidenceLevel).toBeGreaterThanOrEqual(0);
    });

    it('should track learning progress for onboarding messages', () => {
      const baseline = createEmptyBaseline();
      const progress = getLearningProgress(baseline, 7);

      expect(progress).toBeGreaterThanOrEqual(0);
      expect(progress).toBeLessThanOrEqual(100);
    });

    it('should detect deviations that trigger notifications', () => {
      const baseline = createEmptyBaseline();
      // Update baseline with some normal data
      const updated = updateBaseline(baseline, {
        id: 'evt-001',
        timestamp: new Date(),
        source: 'process',
        severity: 'info',
        category: 'process_start',
        description: 'nginx started',
        raw: {},
        host: 'test-host',
        metadata: { processName: 'nginx', processPath: '/usr/sbin/nginx' },
      });

      // Check deviation for a new process
      const deviation = checkDeviation(updated, {
        id: 'evt-002',
        timestamp: new Date(),
        source: 'process',
        severity: 'medium',
        category: 'process_start',
        description: 'cryptominer started',
        raw: {},
        host: 'test-host',
        metadata: { processName: 'cryptominer', processPath: '/tmp/cryptominer' },
      });

      expect(deviation.isDeviation).toBe(true);
      expect(deviation.confidence).toBeGreaterThan(0);
    });
  });

  describe('Peaceful Report Pipeline', () => {
    it('should format peaceful report when no threats detected', () => {
      const message = formatPeacefulReport('en');
      expect(message.text.length).toBeGreaterThan(0);
    });

    it('should format peaceful report in Chinese', () => {
      const message = formatPeacefulReport('zh-TW');
      expect(message.text.length).toBeGreaterThan(0);
    });
  });

  describe('Confirmation Flow Integration', () => {
    it('should format confirmation request for suspicious verdict', () => {
      const confirmation = formatConfirmation(
        {
          verdictId: 'VRD-001',
          conclusion: 'suspicious',
          confidence: 0.65,
          humanSummary: 'Suspicious outbound connection to 185.x.x.x:4444',
          proposedAction: 'Block suspicious outbound connection',
          expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
        },
        'en'
      );

      expect(confirmation.text).toContain('Block');
      expect(confirmation.quickReplies).toBeDefined();
      expect(confirmation.quickReplies!.length).toBeGreaterThan(0);
    });
  });
});
