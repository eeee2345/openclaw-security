/**
 * Formatter tests
 * 格式化器測試
 */

import { describe, it, expect } from 'vitest';
import type {
  ThreatAlert,
  SummaryReport,
  LearningProgress,
  ConfirmationRequest,
} from '../src/types.js';
import {
  formatAlert,
  formatSummary,
  formatLearningProgress,
  formatConfirmation,
  formatPeacefulReport,
} from '../src/agent/formatter.js';

// ---------------------------------------------------------------------------
// Test Data
// ---------------------------------------------------------------------------

function makeAlert(overrides: Partial<ThreatAlert> = {}): ThreatAlert {
  return {
    conclusion: 'malicious',
    confidence: 0.92,
    humanSummary: 'Someone is trying to guess your password.',
    reasoning: 'Multiple failed SSH login attempts from same IP.',
    recommendedAction: 'Enable two-factor authentication.',
    severity: 'high',
    eventDescription: 'SSH brute force from 103.0.0.1',
    actionsTaken: ['Blocked IP 103.0.0.1'],
    timestamp: '2025-01-15T10:30:00Z',
    ...overrides,
  };
}

function makeSummary(overrides: Partial<SummaryReport> = {}): SummaryReport {
  return {
    period: 'daily',
    startDate: '2025-01-15',
    endDate: '2025-01-15',
    totalEvents: 1500,
    threatsBlocked: 12,
    suspiciousEvents: 3,
    topAttackSources: [
      { ip: '103.0.0.1', count: 50, country: 'China' },
      { ip: '198.0.0.1', count: 30, country: 'Russia' },
    ],
    actionsTaken: [
      { action: 'block_ip', count: 8 },
      { action: 'kill_process', count: 4 },
    ],
    ...overrides,
  };
}

function makeProgress(overrides: Partial<LearningProgress> = {}): LearningProgress {
  return {
    day: 3,
    totalDays: 7,
    patternsRecorded: 150,
    eventsAnalyzed: 4200,
    notableFindings: 2,
    ...overrides,
  };
}

function makeConfirmation(overrides: Partial<ConfirmationRequest> = {}): ConfirmationRequest {
  return {
    verdictId: 'v-001',
    conclusion: 'suspicious',
    confidence: 0.75,
    humanSummary: 'Unusual outbound connection detected.',
    proposedAction: 'Block outbound connection to 185.0.0.1',
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Alert Formatting Tests
// ---------------------------------------------------------------------------

describe('formatAlert', () => {
  describe('developer user type', () => {
    it('should include technical details in zh-TW', () => {
      const alert = makeAlert({ mitreTechnique: 'T1110' });
      const result = formatAlert(alert, 'developer', 'zh-TW');

      expect(result.text).toContain('MITRE ATT&CK: T1110');
      expect(result.text).toContain('92%');
      expect(result.text).toContain('103.0.0.1');
      expect(result.text).toContain('malicious');
      expect(result.severity).toBe('critical');
    });

    it('should include technical details in en', () => {
      const alert = makeAlert({ mitreTechnique: 'T1110' });
      const result = formatAlert(alert, 'developer', 'en');

      expect(result.text).toContain('MITRE ATT&CK: T1110');
      expect(result.text).toContain('Conclusion: malicious');
      expect(result.text).toContain('confidence 92%');
    });
  });

  describe('boss user type', () => {
    it('should NOT include technical jargon in zh-TW', () => {
      const alert = makeAlert({ mitreTechnique: 'T1110' });
      const result = formatAlert(alert, 'boss', 'zh-TW');

      expect(result.text).not.toContain('MITRE');
      expect(result.text).not.toContain('T1110');
      expect(result.text).not.toContain('malicious');
      expect(result.text).toContain(alert.humanSummary);
      expect(result.text).toContain(alert.recommendedAction);
    });

    it('should NOT include technical jargon in en', () => {
      const alert = makeAlert({ mitreTechnique: 'T1110' });
      const result = formatAlert(alert, 'boss', 'en');

      expect(result.text).not.toContain('MITRE');
      expect(result.text).not.toContain('T1110');
      expect(result.text).toContain(alert.humanSummary);
    });
  });

  describe('it_admin user type', () => {
    it('should include MITRE reference and compliance note in zh-TW', () => {
      const alert = makeAlert({ mitreTechnique: 'T1110' });
      const result = formatAlert(alert, 'it_admin', 'zh-TW');

      expect(result.text).toContain('MITRE: T1110');
      expect(result.text).toContain('資安事件通報');
    });

    it('should include MITRE and compliance note in en', () => {
      const alert = makeAlert({ mitreTechnique: 'T1110' });
      const result = formatAlert(alert, 'it_admin', 'en');

      expect(result.text).toContain('MITRE: T1110');
      expect(result.text).toContain('security event report');
    });
  });

  describe('severity mapping', () => {
    it('should map critical/high to critical severity', () => {
      const result = formatAlert(makeAlert({ severity: 'critical' }), 'developer', 'en');
      expect(result.severity).toBe('critical');
    });

    it('should map medium to warning severity', () => {
      const result = formatAlert(makeAlert({ severity: 'medium' }), 'developer', 'en');
      expect(result.severity).toBe('warning');
    });

    it('should map low/info to info severity', () => {
      const result = formatAlert(makeAlert({ severity: 'low' }), 'developer', 'en');
      expect(result.severity).toBe('info');
    });
  });

  describe('quick replies', () => {
    it('should include quick reply buttons in zh-TW', () => {
      const result = formatAlert(makeAlert(), 'developer', 'zh-TW');
      expect(result.quickReplies).toBeDefined();
      expect(result.quickReplies!.length).toBe(3);
      expect(result.quickReplies![0]!.action).toBe('details');
    });

    it('should include quick reply buttons in en', () => {
      const result = formatAlert(makeAlert(), 'developer', 'en');
      expect(result.quickReplies).toBeDefined();
      expect(result.quickReplies![0]!.label).toBe('View details');
    });
  });
});

// ---------------------------------------------------------------------------
// Summary Formatting Tests
// ---------------------------------------------------------------------------

describe('formatSummary', () => {
  it('should format daily summary in zh-TW', () => {
    const result = formatSummary(makeSummary(), 'developer', 'zh-TW');
    expect(result.text).toContain('今日');
    expect(result.text).toContain('12');
    expect(result.text).toContain('3');
    expect(result.text).toContain('103.0.0.1');
    expect(result.severity).toBe('info');
  });

  it('should format weekly summary in en', () => {
    const result = formatSummary(makeSummary({ period: 'weekly' }), 'developer', 'en');
    expect(result.text).toContain('This Week');
    expect(result.text).toContain('Attacks blocked: 12');
  });

  it('should show estimated damage avoided', () => {
    const result = formatSummary(makeSummary({ estimatedDamageAvoided: 50000 }), 'developer', 'en');
    expect(result.text).toContain('50,000');
  });

  it('should show trend comparison', () => {
    const result = formatSummary(
      makeSummary({ trendComparison: { thisPeriod: 15, lastPeriod: 10, changePercent: 50 } }),
      'developer',
      'en'
    );
    expect(result.text).toContain('increased');
    expect(result.text).toContain('50%');
  });

  it('should NOT show attack sources for boss', () => {
    const result = formatSummary(makeSummary(), 'boss', 'en');
    expect(result.text).not.toContain('103.0.0.1');
  });

  it('should show recommendations', () => {
    const result = formatSummary(
      makeSummary({ recommendations: ['Enable 2FA', 'Update firewall rules'] }),
      'developer',
      'en'
    );
    expect(result.text).toContain('Enable 2FA');
    expect(result.text).toContain('Update firewall rules');
  });
});

// ---------------------------------------------------------------------------
// Learning Progress Tests
// ---------------------------------------------------------------------------

describe('formatLearningProgress', () => {
  it('should show progress percentage in zh-TW', () => {
    const result = formatLearningProgress(makeProgress(), 'zh-TW');
    expect(result.text).toContain('43%');
    expect(result.text).toContain('150');
    expect(result.text).toContain('4200');
    expect(result.text).toContain('2');
  });

  it('should show learning mode note', () => {
    const result = formatLearningProgress(makeProgress(), 'en');
    expect(result.text).toContain('learning period');
    expect(result.text).toContain('daily summaries');
  });

  it('should show completion message when learning is done', () => {
    const result = formatLearningProgress(makeProgress({ day: 7, totalDays: 7 }), 'en');
    expect(result.text).toContain('complete');
    expect(result.text).toContain('protection mode');
  });

  it('should show completion message in zh-TW', () => {
    const result = formatLearningProgress(makeProgress({ day: 7, totalDays: 7 }), 'zh-TW');
    expect(result.text).toContain('完成');
    expect(result.text).toContain('保護模式');
  });
});

// ---------------------------------------------------------------------------
// Confirmation Tests
// ---------------------------------------------------------------------------

describe('formatConfirmation', () => {
  it('should include confirm and reject buttons', () => {
    const result = formatConfirmation(makeConfirmation(), 'en');
    expect(result.quickReplies).toBeDefined();
    expect(result.quickReplies!.length).toBe(3);
    expect(result.quickReplies![0]!.action).toContain('confirm');
    expect(result.quickReplies![1]!.action).toContain('reject');
  });

  it('should show proposed action', () => {
    const result = formatConfirmation(makeConfirmation(), 'en');
    expect(result.text).toContain('Block outbound connection');
    expect(result.text).toContain('75%');
  });

  it('should map malicious to critical severity', () => {
    const result = formatConfirmation(makeConfirmation({ conclusion: 'malicious' }), 'en');
    expect(result.severity).toBe('critical');
  });

  it('should map suspicious to warning severity', () => {
    const result = formatConfirmation(makeConfirmation({ conclusion: 'suspicious' }), 'en');
    expect(result.severity).toBe('warning');
  });
});

// ---------------------------------------------------------------------------
// Peaceful Report Tests
// ---------------------------------------------------------------------------

describe('formatPeacefulReport', () => {
  it('should return all-clear message in en', () => {
    const result = formatPeacefulReport('en');
    expect(result.text).toContain('Everything is normal');
    expect(result.severity).toBe('info');
  });

  it('should return all-clear message in zh-TW', () => {
    const result = formatPeacefulReport('zh-TW');
    expect(result.text).toContain('一切正常');
  });
});
