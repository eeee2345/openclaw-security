/**
 * Report Templates tests
 * 報告範本測試
 */

import { describe, it, expect } from 'vitest';
import {
  getSectionLabels,
  getStatusLabel,
  getSeverityLabel,
  getPriorityLabel,
  getFrameworkDescription,
} from '../src/templates/index.js';
import type { ReportSectionLabels } from '../src/templates/index.js';

describe('Report Templates', () => {
  describe('getSectionLabels', () => {
    it('should return English labels', () => {
      const labels = getSectionLabels('en');
      expect(labels.title).toBe('Compliance Report');
      expect(labels.executiveSummary).toBe('Executive Summary');
      expect(labels.recommendations).toBe('Recommendations');
      expect(labels.generatedBy).toContain('Panguard AI');
    });

    it('should return Chinese labels', () => {
      const labels = getSectionLabels('zh-TW');
      expect(labels.title).toBe('合規報告');
      expect(labels.executiveSummary).toBe('執行摘要');
      expect(labels.recommendations).toBe('建議');
      expect(labels.generatedBy).toContain('Panguard AI');
    });

    it('should have all required label fields', () => {
      const requiredKeys: (keyof ReportSectionLabels)[] = [
        'title',
        'executiveSummary',
        'complianceOverview',
        'controlDetails',
        'findings',
        'recommendations',
        'statistics',
        'appendix',
        'generatedBy',
        'reportPeriod',
        'organization',
        'reportId',
        'overallScore',
        'controlsPassed',
        'controlsFailed',
        'controlsPartial',
        'controlsNA',
        'severity',
        'priority',
        'estimatedEffort',
        'category',
        'status',
        'evidence',
        'remediation',
      ];
      const enLabels = getSectionLabels('en');
      const zhLabels = getSectionLabels('zh-TW');
      for (const key of requiredKeys) {
        expect(enLabels[key]).toBeDefined();
        expect(enLabels[key].length).toBeGreaterThan(0);
        expect(zhLabels[key]).toBeDefined();
        expect(zhLabels[key].length).toBeGreaterThan(0);
      }
    });
  });

  describe('getStatusLabel', () => {
    it('should return English status labels', () => {
      expect(getStatusLabel('pass', 'en')).toBe('Pass');
      expect(getStatusLabel('fail', 'en')).toBe('Fail');
      expect(getStatusLabel('partial', 'en')).toBe('Partial');
      expect(getStatusLabel('not_applicable', 'en')).toBe('N/A');
    });

    it('should return Chinese status labels', () => {
      expect(getStatusLabel('pass', 'zh-TW')).toBe('通過');
      expect(getStatusLabel('fail', 'zh-TW')).toBe('未通過');
      expect(getStatusLabel('partial', 'zh-TW')).toBe('部分符合');
      expect(getStatusLabel('not_applicable', 'zh-TW')).toBe('不適用');
    });

    it('should fallback to raw value for unknown status', () => {
      expect(getStatusLabel('unknown', 'en')).toBe('unknown');
    });
  });

  describe('getSeverityLabel', () => {
    it('should return English severity labels', () => {
      expect(getSeverityLabel('critical', 'en')).toBe('Critical');
      expect(getSeverityLabel('high', 'en')).toBe('High');
      expect(getSeverityLabel('medium', 'en')).toBe('Medium');
      expect(getSeverityLabel('low', 'en')).toBe('Low');
      expect(getSeverityLabel('info', 'en')).toBe('Info');
    });

    it('should return Chinese severity labels', () => {
      expect(getSeverityLabel('critical', 'zh-TW')).toBe('嚴重');
      expect(getSeverityLabel('high', 'zh-TW')).toBe('高');
      expect(getSeverityLabel('medium', 'zh-TW')).toBe('中');
      expect(getSeverityLabel('low', 'zh-TW')).toBe('低');
      expect(getSeverityLabel('info', 'zh-TW')).toBe('資訊');
    });

    it('should fallback to raw value for unknown severity', () => {
      expect(getSeverityLabel('unknown', 'en')).toBe('unknown');
    });
  });

  describe('getPriorityLabel', () => {
    it('should return English priority labels', () => {
      expect(getPriorityLabel('immediate', 'en')).toBe('Immediate');
      expect(getPriorityLabel('high', 'en')).toBe('High');
      expect(getPriorityLabel('medium', 'en')).toBe('Medium');
      expect(getPriorityLabel('low', 'en')).toBe('Low');
    });

    it('should return Chinese priority labels', () => {
      expect(getPriorityLabel('immediate', 'zh-TW')).toBe('立即');
      expect(getPriorityLabel('high', 'zh-TW')).toBe('高');
      expect(getPriorityLabel('medium', 'zh-TW')).toBe('中');
      expect(getPriorityLabel('low', 'zh-TW')).toBe('低');
    });

    it('should fallback to raw value for unknown priority', () => {
      expect(getPriorityLabel('unknown', 'en')).toBe('unknown');
    });
  });

  describe('getFrameworkDescription', () => {
    it('should return English description for tw_cyber_security_act', () => {
      const desc = getFrameworkDescription('tw_cyber_security_act', 'en');
      expect(desc.fullName).toContain('Taiwan');
      expect(desc.shortDescription.length).toBeGreaterThan(0);
      expect(desc.scope.length).toBeGreaterThan(0);
    });

    it('should return Chinese description for tw_cyber_security_act', () => {
      const desc = getFrameworkDescription('tw_cyber_security_act', 'zh-TW');
      expect(desc.fullName).toContain('資通安全管理法');
      expect(desc.shortDescription.length).toBeGreaterThan(0);
    });

    it('should return description for iso27001', () => {
      const descEn = getFrameworkDescription('iso27001', 'en');
      expect(descEn.fullName).toContain('ISO/IEC 27001');

      const descZh = getFrameworkDescription('iso27001', 'zh-TW');
      expect(descZh.fullName).toContain('ISO/IEC 27001');
    });

    it('should return description for soc2', () => {
      const descEn = getFrameworkDescription('soc2', 'en');
      expect(descEn.fullName).toContain('SOC 2');

      const descZh = getFrameworkDescription('soc2', 'zh-TW');
      expect(descZh.fullName).toContain('SOC 2');
    });

    it('should have scope for all frameworks', () => {
      const frameworks = ['tw_cyber_security_act', 'iso27001', 'soc2'] as const;
      for (const fw of frameworks) {
        const desc = getFrameworkDescription(fw, 'en');
        expect(desc.scope.length).toBeGreaterThan(0);
      }
    });
  });
});
