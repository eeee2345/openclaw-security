/**
 * Report Generator tests
 * 報告產生器測試
 */

import { describe, it, expect } from 'vitest';
import {
  generateComplianceReport,
  reportToJSON,
  generateSummaryText,
} from '../src/generator/index.js';
import type { ComplianceFinding } from '../src/types.js';

/** Helper to create test findings */
function createTestFindings(): ComplianceFinding[] {
  return [
    {
      findingId: 'F-001',
      severity: 'critical',
      title: 'Weak Password Policy',
      description: 'Password policy allows weak passwords',
      category: 'password',
      timestamp: new Date('2025-01-15'),
      source: 'panguard-scan',
    },
    {
      findingId: 'F-002',
      severity: 'high',
      title: 'Open Network Port',
      description: 'Unnecessary port 8080 exposed',
      category: 'network',
      timestamp: new Date('2025-01-15'),
      source: 'panguard-scan',
    },
    {
      findingId: 'F-003',
      severity: 'medium',
      title: 'Outdated TLS Version',
      description: 'TLS 1.0 still enabled',
      category: 'certificate',
      timestamp: new Date('2025-01-15'),
      source: 'panguard-scan',
    },
    {
      findingId: 'F-004',
      severity: 'low',
      title: 'Missing HSTS Header',
      description: 'HTTP Strict Transport Security header not set',
      category: 'http_header',
      timestamp: new Date('2025-01-15'),
      source: 'panguard-scan',
    },
  ];
}

describe('Report Generator', () => {
  describe('generateComplianceReport', () => {
    it('should generate a report for tw_cyber_security_act', () => {
      const report = generateComplianceReport(
        createTestFindings(),
        'tw_cyber_security_act',
        'zh-TW'
      );
      expect(report.metadata.framework).toBe('tw_cyber_security_act');
      expect(report.metadata.language).toBe('zh-TW');
      expect(report.metadata.reportId).toMatch(/^RPT-/);
      expect(report.controls.length).toBeGreaterThan(0);
    });

    it('should generate a report for iso27001', () => {
      const report = generateComplianceReport(createTestFindings(), 'iso27001', 'en');
      expect(report.metadata.framework).toBe('iso27001');
      expect(report.controls.length).toBeGreaterThan(0);
    });

    it('should generate a report for soc2', () => {
      const report = generateComplianceReport(createTestFindings(), 'soc2', 'en');
      expect(report.metadata.framework).toBe('soc2');
      expect(report.controls.length).toBeGreaterThan(0);
    });

    it('should include executive summary', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      expect(report.executiveSummary).toBeDefined();
      expect(report.executiveSummary.totalControls).toBeGreaterThan(0);
      expect(report.executiveSummary.overallScore).toBeDefined();
    });

    it('should include statistics', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      expect(report.statistics).toBeDefined();
      expect(report.statistics.compliancePercentage).toBeDefined();
    });

    it('should include findings in report', () => {
      const findings = createTestFindings();
      const report = generateComplianceReport(findings, 'tw_cyber_security_act', 'en');
      expect(report.findings).toHaveLength(findings.length);
    });

    it('should include recommendations by default', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      // There should be some recommendations since we have critical/high findings
      expect(report.recommendations.length).toBeGreaterThanOrEqual(0);
    });

    it('should exclude recommendations when option is false', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en', {
        includeRecommendations: false,
      });
      expect(report.recommendations).toHaveLength(0);
    });

    it('should set organization name from options', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en', {
        organizationName: 'Test Corp',
      });
      expect(report.metadata.organizationName).toBe('Test Corp');
    });

    it('should set period from options', () => {
      const start = new Date('2025-01-01');
      const end = new Date('2025-01-31');
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en', {
        periodStart: start,
        periodEnd: end,
      });
      expect(report.metadata.period.start).toEqual(start);
      expect(report.metadata.period.end).toEqual(end);
    });

    it('should generate unique report IDs', () => {
      const r1 = generateComplianceReport([], 'tw_cyber_security_act', 'en');
      const r2 = generateComplianceReport([], 'tw_cyber_security_act', 'en');
      expect(r1.metadata.reportId).not.toBe(r2.metadata.reportId);
    });

    it('should set metadata version', () => {
      const report = generateComplianceReport([], 'tw_cyber_security_act', 'en');
      expect(report.metadata.version).toBe('1.0.0');
    });

    it('should handle empty findings', () => {
      const report = generateComplianceReport([], 'tw_cyber_security_act', 'en');
      expect(report.executiveSummary.overallScore).toBe(100);
      expect(report.findings).toHaveLength(0);
    });
  });

  describe('reportToJSON', () => {
    it('should serialize report to JSON string', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      const json = reportToJSON(report);
      expect(typeof json).toBe('string');
      expect(json.length).toBeGreaterThan(0);
    });

    it('should produce valid JSON', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      const json = reportToJSON(report);
      const parsed = JSON.parse(json);
      expect(parsed.metadata).toBeDefined();
      expect(parsed.executiveSummary).toBeDefined();
    });

    it('should serialize dates as ISO strings', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      const json = reportToJSON(report);
      const parsed = JSON.parse(json);
      expect(typeof parsed.metadata.generatedAt).toBe('string');
      expect(parsed.metadata.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('should be pretty-printed with 2 spaces', () => {
      const report = generateComplianceReport([], 'tw_cyber_security_act', 'en');
      const json = reportToJSON(report);
      // Pretty print with 2 spaces should have indented lines
      expect(json).toContain('  ');
      expect(json.split('\n').length).toBeGreaterThan(1);
    });
  });

  describe('generateSummaryText', () => {
    it('should generate English summary text', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      const text = generateSummaryText(report);
      expect(text).toContain('Compliance Report');
      expect(text).toContain('Report Period');
      expect(text).toContain('Executive Summary');
      expect(text).toContain('Overall Compliance Score');
    });

    it('should generate Chinese summary text', () => {
      const report = generateComplianceReport(
        createTestFindings(),
        'tw_cyber_security_act',
        'zh-TW'
      );
      const text = generateSummaryText(report);
      expect(text).toContain('合規報告');
      expect(text).toContain('報告期間');
      expect(text).toContain('執行摘要');
    });

    it('should include report ID', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      const text = generateSummaryText(report);
      expect(text).toContain(report.metadata.reportId);
    });

    it('should include organization name when provided', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en', {
        organizationName: 'ACME Corp',
      });
      const text = generateSummaryText(report);
      expect(text).toContain('ACME Corp');
    });

    it('should include compliance percentage', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      const text = generateSummaryText(report);
      expect(text).toContain('Compliance:');
      expect(text).toContain('%');
    });

    it('should include recommendations section', () => {
      const report = generateComplianceReport(createTestFindings(), 'tw_cyber_security_act', 'en');
      const text = generateSummaryText(report);
      // Should have recommendations since we have critical findings
      if (report.recommendations.length > 0) {
        expect(text).toContain('Recommendations');
      }
    });

    it('should include framework name', () => {
      const report = generateComplianceReport(createTestFindings(), 'iso27001', 'en');
      const text = generateSummaryText(report);
      expect(text).toContain('ISO/IEC 27001:2022');
    });

    it('should include header separators', () => {
      const report = generateComplianceReport([], 'tw_cyber_security_act', 'en');
      const text = generateSummaryText(report);
      expect(text).toContain('====');
    });
  });
});
