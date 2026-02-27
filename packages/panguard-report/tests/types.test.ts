/**
 * PanguardReport types tests
 * PanguardReport 型別測試
 */

import { describe, it, expect } from 'vitest';
import { DEFAULT_REPORT_CONFIG } from '../src/types.js';
import type {
  ComplianceFramework,
  ControlStatus,
  ComplianceControl,
  ComplianceFinding,
  ReportType,
  ReportFormat,
  ReportLanguage,
  ReportConfig,
  ReportMetadata,
  ExecutiveSummary,
  ReportRecommendation,
} from '../src/types.js';

describe('PanguardReport Types', () => {
  describe('DEFAULT_REPORT_CONFIG', () => {
    it('should have default language zh-TW', () => {
      expect(DEFAULT_REPORT_CONFIG.language).toBe('zh-TW');
    });

    it('should have default framework tw_cyber_security_act', () => {
      expect(DEFAULT_REPORT_CONFIG.framework).toBe('tw_cyber_security_act');
    });

    it('should have default output directory', () => {
      expect(DEFAULT_REPORT_CONFIG.outputDir).toBe('./reports');
    });

    it('should include detailed findings by default', () => {
      expect(DEFAULT_REPORT_CONFIG.includeDetailedFindings).toBe(true);
    });

    it('should include recommendations by default', () => {
      expect(DEFAULT_REPORT_CONFIG.includeRecommendations).toBe(true);
    });

    it('should have default format json', () => {
      expect(DEFAULT_REPORT_CONFIG.format).toBe('json');
    });
  });

  describe('Type constraints', () => {
    it('should support all compliance frameworks', () => {
      const frameworks: ComplianceFramework[] = ['tw_cyber_security_act', 'iso27001', 'soc2'];
      expect(frameworks).toHaveLength(3);
    });

    it('should support all control statuses', () => {
      const statuses: ControlStatus[] = ['pass', 'fail', 'partial', 'not_applicable'];
      expect(statuses).toHaveLength(4);
    });

    it('should support all report types', () => {
      const types: ReportType[] = ['compliance', 'incident', 'monthly', 'quarterly', 'annual'];
      expect(types).toHaveLength(5);
    });

    it('should support all report formats', () => {
      const formats: ReportFormat[] = ['pdf', 'json'];
      expect(formats).toHaveLength(2);
    });

    it('should support all report languages', () => {
      const languages: ReportLanguage[] = ['zh-TW', 'en'];
      expect(languages).toHaveLength(2);
    });

    it('should support all finding severities', () => {
      const severities: ComplianceFinding['severity'][] = [
        'critical',
        'high',
        'medium',
        'low',
        'info',
      ];
      expect(severities).toHaveLength(5);
    });

    it('should support all finding sources', () => {
      const sources: ComplianceFinding['source'][] = [
        'panguard-scan',
        'panguard-guard',
        'panguard-trap',
        'manual',
      ];
      expect(sources).toHaveLength(4);
    });
  });

  describe('Type safety', () => {
    it('should create a valid ComplianceControl', () => {
      const control: ComplianceControl = {
        controlId: 'TEST-1',
        category: 'test',
        titleEn: 'Test Control',
        titleZh: '測試控制項',
        descriptionEn: 'A test control',
        descriptionZh: '一個測試控制項',
        relatedCategories: ['test', 'unit'],
      };
      expect(control.controlId).toBe('TEST-1');
      expect(control.relatedCategories).toHaveLength(2);
    });

    it('should create a valid ComplianceFinding', () => {
      const finding: ComplianceFinding = {
        findingId: 'F-001',
        severity: 'high',
        title: 'Test Finding',
        description: 'A test finding',
        category: 'test',
        timestamp: new Date(),
        source: 'panguard-scan',
      };
      expect(finding.findingId).toBe('F-001');
      expect(finding.severity).toBe('high');
    });

    it('should create a valid ReportConfig', () => {
      const config: ReportConfig = {
        language: 'en',
        framework: 'iso27001',
        outputDir: '/tmp/reports',
        includeDetailedFindings: true,
        includeRecommendations: false,
        format: 'json',
        organizationName: 'Test Corp',
      };
      expect(config.language).toBe('en');
      expect(config.organizationName).toBe('Test Corp');
    });

    it('should create a valid ReportMetadata', () => {
      const metadata: ReportMetadata = {
        reportId: 'RPT-202501-0001',
        type: 'compliance',
        framework: 'soc2',
        language: 'en',
        period: { start: new Date('2025-01-01'), end: new Date('2025-01-31') },
        generatedAt: new Date(),
        version: '1.0.0',
      };
      expect(metadata.reportId).toBe('RPT-202501-0001');
      expect(metadata.framework).toBe('soc2');
    });

    it('should create a valid ExecutiveSummary', () => {
      const summary: ExecutiveSummary = {
        overallScore: 85,
        totalControls: 10,
        controlsPassed: 7,
        controlsFailed: 2,
        controlsPartial: 1,
        controlsNA: 0,
        totalFindings: 5,
        criticalFindings: 0,
        highFindings: 2,
        keyRisks: ['Risk A'],
        keyAchievements: ['Achievement A'],
      };
      expect(summary.overallScore).toBe(85);
      expect(summary.keyRisks).toHaveLength(1);
    });

    it('should create a valid ReportRecommendation', () => {
      const rec: ReportRecommendation = {
        priority: 'immediate',
        title: 'Fix Critical Issue',
        description: 'Fix the critical issue',
        relatedControlIds: ['A.5.1'],
        estimatedEffort: '1-3 days',
      };
      expect(rec.priority).toBe('immediate');
      expect(rec.relatedControlIds).toHaveLength(1);
    });
  });
});
