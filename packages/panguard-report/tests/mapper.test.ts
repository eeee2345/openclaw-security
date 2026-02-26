/**
 * Compliance Mapper tests
 * 合規映射引擎測試
 */

import { describe, it, expect } from 'vitest';
import {
  evaluateControls,
  generateExecutiveSummary,
  generateStatistics,
  generateRecommendations,
} from '../src/mapper/index.js';
import type { ComplianceControl, ComplianceFinding } from '../src/types.js';

/** Helper to create a test control */
function createControl(overrides: Partial<ComplianceControl> = {}): ComplianceControl {
  return {
    controlId: 'TEST-1',
    category: 'test',
    titleEn: 'Test Control',
    titleZh: '測試控制項',
    descriptionEn: 'A test control',
    descriptionZh: '一個測試控制項',
    relatedCategories: ['test'],
    ...overrides,
  };
}

/** Helper to create a test finding */
function createFinding(overrides: Partial<ComplianceFinding> = {}): ComplianceFinding {
  return {
    findingId: 'F-001',
    severity: 'medium',
    title: 'Test Finding',
    description: 'A test finding',
    category: 'test',
    timestamp: new Date(),
    source: 'panguard-scan',
    ...overrides,
  };
}

describe('Compliance Mapper', () => {
  describe('evaluateControls', () => {
    it('should pass controls with no findings', () => {
      const controls = [createControl()];
      const result = evaluateControls(controls, []);
      expect(result[0]!.status).toBe('pass');
      expect(result[0]!.relatedFindings).toHaveLength(0);
    });

    it('should fail controls with critical findings', () => {
      const controls = [createControl()];
      const findings = [createFinding({ severity: 'critical', category: 'test' })];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.status).toBe('fail');
      expect(result[0]!.relatedFindings).toHaveLength(1);
    });

    it('should fail controls with high findings', () => {
      const controls = [createControl()];
      const findings = [createFinding({ severity: 'high', category: 'test' })];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.status).toBe('fail');
    });

    it('should partially pass controls with medium findings', () => {
      const controls = [createControl()];
      const findings = [createFinding({ severity: 'medium', category: 'test' })];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.status).toBe('partial');
    });

    it('should pass controls with only low findings', () => {
      const controls = [createControl()];
      const findings = [createFinding({ severity: 'low', category: 'test' })];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.status).toBe('pass');
    });

    it('should pass controls with only info findings', () => {
      const controls = [createControl()];
      const findings = [createFinding({ severity: 'info', category: 'test' })];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.status).toBe('pass');
    });

    it('should match findings by related categories', () => {
      const controls = [
        createControl({ relatedCategories: ['network', 'firewall'] }),
        createControl({ controlId: 'TEST-2', relatedCategories: ['password'] }),
      ];
      const findings = [
        createFinding({ category: 'network_scan', severity: 'high' }),
      ];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.status).toBe('fail'); // matches 'network'
      expect(result[1]!.status).toBe('pass'); // no match
    });

    it('should include evidence for pass', () => {
      const controls = [createControl()];
      const result = evaluateControls(controls, []);
      expect(result[0]!.evidence.length).toBeGreaterThan(0);
      expect(result[0]!.evidence[0]).toContain('No issues detected');
    });

    it('should include evidence for fail', () => {
      const controls = [createControl()];
      const findings = [createFinding({ severity: 'critical', category: 'test', title: 'Critical Bug' })];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.evidence.length).toBeGreaterThan(0);
      // First evidence line is the summary, severity details follow
      expect(result[0]!.evidence.some(e => e.includes('CRITICAL'))).toBe(true);
      expect(result[0]!.evidence.some(e => e.includes('Critical Bug'))).toBe(true);
    });

    it('should include remediation for failed controls', () => {
      const controls = [createControl()];
      const findings = [createFinding({ severity: 'critical', category: 'test' })];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.remediation).toBeDefined();
      expect(result[0]!.remediation).toContain('URGENT');
    });

    it('should include remediation for partial controls', () => {
      const controls = [createControl()];
      const findings = [createFinding({ severity: 'medium', category: 'test' })];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.remediation).toBeDefined();
    });

    it('should not include remediation for passing controls', () => {
      const controls = [createControl()];
      const result = evaluateControls(controls, []);
      expect(result[0]!.remediation).toBeUndefined();
    });

    it('should evaluate multiple controls correctly', () => {
      const controls = [
        createControl({ controlId: 'C-1', relatedCategories: ['access'] }),
        createControl({ controlId: 'C-2', relatedCategories: ['network'] }),
        createControl({ controlId: 'C-3', relatedCategories: ['encryption'] }),
      ];
      const findings = [
        createFinding({ category: 'access_control', severity: 'critical' }),
        createFinding({ findingId: 'F-002', category: 'network', severity: 'medium' }),
      ];
      const result = evaluateControls(controls, findings);
      expect(result[0]!.status).toBe('fail');     // access -> critical
      expect(result[1]!.status).toBe('partial');   // network -> medium
      expect(result[2]!.status).toBe('pass');      // encryption -> no findings
    });
  });

  describe('generateExecutiveSummary', () => {
    it('should generate summary with correct counts', () => {
      const controls = [
        createControl({ relatedCategories: ['access'] }),
        createControl({ controlId: 'C-2', relatedCategories: ['network'] }),
        createControl({ controlId: 'C-3', relatedCategories: ['unused'] }),
      ];
      const findings = [
        createFinding({ category: 'access_control', severity: 'critical' }),
        createFinding({ findingId: 'F-002', category: 'network', severity: 'medium' }),
      ];

      const evaluated = evaluateControls(controls, findings);
      const summary = generateExecutiveSummary(evaluated, findings, 'en');

      expect(summary.totalControls).toBe(3);
      expect(summary.controlsFailed).toBe(1);
      expect(summary.controlsPartial).toBe(1);
      expect(summary.controlsPassed).toBe(1);
      expect(summary.totalFindings).toBe(2);
      expect(summary.criticalFindings).toBe(1);
    });

    it('should calculate overall score correctly', () => {
      const controls = [
        createControl({ controlId: 'C-1', relatedCategories: ['a'] }),
        createControl({ controlId: 'C-2', relatedCategories: ['b'] }),
      ];
      // No findings = all pass
      const evaluated = evaluateControls(controls, []);
      const summary = generateExecutiveSummary(evaluated, [], 'en');
      expect(summary.overallScore).toBe(100);
    });

    it('should calculate score with failures', () => {
      const controls = [
        createControl({ controlId: 'C-1', relatedCategories: ['net'] }),
        createControl({ controlId: 'C-2', relatedCategories: ['unused'] }),
      ];
      const findings = [
        createFinding({ category: 'network', severity: 'critical' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const summary = generateExecutiveSummary(evaluated, findings, 'en');
      // 1 pass (50%) + 1 fail (0%) = 50%
      expect(summary.overallScore).toBe(50);
    });

    it('should include key risks from failed controls', () => {
      const controls = [
        createControl({ titleEn: 'Access Control', relatedCategories: ['access'] }),
      ];
      const findings = [
        createFinding({ category: 'access', severity: 'high' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const summary = generateExecutiveSummary(evaluated, findings, 'en');
      expect(summary.keyRisks).toContain('Access Control');
    });

    it('should use Chinese titles for zh-TW', () => {
      const controls = [
        createControl({ titleZh: '存取控制', relatedCategories: ['access'] }),
      ];
      const findings = [
        createFinding({ category: 'access', severity: 'high' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const summary = generateExecutiveSummary(evaluated, findings, 'zh-TW');
      expect(summary.keyRisks).toContain('存取控制');
    });

    it('should include key achievements', () => {
      const controls = [
        createControl({ relatedCategories: ['unused'] }),
      ];
      const evaluated = evaluateControls(controls, []);
      const summary = generateExecutiveSummary(evaluated, [], 'en');
      expect(summary.keyAchievements.length).toBeGreaterThan(0);
    });

    it('should return 100% score when no controls', () => {
      const summary = generateExecutiveSummary([], [], 'en');
      expect(summary.overallScore).toBe(100);
    });
  });

  describe('generateStatistics', () => {
    it('should count controls by status', () => {
      const controls = [
        createControl({ controlId: 'C-1', relatedCategories: ['access'] }),
        createControl({ controlId: 'C-2', relatedCategories: ['net'] }),
        createControl({ controlId: 'C-3', relatedCategories: ['unused'] }),
      ];
      const findings = [
        createFinding({ category: 'access', severity: 'critical' }),
        createFinding({ findingId: 'F-002', category: 'network', severity: 'medium' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const stats = generateStatistics(evaluated, findings);

      expect(stats.byStatus.fail).toBe(1);
      expect(stats.byStatus.partial).toBe(1);
      expect(stats.byStatus.pass).toBe(1);
    });

    it('should count findings by severity', () => {
      const findings = [
        createFinding({ findingId: 'F-1', severity: 'critical' }),
        createFinding({ findingId: 'F-2', severity: 'high' }),
        createFinding({ findingId: 'F-3', severity: 'high' }),
        createFinding({ findingId: 'F-4', severity: 'low' }),
      ];
      const stats = generateStatistics([], findings);
      expect(stats.findingsBySeverity['critical']).toBe(1);
      expect(stats.findingsBySeverity['high']).toBe(2);
      expect(stats.findingsBySeverity['low']).toBe(1);
    });

    it('should group controls by category', () => {
      const controls = [
        createControl({ controlId: 'C-1', category: 'access_control', relatedCategories: ['unused'] }),
        createControl({ controlId: 'C-2', category: 'access_control', relatedCategories: ['unused'] }),
        createControl({ controlId: 'C-3', category: 'network', relatedCategories: ['unused'] }),
      ];
      const evaluated = evaluateControls(controls, []);
      const stats = generateStatistics(evaluated, []);

      expect(stats.byCategory['access_control']!.total).toBe(2);
      expect(stats.byCategory['network']!.total).toBe(1);
    });

    it('should calculate compliance percentage', () => {
      const controls = [
        createControl({ controlId: 'C-1', relatedCategories: ['unused1'] }),
        createControl({ controlId: 'C-2', relatedCategories: ['unused2'] }),
      ];
      const evaluated = evaluateControls(controls, []);
      const stats = generateStatistics(evaluated, []);
      expect(stats.compliancePercentage).toBe(100);
    });

    it('should handle empty data', () => {
      const stats = generateStatistics([], []);
      expect(stats.compliancePercentage).toBe(100);
      expect(stats.byStatus.pass).toBe(0);
    });
  });

  describe('generateRecommendations', () => {
    it('should generate recommendations for failed controls', () => {
      const controls = [
        createControl({ relatedCategories: ['access'] }),
      ];
      const findings = [
        createFinding({ category: 'access', severity: 'critical' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const recs = generateRecommendations(evaluated, 'en');
      expect(recs).toHaveLength(1);
      expect(recs[0]!.priority).toBe('immediate');
    });

    it('should generate recommendations for partial controls', () => {
      const controls = [
        createControl({ relatedCategories: ['access'] }),
      ];
      const findings = [
        createFinding({ category: 'access', severity: 'medium' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const recs = generateRecommendations(evaluated, 'en');
      expect(recs).toHaveLength(1);
      expect(recs[0]!.priority).toBe('medium');
    });

    it('should not generate recommendations for passing controls', () => {
      const controls = [
        createControl({ relatedCategories: ['unused'] }),
      ];
      const evaluated = evaluateControls(controls, []);
      const recs = generateRecommendations(evaluated, 'en');
      expect(recs).toHaveLength(0);
    });

    it('should sort failed before partial', () => {
      const controls = [
        createControl({ controlId: 'C-1', relatedCategories: ['partial_cat'] }),
        createControl({ controlId: 'C-2', relatedCategories: ['fail_cat'] }),
      ];
      const findings = [
        createFinding({ category: 'partial_category', severity: 'medium' }),
        createFinding({ findingId: 'F-2', category: 'fail_category', severity: 'critical' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const recs = generateRecommendations(evaluated, 'en');
      expect(recs.length).toBeGreaterThanOrEqual(1);
      // Failed control should come first
      if (recs.length >= 2) {
        expect(recs[0]!.priority).toBe('immediate');
      }
    });

    it('should use Chinese titles for zh-TW', () => {
      const controls = [
        createControl({ titleZh: '存取控制', relatedCategories: ['access'] }),
      ];
      const findings = [
        createFinding({ category: 'access', severity: 'high' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const recs = generateRecommendations(evaluated, 'zh-TW');
      expect(recs[0]!.title).toBe('存取控制');
    });

    it('should include related control IDs', () => {
      const controls = [
        createControl({ controlId: 'A.5.1', relatedCategories: ['access'] }),
      ];
      const findings = [
        createFinding({ category: 'access', severity: 'high' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const recs = generateRecommendations(evaluated, 'en');
      expect(recs[0]!.relatedControlIds).toContain('A.5.1');
    });

    it('should include estimated effort', () => {
      const controls = [
        createControl({ relatedCategories: ['access'] }),
      ];
      const findings = [
        createFinding({ category: 'access', severity: 'critical' }),
      ];
      const evaluated = evaluateControls(controls, findings);
      const recs = generateRecommendations(evaluated, 'en');
      expect(recs[0]!.estimatedEffort).toBeDefined();
    });
  });
});
