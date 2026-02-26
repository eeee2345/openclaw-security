/**
 * Integration Test: PanguardScan -> PanguardReport Pipeline
 * 整合測試：PanguardScan -> PanguardReport 管線
 *
 * Tests the full pipeline from security scan findings
 * to compliance report generation.
 * 測試從安全掃描發現到合規報告產生的完整管線。
 */

import { describe, it, expect } from 'vitest';
import type { Finding } from '@openclaw/panguard-scan';
import { sortBySeverity } from '@openclaw/panguard-scan';
import type { ComplianceFinding, ComplianceFramework } from '@openclaw/panguard-report';
import {
  getFrameworkControls,
  getFrameworkName,
  getSupportedFrameworks,
  evaluateControls,
  generateExecutiveSummary,
  generateStatistics,
  generateRecommendations,
  generateComplianceReport,
  reportToJSON,
  generateSummaryText,
  getSectionLabels,
} from '@openclaw/panguard-report';

// ---------------------------------------------------------------------------
// Helpers: Convert PanguardScan findings to PanguardReport ComplianceFinding
// 輔助函式：將 PanguardScan 發現轉換為 PanguardReport 合規發現
// ---------------------------------------------------------------------------

function scanFindingToComplianceFinding(
  finding: Finding,
  source: 'panguard-scan' = 'panguard-scan'
): ComplianceFinding {
  return {
    findingId: finding.id,
    severity: finding.severity as ComplianceFinding['severity'],
    title: finding.title,
    description: finding.description,
    category: finding.category,
    timestamp: new Date(),
    source,
  };
}

// ---------------------------------------------------------------------------
// Test Data: Simulated PanguardScan findings
// 測試資料：模擬的 PanguardScan 掃描發現
// ---------------------------------------------------------------------------

function createMockScanFindings(): Finding[] {
  return [
    {
      id: 'SCAN-001',
      title: 'Weak Password Policy',
      description: 'Password policy allows passwords shorter than 8 characters',
      severity: 'high',
      category: 'password',
      remediation: 'Set minimum password length to 12 characters',
      complianceRef: '4.1',
    },
    {
      id: 'SCAN-002',
      title: 'Open FTP Port',
      description: 'FTP (port 21) is open and accepting connections',
      severity: 'critical',
      category: 'network',
      remediation: 'Close FTP port or switch to SFTP',
    },
    {
      id: 'SCAN-003',
      title: 'Outdated SSL Certificate',
      description: 'SSL certificate will expire in 10 days',
      severity: 'medium',
      category: 'encryption',
      remediation: 'Renew SSL certificate',
    },
    {
      id: 'SCAN-004',
      title: 'No MFA Configured',
      description: 'Multi-factor authentication is not enabled for any user',
      severity: 'high',
      category: 'access_control',
      remediation: 'Enable MFA for all user accounts',
    },
    {
      id: 'SCAN-005',
      title: 'Unnecessary Shared Folder',
      description: 'Shared folder with everyone access detected',
      severity: 'medium',
      category: 'access_control',
      remediation: 'Remove everyone access from shared folders',
    },
    {
      id: 'SCAN-006',
      title: 'Missing Security Updates',
      description: 'System is missing 5 critical security updates',
      severity: 'high',
      category: 'vulnerability',
      remediation: 'Apply all pending security updates',
    },
    {
      id: 'SCAN-007',
      title: 'Suspicious Cron Job',
      description: 'Cron job downloading from unknown URL detected',
      severity: 'critical',
      category: 'monitoring',
      remediation: 'Review and remove suspicious cron jobs',
    },
    {
      id: 'SCAN-008',
      title: 'Firewall Disabled',
      description: 'System firewall is not enabled',
      severity: 'high',
      category: 'network',
      remediation: 'Enable and configure the system firewall',
    },
  ];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PanguardScan -> PanguardReport Pipeline Integration', () => {
  describe('Finding Conversion', () => {
    it('should convert PanguardScan findings to ComplianceFinding format', () => {
      const scanFindings = createMockScanFindings();
      const complianceFindings = scanFindings.map((f) => scanFindingToComplianceFinding(f));

      expect(complianceFindings).toHaveLength(scanFindings.length);
      for (let i = 0; i < scanFindings.length; i++) {
        expect(complianceFindings[i]!.findingId).toBe(scanFindings[i]!.id);
        expect(complianceFindings[i]!.severity).toBe(scanFindings[i]!.severity);
        expect(complianceFindings[i]!.category).toBe(scanFindings[i]!.category);
        expect(complianceFindings[i]!.source).toBe('panguard-scan');
      }
    });

    it('should preserve severity levels during conversion', () => {
      const scanFindings = createMockScanFindings();
      const complianceFindings = scanFindings.map((f) => scanFindingToComplianceFinding(f));

      const criticalCount = complianceFindings.filter((f) => f.severity === 'critical').length;
      const highCount = complianceFindings.filter((f) => f.severity === 'high').length;
      const mediumCount = complianceFindings.filter((f) => f.severity === 'medium').length;

      expect(criticalCount).toBe(2);
      expect(highCount).toBe(4);
      expect(mediumCount).toBe(2);
    });

    it('should maintain finding IDs for traceability', () => {
      const scanFindings = createMockScanFindings();
      const complianceFindings = scanFindings.map((f) => scanFindingToComplianceFinding(f));

      const findingIds = complianceFindings.map((f) => f.findingId);
      expect(new Set(findingIds).size).toBe(findingIds.length); // All unique
      expect(findingIds).toContain('SCAN-001');
      expect(findingIds).toContain('SCAN-007');
    });
  });

  describe('Full Pipeline: Scan -> Evaluate -> Report', () => {
    const frameworks: ComplianceFramework[] = ['tw_cyber_security_act', 'iso27001', 'soc2'];

    for (const framework of frameworks) {
      describe(`Framework: ${framework}`, () => {
        it(`should evaluate controls against scan findings for ${framework}`, () => {
          const scanFindings = createMockScanFindings();
          const complianceFindings = scanFindings.map((f) => scanFindingToComplianceFinding(f));
          const controls = getFrameworkControls(framework);

          const evaluated = evaluateControls(controls, complianceFindings);

          expect(evaluated.length).toBe(controls.length);
          // Some controls should fail or be partial due to critical/high findings
          const failedOrPartial = evaluated.filter(
            (c) => c.status === 'fail' || c.status === 'partial'
          );
          expect(failedOrPartial.length).toBeGreaterThan(0);
        });

        it(`should generate executive summary for ${framework}`, () => {
          const complianceFindings = createMockScanFindings().map((f) =>
            scanFindingToComplianceFinding(f)
          );
          const controls = getFrameworkControls(framework);
          const evaluated = evaluateControls(controls, complianceFindings);

          const summary = generateExecutiveSummary(evaluated, complianceFindings, 'en');

          expect(summary.totalControls).toBe(controls.length);
          expect(summary.overallScore).toBeGreaterThanOrEqual(0);
          expect(summary.overallScore).toBeLessThanOrEqual(100);
          expect(summary.totalFindings).toBe(complianceFindings.length);
          expect(summary.criticalFindings).toBe(2);
          expect(summary.highFindings).toBe(4);
        });

        it(`should generate statistics for ${framework}`, () => {
          const complianceFindings = createMockScanFindings().map((f) =>
            scanFindingToComplianceFinding(f)
          );
          const controls = getFrameworkControls(framework);
          const evaluated = evaluateControls(controls, complianceFindings);

          const stats = generateStatistics(evaluated, complianceFindings);

          expect(stats.compliancePercentage).toBeGreaterThanOrEqual(0);
          expect(stats.compliancePercentage).toBeLessThanOrEqual(100);
          expect(stats.findingsBySeverity['critical']).toBe(2);
          expect(stats.findingsBySeverity['high']).toBe(4);
        });

        it(`should generate recommendations for ${framework}`, () => {
          const complianceFindings = createMockScanFindings().map((f) =>
            scanFindingToComplianceFinding(f)
          );
          const controls = getFrameworkControls(framework);
          const evaluated = evaluateControls(controls, complianceFindings);

          const recommendations = generateRecommendations(evaluated, 'en');

          // Should have recommendations for failed/partial controls
          expect(recommendations.length).toBeGreaterThan(0);
          // Should have immediate/high priority due to critical findings
          const highPriorityCount = recommendations.filter(
            (r) => r.priority === 'immediate' || r.priority === 'high'
          ).length;
          expect(highPriorityCount).toBeGreaterThan(0);
        });

        it(`should generate full compliance report for ${framework}`, () => {
          const complianceFindings = createMockScanFindings().map((f) =>
            scanFindingToComplianceFinding(f)
          );

          const report = generateComplianceReport(complianceFindings, framework, 'en', {
            organizationName: 'Test Corp',
          });

          expect(report.metadata.framework).toBe(framework);
          expect(report.metadata.organizationName).toBe('Test Corp');
          expect(report.metadata.reportId).toMatch(/^RPT-/);
          expect(report.controls.length).toBeGreaterThan(0);
          expect(report.findings).toHaveLength(complianceFindings.length);
          expect(report.executiveSummary.totalFindings).toBe(complianceFindings.length);
          expect(report.statistics.compliancePercentage).toBeDefined();
        });

        it(`should serialize report to JSON for ${framework}`, () => {
          const complianceFindings = createMockScanFindings().map((f) =>
            scanFindingToComplianceFinding(f)
          );
          const report = generateComplianceReport(complianceFindings, framework, 'en');
          const json = reportToJSON(report);

          expect(() => JSON.parse(json)).not.toThrow();
          const parsed = JSON.parse(json);
          expect(parsed.metadata.framework).toBe(framework);
        });

        it(`should generate bilingual summary text for ${framework}`, () => {
          const complianceFindings = createMockScanFindings().map((f) =>
            scanFindingToComplianceFinding(f)
          );
          const enReport = generateComplianceReport(complianceFindings, framework, 'en');
          const zhReport = generateComplianceReport(complianceFindings, framework, 'zh-TW');

          const enSummary = generateSummaryText(enReport);
          const zhSummary = generateSummaryText(zhReport);

          expect(enSummary).toContain(enReport.metadata.reportId);
          expect(zhSummary).toContain(zhReport.metadata.reportId);
          expect(enSummary.length).toBeGreaterThan(100);
          expect(zhSummary.length).toBeGreaterThan(100);
        });
      });
    }
  });

  describe('Cross-Framework Consistency', () => {
    it('should produce consistent finding counts across all frameworks', () => {
      const scanFindings = createMockScanFindings();
      const complianceFindings = scanFindings.map((f) => scanFindingToComplianceFinding(f));

      for (const framework of getSupportedFrameworks()) {
        const report = generateComplianceReport(complianceFindings, framework, 'en');
        expect(report.findings).toHaveLength(complianceFindings.length);
        expect(report.executiveSummary.totalFindings).toBe(complianceFindings.length);
      }
    });

    it('should have framework-specific control counts', () => {
      const controlCounts: Record<string, number> = {};

      for (const framework of getSupportedFrameworks()) {
        const controls = getFrameworkControls(framework);
        controlCounts[framework] = controls.length;
      }

      // Each framework has different numbers of controls
      expect(controlCounts['tw_cyber_security_act']).toBe(10);
      expect(controlCounts['iso27001']).toBe(30);
      expect(controlCounts['soc2']).toBe(10);
    });

    it('should have bilingual framework names', () => {
      for (const framework of getSupportedFrameworks()) {
        const enName = getFrameworkName(framework, 'en');
        const zhName = getFrameworkName(framework, 'zh-TW');

        expect(enName.length).toBeGreaterThan(0);
        expect(zhName.length).toBeGreaterThan(0);
        // Some framework names may be identical in both languages (e.g., ISO standards)
      }
    });

    it('should have bilingual report labels', () => {
      const enLabels = getSectionLabels('en');
      const zhLabels = getSectionLabels('zh-TW');

      expect(enLabels.title).not.toBe(zhLabels.title);
      expect(enLabels.executiveSummary).not.toBe(zhLabels.executiveSummary);
    });
  });

  describe('Severity Sorting Pipeline', () => {
    it('should sort findings by severity before feeding to report', () => {
      const findings = createMockScanFindings();
      const sorted = [...findings].sort(sortBySeverity);

      // Critical findings first
      expect(sorted[0]!.severity).toBe('critical');
      expect(sorted[1]!.severity).toBe('critical');
      // Then high
      expect(sorted[2]!.severity).toBe('high');

      // Convert sorted findings and verify order preserved
      const complianceFindings = sorted.map((f) => scanFindingToComplianceFinding(f));
      expect(complianceFindings[0]!.severity).toBe('critical');
    });
  });
});
