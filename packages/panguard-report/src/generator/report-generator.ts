/**
 * Report Generator
 * 報告產生器
 *
 * Generates compliance reports in JSON format.
 * (PDF generation uses the existing PanguardScan PDF module pattern.)
 * 產生 JSON 格式的合規報告。
 * （PDF 產生使用現有的 PanguardScan PDF 模組模式。）
 *
 * @module @panguard-ai/panguard-report/generator/report-generator
 */

import { createLogger } from '@panguard-ai/core';
import type {
  ComplianceFinding,
  ComplianceFramework,
  ComplianceReportData,
  ReportLanguage,
  ReportMetadata,
} from '../types.js';
import { getFrameworkControls, getFrameworkName } from '../frameworks/index.js';
import {
  evaluateControls,
  generateExecutiveSummary,
  generateStatistics,
  generateRecommendations,
} from '../mapper/index.js';

const logger = createLogger('panguard-report:generator');

let reportCounter = 0;

/**
 * Generate a compliance report
 * 產生合規報告
 */
export function generateComplianceReport(
  findings: ComplianceFinding[],
  framework: ComplianceFramework,
  language: ReportLanguage,
  options?: {
    organizationName?: string;
    periodStart?: Date;
    periodEnd?: Date;
    includeRecommendations?: boolean;
  }
): ComplianceReportData {
  const now = new Date();
  reportCounter += 1;

  // Get framework controls
  const controls = getFrameworkControls(framework);

  // Evaluate controls against findings
  const evaluatedControls = evaluateControls(controls, findings);

  // Generate executive summary
  const executiveSummary = generateExecutiveSummary(evaluatedControls, findings, language);

  // Generate statistics
  const statistics = generateStatistics(evaluatedControls, findings);

  // Generate recommendations
  const includeRecs = options?.includeRecommendations ?? true;
  const recommendations = includeRecs ? generateRecommendations(evaluatedControls, language) : [];

  // Build metadata
  const metadata: ReportMetadata = {
    reportId: `RPT-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}-${reportCounter.toString().padStart(4, '0')}`,
    type: 'compliance',
    framework,
    language,
    period: {
      start: options?.periodStart ?? new Date(now.getFullYear(), now.getMonth(), 1),
      end: options?.periodEnd ?? now,
    },
    generatedAt: now,
    organizationName: options?.organizationName,
    version: '1.0.0',
  };

  const frameworkName = getFrameworkName(framework, language);
  logger.info(
    `Compliance report generated: ${metadata.reportId} (${frameworkName}) / 合規報告已產生`
  );

  return {
    metadata,
    executiveSummary,
    controls: evaluatedControls,
    findings,
    statistics,
    recommendations,
  };
}

/**
 * Generate JSON output from report data
 * 從報告資料產生 JSON 輸出
 */
export function reportToJSON(report: ComplianceReportData): string {
  return JSON.stringify(
    report,
    (_key, value) => {
      if (value instanceof Date) {
        return value.toISOString();
      }
      return value;
    },
    2
  );
}

/**
 * Generate a human-readable summary text
 * 產生人類可讀的摘要文字
 */
export function generateSummaryText(report: ComplianceReportData): string {
  const { metadata, executiveSummary: es, statistics } = report;
  const isZh = metadata.language === 'zh-TW';
  const frameworkName = getFrameworkName(metadata.framework, metadata.language);
  const lines: string[] = [];

  // Header
  lines.push('='.repeat(60));
  lines.push(isZh ? `${frameworkName} 合規報告` : `${frameworkName} Compliance Report`);
  lines.push('='.repeat(60));
  lines.push('');

  // Period
  const startStr = metadata.period.start.toISOString().split('T')[0];
  const endStr = metadata.period.end.toISOString().split('T')[0];
  lines.push(
    isZh
      ? `報告期間 / Report Period: ${startStr} ~ ${endStr}`
      : `Report Period: ${startStr} ~ ${endStr}`
  );
  if (metadata.organizationName) {
    lines.push(
      isZh
        ? `組織 / Organization: ${metadata.organizationName}`
        : `Organization: ${metadata.organizationName}`
    );
  }
  lines.push(`Report ID: ${metadata.reportId}`);
  lines.push('');

  // Executive Summary
  lines.push(isZh ? '--- 執行摘要 ---' : '--- Executive Summary ---');
  lines.push(
    isZh
      ? `整體合規分數 / Overall Score: ${es.overallScore}%`
      : `Overall Compliance Score: ${es.overallScore}%`
  );
  lines.push(
    isZh
      ? `控制項: ${es.controlsPassed} 通過 / ${es.controlsFailed} 未通過 / ${es.controlsPartial} 部分 / ${es.controlsNA} 不適用`
      : `Controls: ${es.controlsPassed} passed / ${es.controlsFailed} failed / ${es.controlsPartial} partial / ${es.controlsNA} N/A`
  );
  lines.push(
    isZh
      ? `發現: ${es.totalFindings} 個 (${es.criticalFindings} 嚴重, ${es.highFindings} 高風險)`
      : `Findings: ${es.totalFindings} total (${es.criticalFindings} critical, ${es.highFindings} high)`
  );
  lines.push('');

  // Key Risks
  if (es.keyRisks.length > 0) {
    lines.push(isZh ? '主要風險:' : 'Key Risks:');
    for (const risk of es.keyRisks) {
      lines.push(`  - ${risk}`);
    }
    lines.push('');
  }

  // Recommendations
  if (report.recommendations.length > 0) {
    lines.push(isZh ? '--- 建議 ---' : '--- Recommendations ---');
    for (const rec of report.recommendations.slice(0, 5)) {
      const priorityLabel = rec.priority.toUpperCase();
      lines.push(`  [${priorityLabel}] ${rec.title}`);
    }
    lines.push('');
  }

  lines.push(`Compliance: ${statistics.compliancePercentage}%`);

  return lines.join('\n');
}
