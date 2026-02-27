/**
 * Compliance Mapping Engine
 * 合規映射引擎
 *
 * Maps security findings to compliance controls and evaluates status.
 * 將資安發現映射到合規控制項並評估狀態。
 *
 * @module @panguard-ai/panguard-report/mapper/compliance-mapper
 */

import { createLogger } from '@panguard-ai/core';
import type {
  ComplianceControl,
  ComplianceFinding,
  EvaluatedControl,
  ControlStatus,
  ExecutiveSummary,
  ComplianceStatistics,
  ReportRecommendation,
} from '../types.js';

const logger = createLogger('panguard-report:mapper');

/** Relevance score threshold: findings must score at least this to be mapped */
const RELEVANCE_THRESHOLD = 5;

/**
 * Calculate a relevance score between a finding and a control.
 * Multi-signal scoring replaces the previous `.includes()` approach.
 *
 * Signals:
 * - Exact category match: 10 points
 * - Partial category match (substring): 3 points
 * - Control description keyword match: 2 points
 * - CVE finding + vulnerability_management control: 5 points
 */
function calculateRelevance(control: ComplianceControl, finding: ComplianceFinding): number {
  let score = 0;
  const findingCatLower = finding.category.toLowerCase();

  for (const cat of control.relatedCategories) {
    const catLower = cat.toLowerCase();
    if (findingCatLower === catLower) {
      score += 10; // Exact match
    } else if (findingCatLower.includes(catLower) || catLower.includes(findingCatLower)) {
      score += 3; // Partial match
    }
  }

  // Check control description keywords against finding title/description
  const controlKeywords = extractKeywords(control.descriptionEn);
  const findingText = `${finding.title} ${finding.description}`.toLowerCase();
  for (const keyword of controlKeywords) {
    if (findingText.includes(keyword)) {
      score += 2;
      break; // Only count once to avoid over-scoring
    }
  }

  // CVE findings + vulnerability management controls get a boost
  if (
    finding.findingId.startsWith('CVE-') &&
    control.relatedCategories.some(
      (c) => c.toLowerCase().includes('vulnerability') || c.toLowerCase().includes('patch')
    )
  ) {
    score += 5;
  }

  return score;
}

/** Extract meaningful keywords from a description (>3 chars, lowercase) */
function extractKeywords(text: string): string[] {
  const stopWords = new Set([
    'the',
    'and',
    'for',
    'are',
    'this',
    'that',
    'with',
    'from',
    'shall',
    'should',
    'must',
    'have',
    'been',
    'will',
  ]);
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 3 && !stopWords.has(w))
    .slice(0, 10); // Limit to avoid excessive processing
}

/**
 * Map findings to compliance controls and evaluate each control's status.
 * Uses multi-signal relevance scoring instead of simple substring matching.
 */
export function evaluateControls(
  controls: ComplianceControl[],
  findings: ComplianceFinding[]
): EvaluatedControl[] {
  return controls.map((control) => {
    // Find related findings using relevance scoring
    const relatedFindings = findings.filter(
      (finding) => calculateRelevance(control, finding) >= RELEVANCE_THRESHOLD
    );

    // Determine status
    const status = determineControlStatus(relatedFindings);

    // Build evidence
    const evidence = buildEvidence(control, relatedFindings, status);

    // Build remediation
    const remediation =
      status === 'fail' || status === 'partial'
        ? buildRemediation(control, relatedFindings)
        : undefined;

    return {
      ...control,
      status,
      evidence,
      relatedFindings,
      remediation,
    };
  });
}

/**
 * Determine control status based on related findings
 * 根據相關發現判定控制項狀態
 */
function determineControlStatus(findings: ComplianceFinding[]): ControlStatus {
  if (findings.length === 0) {
    return 'pass'; // No findings = compliant
  }

  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasHigh = findings.some((f) => f.severity === 'high');
  const hasMedium = findings.some((f) => f.severity === 'medium');

  if (hasCritical || hasHigh) {
    return 'fail';
  }
  if (hasMedium) {
    return 'partial';
  }
  return 'pass'; // Only low/info findings
}

/**
 * Build evidence strings for a control evaluation.
 * Provides specific, descriptive evidence instead of generic placeholders.
 * 為控制項評估建構證據字串。提供具體描述性證據而非通用佔位符。
 */
function buildEvidence(
  control: ComplianceControl,
  findings: ComplianceFinding[],
  status: ControlStatus
): string[] {
  const evidence: string[] = [];

  if (status === 'pass') {
    // Describe what was actually checked rather than a generic "no findings"
    evidence.push(
      `Automated scan of ${control.relatedCategories.join(', ')} controls completed. ` +
        `No issues detected for ${control.controlId} (${control.titleEn}).`
    );
    evidence.push(
      `自動掃描 ${control.relatedCategories.join('、')} 控制項完成。` +
        `${control.controlId}（${control.titleZh}）未偵測到問題。`
    );
  } else {
    evidence.push(
      `${findings.length} finding(s) detected related to ${control.controlId} (${control.titleEn}):`
    );
    evidence.push(
      `偵測到 ${findings.length} 個與 ${control.controlId}（${control.titleZh}）相關的發現：`
    );
    for (const finding of findings) {
      evidence.push(
        `  [${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`
      );
    }
  }

  return evidence;
}

/**
 * Build remediation suggestion
 * 建構修復建議
 */
function buildRemediation(control: ComplianceControl, findings: ComplianceFinding[]): string {
  const criticalCount = findings.filter(
    (f) => f.severity === 'critical' || f.severity === 'high'
  ).length;
  const prefix = criticalCount > 0 ? 'URGENT / 緊急: ' : '';
  return (
    `${prefix}Address ${findings.length} finding(s) related to ${control.titleEn} (${control.controlId}). ` +
    `處理與 ${control.titleZh}（${control.controlId}）相關的 ${findings.length} 個發現。`
  );
}

/**
 * Generate executive summary from evaluated controls
 * 從已評估的控制項產生執行摘要
 */
export function generateExecutiveSummary(
  controls: EvaluatedControl[],
  findings: ComplianceFinding[],
  language: 'zh-TW' | 'en'
): ExecutiveSummary {
  const passed = controls.filter((c) => c.status === 'pass').length;
  const failed = controls.filter((c) => c.status === 'fail').length;
  const partial = controls.filter((c) => c.status === 'partial').length;
  const na = controls.filter((c) => c.status === 'not_applicable').length;
  const applicable = controls.length - na;
  const score = applicable > 0 ? Math.round(((passed + partial * 0.5) / applicable) * 100) : 100;

  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;

  // Key risks
  const keyRisks: string[] = [];
  const failedControls = controls.filter((c) => c.status === 'fail');
  for (const c of failedControls.slice(0, 3)) {
    keyRisks.push(language === 'zh-TW' ? c.titleZh : c.titleEn);
  }

  // Key achievements
  const keyAchievements: string[] = [];
  if (passed > 0) {
    keyAchievements.push(
      language === 'zh-TW' ? `${passed} 個控制項完全符合` : `${passed} controls fully compliant`
    );
  }
  if (critical === 0) {
    keyAchievements.push(language === 'zh-TW' ? '無嚴重等級發現' : 'No critical findings');
  }

  logger.info(`Executive summary generated: score=${score}% / 執行摘要已產生: 分數=${score}%`);

  return {
    overallScore: score,
    totalControls: controls.length,
    controlsPassed: passed,
    controlsFailed: failed,
    controlsPartial: partial,
    controlsNA: na,
    totalFindings: findings.length,
    criticalFindings: critical,
    highFindings: high,
    keyRisks,
    keyAchievements,
  };
}

/**
 * Generate compliance statistics
 * 產生合規統計
 */
export function generateStatistics(
  controls: EvaluatedControl[],
  findings: ComplianceFinding[]
): ComplianceStatistics {
  const byStatus: Record<ControlStatus, number> = {
    pass: 0,
    fail: 0,
    partial: 0,
    not_applicable: 0,
  };

  const byCategory: Record<string, { total: number; passed: number; failed: number }> = {};

  for (const control of controls) {
    byStatus[control.status]++;

    if (!byCategory[control.category]) {
      byCategory[control.category] = { total: 0, passed: 0, failed: 0 };
    }
    byCategory[control.category]!.total++;
    if (control.status === 'pass') byCategory[control.category]!.passed++;
    if (control.status === 'fail') byCategory[control.category]!.failed++;
  }

  const findingsBySeverity: Record<string, number> = {};
  for (const finding of findings) {
    findingsBySeverity[finding.severity] = (findingsBySeverity[finding.severity] ?? 0) + 1;
  }

  const applicable = controls.length - byStatus.not_applicable;
  const compliancePercentage =
    applicable > 0
      ? Math.round(((byStatus.pass + byStatus.partial * 0.5) / applicable) * 100)
      : 100;

  return {
    byStatus,
    byCategory,
    findingsBySeverity,
    compliancePercentage,
  };
}

/**
 * Generate recommendations from evaluated controls
 * 從已評估的控制項產生建議
 */
export function generateRecommendations(
  controls: EvaluatedControl[],
  language: 'zh-TW' | 'en'
): ReportRecommendation[] {
  const recommendations: ReportRecommendation[] = [];

  // Sort by severity: fail first, then partial
  const actionableControls = controls
    .filter((c) => c.status === 'fail' || c.status === 'partial')
    .sort((a, b) => {
      if (a.status === 'fail' && b.status !== 'fail') return -1;
      if (a.status !== 'fail' && b.status === 'fail') return 1;
      return 0;
    });

  for (const control of actionableControls) {
    const hasCritical = control.relatedFindings.some(
      (f) => f.severity === 'critical' || f.severity === 'high'
    );

    recommendations.push({
      priority: hasCritical ? 'immediate' : control.status === 'fail' ? 'high' : 'medium',
      title: language === 'zh-TW' ? control.titleZh : control.titleEn,
      description:
        control.remediation ??
        (language === 'zh-TW'
          ? `處理與 ${control.controlId} 相關的 ${control.relatedFindings.length} 個發現`
          : `Address ${control.relatedFindings.length} finding(s) related to ${control.controlId}`),
      relatedControlIds: [control.controlId],
      estimatedEffort: hasCritical ? '1-3 days' : '1-2 weeks',
    });
  }

  return recommendations;
}
