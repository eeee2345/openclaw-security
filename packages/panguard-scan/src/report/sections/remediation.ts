/**
 * Remediation recommendations section renderer for the PDF security report
 * PDF 安全報告的修復建議區段渲染器
 *
 * Groups findings by priority and presents numbered remediation steps.
 * De-duplicates similar remediation recommendations within each group.
 * 按優先級分組發現並呈現編號的修復步驟。在每個分組中去除重複的修復建議。
 *
 * @module @panguard-ai/panguard-scan/report/sections/remediation
 */

import type { Language, Severity } from '@panguard-ai/core';
import type { Finding, ScanResult } from '../../scanners/types.js';
import { sortBySeverity } from '../../scanners/types.js';
import { COLORS, FONTS, LAYOUT } from '../styles.js';

/**
 * Maximum y-coordinate before forcing a page break
 * 強制分頁前的最大 y 座標
 */
const PAGE_BREAK_THRESHOLD = LAYOUT.pageHeight - LAYOUT.margin - LAYOUT.footerHeight - 40;

/**
 * Check if there is enough space on the current page and add a new
 * page if not.
 * 檢查當前頁面是否有足夠空間，若不足則新增頁面。
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @param requiredHeight - Minimum remaining height needed / 所需最小剩餘高度
 */
function ensureSpace(doc: PDFKit.PDFDocument, requiredHeight: number): void {
  if (doc.y + requiredHeight > PAGE_BREAK_THRESHOLD) {
    doc.addPage();
    doc.y = LAYOUT.margin;
  }
}

/**
 * Priority group definition for organizing findings
 * 優先級分組定義，用於組織發現
 */
interface PriorityGroup {
  /**
   * Group header text in English
   * 分組標題文字（英文）
   */
  headerEn: string;

  /**
   * Group header text in Traditional Chinese
   * 分組標題文字（繁體中文）
   */
  headerZh: string;

  /**
   * Severity levels included in this group
   * 此分組中包含的嚴重等級
   */
  severities: Severity[];

  /**
   * Color for the group header
   * 分組標題的顏色
   */
  color: string;
}

/**
 * Priority groups ordered by urgency
 * 按緊急程度排序的優先級分組
 */
const PRIORITY_GROUPS: PriorityGroup[] = [
  {
    headerEn: 'Immediate Action Required',
    headerZh: '需立即處理',
    severities: ['critical', 'high'],
    color: COLORS.critical,
  },
  {
    headerEn: 'Should Be Addressed Soon',
    headerZh: '應盡快處理',
    severities: ['medium'],
    color: COLORS.medium,
  },
  {
    headerEn: 'Recommended Improvements',
    headerZh: '建議改善項目',
    severities: ['low', 'info'],
    color: COLORS.low,
  },
];

/**
 * De-duplicate remediation strings, keeping unique entries only.
 * Comparison is case-insensitive and ignores leading/trailing whitespace.
 * 去除重複的修復建議字串，僅保留唯一條目。
 * 比較時不區分大小寫，且忽略前後空白。
 *
 * @param findings - Array of findings / 發現陣列
 * @returns Array of unique remediation strings / 唯一修復建議字串陣列
 */
function deduplicateRemediations(findings: Finding[]): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];

  for (const finding of findings) {
    const normalized = finding.remediation.trim().toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      unique.push(finding.remediation.trim());
    }
  }

  return unique;
}

/**
 * Render the remediation recommendations section of the PDF report
 * 渲染 PDF 報告的修復建議區段
 *
 * Findings are grouped into three priority tiers: critical+high,
 * medium, and low+info. Within each group, remediation steps are
 * de-duplicated and numbered sequentially.
 * 發現被分為三個優先級層：嚴重+高、中等和低+資訊。在每個分組中，
 * 修復步驟會去除重複並按順序編號。
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @param result - Complete scan result / 完整掃描結果
 * @param lang - Output language / 輸出語言
 */
export function renderRemediation(
  doc: PDFKit.PDFDocument,
  result: ScanResult,
  lang: Language
): void {
  const isZh = lang === 'zh-TW';

  // -- Section title --
  const sectionTitle = isZh ? '修復建議' : 'Remediation Recommendations';
  doc
    .font(FONTS.heading)
    .fontSize(18)
    .fillColor(COLORS.primary)
    .text(sectionTitle, LAYOUT.margin, LAYOUT.margin);

  // Underline
  doc
    .strokeColor(COLORS.accent)
    .lineWidth(1)
    .moveTo(LAYOUT.margin, doc.y + 4)
    .lineTo(LAYOUT.margin + LAYOUT.contentWidth, doc.y + 4)
    .stroke();

  doc.moveDown(1);

  if (result.findings.length === 0) {
    const noIssuesText = isZh
      ? '未發現需要修復的安全問題。'
      : 'No security issues requiring remediation were found.';

    doc
      .font(FONTS.body)
      .fontSize(11)
      .fillColor(COLORS.low)
      .text(noIssuesText, LAYOUT.margin, doc.y, {
        width: LAYOUT.contentWidth,
      });
    return;
  }

  const sortedFindings = [...result.findings].sort(sortBySeverity);

  for (const group of PRIORITY_GROUPS) {
    const groupFindings = sortedFindings.filter((f) => group.severities.includes(f.severity));

    if (groupFindings.length === 0) {
      continue;
    }

    ensureSpace(doc, 60);

    // -- Group header --
    const header = isZh ? group.headerZh : group.headerEn;

    doc.rect(LAYOUT.margin, doc.y, LAYOUT.contentWidth, 22).fillOpacity(0.08).fill(group.color);

    doc.fillOpacity(1);

    doc
      .font(FONTS.heading)
      .fontSize(12)
      .fillColor(group.color)
      .text(header, LAYOUT.margin + 10, doc.y - 16, {
        width: LAYOUT.contentWidth - 20,
      });

    doc.moveDown(0.8);

    // -- Numbered remediation steps --
    const remediations = deduplicateRemediations(groupFindings);

    remediations.forEach((remediation, index) => {
      ensureSpace(doc, 30);

      doc
        .font(FONTS.body)
        .fontSize(9)
        .fillColor(COLORS.text)
        .text(`${index + 1}. ${remediation}`, LAYOUT.margin + 20, doc.y, {
          width: LAYOUT.contentWidth - 40,
          lineGap: 2,
        });

      doc.moveDown(0.4);
    });

    doc.moveDown(0.8);
  }
}
