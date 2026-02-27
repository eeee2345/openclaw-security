/**
 * Detailed findings list renderer for the PDF security report
 * PDF 安全報告的詳細發現清單渲染器
 *
 * Renders each security finding with severity badge, description,
 * remediation advice, and compliance references. Handles page breaks
 * automatically when content approaches the page bottom margin.
 * 渲染每個安全發現，包含嚴重度標記、描述、修復建議和合規參照。
 * 當內容接近頁面底部邊距時自動處理分頁。
 *
 * @module @panguard-ai/panguard-scan/report/sections/findings-table
 */

import type { Language } from '@panguard-ai/core';
import type { Finding, ScanResult } from '../../scanners/types.js';
import { sortBySeverity } from '../../scanners/types.js';
import { COLORS, FONTS, LAYOUT, severityColor } from '../styles.js';

/**
 * Estimated height in points for a single finding entry.
 * Used to decide whether a page break is needed before rendering.
 * 單一發現條目的估計高度（點），用於在渲染前判斷是否需要分頁。
 */
const ESTIMATED_FINDING_HEIGHT = 120;

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
 * Render a single finding entry
 * 渲染單一發現條目
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @param finding - Security finding to render / 要渲染的安全發現
 * @param lang - Output language / 輸出語言
 */
function renderFinding(doc: PDFKit.PDFDocument, finding: Finding, lang: Language): void {
  const isZh = lang === 'zh-TW';

  ensureSpace(doc, ESTIMATED_FINDING_HEIGHT);

  const startY = doc.y;
  const badgeColor = severityColor(finding.severity);

  // -- Severity badge (small colored rectangle with text) --
  const badgeWidth = 60;
  const badgeHeight = 14;

  doc.rect(LAYOUT.margin, startY, badgeWidth, badgeHeight).fill(badgeColor);

  doc
    .font(FONTS.heading)
    .fontSize(8)
    .fillColor(COLORS.white)
    .text(finding.severity.toUpperCase(), LAYOUT.margin + 4, startY + 2, { width: badgeWidth - 8 });

  // -- Finding title --
  doc
    .font(FONTS.heading)
    .fontSize(11)
    .fillColor(COLORS.text)
    .text(finding.title, LAYOUT.margin + badgeWidth + 8, startY, {
      width: LAYOUT.contentWidth - badgeWidth - 8,
    });

  doc.moveDown(0.4);

  // -- Description --
  doc
    .font(FONTS.body)
    .fontSize(9)
    .fillColor(COLORS.text)
    .text(finding.description, LAYOUT.margin + 10, doc.y, {
      width: LAYOUT.contentWidth - 20,
      lineGap: 2,
    });

  doc.moveDown(0.4);

  // -- Remediation --
  const remediationLabel = isZh ? '修復建議:' : 'Remediation:';
  doc
    .font(FONTS.heading)
    .fontSize(9)
    .fillColor(COLORS.accent)
    .text(remediationLabel, LAYOUT.margin + 10, doc.y, { continued: true });

  doc
    .font(FONTS.body)
    .fontSize(9)
    .fillColor(COLORS.text)
    .text(` ${finding.remediation}`, {
      width: LAYOUT.contentWidth - 20,
      lineGap: 2,
    });

  // -- Details (if present, smaller font) --
  if (finding.details) {
    doc.moveDown(0.3);
    doc
      .font(FONTS.mono)
      .fontSize(7)
      .fillColor(COLORS.lightText)
      .text(finding.details, LAYOUT.margin + 10, doc.y, {
        width: LAYOUT.contentWidth - 20,
        lineGap: 1,
      });
  }

  // -- Compliance reference (if present) --
  if (finding.complianceRef) {
    doc.moveDown(0.2);
    const complianceLabel = isZh ? '合規參照:' : 'Compliance Ref:';
    doc
      .font(FONTS.body)
      .fontSize(8)
      .fillColor(COLORS.lightText)
      .text(`${complianceLabel} ${finding.complianceRef}`, LAYOUT.margin + 10, doc.y, {
        width: LAYOUT.contentWidth - 20,
      });
  }

  // -- Separator line --
  doc.moveDown(0.6);
  doc
    .strokeColor(COLORS.border)
    .lineWidth(0.5)
    .moveTo(LAYOUT.margin + 10, doc.y)
    .lineTo(LAYOUT.pageWidth - LAYOUT.margin - 10, doc.y)
    .stroke();

  doc.moveDown(0.6);
}

/**
 * Render the detailed findings list section of the PDF report
 * 渲染 PDF 報告的詳細發現清單區段
 *
 * Findings are sorted by severity (most severe first). If there are
 * no findings, a message indicating no significant issues is displayed.
 * 發現按嚴重度排序（最嚴重的在前）。如果沒有發現，則顯示未發現重大問題的訊息。
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @param result - Complete scan result / 完整掃描結果
 * @param lang - Output language / 輸出語言
 */
export function renderFindingsTable(
  doc: PDFKit.PDFDocument,
  result: ScanResult,
  lang: Language
): void {
  const isZh = lang === 'zh-TW';

  // -- Section title --
  const sectionTitle = isZh ? '詳細發現' : 'Detailed Findings';
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

  // Finding count summary
  const countText = isZh
    ? `共發現 ${result.findings.length} 項安全問題`
    : `Total findings: ${result.findings.length}`;

  doc
    .font(FONTS.body)
    .fontSize(10)
    .fillColor(COLORS.lightText)
    .text(countText, LAYOUT.margin, doc.y);

  doc.moveDown(1);

  // -- Render findings or empty message --
  if (result.findings.length === 0) {
    const noIssuesText = isZh
      ? '未發現重大安全問題。系統整體安全態勢良好。'
      : 'No significant security issues found. The system security posture is healthy.';

    doc
      .font(FONTS.body)
      .fontSize(12)
      .fillColor(COLORS.low)
      .text(noIssuesText, LAYOUT.margin + 20, doc.y, {
        width: LAYOUT.contentWidth - 40,
      });
  } else {
    const sortedFindings: Finding[] = [...result.findings].sort(sortBySeverity);

    for (const finding of sortedFindings) {
      renderFinding(doc, finding, lang);
    }
  }
}
