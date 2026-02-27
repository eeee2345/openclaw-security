/**
 * Compliance mapping table renderer for the PDF security report
 * PDF 安全報告的合規對照表渲染器
 *
 * Renders the Taiwan ISMS (Information Security Management System)
 * compliance mapping table with status indicators and related findings.
 * 渲染台灣資通安全管理法（ISMS）合規對照表，包含狀態指標和相關發現。
 *
 * @module @panguard-ai/panguard-scan/report/sections/compliance
 */

import type { Language } from '@panguard-ai/core';
import type { ScanResult } from '../../scanners/types.js';
import { COLORS, FONTS, LAYOUT } from '../styles.js';
import { mapFindingsToCompliance } from '../compliance-map.js';
import type { ComplianceStatus } from '../compliance-map.js';

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
 * Return the display color for a compliance status
 * 回傳合規狀態的顯示顏色
 *
 * @param status - Compliance status / 合規狀態
 * @returns Hex color string / 十六進位顏色字串
 */
function statusColor(status: ComplianceStatus['status']): string {
  switch (status) {
    case 'compliant':
      return COLORS.low; // green
    case 'non_compliant':
      return COLORS.critical; // red
    case 'partial':
      return COLORS.medium; // orange
    case 'not_applicable':
      return COLORS.lightText; // gray
    default:
      return COLORS.lightText;
  }
}

/**
 * Return the display text for a compliance status
 * 回傳合規狀態的顯示文字
 *
 * @param status - Compliance status / 合規狀態
 * @param isZh - Whether output is Traditional Chinese / 是否為繁體中文輸出
 * @returns Status display text / 狀態顯示文字
 */
function statusText(status: ComplianceStatus['status'], isZh: boolean): string {
  switch (status) {
    case 'compliant':
      return isZh ? '合規' : 'Compliant';
    case 'non_compliant':
      return isZh ? '不合規' : 'Non-Compliant';
    case 'partial':
      return isZh ? '部分合規' : 'Partial';
    case 'not_applicable':
      return isZh ? '不適用' : 'N/A';
    default:
      return isZh ? '未知' : 'Unknown';
  }
}

/**
 * Render the compliance mapping table section of the PDF report
 * 渲染 PDF 報告的合規對照表區段
 *
 * Displays a table mapping each Taiwan ISMS article to its compliance
 * status based on scan findings. Each row shows the article reference,
 * title, status (with color coding), and the number of related findings.
 * 顯示將每個台灣資通安全管理法條文對應到其合規狀態的表格（基於掃描發現）。
 * 每行顯示條文參照、標題、狀態（帶顏色編碼）和相關發現數量。
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @param result - Complete scan result / 完整掃描結果
 * @param lang - Output language / 輸出語言
 */
export function renderCompliance(
  doc: PDFKit.PDFDocument,
  result: ScanResult,
  lang: Language
): void {
  const isZh = lang === 'zh-TW';

  // -- Section title --
  const sectionTitle = isZh ? '台灣資通安全管理法合規對照' : 'Taiwan ISMS Compliance Mapping';

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

  // Introductory text
  const introText = isZh
    ? '以下表格將掃描發現對應到台灣資通安全管理法的相關條文，以評估系統的合規狀態。'
    : 'The following table maps scan findings to relevant articles of the Taiwan Information Security Management Act to assess system compliance status.';

  doc.font(FONTS.body).fontSize(9).fillColor(COLORS.text).text(introText, LAYOUT.margin, doc.y, {
    width: LAYOUT.contentWidth,
    lineGap: 2,
  });

  doc.moveDown(1);

  // -- Get compliance data --
  const complianceStatuses = mapFindingsToCompliance(result.findings);

  // -- Table header --
  const tableStartY = doc.y;
  const rowHeight = 24;
  const col1X = LAYOUT.margin; // Ref
  const col2X = LAYOUT.margin + 40; // Article title
  const col3X = LAYOUT.margin + 240; // Status
  const col4X = LAYOUT.margin + 340; // Related Findings
  const tableWidth = LAYOUT.contentWidth;

  // Header row background
  doc.rect(col1X, tableStartY, tableWidth, rowHeight).fillOpacity(0.08).fill(COLORS.primary);

  doc.fillOpacity(1);

  // Header labels
  doc.font(FONTS.heading).fontSize(8).fillColor(COLORS.primary);

  doc.text(isZh ? '編號' : 'Ref', col1X + 4, tableStartY + 7);
  doc.text(isZh ? '條文' : 'Article', col2X + 4, tableStartY + 7);
  doc.text(isZh ? '狀態' : 'Status', col3X + 4, tableStartY + 7);
  doc.text(isZh ? '相關發現' : 'Findings', col4X + 4, tableStartY + 7);

  // -- Table rows --
  let currentY = tableStartY + rowHeight;

  complianceStatuses.forEach((entry, index) => {
    ensureSpace(doc, rowHeight + 4);

    // If we had a page break, update currentY
    if (doc.y < currentY) {
      currentY = doc.y;
    }

    // Alternating row background
    if (index % 2 === 0) {
      doc.rect(col1X, currentY, tableWidth, rowHeight).fillOpacity(0.03).fill(COLORS.secondary);
      doc.fillOpacity(1);
    }

    // Reference number
    doc
      .font(FONTS.mono)
      .fontSize(8)
      .fillColor(COLORS.text)
      .text(entry.ref, col1X + 4, currentY + 7, { width: 32 });

    // Article title
    const title = isZh ? entry.titleZh : entry.titleEn;
    doc
      .font(FONTS.body)
      .fontSize(8)
      .fillColor(COLORS.text)
      .text(title, col2X + 4, currentY + 7, { width: 190 });

    // Status with color
    const sColor = statusColor(entry.status);
    const sText = statusText(entry.status, isZh);
    doc
      .font(FONTS.heading)
      .fontSize(8)
      .fillColor(sColor)
      .text(sText, col3X + 4, currentY + 7, { width: 90 });

    // Related findings count
    const findingsCount = entry.relatedFindings.length;
    const findingsText = findingsCount > 0 ? String(findingsCount) : '-';
    doc
      .font(FONTS.body)
      .fontSize(8)
      .fillColor(findingsCount > 0 ? COLORS.text : COLORS.lightText)
      .text(findingsText, col4X + 4, currentY + 7, { width: 60 });

    currentY += rowHeight;
  });

  // Update doc.y to after the table
  doc.y = currentY;
  doc.moveDown(1);

  // -- Legend --
  ensureSpace(doc, 60);

  const legendTitle = isZh ? '狀態說明' : 'Status Legend';
  doc
    .font(FONTS.heading)
    .fontSize(10)
    .fillColor(COLORS.secondary)
    .text(legendTitle, LAYOUT.margin, doc.y);

  doc.moveDown(0.4);

  const legendItems: Array<{ status: ComplianceStatus['status']; descEn: string; descZh: string }> =
    [
      {
        status: 'compliant',
        descEn: 'Compliant - No issues found for this area',
        descZh: '合規 - 此領域未發現問題',
      },
      {
        status: 'non_compliant',
        descEn: 'Non-Compliant - Critical or high severity issues detected',
        descZh: '不合規 - 偵測到嚴重或高嚴重度的問題',
      },
      {
        status: 'partial',
        descEn: 'Partial - Medium or low severity issues detected',
        descZh: '部分合規 - 偵測到中等或低嚴重度的問題',
      },
      {
        status: 'not_applicable',
        descEn: 'N/A - Not covered by this scan',
        descZh: '不適用 - 本次掃描未涵蓋',
      },
    ];

  for (const item of legendItems) {
    const color = statusColor(item.status);
    const text = isZh ? item.descZh : item.descEn;

    // Small colored dot
    doc.circle(LAYOUT.margin + 14, doc.y + 5, 4).fill(color);

    doc
      .font(FONTS.body)
      .fontSize(8)
      .fillColor(COLORS.text)
      .text(text, LAYOUT.margin + 24, doc.y - 5, {
        width: LAYOUT.contentWidth - 30,
      });

    doc.moveDown(0.3);
  }
}
