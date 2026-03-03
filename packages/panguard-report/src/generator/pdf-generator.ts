/**
 * Compliance Report PDF Generator
 * 合規報告 PDF 產生器
 *
 * Generates professional PDF compliance reports with CJK font support,
 * cover page, executive summary, findings table, compliance matrix,
 * and page footers with confidential watermark.
 *
 * 產生具有 CJK 字型支援的專業 PDF 合規報告，包含封面頁、執行摘要、
 * 發現列表、合規矩陣，以及帶有機密浮水印的頁尾。
 *
 * @module @panguard-ai/panguard-report/generator/pdf-generator
 */

import PDFDocument from 'pdfkit';
import { createWriteStream } from 'node:fs';
import { access, constants, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type {
  ComplianceFinding,
  ComplianceReportData,
  EvaluatedControl,
  ReportLanguage,
} from '../types.js';
import { getFrameworkName, getFrameworkControls } from '../frameworks/index.js';
import {
  evaluateControls,
  generateExecutiveSummary,
  generateStatistics,
  generateRecommendations,
} from '../mapper/index.js';
import { getSectionLabels, getSeverityLabel, getStatusLabel } from '../templates/index.js';

const logger = createLogger('panguard-report:pdf');

// ---------------------------------------------------------------------------
// Layout & Style Constants
// 版面配置與樣式常數
// ---------------------------------------------------------------------------

/** Color palette for severity badges and layout / 嚴重度標記與版面配置的色彩配置 */
const COLORS = {
  primary: '#1a365d',
  secondary: '#2d3748',
  accent: '#3182ce',
  critical: '#c53030',
  high: '#c05621',
  medium: '#b7791f',
  low: '#2b6cb0',
  info: '#718096',
  pass: '#276749',
  fail: '#c53030',
  partial: '#b7791f',
  background: '#f7fafc',
  white: '#ffffff',
  text: '#2d3748',
  lightText: '#718096',
  border: '#e2e8f0',
  watermark: '#e2e8f0',
} as const;

/** Font families / 字型家族 */
const FONTS = {
  heading: 'Helvetica-Bold',
  body: 'Helvetica',
  mono: 'Courier',
} as const;

/** A4 page layout dimensions in points / A4 頁面版面尺寸（點） */
const LAYOUT = {
  pageWidth: 595.28,
  pageHeight: 841.89,
  margin: 50,
  contentWidth: 495.28,
  headerHeight: 30,
  footerHeight: 20,
} as const;

// ---------------------------------------------------------------------------
// PDF Report Options
// PDF 報告選項
// ---------------------------------------------------------------------------

/** Options for PDF report generation / PDF 報告產生選項 */
export interface PDFReportOptions {
  /** Report title / 報告標題 */
  title: string;
  /** Compliance framework identifier / 合規框架識別碼 */
  framework: string;
  /** Output language / 輸出語言 */
  lang: 'zh-TW' | 'en';
  /** Output file path / 輸出檔案路徑 */
  outputPath: string;
  /** Compliance findings / 合規發現 */
  findings: ComplianceFinding[];
  /** Pre-computed assessment result (optional) / 預先計算的評估結果（選用） */
  assessmentResult?: ComplianceReportData;
  /** Report generation timestamp / 報告產生時間戳 */
  generatedAt?: string;
  /** Organization name / 組織名稱 */
  organizationName?: string;
  /** Disable PDF stream compression (useful for testing) / 停用 PDF 壓縮（測試用） */
  compress?: boolean;
}

// ---------------------------------------------------------------------------
// CJK Font Detection
// CJK 字型偵測
// ---------------------------------------------------------------------------

/**
 * CJK font search paths per platform
 * 各平台的 CJK 字型搜尋路徑
 */
const CJK_FONT_PATHS: Record<string, Array<{ path: string; family?: string }>> = {
  darwin: [
    { path: '/System/Library/Fonts/STHeiti Light.ttc', family: 'STHeitiTC-Light' },
    { path: '/System/Library/Fonts/PingFang.ttc', family: 'PingFangTC-Regular' },
  ],
  linux: [
    {
      path: '/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc',
      family: 'Noto Sans CJK TC',
    },
    {
      path: '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc',
      family: 'Noto Sans CJK TC',
    },
  ],
};

/**
 * Check if a file exists at the given path
 * 檢查指定路徑是否存在檔案
 */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Attempt to detect and register a CJK font for Chinese text rendering
 * 嘗試偵測並註冊 CJK 字型以進行中文文字渲染
 */
export async function registerCjkFont(doc: PDFKit.PDFDocument): Promise<boolean> {
  const platform = process.platform;
  const candidates = CJK_FONT_PATHS[platform];

  if (!candidates || candidates.length === 0) {
    logger.warn('No CJK font candidates for this platform', { platform });
    return false;
  }

  for (const candidate of candidates) {
    const exists = await fileExists(candidate.path);
    if (exists) {
      try {
        if (candidate.family) {
          doc.registerFont('CJK', candidate.path, candidate.family);
        } else {
          doc.registerFont('CJK', candidate.path);
        }
        // Verify the font can actually be used by switching to it
        // Some TTC files may register but fail on use
        doc.font('CJK');
        // Reset to default font
        doc.font(FONTS.body);
        logger.info('CJK font registered and verified successfully', { path: candidate.path });
        return true;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn('Failed to register or verify CJK font', {
          path: candidate.path,
          error: message,
        });
      }
    }
  }

  logger.warn(
    'No CJK font found on this system. Chinese characters may not render correctly.',
    { platform }
  );
  return false;
}

// ---------------------------------------------------------------------------
// Helper: Severity Color
// 輔助: 嚴重度顏色
// ---------------------------------------------------------------------------

/**
 * Return the color associated with a given severity level
 * 根據給定的嚴重等級回傳對應的顏色
 */
function severityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return COLORS.critical;
    case 'high':
      return COLORS.high;
    case 'medium':
      return COLORS.medium;
    case 'low':
      return COLORS.low;
    case 'info':
      return COLORS.info;
    default:
      return COLORS.lightText;
  }
}

/**
 * Return the color associated with a control status
 * 根據控制項狀態回傳對應的顏色
 */
function statusColor(status: string): string {
  switch (status) {
    case 'pass':
      return COLORS.pass;
    case 'fail':
      return COLORS.fail;
    case 'partial':
      return COLORS.partial;
    default:
      return COLORS.lightText;
  }
}

// ---------------------------------------------------------------------------
// Helper: Font selection for CJK
// 輔助: CJK 字型選擇
// ---------------------------------------------------------------------------

/**
 * Select the appropriate font based on CJK availability and style
 * 根據 CJK 可用性與樣式選擇適當字型
 */
function selectFont(hasCjk: boolean, style: 'heading' | 'body' | 'mono'): string {
  if (hasCjk && style !== 'mono') {
    return 'CJK';
  }
  return FONTS[style];
}

// ---------------------------------------------------------------------------
// Helper: Check remaining page space
// 輔助: 檢查頁面剩餘空間
// ---------------------------------------------------------------------------

/**
 * Check if there is enough vertical space remaining on the current page.
 * If not, add a new page and return the new Y position.
 * 檢查目前頁面是否有足夠的垂直空間，如果不夠則新增頁面並回傳新的 Y 位置。
 */
function ensureSpace(
  doc: PDFKit.PDFDocument,
  currentY: number,
  requiredHeight: number
): number {
  const maxY = LAYOUT.pageHeight - LAYOUT.margin - LAYOUT.footerHeight - 10;
  if (currentY + requiredHeight > maxY) {
    doc.addPage();
    return LAYOUT.margin;
  }
  return currentY;
}

// ---------------------------------------------------------------------------
// Section 1: Cover Page
// 區段 1: 封面頁
// ---------------------------------------------------------------------------

/**
 * Render the cover page
 * 渲染封面頁
 */
function renderCoverPage(
  doc: PDFKit.PDFDocument,
  options: PDFReportOptions,
  hasCjk: boolean
): void {
  const isZh = options.lang === 'zh-TW';
  const font = selectFont(hasCjk, 'body');
  const headingFont = selectFont(hasCjk, 'heading');

  // Background accent bar at top
  doc.rect(0, 0, LAYOUT.pageWidth, 6).fill(COLORS.primary);

  // Title
  const titleY = 200;
  doc
    .font(headingFont)
    .fontSize(28)
    .fillColor(COLORS.primary)
    .text(options.title, LAYOUT.margin, titleY, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  // Framework name
  const frameworkName = getFrameworkName(
    options.framework as 'tw_cyber_security_act' | 'iso27001' | 'soc2',
    options.lang
  );
  doc
    .font(font)
    .fontSize(16)
    .fillColor(COLORS.secondary)
    .text(frameworkName, LAYOUT.margin, titleY + 50, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  // Separator line
  const sepY = titleY + 90;
  doc
    .strokeColor(COLORS.accent)
    .lineWidth(2)
    .moveTo(LAYOUT.pageWidth / 2 - 80, sepY)
    .lineTo(LAYOUT.pageWidth / 2 + 80, sepY)
    .stroke();

  // Date
  const dateStr = options.generatedAt ?? new Date().toISOString().split('T')[0];
  const dateLabel = isZh ? `產生日期: ${dateStr}` : `Generated: ${dateStr}`;
  doc
    .font(font)
    .fontSize(12)
    .fillColor(COLORS.lightText)
    .text(dateLabel, LAYOUT.margin, sepY + 20, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  // Organization name
  if (options.organizationName) {
    const orgLabel = isZh
      ? `組織: ${options.organizationName}`
      : `Organization: ${options.organizationName}`;
    doc
      .font(font)
      .fontSize(12)
      .fillColor(COLORS.lightText)
      .text(orgLabel, LAYOUT.margin, sepY + 40, {
        width: LAYOUT.contentWidth,
        align: 'center',
      });
  }

  // Brand footer
  const brandY = LAYOUT.pageHeight - LAYOUT.margin - 40;
  doc
    .font(font)
    .fontSize(10)
    .fillColor(COLORS.lightText)
    .text('Generated by Panguard AI', LAYOUT.margin, brandY, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  doc
    .font(font)
    .fontSize(8)
    .fillColor(COLORS.lightText)
    .text('https://panguard.ai', LAYOUT.margin, brandY + 16, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });
}

// ---------------------------------------------------------------------------
// Section 2: Executive Summary
// 區段 2: 執行摘要
// ---------------------------------------------------------------------------

/**
 * Render the executive summary section
 * 渲染執行摘要區段
 */
function renderExecutiveSummary(
  doc: PDFKit.PDFDocument,
  reportData: ComplianceReportData,
  lang: ReportLanguage,
  hasCjk: boolean
): void {
  const isZh = lang === 'zh-TW';
  const labels = getSectionLabels(lang);
  const font = selectFont(hasCjk, 'body');
  const headingFont = selectFont(hasCjk, 'heading');
  const es = reportData.executiveSummary;

  let y: number = LAYOUT.margin;

  // Section title
  doc
    .font(headingFont)
    .fontSize(20)
    .fillColor(COLORS.primary)
    .text(labels.executiveSummary, LAYOUT.margin, y);
  y += 35;

  // Separator
  doc
    .strokeColor(COLORS.border)
    .lineWidth(1)
    .moveTo(LAYOUT.margin, y)
    .lineTo(LAYOUT.pageWidth - LAYOUT.margin, y)
    .stroke();
  y += 15;

  // Overall score
  const scoreLabel = isZh
    ? `整體合規分數: ${es.overallScore}%`
    : `Overall Compliance Score: ${es.overallScore}%`;
  const scoreColor = es.overallScore >= 80 ? COLORS.pass : es.overallScore >= 50 ? COLORS.medium : COLORS.fail;
  doc
    .font(headingFont)
    .fontSize(16)
    .fillColor(scoreColor)
    .text(scoreLabel, LAYOUT.margin, y);
  y += 30;

  // Controls summary
  const controlLines = isZh
    ? [
        `控制項總數: ${es.totalControls}`,
        `通過: ${es.controlsPassed}  |  未通過: ${es.controlsFailed}  |  部分符合: ${es.controlsPartial}  |  不適用: ${es.controlsNA}`,
      ]
    : [
        `Total Controls: ${es.totalControls}`,
        `Passed: ${es.controlsPassed}  |  Failed: ${es.controlsFailed}  |  Partial: ${es.controlsPartial}  |  N/A: ${es.controlsNA}`,
      ];

  for (const line of controlLines) {
    doc.font(font).fontSize(11).fillColor(COLORS.text).text(line, LAYOUT.margin, y);
    y += 18;
  }
  y += 5;

  // Findings summary
  const findingLines = isZh
    ? [
        `發現總數: ${es.totalFindings}`,
        `嚴重: ${es.criticalFindings}  |  高風險: ${es.highFindings}`,
      ]
    : [
        `Total Findings: ${es.totalFindings}`,
        `Critical: ${es.criticalFindings}  |  High: ${es.highFindings}`,
      ];

  for (const line of findingLines) {
    doc.font(font).fontSize(11).fillColor(COLORS.text).text(line, LAYOUT.margin, y);
    y += 18;
  }
  y += 10;

  // Key risks
  if (es.keyRisks.length > 0) {
    const risksTitle = isZh ? '主要風險:' : 'Key Risks:';
    doc.font(headingFont).fontSize(12).fillColor(COLORS.fail).text(risksTitle, LAYOUT.margin, y);
    y += 18;

    for (const risk of es.keyRisks) {
      y = ensureSpace(doc, y, 16);
      doc
        .font(font)
        .fontSize(10)
        .fillColor(COLORS.text)
        .text(`  - ${risk}`, LAYOUT.margin + 10, y, { width: LAYOUT.contentWidth - 10 });
      y += 16;
    }
    y += 5;
  }

  // Key achievements
  if (es.keyAchievements.length > 0) {
    const achieveTitle = isZh ? '主要成果:' : 'Key Achievements:';
    doc
      .font(headingFont)
      .fontSize(12)
      .fillColor(COLORS.pass)
      .text(achieveTitle, LAYOUT.margin, y);
    y += 18;

    for (const achievement of es.keyAchievements) {
      y = ensureSpace(doc, y, 16);
      doc
        .font(font)
        .fontSize(10)
        .fillColor(COLORS.text)
        .text(`  - ${achievement}`, LAYOUT.margin + 10, y, {
          width: LAYOUT.contentWidth - 10,
        });
      y += 16;
    }
  }
}

// ---------------------------------------------------------------------------
// Section 3: Findings Table
// 區段 3: 發現列表
// ---------------------------------------------------------------------------

/**
 * Render the findings table section
 * 渲染發現列表區段
 */
function renderFindingsTable(
  doc: PDFKit.PDFDocument,
  findings: ComplianceFinding[],
  lang: ReportLanguage,
  hasCjk: boolean
): void {
  const isZh = lang === 'zh-TW';
  const labels = getSectionLabels(lang);
  const font = selectFont(hasCjk, 'body');
  const headingFont = selectFont(hasCjk, 'heading');

  let y: number = LAYOUT.margin;

  // Section title
  doc
    .font(headingFont)
    .fontSize(20)
    .fillColor(COLORS.primary)
    .text(labels.findings, LAYOUT.margin, y);
  y += 35;

  // Separator
  doc
    .strokeColor(COLORS.border)
    .lineWidth(1)
    .moveTo(LAYOUT.margin, y)
    .lineTo(LAYOUT.pageWidth - LAYOUT.margin, y)
    .stroke();
  y += 15;

  if (findings.length === 0) {
    const noFindings = isZh ? '未發現任何問題。' : 'No findings detected.';
    doc.font(font).fontSize(11).fillColor(COLORS.lightText).text(noFindings, LAYOUT.margin, y);
    return;
  }

  // Sort findings by severity: critical > high > medium > low > info
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  const sortedFindings = [...findings].sort(
    (a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  for (const finding of sortedFindings) {
    // Each finding needs approximately 80pt of vertical space
    y = ensureSpace(doc, y, 80);

    // Severity badge
    const badgeColor = severityColor(finding.severity);
    const badgeWidth = 60;
    const badgeHeight = 16;
    doc
      .roundedRect(LAYOUT.margin, y, badgeWidth, badgeHeight, 3)
      .fill(badgeColor);
    doc
      .font(FONTS.body)
      .fontSize(8)
      .fillColor(COLORS.white)
      .text(
        getSeverityLabel(finding.severity, lang).toUpperCase(),
        LAYOUT.margin + 2,
        y + 3,
        { width: badgeWidth - 4, align: 'center' }
      );

    // Finding ID
    doc
      .font(FONTS.mono)
      .fontSize(8)
      .fillColor(COLORS.lightText)
      .text(finding.findingId, LAYOUT.margin + badgeWidth + 10, y + 3);

    y += badgeHeight + 5;

    // Title
    doc
      .font(headingFont)
      .fontSize(11)
      .fillColor(COLORS.text)
      .text(finding.title, LAYOUT.margin + 10, y, { width: LAYOUT.contentWidth - 10 });
    y += 18;

    // Description
    doc
      .font(font)
      .fontSize(9)
      .fillColor(COLORS.secondary)
      .text(finding.description, LAYOUT.margin + 10, y, {
        width: LAYOUT.contentWidth - 20,
      });
    y += doc.heightOfString(finding.description, {
      width: LAYOUT.contentWidth - 20,
    });
    y += 12;

    // Light separator between findings
    doc
      .strokeColor(COLORS.border)
      .lineWidth(0.5)
      .moveTo(LAYOUT.margin + 10, y)
      .lineTo(LAYOUT.pageWidth - LAYOUT.margin - 10, y)
      .stroke();
    y += 10;
  }
}

// ---------------------------------------------------------------------------
// Section 4: Compliance Matrix
// 區段 4: 合規矩陣
// ---------------------------------------------------------------------------

/**
 * Render the compliance matrix section
 * 渲染合規矩陣區段
 */
function renderComplianceMatrix(
  doc: PDFKit.PDFDocument,
  controls: EvaluatedControl[],
  lang: ReportLanguage,
  hasCjk: boolean
): void {
  const isZh = lang === 'zh-TW';
  const labels = getSectionLabels(lang);
  const font = selectFont(hasCjk, 'body');
  const headingFont = selectFont(hasCjk, 'heading');

  let y: number = LAYOUT.margin;

  // Section title
  doc
    .font(headingFont)
    .fontSize(20)
    .fillColor(COLORS.primary)
    .text(labels.complianceOverview, LAYOUT.margin, y);
  y += 35;

  // Separator
  doc
    .strokeColor(COLORS.border)
    .lineWidth(1)
    .moveTo(LAYOUT.margin, y)
    .lineTo(LAYOUT.pageWidth - LAYOUT.margin, y)
    .stroke();
  y += 15;

  // Table header
  const colWidths = {
    id: 70,
    title: 220,
    status: 70,
    findings: 135,
  };
  const headerLabels = isZh
    ? { id: '控制項 ID', title: '標題', status: '狀態', findings: '相關發現' }
    : { id: 'Control ID', title: 'Title', status: 'Status', findings: 'Findings' };

  // Header background
  doc.rect(LAYOUT.margin, y, LAYOUT.contentWidth, 20).fill(COLORS.primary);

  let headerX = LAYOUT.margin + 5;
  doc.font(FONTS.body).fontSize(8).fillColor(COLORS.white);
  doc.text(headerLabels.id, headerX, y + 5, { width: colWidths.id });
  headerX += colWidths.id;
  doc.text(headerLabels.title, headerX, y + 5, { width: colWidths.title });
  headerX += colWidths.title;
  doc.text(headerLabels.status, headerX, y + 5, { width: colWidths.status, align: 'center' });
  headerX += colWidths.status;
  doc.text(headerLabels.findings, headerX, y + 5, { width: colWidths.findings });
  y += 22;

  // Table rows
  let rowIndex = 0;
  for (const control of controls) {
    y = ensureSpace(doc, y, 22);

    // Alternating row background
    if (rowIndex % 2 === 0) {
      doc.rect(LAYOUT.margin, y, LAYOUT.contentWidth, 20).fill(COLORS.background);
    }

    let cellX = LAYOUT.margin + 5;

    // Control ID
    doc
      .font(FONTS.mono)
      .fontSize(7)
      .fillColor(COLORS.text)
      .text(control.controlId, cellX, y + 5, { width: colWidths.id });
    cellX += colWidths.id;

    // Title (use localized title)
    const title = isZh ? control.titleZh : control.titleEn;
    const truncatedTitle = title.length > 40 ? `${title.substring(0, 37)}...` : title;
    doc
      .font(font)
      .fontSize(7)
      .fillColor(COLORS.text)
      .text(truncatedTitle, cellX, y + 5, { width: colWidths.title });
    cellX += colWidths.title;

    // Status badge
    const sColor = statusColor(control.status);
    const statusLabel = getStatusLabel(control.status, lang);
    doc
      .roundedRect(cellX + 10, y + 3, 50, 14, 2)
      .fill(sColor);
    doc
      .font(FONTS.body)
      .fontSize(7)
      .fillColor(COLORS.white)
      .text(statusLabel, cellX + 10, y + 5, { width: 50, align: 'center' });
    cellX += colWidths.status;

    // Related findings count
    const findingCount = control.relatedFindings.length;
    const findingText =
      findingCount === 0
        ? '-'
        : `${findingCount} ${isZh ? '個' : findingCount === 1 ? 'finding' : 'findings'}`;
    doc
      .font(font)
      .fontSize(7)
      .fillColor(findingCount > 0 ? COLORS.fail : COLORS.lightText)
      .text(findingText, cellX, y + 5, { width: colWidths.findings });

    y += 20;
    rowIndex += 1;
  }
}

// ---------------------------------------------------------------------------
// Page Footer
// 頁尾
// ---------------------------------------------------------------------------

/**
 * Add a page footer with page number, brand name, and confidential watermark
 * 新增包含頁碼、品牌名稱和機密浮水印的頁尾
 */
function addPageFooter(doc: PDFKit.PDFDocument, pageNumber: number): void {
  const footerY = LAYOUT.pageHeight - LAYOUT.margin;

  // Separator line
  doc
    .strokeColor(COLORS.border)
    .lineWidth(0.5)
    .moveTo(LAYOUT.margin, footerY - 10)
    .lineTo(LAYOUT.pageWidth - LAYOUT.margin, footerY - 10)
    .stroke();

  // Brand name on left
  doc
    .font(FONTS.body)
    .fontSize(7)
    .fillColor(COLORS.lightText)
    .text('Panguard AI', LAYOUT.margin, footerY - 4, {
      width: LAYOUT.contentWidth / 3,
      align: 'left',
    });

  // Confidential in center
  doc
    .font(FONTS.body)
    .fontSize(7)
    .fillColor(COLORS.watermark)
    .text('Confidential', LAYOUT.margin + LAYOUT.contentWidth / 3, footerY - 4, {
      width: LAYOUT.contentWidth / 3,
      align: 'center',
    });

  // Page number on right
  doc
    .font(FONTS.body)
    .fontSize(7)
    .fillColor(COLORS.lightText)
    .text(String(pageNumber), LAYOUT.margin + (LAYOUT.contentWidth * 2) / 3, footerY - 4, {
      width: LAYOUT.contentWidth / 3,
      align: 'right',
    });
}

// ---------------------------------------------------------------------------
// Main Generator Function
// 主要產生器函式
// ---------------------------------------------------------------------------

/**
 * Generate a complete PDF compliance report
 * 產生完整的 PDF 合規報告
 *
 * Creates a multi-page PDF document with the following sections:
 * 1. Cover page with report title, framework name, date
 * 2. Executive summary with overall score, pass/fail counts
 * 3. Findings table with severity badges, descriptions
 * 4. Compliance matrix showing framework requirements vs results
 * 5. Page footers with page numbers and "Confidential" watermark
 *
 * 建立多頁 PDF 文件，包含以下區段：
 * 1. 封面頁（含報告標題、框架名稱、日期）
 * 2. 執行摘要（含整體分數、通過/未通過計數）
 * 3. 發現列表（含嚴重度標記、描述）
 * 4. 合規矩陣（顯示框架要求與評估結果對照）
 * 5. 頁尾（含頁碼和「機密」浮水印）
 *
 * @param options - PDF report generation options / PDF 報告產生選項
 * @returns Path to the generated PDF file / 產生的 PDF 檔案路徑
 */
export async function generatePDFReport(options: PDFReportOptions): Promise<string> {
  logger.info('Starting PDF compliance report generation', {
    outputPath: options.outputPath,
    lang: options.lang,
    framework: options.framework,
  });

  // Ensure output directory exists
  const outputDir = dirname(options.outputPath);
  await mkdir(outputDir, { recursive: true });

  // Build or use provided assessment result
  const reportData: ComplianceReportData = options.assessmentResult ?? buildReportData(options);

  // Create PDF document
  const doc = new PDFDocument({
    size: 'A4',
    margins: {
      top: LAYOUT.margin,
      bottom: LAYOUT.margin,
      left: LAYOUT.margin,
      right: LAYOUT.margin,
    },
    info: {
      Title: options.title,
      Author: 'Panguard AI',
      Creator: 'PanguardReport PDF Generator',
      Producer: 'PDFKit',
    },
    autoFirstPage: true,
    bufferPages: true,
    compress: options.compress ?? true,
  }) as unknown as PDFKit.PDFDocument;

  // Register CJK font for zh-TW
  let hasCjkFont = false;
  if (options.lang === 'zh-TW') {
    hasCjkFont = await registerCjkFont(doc);
    if (hasCjkFont) {
      logger.info('CJK font available; Chinese text should render correctly');
    } else {
      logger.warn(
        'CJK font not available; falling back to Helvetica. ' +
          'Chinese characters will not render correctly but the report will not crash.'
      );
    }
  }

  // Pipe to output file
  const writeStream = createWriteStream(options.outputPath);
  (doc as unknown as NodeJS.ReadableStream).pipe(writeStream);

  // -- Section 1: Cover page --
  logger.info('Rendering cover page');
  renderCoverPage(doc, options, hasCjkFont);

  // -- Section 2: Executive summary --
  logger.info('Rendering executive summary');
  doc.addPage();
  renderExecutiveSummary(doc, reportData, options.lang, hasCjkFont);

  // -- Section 3: Findings table --
  logger.info('Rendering findings table');
  doc.addPage();
  renderFindingsTable(doc, reportData.findings, options.lang, hasCjkFont);

  // -- Section 4: Compliance matrix --
  logger.info('Rendering compliance matrix');
  doc.addPage();
  renderComplianceMatrix(doc, reportData.controls, options.lang, hasCjkFont);

  // -- Add page footers to all pages --
  const pageRange = doc.bufferedPageRange();
  for (let i = pageRange.start; i < pageRange.start + pageRange.count; i++) {
    doc.switchToPage(i);
    addPageFooter(doc, i + 1);
  }

  // Finalize the document
  doc.end();

  // Return a promise that resolves when the write stream finishes
  return new Promise<string>((resolve, reject) => {
    writeStream.on('finish', () => {
      logger.info('PDF compliance report generated successfully', {
        outputPath: options.outputPath,
      });
      resolve(options.outputPath);
    });
    writeStream.on('error', (err: Error) => {
      logger.error('Failed to write PDF compliance report', {
        outputPath: options.outputPath,
        error: err.message,
      });
      reject(new Error(
        `Failed to write PDF report to ${options.outputPath}: ${err.message}`
      ));
    });
  });
}

// ---------------------------------------------------------------------------
// Internal: Build report data from options
// 內部: 從選項建構報告資料
// ---------------------------------------------------------------------------

/**
 * Build a ComplianceReportData from the provided options when no
 * pre-computed assessmentResult is given.
 * 當未提供預先計算的 assessmentResult 時，從選項建構 ComplianceReportData。
 */
function buildReportData(options: PDFReportOptions): ComplianceReportData {
  const framework = options.framework as 'tw_cyber_security_act' | 'iso27001' | 'soc2';
  const controls = getFrameworkControls(framework);
  const evaluatedControls = evaluateControls(controls, options.findings);
  const executiveSummary = generateExecutiveSummary(
    evaluatedControls,
    options.findings,
    options.lang
  );
  const statistics = generateStatistics(evaluatedControls, options.findings);
  const recommendations = generateRecommendations(evaluatedControls, options.lang);

  const now = new Date();
  return {
    metadata: {
      reportId: `RPT-PDF-${now.getTime()}`,
      type: 'compliance',
      framework,
      language: options.lang,
      period: {
        start: new Date(now.getFullYear(), now.getMonth(), 1),
        end: now,
      },
      generatedAt: now,
      organizationName: options.organizationName,
      version: '1.0.0',
    },
    executiveSummary,
    controls: evaluatedControls,
    findings: options.findings,
    statistics,
    recommendations,
  };
}
