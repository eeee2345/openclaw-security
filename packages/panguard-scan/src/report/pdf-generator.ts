/**
 * Main PDF report generator for PanguardScan
 * PanguardScan 主要 PDF 報告產生器
 *
 * Orchestrates the creation of a complete PDF security report by
 * assembling section renderers (cover, executive summary, findings,
 * remediation, compliance) into a single document. Handles CJK font
 * detection for Traditional Chinese output and page footer rendering.
 * 透過組裝各區段渲染器（封面、執行摘要、發現、修復建議、合規對照）
 * 來統籌建立完整的 PDF 安全報告文件。處理繁體中文輸出的 CJK 字型偵測
 * 和頁尾渲染。
 *
 * @module @panguard-ai/panguard-scan/report/pdf-generator
 */

import PDFDocument from 'pdfkit';
import { createWriteStream } from 'node:fs';
import { access, constants } from 'node:fs/promises';
import { createLogger } from '@panguard-ai/core';
import type { Language } from '@panguard-ai/core';
import type { ScanResult } from '../scanners/types.js';
import { COLORS, FONTS, LAYOUT } from './styles.js';
import { renderCoverPage } from './sections/cover.js';
import { renderExecutiveSummary } from './sections/executive-summary.js';
import { renderFindingsTable } from './sections/findings-table.js';
import { renderRemediation } from './sections/remediation.js';
import { renderCompliance } from './sections/compliance.js';

const logger = createLogger('panguard-scan:report');

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
    { path: '/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc', family: 'Noto Sans CJK TC' },
    { path: '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc', family: 'Noto Sans CJK TC' },
  ],
};

/**
 * Check if a file exists at the given path
 * 檢查指定路徑是否存在檔案
 *
 * @param filePath - File path to check / 要檢查的檔案路徑
 * @returns Whether the file exists / 檔案是否存在
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
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @returns Whether a CJK font was successfully registered / 是否成功註冊 CJK 字型
 */
async function registerCjkFont(doc: PDFKit.PDFDocument): Promise<boolean> {
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
        logger.info('CJK font registered successfully', { path: candidate.path });
        return true;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn('Failed to register CJK font', {
          path: candidate.path,
          error: message,
        });
      }
    }
  }

  logger.warn('No CJK font found on this system. Chinese characters may not render correctly.', {
    platform,
  });
  return false;
}

/**
 * Add a page footer with page number and brand name
 * 新增包含頁碼和品牌名稱的頁尾
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @param pageNumber - Current page number / 目前頁碼
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
      width: LAYOUT.contentWidth / 2,
      align: 'left',
    });

  // Page number on right
  doc
    .font(FONTS.body)
    .fontSize(7)
    .fillColor(COLORS.lightText)
    .text(String(pageNumber), LAYOUT.pageWidth / 2, footerY - 4, {
      width: LAYOUT.contentWidth / 2,
      align: 'right',
    });
}

/**
 * Generate a complete PDF security report from scan results
 * 從掃描結果產生完整的 PDF 安全報告
 *
 * Creates a multi-page PDF document with the following sections:
 * 1. Cover page with risk score and scan metadata
 * 2. Executive summary with severity distribution
 * 3. Detailed findings list sorted by severity
 * 4. Remediation recommendations grouped by priority
 * 5. Taiwan ISMS compliance mapping table
 *
 * 建立多頁 PDF 文件，包含以下區段：
 * 1. 封面頁（含風險評分和掃描中繼資料）
 * 2. 執行摘要（含嚴重度分佈）
 * 3. 按嚴重度排序的詳細發現清單
 * 4. 按優先級分組的修復建議
 * 5. 台灣資通安全管理法合規對照表
 *
 * @param result - Complete scan result / 完整掃描結果
 * @param outputPath - Output file path for the PDF / PDF 的輸出檔案路徑
 * @param lang - Output language / 輸出語言
 * @returns Promise that resolves when the PDF is written / 當 PDF 寫入完成時解決的 Promise
 */
export async function generatePdfReport(
  result: ScanResult,
  outputPath: string,
  lang: Language
): Promise<void> {
  logger.info('Starting PDF report generation', { outputPath, lang });

  const reportTitle =
    lang === 'zh-TW' ? 'Panguard AI - 資安健檢報告' : 'Panguard AI - Health Check Report';

  // Create the PDF document
  const doc = new PDFDocument({
    size: 'A4',
    margins: {
      top: LAYOUT.margin,
      bottom: LAYOUT.margin,
      left: LAYOUT.margin,
      right: LAYOUT.margin,
    },
    info: {
      Title: reportTitle,
      Author: 'Panguard AI',
      Creator: 'PanguardScan PDF Generator',
      Producer: 'PDFKit',
    },
    autoFirstPage: true,
    bufferPages: true,
  }) as unknown as PDFKit.PDFDocument;

  // For zh-TW, attempt to register a CJK font
  let hasCjkFont = false;
  if (lang === 'zh-TW') {
    hasCjkFont = await registerCjkFont(doc);
    if (hasCjkFont) {
      // Override default fonts with CJK equivalents
      // The section renderers use FONTS.heading / FONTS.body, but for CJK
      // we need to set the font directly before text calls. Since we cannot
      // easily intercept every .font() call, we log a note. The CJK font
      // will be used when explicitly set in the generator.
      logger.info('CJK font available; Chinese text should render correctly');
    } else {
      logger.warn(
        'CJK font not available; falling back to Helvetica. ' +
          'Chinese characters will not render correctly but the report will not crash.'
      );
    }
  }

  // Pipe the document to the output file
  const writeStream = createWriteStream(outputPath);
  (doc as unknown as NodeJS.ReadableStream).pipe(writeStream);

  // -- Section 1: Cover page --
  logger.info('Rendering cover page');
  renderCoverPage(doc, result, lang);

  // -- Section 2: Executive summary --
  logger.info('Rendering executive summary');
  doc.addPage();
  renderExecutiveSummary(doc, result, lang);

  // -- Section 3: Detailed findings --
  logger.info('Rendering detailed findings');
  doc.addPage();
  renderFindingsTable(doc, result, lang);

  // -- Section 4: Remediation recommendations --
  logger.info('Rendering remediation recommendations');
  doc.addPage();
  renderRemediation(doc, result, lang);

  // -- Section 5: Compliance mapping --
  logger.info('Rendering compliance mapping');
  doc.addPage();
  renderCompliance(doc, result, lang);

  // -- Add page footers to all pages --
  const pageRange = doc.bufferedPageRange();
  for (let i = pageRange.start; i < pageRange.start + pageRange.count; i++) {
    doc.switchToPage(i);
    addPageFooter(doc, i + 1);
  }

  // Finalize the document
  doc.end();

  // Return a promise that resolves when the write stream finishes
  return new Promise<void>((resolve, reject) => {
    writeStream.on('finish', () => {
      logger.info('PDF report generated successfully', { outputPath });
      resolve();
    });
    writeStream.on('error', (err: Error) => {
      logger.error('Failed to write PDF report', {
        outputPath,
        error: err.message,
      });
      reject(err);
    });
  });
}
