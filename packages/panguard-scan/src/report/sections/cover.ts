/**
 * Cover page renderer for the PDF security report
 * PDF 安全報告的封面頁渲染器
 *
 * Renders the first page of the report including branding, scan
 * metadata, risk score, and confidentiality notice.
 * 渲染報告的第一頁，包括品牌標識、掃描中繼資料、風險評分和機密性聲明。
 *
 * @module @panguard-ai/panguard-scan/report/sections/cover
 */

import type { Language } from '@panguard-ai/core';
import type { ScanResult } from '../../scanners/types.js';
import { COLORS, FONTS, LAYOUT, severityColor } from '../styles.js';

/**
 * Render the cover page of the PDF report
 * 渲染 PDF 報告的封面頁
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @param result - Complete scan result / 完整掃描結果
 * @param lang - Output language / 輸出語言
 */
export function renderCoverPage(doc: PDFKit.PDFDocument, result: ScanResult, lang: Language): void {
  const isZh = lang === 'zh-TW';
  const centerX = LAYOUT.pageWidth / 2;

  // -- Brand name at top --
  doc
    .font(FONTS.heading)
    .fontSize(28)
    .fillColor(COLORS.primary)
    .text('PANGUARD AI', LAYOUT.margin, 120, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  // -- Report title --
  const reportTitle = isZh ? '資安健檢報告' : 'Security Health Check Report';
  doc.fontSize(20).fillColor(COLORS.secondary).text(reportTitle, LAYOUT.margin, 170, {
    width: LAYOUT.contentWidth,
    align: 'center',
  });

  // -- Horizontal separator line --
  const lineY = 210;
  doc
    .strokeColor(COLORS.accent)
    .lineWidth(2)
    .moveTo(LAYOUT.margin + 80, lineY)
    .lineTo(LAYOUT.pageWidth - LAYOUT.margin - 80, lineY)
    .stroke();

  // -- Scan information --
  const scanDate = new Date(result.scannedAt).toLocaleDateString(isZh ? 'zh-TW' : 'en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  const scanMode =
    result.config.depth === 'full'
      ? isZh
        ? '完整掃描'
        : 'Full Scan'
      : isZh
        ? '快速掃描'
        : 'Quick Scan';

  const infoStartY = 240;
  const labelWidth = 160;
  const lineHeight = 26;

  const infoItems: Array<{ label: string; value: string }> = [
    {
      label: isZh ? '主機名稱' : 'Hostname',
      value: result.discovery.hostname,
    },
    {
      label: isZh ? '作業系統' : 'Operating System',
      value: `${result.discovery.os.distro} ${result.discovery.os.version}`,
    },
    {
      label: isZh ? '掃描日期' : 'Scan Date',
      value: scanDate,
    },
    {
      label: isZh ? '掃描模式' : 'Scan Mode',
      value: scanMode,
    },
  ];

  infoItems.forEach((item, index) => {
    const y = infoStartY + index * lineHeight;
    doc
      .font(FONTS.heading)
      .fontSize(11)
      .fillColor(COLORS.lightText)
      .text(`${item.label}:`, centerX - labelWidth, y, {
        width: labelWidth - 10,
        align: 'right',
      });
    doc
      .font(FONTS.body)
      .fontSize(11)
      .fillColor(COLORS.text)
      .text(item.value, centerX + 10, y, {
        width: LAYOUT.contentWidth / 2,
        align: 'left',
      });
  });

  // -- Large risk score display --
  const scoreY = 380;
  const scoreColor = severityColor(result.riskLevel);

  // Score circle background
  const circleRadius = 60;
  doc
    .circle(centerX, scoreY + circleRadius, circleRadius)
    .fillOpacity(0.1)
    .fill(scoreColor);

  // Reset fill opacity
  doc.fillOpacity(1);

  // Score number
  doc
    .font(FONTS.heading)
    .fontSize(48)
    .fillColor(scoreColor)
    .text(String(result.riskScore), LAYOUT.margin, scoreY + circleRadius - 28, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  // Score label "/ 100"
  doc
    .font(FONTS.body)
    .fontSize(14)
    .fillColor(COLORS.lightText)
    .text('/ 100', LAYOUT.margin, scoreY + circleRadius + 26, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  // -- Risk level label --
  const riskLevelLabels: Record<string, { en: string; zh: string }> = {
    critical: { en: 'CRITICAL RISK', zh: '極高風險' },
    high: { en: 'HIGH RISK', zh: '高風險' },
    medium: { en: 'MEDIUM RISK', zh: '中等風險' },
    low: { en: 'LOW RISK', zh: '低風險' },
    info: { en: 'MINIMAL RISK', zh: '極低風險' },
  };

  const riskLabel = riskLevelLabels[result.riskLevel];
  const riskText = riskLabel
    ? isZh
      ? riskLabel.zh
      : riskLabel.en
    : isZh
      ? '未知風險'
      : 'UNKNOWN RISK';

  doc
    .font(FONTS.heading)
    .fontSize(18)
    .fillColor(scoreColor)
    .text(riskText, LAYOUT.margin, scoreY + circleRadius + 56, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  // -- Risk score explanation --
  const explanationY = scoreY + circleRadius + 100;
  const explanation = isZh
    ? '風險評分基於系統配置、網路安全、存取控制和已知弱點的綜合評估。分數越高代表風險越大。'
    : 'The risk score is a composite assessment based on system configuration, network security, access controls, and known vulnerabilities. A higher score indicates greater risk.';

  doc
    .font(FONTS.body)
    .fontSize(10)
    .fillColor(COLORS.lightText)
    .text(explanation, LAYOUT.margin + 40, explanationY, {
      width: LAYOUT.contentWidth - 80,
      align: 'center',
    });

  // -- Confidential notice at bottom --
  const confidentialText = isZh
    ? '機密文件 - 僅供授權人員閱覽'
    : 'CONFIDENTIAL - For Authorized Personnel Only';

  doc
    .font(FONTS.heading)
    .fontSize(9)
    .fillColor(COLORS.lightText)
    .text(confidentialText, LAYOUT.margin, LAYOUT.pageHeight - LAYOUT.margin - 40, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });

  // Generation timestamp
  const generatedText = isZh
    ? `報告產生時間: ${new Date().toLocaleString('zh-TW')}`
    : `Report generated: ${new Date().toLocaleString('en-US')}`;

  doc
    .font(FONTS.body)
    .fontSize(8)
    .fillColor(COLORS.lightText)
    .text(generatedText, LAYOUT.margin, LAYOUT.pageHeight - LAYOUT.margin - 24, {
      width: LAYOUT.contentWidth,
      align: 'center',
    });
}
