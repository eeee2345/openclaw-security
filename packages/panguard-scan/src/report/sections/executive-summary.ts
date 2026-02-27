/**
 * Executive summary section renderer for the PDF security report
 * PDF 安全報告的執行摘要區段渲染器
 *
 * Renders the executive summary page including risk score explanation,
 * severity distribution, system overview, and top critical findings.
 * 渲染執行摘要頁面，包括風險評分說明、嚴重度分佈、系統概覽和最關鍵的發現。
 *
 * @module @panguard-ai/panguard-scan/report/sections/executive-summary
 */

import type { Language, Severity } from '@panguard-ai/core';
import type { ScanResult } from '../../scanners/types.js';
import { COLORS, FONTS, LAYOUT, severityColor } from '../styles.js';

/**
 * Render the executive summary section of the PDF report
 * 渲染 PDF 報告的執行摘要區段
 *
 * @param doc - PDFKit document instance / PDFKit 文件實例
 * @param result - Complete scan result / 完整掃描結果
 * @param lang - Output language / 輸出語言
 */
export function renderExecutiveSummary(
  doc: PDFKit.PDFDocument,
  result: ScanResult,
  lang: Language
): void {
  const isZh = lang === 'zh-TW';

  // -- Section title --
  const sectionTitle = isZh ? '執行摘要' : 'Executive Summary';
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

  // -- Risk score explanation --
  const riskExplanation = isZh
    ? `本次掃描的總體風險評分為 ${result.riskScore} 分（滿分 100）。此評分綜合考量了系統配置、網路安全態勢、存取控制措施和已偵測到的弱點。分數越高表示系統面臨的安全風險越大，建議優先處理高嚴重度的問題。`
    : `The overall risk score for this scan is ${result.riskScore} out of 100. This score is a composite evaluation of system configuration, network security posture, access control measures, and detected vulnerabilities. A higher score indicates greater security risk. Prioritize addressing high-severity issues first.`;

  doc
    .font(FONTS.body)
    .fontSize(10)
    .fillColor(COLORS.text)
    .text(riskExplanation, LAYOUT.margin, doc.y + 10, {
      width: LAYOUT.contentWidth,
      lineGap: 3,
    });

  doc.moveDown(1.5);

  // -- Severity distribution table --
  const severityTitle = isZh ? '嚴重度分佈' : 'Severity Distribution';
  doc
    .font(FONTS.heading)
    .fontSize(13)
    .fillColor(COLORS.secondary)
    .text(severityTitle, LAYOUT.margin, doc.y);

  doc.moveDown(0.5);

  const severityLevels: Array<{ key: Severity; en: string; zh: string }> = [
    { key: 'critical', en: 'Critical', zh: '嚴重' },
    { key: 'high', en: 'High', zh: '高' },
    { key: 'medium', en: 'Medium', zh: '中' },
    { key: 'low', en: 'Low', zh: '低' },
    { key: 'info', en: 'Info', zh: '資訊' },
  ];

  const severityCounts = new Map<Severity, number>();
  for (const level of severityLevels) {
    severityCounts.set(level.key, result.findings.filter((f) => f.severity === level.key).length);
  }

  const tableStartY = doc.y;
  const rowHeight = 22;
  const col1X = LAYOUT.margin;
  const col2X = LAYOUT.margin + 140;
  const col3X = LAYOUT.margin + 220;
  const tableWidth = LAYOUT.contentWidth;

  // Table header
  doc.rect(col1X, tableStartY, tableWidth, rowHeight).fillOpacity(0.08).fill(COLORS.primary);

  doc.fillOpacity(1);

  doc
    .font(FONTS.heading)
    .fontSize(9)
    .fillColor(COLORS.primary)
    .text(isZh ? '嚴重等級' : 'Severity', col1X + 8, tableStartY + 6)
    .text(isZh ? '數量' : 'Count', col2X + 8, tableStartY + 6)
    .text(isZh ? '比例' : 'Percentage', col3X + 8, tableStartY + 6);

  const totalFindings = result.findings.length;

  severityLevels.forEach((level, index) => {
    const y = tableStartY + rowHeight + index * rowHeight;
    const count = severityCounts.get(level.key) ?? 0;
    const percentage = totalFindings > 0 ? `${Math.round((count / totalFindings) * 100)}%` : '0%';

    // Alternating row background
    if (index % 2 === 0) {
      doc.rect(col1X, y, tableWidth, rowHeight).fillOpacity(0.03).fill(COLORS.secondary);
      doc.fillOpacity(1);
    }

    // Severity color badge
    const badgeColor = severityColor(level.key);
    doc.rect(col1X + 8, y + 5, 10, 12).fill(badgeColor);

    const label = isZh ? level.zh : level.en;
    doc
      .font(FONTS.body)
      .fontSize(9)
      .fillColor(COLORS.text)
      .text(label, col1X + 24, y + 6)
      .text(String(count), col2X + 8, y + 6)
      .text(percentage, col3X + 8, y + 6);
  });

  // Move y position past the table
  const tableEndY = tableStartY + rowHeight + severityLevels.length * rowHeight;
  doc.y = tableEndY;
  doc.moveDown(1.5);

  // -- System overview --
  const overviewTitle = isZh ? '系統概覽' : 'System Overview';
  doc
    .font(FONTS.heading)
    .fontSize(13)
    .fillColor(COLORS.secondary)
    .text(overviewTitle, LAYOUT.margin, doc.y);

  doc.moveDown(0.5);

  const ipAddresses =
    result.discovery.network.interfaces
      .filter((iface) => !iface.internal && iface.ip)
      .map((iface) => iface.ip)
      .join(', ') || (isZh ? '未偵測到' : 'Not detected');

  const openPortsCount = result.discovery.openPorts.length;
  const runningServicesCount = result.discovery.services.filter(
    (s) => s.status === 'running'
  ).length;

  const overviewItems: Array<{ label: string; value: string }> = [
    {
      label: isZh ? '作業系統' : 'Operating System',
      value: `${result.discovery.os.distro} ${result.discovery.os.version} (${result.discovery.os.arch})`,
    },
    {
      label: isZh ? '主機名稱' : 'Hostname',
      value: result.discovery.hostname,
    },
    {
      label: isZh ? 'IP 位址' : 'IP Addresses',
      value: ipAddresses,
    },
    {
      label: isZh ? '開放埠數量' : 'Open Ports',
      value: String(openPortsCount),
    },
    {
      label: isZh ? '執行中服務' : 'Running Services',
      value: String(runningServicesCount),
    },
  ];

  overviewItems.forEach((item) => {
    doc
      .font(FONTS.heading)
      .fontSize(9)
      .fillColor(COLORS.lightText)
      .text(`${item.label}: `, LAYOUT.margin + 10, doc.y, {
        continued: true,
      });
    doc.font(FONTS.body).fontSize(9).fillColor(COLORS.text).text(item.value);
    doc.moveDown(0.2);
  });

  doc.moveDown(1);

  // -- Top 3 most critical findings --
  const topFindingsTitle = isZh ? '最關鍵發現 (前三項)' : 'Top Critical Findings';
  doc
    .font(FONTS.heading)
    .fontSize(13)
    .fillColor(COLORS.secondary)
    .text(topFindingsTitle, LAYOUT.margin, doc.y);

  doc.moveDown(0.5);

  const topFindings = result.findings.slice(0, 3);

  if (topFindings.length === 0) {
    const noFindingsText = isZh ? '未發現重大安全問題。' : 'No significant security issues found.';
    doc
      .font(FONTS.body)
      .fontSize(10)
      .fillColor(COLORS.lightText)
      .text(noFindingsText, LAYOUT.margin + 10, doc.y);
  } else {
    topFindings.forEach((finding, index) => {
      const badgeColor = severityColor(finding.severity);
      const y = doc.y;

      // Numbered label
      doc
        .font(FONTS.heading)
        .fontSize(10)
        .fillColor(COLORS.text)
        .text(`${index + 1}.`, LAYOUT.margin + 10, y, {
          continued: true,
        });

      // Severity badge inline
      doc
        .font(FONTS.body)
        .fontSize(8)
        .fillColor(badgeColor)
        .text(` [${finding.severity.toUpperCase()}] `, { continued: true });

      // Finding title
      doc
        .font(FONTS.heading)
        .fontSize(10)
        .fillColor(COLORS.text)
        .text(finding.title, {
          width: LAYOUT.contentWidth - 40,
        });

      doc.moveDown(0.3);
    });
  }
}
