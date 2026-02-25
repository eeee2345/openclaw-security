/**
 * PanguardScan CLI command implementations
 * PanguardScan CLI 指令實作
 *
 * @module @openclaw/panguard-scan/cli/commands
 */

import {
  initI18n, t, createLogger,
  c, colorSeverity, banner, spinner, table, box,
  scoreDisplay, divider, formatDuration, symbols, statusPanel,
} from '@openclaw/core';
import { runScan } from '../scanners/index.js';
import { generatePdfReport } from '../report/index.js';
import type { ScanConfig } from '../scanners/types.js';

const logger = createLogger('panguard-scan:cli');

/**
 * Execute a security scan and generate a report
 * 執行安全掃描並產生報告
 */
export async function executeScan(config: ScanConfig): Promise<void> {
  await initI18n(config.lang);

  // Banner
  console.log(banner());

  const mode = config.depth === 'quick'
    ? t('panguard-scan:cli.quickMode')
    : t('panguard-scan:cli.fullMode');
  console.log(`  ${symbols.scan} ${mode}`);
  console.log('');

  // Scan with spinner
  const sp = spinner(t('panguard-scan:cli.scanning', { defaultValue: 'Scanning system security...' }));
  const result = await runScan(config);
  sp.succeed(t('panguard-scan:cli.complete') + ` ${c.dim(`(${formatDuration(result.scanDuration)})`)}`);

  // Security Score
  const safetyScore = Math.max(0, 100 - result.riskScore);
  const grade = safetyScore >= 90 ? 'A' : safetyScore >= 75 ? 'B' : safetyScore >= 60 ? 'C' : safetyScore >= 40 ? 'D' : 'F';
  console.log(scoreDisplay(safetyScore, grade));

  // Status panel (matching mockup "PANGUARD AI Security Status")
  const riskLabel = t(`panguard-scan:severity.${result.riskLevel}`);
  console.log(statusPanel('PANGUARD AI Security Status', [
    {
      label: 'Status',
      value: result.riskScore <= 25 ? c.safe('PROTECTED') : result.riskScore <= 50 ? c.caution('AT RISK') : c.critical('VULNERABLE'),
      status: result.riskScore <= 25 ? 'safe' : result.riskScore <= 50 ? 'caution' : 'critical',
    },
    {
      label: 'Risk Score',
      value: `${result.riskScore}/100 (${riskLabel})`,
      status: result.riskScore <= 25 ? 'safe' : result.riskScore <= 50 ? 'caution' : 'critical',
    },
    {
      label: 'Issues Found',
      value: String(result.findings.length),
      status: result.findings.length === 0 ? 'safe' : 'caution',
    },
    {
      label: 'Scan Duration',
      value: formatDuration(result.scanDuration),
    },
  ]));

  // Findings table
  if (result.findings.length > 0) {
    console.log(divider(`${result.findings.length} Finding(s)`));
    console.log('');

    const columns = [
      { header: '#', key: 'num', width: 4, align: 'right' as const },
      { header: 'Severity', key: 'severity', width: 10 },
      { header: 'Finding', key: 'title', width: 42 },
      { header: 'Status', key: 'status', width: 8 },
    ];

    const coloredRows = result.findings.map((finding, i) => ({
      num: String(i + 1),
      severity: colorSeverity(finding.severity),
      title: finding.title,
      status: (finding as unknown as Record<string, unknown>)['fixed'] ? c.safe('Fixed') : c.critical('Open'),
    }));

    console.log(table(columns, coloredRows));
    console.log('');

    // Summary counts
    const critCount = result.findings.filter(f => f.severity === 'critical').length;
    const highCount = result.findings.filter(f => f.severity === 'high').length;
    const medCount = result.findings.filter(f => f.severity === 'medium').length;
    const lowCount = result.findings.filter(f => f.severity === 'low').length;

    const parts: string[] = [];
    if (critCount > 0) parts.push(c.critical(`${critCount} Critical`));
    if (highCount > 0) parts.push(c.alert(`${highCount} High`));
    if (medCount > 0) parts.push(c.caution(`${medCount} Medium`));
    if (lowCount > 0) parts.push(c.sage(`${lowCount} Low`));

    if (parts.length > 0) {
      console.log(`  ${parts.join(c.dim(' | '))}`);
      console.log('');
    }
  } else {
    console.log(box(
      `${symbols.pass} ${t('panguard-scan:cli.noFindings', { defaultValue: 'No security issues found!' })}`,
      { borderColor: c.safe, title: 'All Clear' }
    ));
    console.log('');
  }

  // PDF report
  if (config.output) {
    const reportSp = spinner(t('panguard-scan:cli.generating', { defaultValue: 'Generating PDF report...' }));
    try {
      await generatePdfReport(result, config.output, config.lang);
      reportSp.succeed(t('panguard-scan:cli.reportSaved', { path: config.output, defaultValue: `Report saved: ${config.output}` }));
    } catch (err) {
      reportSp.fail(`Error generating report: ${err instanceof Error ? err.message : err}`);
      logger.error('Failed to generate PDF report', { error: err instanceof Error ? err.message : String(err) });
    }
  }

  console.log(c.dim(`  Scan completed at ${new Date().toLocaleString()}`));
  console.log('');
}
