#!/usr/bin/env node
/**
 * PanguardScan CLI Entry Point
 * PanguardScan 命令列介面進入點
 *
 * @module @panguard-ai/panguard-scan/cli
 */

import { Command } from 'commander';
import path from 'node:path';
import type { Language } from '@panguard-ai/core';
import { setLogLevel } from '@panguard-ai/core';
import { PANGUARD_SCAN_VERSION } from '../index.js';
import { executeScan } from './commands.js';
import { runRemoteScan } from '../scanners/remote/index.js';
import { sortBySeverity } from '../scanners/types.js';
import type { Severity } from '@panguard-ai/core';

/**
 * Get all severity levels that are at or above the given threshold
 * 取得達到或超過指定閾值的所有嚴重等級
 *
 * @param severity - Minimum severity threshold / 最低嚴重等級閾值
 * @returns Array of severity strings at or above the threshold / 達到或超過閾值的嚴重等級陣列
 */
function getFailSeverities(severity: string): Severity[] {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const idx = order.indexOf(severity as Severity);
  if (idx === -1) return ['critical'];
  return order.slice(0, idx + 1);
}

const program = new Command();

program
  .name('panguard-scan')
  .description('PanguardScan - 60-second security health check tool / 60 秒資安健檢工具')
  .version(PANGUARD_SCAN_VERSION);

// ---------------------------------------------------------------------------
// code subcommand - SAST source code scanner
// code 子命令 - SAST 原始碼掃描器
// ---------------------------------------------------------------------------
program
  .command('code')
  .description(
    'Scan source code for security vulnerabilities (SAST) / 掃描原始碼安全漏洞'
  )
  .option('--dir <directory>', 'Source code directory to scan / 要掃描的原始碼目錄', '.')
  .option('--lang <language>', 'Language: en or zh-TW / 語言', 'en')
  .option('--json', 'Output pure JSON (for AI agents) / 輸出純 JSON', false)
  .option(
    '--fail-on <severity>',
    'Exit with code 1 if findings at this severity level exist / 若發現達到此嚴重等級則以非零碼退出'
  )
  .option('--output <path>', 'Output PDF report path / 輸出 PDF 報告路徑')
  .action(
    async (options: {
      dir: string;
      lang: string;
      json: boolean;
      failOn?: string;
      output?: string;
    }) => {
      const _lang: Language = options.lang === 'zh-TW' ? 'zh-TW' : 'en';
      const { checkSourceCode } = await import('../scanners/sast-checker.js');
      const { checkHardcodedSecrets } = await import('../scanners/secrets-checker.js');

      if (!options.json) {
        setLogLevel('silent');
        console.error(
          `Scanning ${path.resolve(options.dir)} for security issues...`
        );
      } else {
        setLogLevel('silent');
      }

      const [codeFindings, secretFindings] = await Promise.all([
        checkSourceCode(options.dir),
        checkHardcodedSecrets(options.dir),
      ]);

      const allFindings = [...codeFindings, ...secretFindings].sort(sortBySeverity);

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              version: PANGUARD_SCAN_VERSION,
              timestamp: new Date().toISOString(),
              scan_type: 'sast',
              target: path.resolve(options.dir),
              findings_count: allFindings.length,
              findings: allFindings.map((f, i) => ({
                seq: i + 1,
                id: f.id,
                title: f.title,
                description: f.description,
                severity: f.severity,
                category: f.category,
                remediation: f.remediation,
                complianceRef: f.complianceRef,
                details: f.details,
              })),
              powered_by: 'Panguard AI',
              agent_friendly: true,
            },
            null,
            2
          )
        );
      } else {
        // Human-friendly output
        // 人性化輸出
        if (allFindings.length === 0) {
          console.log('No security issues found.');
        } else {
          console.log(`\nFound ${allFindings.length} finding(s):\n`);
          for (const f of allFindings) {
            console.log(`  [${f.severity.toUpperCase()}] ${f.title}`);
            if (f.details) {
              console.log(`         ${f.details}`);
            }
          }

          const critCount = allFindings.filter((f) => f.severity === 'critical').length;
          const highCount = allFindings.filter((f) => f.severity === 'high').length;
          const medCount = allFindings.filter((f) => f.severity === 'medium').length;
          const lowCount = allFindings.filter((f) => f.severity === 'low').length;

          const parts: string[] = [];
          if (critCount > 0) parts.push(`${critCount} Critical`);
          if (highCount > 0) parts.push(`${highCount} High`);
          if (medCount > 0) parts.push(`${medCount} Medium`);
          if (lowCount > 0) parts.push(`${lowCount} Low`);

          console.log(`\nSummary: ${parts.join(' | ')}`);
        }
        console.log('');
      }

      // Handle --fail-on
      // 處理 --fail-on 選項
      if (options.failOn) {
        const failSeverities = getFailSeverities(options.failOn);
        const hasFailingFindings = allFindings.some((f) =>
          failSeverities.includes(f.severity)
        );
        if (hasFailingFindings) {
          process.exit(1);
        }
      }
    }
  );

// ---------------------------------------------------------------------------
// Default scan command (root action)
// 預設掃描指令（根動作）
// ---------------------------------------------------------------------------
program
  .option('--quick', 'Quick scan mode (~30 seconds) / 快速掃描模式', false)
  .option(
    '--output <path>',
    'Output PDF report path / 輸出 PDF 報告路徑',
    'panguard-scan-report.pdf'
  )
  .option('--lang <language>', 'Language: en or zh-TW / 語言', 'en')
  .option('--verbose', 'Verbose output / 詳細輸出', false)
  .option('--json', 'Output pure JSON to stdout (for AI agents) / 輸出純 JSON', false)
  .option('--target <host>', 'Remote target (IP or domain) / 遠端目標')
  .action(
    async (options: {
      quick: boolean;
      output: string;
      lang: string;
      verbose: boolean;
      json: boolean;
      target?: string;
    }) => {
      const lang: Language = options.lang === 'zh-TW' ? 'zh-TW' : 'en';

      // Remote scan mode
      if (options.target) {
        setLogLevel('silent');
        const result = await runRemoteScan({ target: options.target, lang });
        const safetyScore = Math.max(0, 100 - result.riskScore);
        const grade =
          safetyScore >= 90
            ? 'A'
            : safetyScore >= 75
              ? 'B'
              : safetyScore >= 60
                ? 'C'
                : safetyScore >= 40
                  ? 'D'
                  : 'F';

        if (options.json) {
          console.log(
            JSON.stringify(
              {
                version: PANGUARD_SCAN_VERSION,
                timestamp: result.scannedAt,
                target: options.target,
                risk_score: result.riskScore,
                risk_level: result.riskLevel,
                grade,
                scan_duration_ms: result.scanDuration,
                findings_count: result.findings.length,
                findings: result.findings.map((f, i) => ({
                  id: i + 1,
                  severity: f.severity,
                  title: f.title,
                  category: f.category,
                  description: f.description,
                  remediation: f.remediation,
                })),
                powered_by: 'Panguard AI',
                agent_friendly: true,
              },
              null,
              2
            )
          );
        } else {
          // Human-friendly remote output delegated to executeScan is not available here;
          // print a simple summary
          const { banner, scoreDisplay, symbols, c, formatDuration } =
            await import('@panguard-ai/core');
          console.log(banner(PANGUARD_SCAN_VERSION));
          console.log(`  ${symbols.scan} Remote Scan: ${c.bold(options.target)}`);
          console.log(scoreDisplay(safetyScore, grade));
          console.log(
            `  Findings: ${result.findings.length} | Duration: ${formatDuration(result.scanDuration)}`
          );
          for (const f of result.findings) {
            console.log(`  ${c.dim('-')} [${f.severity.toUpperCase()}] ${f.title}`);
          }
          console.log('');
        }
        return;
      }

      // JSON mode for local scan
      if (options.json) {
        setLogLevel('silent');
        const { runScan } = await import('../scanners/index.js');
        const result = await runScan({
          depth: options.quick ? 'quick' : 'full',
          lang,
          verbose: false,
        });
        const safetyScore = Math.max(0, 100 - result.riskScore);
        const grade =
          safetyScore >= 90
            ? 'A'
            : safetyScore >= 75
              ? 'B'
              : safetyScore >= 60
                ? 'C'
                : safetyScore >= 40
                  ? 'D'
                  : 'F';

        console.log(
          JSON.stringify(
            {
              version: PANGUARD_SCAN_VERSION,
              timestamp: result.scannedAt,
              target: 'localhost',
              risk_score: result.riskScore,
              risk_level: result.riskLevel,
              grade,
              scan_duration_ms: result.scanDuration,
              findings_count: result.findings.length,
              findings: result.findings.map((f, i) => ({
                id: i + 1,
                severity: f.severity,
                title: f.title,
                category: f.category,
                description: f.description,
                remediation: f.remediation,
              })),
              system: {
                os: `${result.discovery.os.distro} ${result.discovery.os.version}`,
                arch: result.discovery.os.arch,
                open_ports: result.discovery.openPorts.length,
                running_services: result.discovery.services.length,
                firewall_enabled: result.discovery.security.firewall.enabled,
                security_tools_detected: result.discovery.security.existingTools.length,
              },
              powered_by: 'Panguard AI',
              agent_friendly: true,
            },
            null,
            2
          )
        );
        return;
      }

      // Normal human-friendly scan
      await executeScan({
        depth: options.quick ? 'quick' : 'full',
        lang,
        output: options.output,
        verbose: options.verbose,
      });
    }
  );

program.parseAsync().catch((err: unknown) => {
  console.error('Fatal error:', err instanceof Error ? err.message : err);
  process.exit(1);
});
