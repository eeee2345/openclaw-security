#!/usr/bin/env node
/**
 * PanguardScan CLI Entry Point
 * PanguardScan 命令列介面進入點
 *
 * @module @panguard-ai/panguard-scan/cli
 */

import { Command } from 'commander';
import type { Language } from '@panguard-ai/core';
import { setLogLevel } from '@panguard-ai/core';
import { PANGUARD_SCAN_VERSION } from '../index.js';
import { executeScan } from './commands.js';
import { runRemoteScan } from '../scanners/remote/index.js';

const program = new Command();

program
  .name('panguard-scan')
  .description('PanguardScan - 60-second security health check tool / 60 秒資安健檢工具')
  .version(PANGUARD_SCAN_VERSION)
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
          console.log(banner());
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
