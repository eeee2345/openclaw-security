/**
 * panguard scan - Security scanning command
 * panguard scan - 安全掃描命令
 */

import { Command } from 'commander';
import type { Language } from '@panguard-ai/core';
import {
  c,
  banner,
  spinner,
  statusPanel,
  divider,
  scoreDisplay,
  colorSeverity,
  table,
  box,
  symbols,
  formatDuration,
  setLogLevel,
} from '@panguard-ai/core';
import { runScan, runRemoteScan } from '@panguard-ai/panguard-scan';
import { requireAuth } from '../auth-guard.js';

export function scanCommand(): Command {
  return new Command('scan')
    .description('Run a security scan / 執行安全掃描')
    .option('--quick', 'Quick scan mode (~30s) / 快速掃描模式', false)
    .option('--output <path>', 'Output PDF report path / 輸出 PDF 報告路徑')
    .option('--lang <language>', 'Language: en or zh-TW / 語言', 'en')
    .option('--verbose', 'Verbose output / 詳細輸出', false)
    .option('--json', 'Output pure JSON to stdout (for AI agents) / 輸出純 JSON', false)
    .option('--target <host>', 'Remote target (IP or domain) / 遠端目標')
    .action(
      async (options: {
        quick: boolean;
        output?: string;
        lang: string;
        verbose: boolean;
        json: boolean;
        target?: string;
      }) => {
        // Auth: quick scan = free, full scan = starter, remote scan = solo
        const tier = options.target ? 'solo' : options.quick ? 'free' : 'solo';
        const check = requireAuth(tier);
        if (!check.authenticated || !check.authorized) {
          const { withAuth } = await import('../auth-guard.js');
          await withAuth(tier, async () => {})(options);
          return;
        }
        const lang: Language = options.lang === 'zh-TW' ? 'zh-TW' : 'en';

        // Remote scan mode
        if (options.target) {
          setLogLevel('silent');
          if (options.json) {
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
            const output = {
              version: '0.5.0',
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
              system: {
                os: 'remote',
                arch: 'remote',
                open_ports: result.discovery.openPorts.length,
                running_services: 0,
                firewall_enabled: false,
                security_tools_detected: 0,
              },
              powered_by: 'Panguard AI',
              agent_friendly: true,
            };
            console.log(JSON.stringify(output, null, 2));
            return;
          }

          // Human-friendly remote scan output
          console.log(banner());
          console.log(`  ${symbols.scan} Remote Scan: ${c.bold(options.target)}`);
          console.log('');
          const sp = spinner(`Scanning ${options.target}...`);
          const result = await runRemoteScan({ target: options.target, lang });
          sp.succeed(`Remote scan complete ${c.dim(`(${formatDuration(result.scanDuration)})`)}`);

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
          console.log(scoreDisplay(safetyScore, grade));

          console.log(
            statusPanel(`PANGUARD AI Remote Scan: ${options.target}`, [
              { label: 'Risk Score', value: `${result.riskScore}/100` },
              { label: 'Issues', value: String(result.findings.length) },
              { label: 'Open Ports', value: String(result.discovery.openPorts.length) },
            ])
          );

          if (result.findings.length > 0) {
            console.log(divider(`${result.findings.length} Finding(s)`));
            console.log('');
            const columns = [
              { header: '#', key: 'num', width: 4, align: 'right' as const },
              { header: 'Severity', key: 'severity', width: 10 },
              { header: 'Finding', key: 'title', width: 50 },
            ];
            const rows = result.findings.map((f, i) => ({
              num: String(i + 1),
              severity: colorSeverity(f.severity),
              title: f.title,
            }));
            console.log(table(columns, rows));
          } else {
            console.log(
              box(`${symbols.pass} No issues found!`, { borderColor: c.safe, title: 'All Clear' })
            );
          }
          console.log('');
          return;
        }

        // JSON mode: pure JSON to stdout, no terminal UI
        if (options.json) {
          setLogLevel('silent');
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

          const output = {
            version: '0.5.0',
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
              manual_fix: f.manualFix ?? null,
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
          };
          console.log(JSON.stringify(output, null, 2));
          return;
        }

        // Suppress structured JSON logs unless --verbose
        if (!options.verbose) {
          setLogLevel('silent');
        }

        console.log(banner());
        const mode = options.quick ? 'Quick Scan' : 'Full Scan';
        console.log(`  ${symbols.scan} ${mode}`);
        console.log('');

        const sp = spinner('Scanning system security...');
        const result = await runScan({
          depth: options.quick ? 'quick' : 'full',
          lang,
          output: options.output,
          verbose: options.verbose,
        });
        sp.succeed(`Scan complete ${c.dim(`(${formatDuration(result.scanDuration)})`)}`);

        // Security Score
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
        console.log(scoreDisplay(safetyScore, grade));

        // Status panel
        console.log(
          statusPanel('PANGUARD AI Security Status', [
            {
              label: 'Status',
              value:
                result.riskScore <= 25
                  ? c.safe('PROTECTED')
                  : result.riskScore <= 50
                    ? c.caution('AT RISK')
                    : c.critical('VULNERABLE'),
              status:
                result.riskScore <= 25 ? 'safe' : result.riskScore <= 50 ? 'caution' : 'critical',
            },
            {
              label: 'Risk Score',
              value: `${result.riskScore}/100`,
              status:
                result.riskScore <= 25 ? 'safe' : result.riskScore <= 50 ? 'caution' : 'critical',
            },
            {
              label: 'Issues Found',
              value: String(result.findings.length),
              status: result.findings.length === 0 ? 'safe' : 'caution',
            },
            { label: 'Scan Duration', value: formatDuration(result.scanDuration) },
          ])
        );

        // Findings
        if (result.findings.length > 0) {
          console.log(divider(`${result.findings.length} Finding(s)`));
          console.log('');

          const columns = [
            { header: '#', key: 'num', width: 4, align: 'right' as const },
            { header: 'Severity', key: 'severity', width: 10 },
            { header: 'Finding', key: 'title', width: 42 },
          ];

          const rows = result.findings.map((f, i) => ({
            num: String(i + 1),
            severity: colorSeverity(f.severity),
            title: f.title,
          }));

          console.log(table(columns, rows));

          // Show manual fix commands for free tier
          const check = requireAuth('solo');
          if (!check.authorized) {
            let fixableCount = 0;
            console.log('');
            for (const f of result.findings) {
              if (f.manualFix && f.manualFix.length > 0) {
                fixableCount++;
                console.log(`  ${colorSeverity(f.severity).padEnd(10)} ${f.title}`);
                console.log(c.dim('          Manual fix:'));
                for (const cmd of f.manualFix) {
                  console.log(c.dim(`          $ ${cmd}`));
                }
                console.log('');
              }
            }
            if (fixableCount > 0) {
              console.log(
                box(
                  `\u26A1 Upgrade to Solo ($9/mo) to auto-fix all ${fixableCount} issues:\n  $ panguard scan --fix`,
                  { borderColor: c.sage, title: 'Panguard AI' }
                )
              );
            }
          }
          console.log('');
        } else {
          console.log(
            box(`${symbols.pass} No security issues found!`, {
              borderColor: c.safe,
              title: 'All Clear',
            })
          );
          console.log('');
        }

        // PDF report
        if (options.output) {
          const { generatePdfReport } = await import('@panguard-ai/panguard-scan');
          const reportSp = spinner('Generating PDF report...');
          try {
            await generatePdfReport(result, options.output, lang);
            reportSp.succeed(`Report saved: ${options.output}`);
          } catch (err) {
            reportSp.fail(`Error: ${err instanceof Error ? err.message : err}`);
          }
        }

        console.log(c.dim(`  Scan completed at ${new Date().toLocaleString()}`));
        console.log('');
      }
    );
}
