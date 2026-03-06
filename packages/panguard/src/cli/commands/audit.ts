/**
 * panguard audit - Skill security auditing command
 * panguard audit - 技能安全審計命令
 */

import { Command } from 'commander';
import path from 'node:path';
import {
  c,
  banner,
  divider,
  box,
  symbols,
  setLogLevel,
} from '@panguard-ai/core';

export function auditCommand(): Command {
  const cmd = new Command('audit')
    .description('Audit security of OpenClaw skills / 審計 OpenClaw 技能的安全性');

  cmd
    .command('skill')
    .description('Audit a SKILL.md directory for security issues / 審計 SKILL.md 目錄的安全問題')
    .argument('<path>', 'Path to skill directory containing SKILL.md / 包含 SKILL.md 的技能目錄路徑')
    .option('--json', 'Output as JSON / 以 JSON 格式輸出', false)
    .option('--verbose', 'Verbose output / 詳細輸出', false)
    .action(async (skillPath: string, options: { json: boolean; verbose: boolean }) => {
      if (options.verbose) setLogLevel('debug');

      const resolvedPath = path.resolve(skillPath);

      if (!options.json) {
        banner('Panguard Skill Auditor');
        console.log(c.dim(`  Scanning: ${resolvedPath}`));
        console.log();
      }

      const { auditSkill } = await import('@panguard-ai/panguard-skill-auditor');
      const report = await auditSkill(resolvedPath);

      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
        return;
      }

      // Pretty output
      const levelColors: Record<string, (s: string) => string> = {
        LOW: c.green,
        MEDIUM: c.yellow,
        HIGH: c.red,
        CRITICAL: (s: string) => c.bold(c.red(s)),
      };
      const colorFn = levelColors[report.riskLevel] ?? c.dim;

      console.log(box([
        `${c.bold('Panguard Skill Audit Report')}`,
        '',
        `Skill:      ${report.manifest?.name ?? 'Unknown'}${report.manifest?.metadata?.version ? ` v${report.manifest.metadata.version}` : ''}`,
        `Author:     ${report.manifest?.metadata?.author ?? 'Unknown'}`,
        `Risk Score: ${colorFn(`${report.riskScore}/100 (${report.riskLevel})`)}`,
        `Duration:   ${report.durationMs}ms`,
      ].join('\n')));

      console.log();

      for (const check of report.checks) {
        const icon = check.status === 'pass' ? c.green(symbols.pass)
          : check.status === 'fail' ? c.red(symbols.fail)
          : check.status === 'warn' ? c.yellow(symbols.warn)
          : c.blue(symbols.info);
        const statusLabel = check.status === 'pass' ? 'PASS'
          : check.status === 'fail' ? 'FAIL'
          : check.status === 'warn' ? 'WARN'
          : 'INFO';
        console.log(`  ${icon} [${statusLabel}] ${check.label}`);
      }

      console.log();
      divider();

      if (report.findings.length > 0 && options.verbose) {
        console.log();
        console.log(c.bold('  Detailed Findings:'));
        console.log();
        for (const finding of report.findings) {
          const sevColor = finding.severity === 'critical' ? c.red
            : finding.severity === 'high' ? c.yellow
            : c.dim;
          console.log(`  ${sevColor(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);
          console.log(`    ${c.dim(finding.description)}`);
          if (finding.location) console.log(`    ${c.dim(`at ${finding.location}`)}`);
          console.log();
        }
      }

      // Exit code
      if (report.riskLevel === 'CRITICAL') process.exitCode = 2;
      else if (report.riskLevel === 'HIGH') process.exitCode = 1;
    });

  return cmd;
}
