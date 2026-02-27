/**
 * panguard hardening - Security hardening audit and migration
 * panguard hardening - 安全強化稽核與遷移
 *
 * @module @panguard-ai/panguard/cli/commands/hardening
 */

import { Command } from 'commander';
import {
  c,
  symbols,
  table,
  box,
  divider,
  header,
} from '@panguard-ai/core';
import type { TableColumn } from '@panguard-ai/core';
import {
  runSecurityAudit,
  loadSecurityPolicy,
  migrateCredentials,
  EncryptedFileCredentialStore,
} from '@panguard-ai/security-hardening';
import type { VulnerabilityFinding } from '@panguard-ai/security-hardening';

function severityColor(severity: string, text: string): string {
  switch (severity) {
    case 'critical':
      return c.critical(text);
    case 'high':
      return c.alert(text);
    case 'medium':
      return c.caution(text);
    case 'low':
      return c.sage(text);
    default:
      return c.dim(text);
  }
}

export function hardeningCommand(): Command {
  const cmd = new Command('hardening')
    .description('Security hardening tools / 安全強化工具');

  cmd
    .command('audit')
    .description('Run security self-audit / 執行安全自檢')
    .option('--json', 'Output as JSON')
    .action(async (opts: { json?: boolean }) => {
      const policy = loadSecurityPolicy({});
      const report = runSecurityAudit(policy);

      if (opts.json) {
        console.log(JSON.stringify(report, null, 2));
        return;
      }

      console.log('');
      console.log(header('Panguard Security Audit / 安全自檢報告'));

      // Risk score
      const scoreColor =
        report.riskScore === 0
          ? c.safe
          : report.riskScore <= 50
            ? c.caution
            : c.critical;
      console.log(
        `  Risk Score: ${scoreColor(`${report.riskScore}/100`)}` +
          `  ${c.dim(`(${report.findings.length} checks, ${report.findings.filter((f: VulnerabilityFinding) => !f.fixed).length} unfixed)`)}`
      );
      console.log('');

      // Findings table
      console.log(divider('Findings'));
      console.log('');

      const columns: TableColumn[] = [
        { header: '#', key: 'num', width: 4, align: 'right' },
        { header: 'ID', key: 'id', width: 16 },
        { header: 'Severity', key: 'severity', width: 10 },
        { header: 'Status', key: 'status', width: 8 },
        { header: 'Finding', key: 'title', width: 42 },
      ];

      const rows = report.findings.map((f: VulnerabilityFinding, i: number) => ({
        num: String(i + 1),
        id: f.id,
        severity: severityColor(f.severity, f.severity.toUpperCase()),
        status: f.fixed ? c.safe('Fixed') : c.critical('Open'),
        title: f.title,
      }));

      console.log(table(columns, rows));
      console.log('');

      // Recommendations
      if (report.recommendations.length > 0) {
        console.log(divider('Recommendations'));
        console.log('');
        for (const rec of report.recommendations) {
          console.log(`  ${symbols.warn} ${rec}`);
        }
        console.log('');
      } else {
        console.log(
          box(`${symbols.pass} All security checks passed!`, {
            borderColor: c.safe,
            title: 'All Clear',
          })
        );
        console.log('');
      }
    });

  cmd
    .command('migrate')
    .description('Migrate plaintext credentials to encrypted storage / 遷移明文憑證到加密儲存')
    .option('--dry-run', 'Report only, do not migrate / 僅報告不遷移', false)
    .option('--key <key>', 'Encryption key (or set PANGUARD_CREDENTIAL_KEY env var)')
    .action(async (opts: { dryRun: boolean; key?: string }) => {
      const encryptionKey = opts.key ?? process.env['PANGUARD_CREDENTIAL_KEY'];
      if (!encryptionKey && !opts.dryRun) {
        console.error(
          `${symbols.fail} Encryption key required. Use --key <key> or set PANGUARD_CREDENTIAL_KEY env var.`
        );
        process.exit(1);
      }

      const store = new EncryptedFileCredentialStore(encryptionKey ?? 'dry-run');
      const report = await migrateCredentials(store, undefined, opts.dryRun);

      if (report.scanned === 0) {
        console.log(
          `${symbols.pass} No plaintext credentials found. Nothing to migrate.`
        );
        return;
      }

      console.log('');
      console.log(header('Credential Migration Report / 憑證遷移報告'));
      console.log(`  Scanned:  ${report.scanned}`);
      console.log(`  Migrated: ${c.safe(String(report.migrated))}`);
      if (report.failed > 0) {
        console.log(`  Failed:   ${c.critical(String(report.failed))}`);
        for (const err of report.errors) {
          console.log(`    ${symbols.fail} ${err}`);
        }
      }
      if (opts.dryRun) {
        console.log(c.dim('  (dry run - no changes made)'));
      }
      console.log('');
    });

  return cmd;
}
