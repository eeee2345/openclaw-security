/**
 * panguard report - Compliance report generation
 * panguard report - 合規報告產生
 */

import { Command } from 'commander';
import { executeCli } from '@openclaw/panguard-report';
import { withAuth } from '../auth-guard.js';

export function reportCommand(): Command {
  const cmd = new Command('report')
    .description('Compliance report generation / \u5408\u898F\u5831\u544A\u7522\u751F');

  cmd.command('generate')
    .description('Generate a compliance report / \u7522\u751F\u5408\u898F\u5831\u544A')
    .option('--framework <name>', 'Compliance framework (iso27001, soc2, tw_cyber_security_act)')
    .option('--language <lang>', 'Report language (en, zh-TW)')
    .option('--format <fmt>', 'Output format (json, pdf)')
    .option('--output-dir <path>', 'Output directory / \u8F38\u51FA\u76EE\u9304')
    .option('--org <name>', 'Organization name / \u7D44\u7E54\u540D\u7A31')
    .option('--input <file>', 'Findings input file (JSON)')
    .action(withAuth('team', async (opts: Record<string, string | undefined>) => {
      const args = ['generate'];
      if (opts['framework']) args.push('--framework', opts['framework']);
      if (opts['language']) args.push('--language', opts['language']);
      if (opts['format']) args.push('--format', opts['format']);
      if (opts['outputDir']) args.push('--output-dir', opts['outputDir']);
      if (opts['org']) args.push('--org', opts['org']);
      if (opts['input']) args.push('--input', opts['input']);
      await executeCli(args);
    }));

  cmd.command('summary')
    .description('Show brief compliance summary / 顯示簡短合規摘要')
    .option('--framework <name>', 'Compliance framework')
    .option('--language <lang>', 'Report language')
    .option('--input <file>', 'Findings input file (JSON)')
    .action(withAuth('team', async (opts: Record<string, string | undefined>) => {
      const args = ['summary'];
      if (opts['framework']) args.push('--framework', opts['framework']);
      if (opts['language']) args.push('--language', opts['language']);
      if (opts['input']) args.push('--input', opts['input']);
      await executeCli(args);
    }));

  cmd.command('list-frameworks')
    .description('List supported compliance frameworks / 列出支援的合規框架')
    .action(async () => {
      await executeCli(['list-frameworks']);
    });

  cmd.command('validate')
    .description('Validate findings input file / 驗證發現輸入檔案')
    .option('--input <file>', 'Input file path')
    .action(async (opts: Record<string, string | undefined>) => {
      const args = ['validate'];
      if (opts['input']) args.push('--input', opts['input']);
      await executeCli(args);
    });

  return cmd;
}
