/**
 * panguard trap - Honeypot system management
 * panguard trap - 蜜罐系統管理
 */

import { Command } from 'commander';
import { executeCli } from '@openclaw/panguard-trap';
import { withAuth } from '../auth-guard.js';

export function trapCommand(): Command {
  const cmd = new Command('trap')
    .description('Honeypot system management / \u871C\u7F50\u7CFB\u7D71\u7BA1\u7406');

  cmd.command('start')
    .description('Start honeypot services / \u555F\u52D5\u871C\u7F50\u670D\u52D9')
    .option('--services <types>', 'Comma-separated service types (ssh,http,ftp,...)')
    .option('--data-dir <path>', 'Data directory / \u8CC7\u6599\u76EE\u9304')
    .option('--no-cloud', 'Disable Threat Cloud upload')
    .action(withAuth('team', async (opts: Record<string, string | undefined>) => {
      const args = ['start'];
      if (opts['services']) args.push('--services', opts['services']);
      if (opts['dataDir']) args.push('--data-dir', opts['dataDir']);
      if (opts['cloud'] === 'false') args.push('--no-cloud');
      await executeCli(args);
    }));

  cmd.command('stop')
    .description('Stop honeypot services / \u505C\u6B62\u871C\u7F50\u670D\u52D9')
    .action(withAuth('team', async () => {
      await executeCli(['stop']);
    }));

  cmd.command('status')
    .description('Show current status / 顯示目前狀態')
    .action(async () => {
      await executeCli(['status']);
    });

  cmd.command('config')
    .description('Show configuration / 顯示配置')
    .option('--services <types>', 'Comma-separated service types')
    .action(async (opts: Record<string, string | undefined>) => {
      const args = ['config'];
      if (opts['services']) args.push('--services', opts['services']);
      await executeCli(args);
    });

  cmd.command('profiles')
    .description('Show attacker profiles / 顯示攻擊者 profiles')
    .action(async () => {
      await executeCli(['profiles']);
    });

  cmd.command('intel')
    .description('Show threat intelligence / 顯示威脅情報')
    .action(async () => {
      await executeCli(['intel']);
    });

  return cmd;
}
