/**
 * panguard guard - Guard engine management
 * panguard guard - 守護引擎管理
 */

import { Command } from 'commander';
import { runCLI } from '@panguard-ai/panguard-guard';

export function guardCommand(): Command {
  const cmd = new Command('guard').description(
    'Guard engine management / \u5B88\u8B77\u5F15\u64CE\u7BA1\u7406'
  );

  cmd
    .command('start')
    .description('Start the guard engine / \u555F\u52D5\u5B88\u8B77\u5F15\u64CE')
    .option('--data-dir <path>', 'Data directory / \u8CC7\u6599\u76EE\u9304')
    .option('--verbose', 'Verbose output (show all event logs) / \u8A73\u7D30\u8F38\u51FA', false)
    .action(async (opts: { dataDir?: string; verbose: boolean }) => {
      const args = ['start'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      if (opts.verbose) args.push('--verbose');
      await runCLI(args);
    });

  cmd
    .command('stop')
    .description('Stop the guard engine / \u505C\u6B62\u5B88\u8B77\u5F15\u64CE')
    .option('--data-dir <path>', 'Data directory / \u8CC7\u6599\u76EE\u9304')
    .action(async (opts: { dataDir?: string }) => {
      const args = ['stop'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      await runCLI(args);
    });

  cmd
    .command('status')
    .description('Show engine status / 顯示引擎狀態')
    .option('--data-dir <path>', 'Data directory / 資料目錄')
    .action(async (opts: { dataDir?: string }) => {
      const args = ['status'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      await runCLI(args);
    });

  cmd
    .command('config')
    .description('Show current configuration / 顯示當前配置')
    .option('--data-dir <path>', 'Data directory / 資料目錄')
    .action(async (opts: { dataDir?: string }) => {
      const args = ['config'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      await runCLI(args);
    });

  cmd
    .command('generate-key [tier]')
    .description('Generate a test license key / 產生測試授權金鑰')
    .action(async (tier?: string) => {
      const args = ['generate-key'];
      if (tier) args.push(tier);
      await runCLI(args);
    });

  cmd
    .command('install')
    .description('Install as system service / 安裝為系統服務')
    .option('--data-dir <path>', 'Data directory / 資料目錄')
    .action(async (opts: { dataDir?: string }) => {
      const args = ['install'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      await runCLI(args);
    });

  cmd
    .command('uninstall')
    .description('Remove system service / 移除系統服務')
    .action(async () => {
      await runCLI(['uninstall']);
    });

  return cmd;
}
