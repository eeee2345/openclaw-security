/**
 * `panguard upgrade` - All features are free and open source
 * `panguard upgrade` - 所有功能皆免費開源
 *
 * Informs users that all features are available at no cost.
 *
 * @module @panguard-ai/panguard/cli/commands/upgrade
 */

import { Command } from 'commander';

export function upgradeCommand(): Command {
  const cmd = new Command('upgrade')
    .description('Upgrade your plan / 升級方案')
    .option('--lang <language>', 'Language override')
    .action(async (_opts: { lang?: string }) => {
      console.log('All Panguard features are free and open source.');
      console.log('Visit https://github.com/panguard-ai/panguard-ai for more info.');
    });

  cmd
    .command('portal')
    .description('Open subscription management portal / 開啟訂閱管理')
    .action(async () => {
      console.log('All Panguard features are free and open source.');
      console.log('Visit https://github.com/panguard-ai/panguard-ai for more info.');
    });

  cmd
    .command('status')
    .description('Check billing status / 查看帳單狀態')
    .action(async () => {
      console.log('All Panguard features are free and open source.');
      console.log('Visit https://github.com/panguard-ai/panguard-ai for more info.');
    });

  return cmd;
}

