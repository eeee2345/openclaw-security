/**
 * `panguard init` - Interactive setup wizard
 * `panguard init` - 互動式設定精靈
 *
 * @module @panguard-ai/panguard/cli/commands/init
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { spinner } from '@panguard-ai/core';
import { runInitWizard, writeConfig } from '../../init/index.js';
import type { PanguardConfig } from '../../init/types.js';

export function initCommand(): Command {
  return new Command('init')
    .description('Interactive setup wizard / \u4E92\u52D5\u5F0F\u8A2D\u5B9A\u7CBE\u9748')
    .option('--lang <language>', 'Language: en or zh-TW')
    .option('--config <path>', 'Import config from JSON file (non-interactive)')
    .action(async (opts: { lang?: string; config?: string }) => {
      if (opts.config) {
        // Non-interactive: import existing config file
        await importConfig(opts.config);
      } else {
        // Interactive wizard
        await runInitWizard(opts.lang);
      }
    });
}

async function importConfig(configPath: string): Promise<void> {
  const sp = spinner('Importing configuration...');

  try {
    const json = readFileSync(configPath, 'utf-8');
    const config = JSON.parse(json) as PanguardConfig;

    if (!config.version || !config.organization) {
      sp.fail('Invalid configuration file format');
      return;
    }

    const outputPath = writeConfig(config);
    sp.succeed(`Configuration imported to ${outputPath}`);
  } catch (err) {
    sp.fail(`Failed to import: ${err instanceof Error ? err.message : String(err)}`);
  }
}
