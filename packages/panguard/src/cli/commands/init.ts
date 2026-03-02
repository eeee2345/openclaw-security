/**
 * `panguard init` - Interactive setup wizard
 * `panguard init` - 互動式設定精靈
 *
 * @module @panguard-ai/panguard/cli/commands/init
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spinner } from '@panguard-ai/core';
import { runInitWizard, writeConfig, validateConfigSchema } from '../../init/index.js';
import type { PanguardConfig } from '../../init/types.js';

export function initCommand(): Command {
  return new Command('init')
    .description('Interactive setup wizard / \u4E92\u52D5\u5F0F\u8A2D\u5B9A\u7CBE\u9748')
    .option('--lang <language>', 'Language: en or zh-TW')
    .option('--advanced', 'Full advanced wizard for power users / \u5B8C\u6574\u8A2D\u5B9A\u7CBE\u9748', false)
    .option('--config <path>', 'Import config from JSON file (non-interactive)')
    .action(async (opts: { lang?: string; config?: string; advanced: boolean }) => {
      if (opts.config) {
        // Non-interactive: import existing config file
        await importConfig(opts.config);
      } else {
        // Interactive wizard (default: quick, --advanced: full)
        await runInitWizard(opts.lang, opts.advanced);
      }
    });
}

async function importConfig(rawPath: string): Promise<void> {
  const sp = spinner('Importing configuration...');

  // Resolve to absolute path and validate extension
  const resolvedPath = resolve(rawPath);
  if (!resolvedPath.endsWith('.json')) {
    sp.fail('Config file must have a .json extension');
    return;
  }

  try {
    const json = readFileSync(resolvedPath, 'utf-8');
    const parsed: unknown = JSON.parse(json);

    if (!validateConfigSchema(parsed)) {
      sp.fail('Invalid configuration file: missing required fields (version, meta, organization, environment, security)');
      return;
    }

    const config = parsed as PanguardConfig;
    const outputPath = writeConfig(config);
    sp.succeed(`Configuration imported to ${outputPath}`);
  } catch (err) {
    sp.fail(`Failed to import: ${err instanceof Error ? err.message : String(err)}`);
  }
}
