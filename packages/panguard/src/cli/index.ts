#!/usr/bin/env node
/**
 * Panguard AI - Unified CLI
 * Panguard AI - 統一命令列介面
 *
 * Single entry point for all Panguard security tools.
 * 所有 Panguard 資安工具的統一入口。
 *
 * @module @panguard-ai/panguard/cli
 */

import { Command } from 'commander';
import { PANGUARD_VERSION } from '../index.js';
import { scanCommand } from './commands/scan.js';
import { guardCommand } from './commands/guard.js';
import { reportCommand } from './commands/report.js';
import { chatCommand } from './commands/chat.js';
import { trapCommand } from './commands/trap.js';
import { threatCommand } from './commands/threat.js';
import { demoCommand } from './commands/demo.js';
import { initCommand } from './commands/init.js';
import { deployCommand } from './commands/deploy.js';
import { statusCommand } from './commands/status.js';
import { loginCommand } from './commands/login.js';
import { logoutCommand } from './commands/logout.js';
import { whoamiCommand } from './commands/whoami.js';
import { serveCommand } from './commands/serve.js';
import { adminCommand } from './commands/admin.js';
import { startInteractive } from './interactive.js';
import { refreshTierInBackground } from './auth-guard.js';

const program = new Command();

program
  .name('panguard')
  .description('Panguard AI - Unified Security Platform / 統一資安平台')
  .version(PANGUARD_VERSION);

program.addCommand(scanCommand());
program.addCommand(guardCommand());
program.addCommand(reportCommand());
program.addCommand(chatCommand());
program.addCommand(trapCommand());
program.addCommand(threatCommand());
program.addCommand(demoCommand());
program.addCommand(initCommand());
program.addCommand(deployCommand());
program.addCommand(statusCommand());
program.addCommand(loginCommand());
program.addCommand(logoutCommand());
program.addCommand(whoamiCommand());
program.addCommand(serveCommand());
program.addCommand(adminCommand());

// If no subcommand given (just `panguard` or `panguard --lang zh-TW`),
// launch interactive mode. Check before commander parses so that
// `panguard help` and `panguard --help` still work normally.
// Refresh tier from server in background (non-blocking)
refreshTierInBackground();

const userArgs = process.argv.slice(2);
const helpFlags = new Set(['-h', '--help', '-V', '--version']);
const hasSubcommand = userArgs.some(a => !a.startsWith('-'));
const hasHelpOrVersion = userArgs.some(a => helpFlags.has(a));

if (!hasSubcommand && !hasHelpOrVersion) {
  // Extract --lang value if present
  const langIdx = userArgs.indexOf('--lang');
  const lang = langIdx >= 0 ? userArgs[langIdx + 1] : undefined;
  startInteractive(lang).catch((err: unknown) => {
    console.error('Fatal error:', err instanceof Error ? err.message : err);
    process.exit(1);
  });
} else {
  program.parseAsync().catch((err: unknown) => {
    console.error('Fatal error:', err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
