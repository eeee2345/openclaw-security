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

import { existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
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
import { hardeningCommand } from './commands/hardening.js';
import { managerCommand } from './commands/manager.js';
import { upgradeCommand } from './commands/upgrade.js';
import { configCommand } from './commands/config.js';
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
program.addCommand(hardeningCommand());
program.addCommand(managerCommand());
program.addCommand(upgradeCommand());
program.addCommand(configCommand());

// ---------------------------------------------------------------------------
// First-run welcome banner (shown once, then a marker file is created)
// ---------------------------------------------------------------------------
function showWelcomeIfFirstRun(): void {
  const pgDir = join(homedir(), '.panguard');
  const marker = join(pgDir, '.welcome-shown');
  if (existsSync(marker)) return;
  try {
    if (!existsSync(pgDir)) mkdirSync(pgDir, { recursive: true });
    writeFileSync(marker, PANGUARD_VERSION, 'utf-8');
  } catch {
    // non-fatal — skip banner if we can't write marker
    return;
  }
  const G = '\x1b[32m\x1b[1m';
  const R = '\x1b[0m';
  const D = '\x1b[2m';
  const C = '\x1b[36m';
  const B = '\x1b[1m';
  console.log(`
${G}  ____                                      _     _    _${R}
${G} |  _ \\ __ _ _ __   __ _ _   _  __ _ _ __ __| |   / \\  |_|${R}
${G} | |_) / _\` | '_ \\ / _\` | | | |/ _\` | '__/ _\` |  / _ \\  | |${R}
${G} |  __/ (_| | | | | (_| | |_| | (_| | | | (_| | / ___ \\ | |${R}
${G} |_|   \\__,_|_| |_|\\__, |\\__,_|\\__,_|_|  \\__,_|/_/   \\_\\|_|${R}
${G}                    |___/${R}
${D}  AI-Powered Endpoint Security v${PANGUARD_VERSION}${R}

${B}  Welcome to Panguard AI!${R} Get started:

${C}    panguard scan${R}          ${D}Run a security scan on this machine${R}
${C}    panguard guard start${R}   ${D}Start real-time threat monitoring${R}
${C}    panguard login${R}         ${D}Log in to your Panguard account${R}
${C}    panguard --help${R}        ${D}Show all available commands${R}

${D}  Docs: https://panguard.ai/docs/getting-started${R}
`);
}

showWelcomeIfFirstRun();

// Refresh tier from server in background (non-blocking)
refreshTierInBackground();

const userArgs = process.argv.slice(2);
const helpFlags = new Set(['-h', '--help', '-V', '--version']);
const hasSubcommand = userArgs.some((a) => !a.startsWith('-'));
const hasHelpOrVersion = userArgs.some((a) => helpFlags.has(a));

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
