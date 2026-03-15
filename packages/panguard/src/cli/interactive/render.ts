/**
 * Rendering functions for interactive CLI UI
 * @module @panguard-ai/panguard/cli/interactive/render
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { c, box } from '@panguard-ai/core';
import { PANGUARD_VERSION } from '../../index.js';
import { renderLogo, theme } from '../theme.js';
import { moduleCountDisplay } from '../ux-helpers.js';
import type { Lang } from '../menu.js';
import { MENU_DEFS } from './menu-defs.js';

// ---------------------------------------------------------------------------
// Guard process helpers
// ---------------------------------------------------------------------------

export function isGuardRunning(): { running: boolean; pid?: number } {
  const pidPath = join(homedir(), '.panguard-guard', 'panguard-guard.pid');
  if (!existsSync(pidPath)) return { running: false };
  try {
    const pid = parseInt(readFileSync(pidPath, 'utf-8').trim(), 10);
    process.kill(pid, 0);
    return { running: true, pid };
  } catch {
    return { running: false };
  }
}

// ---------------------------------------------------------------------------
// MCP detection helper
// ---------------------------------------------------------------------------

export async function isMCPConfigured(): Promise<boolean> {
  try {
    const mcpConfig = await import('@panguard-ai/panguard-mcp/config');
    const platforms = await mcpConfig.detectPlatforms();
    return platforms.some(
      (p: { detected: boolean; alreadyConfigured: boolean }) => p.detected && p.alreadyConfigured
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Status panel with box border
// ---------------------------------------------------------------------------

export function renderStatusPanel(lang: Lang): void {
  const guardStatus = isGuardRunning();
  const modulesValue = moduleCountDisplay(lang);

  const guardLine = guardStatus.running
    ? `${c.safe('PROTECTED')} ${c.dim(`(PID: ${guardStatus.pid})`)}`
    : c.dim('Inactive');

  const lines =
    lang === 'zh-TW'
      ? [
          `\u9632\u8B77\u72C0\u614B\uFF1A${guardLine}`,
          `\u53EF\u7528\u6A21\u7D44\uFF1A${modulesValue}`,
          `\u7248\u672C\uFF1A  v${PANGUARD_VERSION}`,
        ]
      : [
          `Protection: ${guardLine}`,
          `Modules:    ${modulesValue}`,
          `Version:    v${PANGUARD_VERSION}`,
        ];

  const title = lang === 'zh-TW' ? '\u7CFB\u7D71\u72C0\u614B / System Status' : 'System Status';
  console.log(box(lines.join('\n'), { borderColor: c.sage, title }));
}

// ---------------------------------------------------------------------------
// Menu rendering
// ---------------------------------------------------------------------------

export function renderMenu(lang: Lang): void {
  const titleText = lang === 'zh-TW' ? '\u4E3B\u9078\u55AE / Main Menu' : 'Main Menu';
  console.log(`         ${theme.title(titleText)}`);
  console.log('');

  for (const def of MENU_DEFS) {
    const name = lang === 'zh-TW' ? def.zh : def.en;
    const desc = lang === 'zh-TW' ? def.zhDesc : def.enDesc;
    const badge = def.tierBadge ? ` ${c.dim(def.tierBadge)}` : '';
    const iconStr = def.icon === '\u2713' ? c.safe(def.icon) : c.dim(def.icon);

    console.log(`  ${iconStr}  ${c.sage(`[${def.number}]`)}  ${name}${badge}`);
    console.log(`           ${c.dim(desc)}`);
    console.log('');
  }
}

// ---------------------------------------------------------------------------
// Footer shortcuts
// ---------------------------------------------------------------------------

export function renderFooter(lang: Lang): void {
  const quit = lang === 'zh-TW' ? '\u9000\u51FA' : 'Quit';
  const help = lang === 'zh-TW' ? '\u8AAA\u660E' : 'Help';
  const langToggle = '\u4E2D/EN';

  console.log(`${c.dim(`[q] ${quit}   [h] ${help}   [b] ${langToggle}`)}`);
  console.log('');
}

// ---------------------------------------------------------------------------
// Help display
// ---------------------------------------------------------------------------

export function showHelp(lang: Lang): void {
  console.log('');
  const title = lang === 'zh-TW' ? '\u6307\u4EE4\u8AAA\u660E' : 'Available Commands';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const menuTitle = lang === 'zh-TW' ? '\u4E3B\u9078\u55AE' : 'Main Menu';
  console.log(`  ${c.sage(menuTitle)}`);
  console.log(
    c.dim(
      lang === 'zh-TW'
        ? '  [0]-[8]  \u6309\u6578\u5B57\u9375\u5373\u523B\u9078\u64C7\uFF08\u4E0D\u9700\u6309 Enter\uFF09'
        : '  [0]-[8]  Press number key to select instantly (no Enter needed)'
    )
  );
  console.log('');

  const promptTitle = lang === 'zh-TW' ? '\u6587\u5B57\u6307\u4EE4' : 'Text Commands';
  console.log(`  ${c.sage(promptTitle)}`);

  const cmds = [
    { cmd: 'setup', en: 'Connect AI agents via MCP', zh: '\u900F\u904E MCP \u9023\u63A5 AI \u4EE3\u7406' },
    { cmd: 'audit', en: 'Audit AI agent skills', zh: '\u5BE9\u8A08 AI \u4EE3\u7406\u6280\u80FD' },
    { cmd: 'status', en: 'System status overview', zh: '\u7CFB\u7D71\u72C0\u614B\u7E3D\u89BD' },
    { cmd: 'config', en: 'Settings management', zh: '\u8A2D\u5B9A\u7BA1\u7406' },
    { cmd: 'hardening', en: 'Security hardening', zh: '\u5B89\u5168\u52A0\u56FA' },
    { cmd: 'doctor', en: 'Health diagnostics', zh: '\u5065\u5EB7\u8A3A\u65B7' },
    { cmd: 'help', en: 'Show this help', zh: '\u986F\u793A\u6B64\u8AAA\u660E' },
  ];

  for (const { cmd, en, zh } of cmds) {
    const desc = lang === 'zh-TW' ? zh : en;
    console.log(`  ${c.sage(cmd.padEnd(14))} ${c.dim(desc)}`);
  }

  const shortcutTitle = lang === 'zh-TW' ? '\u5FEB\u6377\u9375' : 'Shortcuts';
  console.log('');
  console.log(`  ${c.sage(shortcutTitle)}`);
  console.log(
    c.dim(
      `  [q] ${lang === 'zh-TW' ? '\u9000\u51FA' : 'Quit'}   [h] ${lang === 'zh-TW' ? '\u8AAA\u660E' : 'Help'}   [b] ${lang === 'zh-TW' ? '\u5207\u63DB\u8A9E\u8A00' : 'Toggle language'}`
    )
  );
  console.log('');
}

// ---------------------------------------------------------------------------
// Startup screen
// ---------------------------------------------------------------------------

export function renderStartup(lang: Lang): void {
  console.clear();
  renderLogo();
  console.log('');
  console.log(c.dim('  AI-Powered Security Platform'));
  console.log('');
  renderStatusPanel(lang);
  console.log('');
  renderMenu(lang);
  renderFooter(lang);
}
