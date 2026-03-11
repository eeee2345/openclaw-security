/**
 * Panguard AI - Interactive CLI Mode
 *
 * Number-key menu [0]-[8] with panguard > prompt for text commands.
 * Box-bordered status panel, breadcrumb navigation, no "press any key" interrupts.
 *
 * @module @panguard-ai/panguard/cli/interactive
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { c, spinner, colorSeverity, formatDuration, box } from '@panguard-ai/core';
import { PANGUARD_VERSION } from '../index.js';
import { renderLogo, theme } from './theme.js';
import {
  waitForMainInput,
  pressAnyKey,
  cleanupTerminal,
  renderCompactMenu,
  waitForCompactChoice,
} from './menu.js';
import type { MenuItem, Lang } from './menu.js';
import { checkFeatureAccess, showUpgradePrompt, getLicense } from './auth-guard.js';
import { breadcrumb, nextSteps, confirmDestructive, moduleCountDisplay, formatError } from './ux-helpers.js';

// ---------------------------------------------------------------------------
// Language management
// ---------------------------------------------------------------------------

const CONFIG_DIR = join(homedir(), '.panguard');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

function detectLang(): Lang {
  if (existsSync(CONFIG_PATH)) {
    try {
      const data = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
      if (data.lang === 'zh-TW' || data.lang === 'en') return data.lang;
    } catch {
      /* ignore */
    }
  }
  const sysLang = process.env['LANG'] ?? process.env['LC_ALL'] ?? '';
  if (sysLang.includes('zh')) return 'zh-TW';
  return 'en';
}

function saveLang(lang: Lang): void {
  try {
    let config: Record<string, unknown> = {};
    if (existsSync(CONFIG_PATH)) {
      config = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
    }
    config['lang'] = lang;
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  } catch {
    /* best effort */
  }
}

let currentLang: Lang = 'en';

// ---------------------------------------------------------------------------
// Menu definitions — 9 core items matching the redesigned UI
// ---------------------------------------------------------------------------

interface MenuDef {
  key: string;
  icon: string;
  number: number;
  en: string;
  zh: string;
  enDesc: string;
  zhDesc: string;
  tierBadge: string; // Display badge (all features free, always '')
  featureKey: string; // Key for FEATURE_TIER gating
}

const MENU_DEFS: MenuDef[] = [
  {
    key: 'setup',
    icon: '>',
    number: 0,
    en: 'Setup Wizard',
    zh: '\u521D\u59CB\u8A2D\u5B9A',
    enDesc: 'Configure all modules with guided setup',
    zhDesc: '\u958B\u555F\u6B64\u5F15\u64CE\uFF0C\u81EA\u52D5\u914D\u7F6E\u6240\u6709\u6A21\u7D44',
    tierBadge: '',
    featureKey: 'setup',
  },
  {
    key: 'scan',
    icon: '\u26A1',
    number: 1,
    en: 'Security Scan',
    zh: '\u5B89\u5168\u6383\u63CF',
    enDesc: 'Scan system security and analyze risks',
    zhDesc: '\u6383\u63CF\u7CFB\u7D71\u5B89\u5168\u72C0\u614B\uFF0C\u5206\u6790\u6240\u6709\u98A8\u96AA',
    tierBadge: '',
    featureKey: 'scan',
  },
  {
    key: 'report',
    icon: '\u25A0',
    number: 2,
    en: 'Compliance Report [Coming Soon]',
    zh: '\u5408\u898F\u5831\u544A [\u5373\u5C07\u63A8\u51FA]',
    enDesc: 'ISO 27001, SOC 2, TW Cyber Security Act — under development',
    zhDesc: 'ISO 27001\u3001SOC 2\u3001\u8CC7\u5B89\u7BA1\u7406\u6CD5 \u2014 \u958B\u767C\u4E2D',
    tierBadge: '',
    featureKey: 'report',
  },
  {
    key: 'guard',
    icon: '\u2713',
    number: 3,
    en: 'Guard Engine',
    zh: '\u5B88\u8B77\u5F15\u64CE',
    enDesc: 'Real-time monitoring and continuous protection',
    zhDesc: '\u5373\u6642\u76E3\u63A7\u9023\u7E8C\u9632\u8B77\u7CFB\u7D71',
    tierBadge: '',
    featureKey: 'guard',
  },
  {
    key: 'trap',
    icon: '\u00B7',
    number: 4,
    en: 'Honeypot System [Coming Soon]',
    zh: '\u871C\u7F50\u7CFB\u7D71 [\u5373\u5C07\u63A8\u51FA]',
    enDesc: 'Decoy services to detect attackers — under development',
    zhDesc: '\u8A98\u990C\u670D\u52D9\u5075\u6E2C\u653B\u64CA\u8005 \u2014 \u958B\u767C\u4E2D',
    tierBadge: '',
    featureKey: 'trap',
  },
  {
    key: 'notify',
    icon: '\u00B7',
    number: 5,
    en: 'Notifications',
    zh: '\u901A\u77E5\u7CFB\u7D71',
    enDesc: 'LINE, Telegram, Slack, Email, Webhook channels',
    zhDesc: 'LINE\u3001Telegram\u3001Slack\u3001Email\u3001Webhook \u901A\u77E5\u7BA1\u9053',
    tierBadge: '',
    featureKey: 'notify',
  },
  {
    key: 'threat-cloud',
    icon: '\u00B7',
    number: 6,
    en: 'Threat Cloud',
    zh: '\u5A01\u8105\u60C5\u5831',
    enDesc: 'Threat intelligence REST API server',
    zhDesc: '\u5A01\u8105\u60C5\u5831 REST API \u4F3A\u670D\u52D9',
    tierBadge: '',
    featureKey: 'threat-cloud',
  },
  {
    key: 'demo',
    icon: '\u00B7',
    number: 7,
    en: 'Auto Demo',
    zh: '\u81EA\u52D5\u5C55\u793A',
    enDesc: 'Run through all security modules',
    zhDesc: '\u81EA\u52D5\u57F7\u884C\u7D9C\u5408\u529F\u80FD\u5C55\u793A',
    tierBadge: '',
    featureKey: 'demo',
  },
  {
    key: 'audit',
    icon: '\u25A0',
    number: 8,
    en: 'Skill Auditor',
    zh: '\u6280\u80FD\u5BE9\u8A08',
    enDesc: 'Audit AI agent skills for security issues',
    zhDesc: '\u5BE9\u8A08 AI \u4EE3\u7406\u6280\u80FD\u7684\u5B89\u5168\u554F\u984C',
    tierBadge: '',
    featureKey: 'audit',
  },
];

// ---------------------------------------------------------------------------
// MCP detection helper
// ---------------------------------------------------------------------------

async function isMCPConfigured(): Promise<boolean> {
  try {
    const mcpConfig = await import('@panguard-ai/panguard-mcp/config');
    const platforms = await mcpConfig.detectPlatforms();
    return platforms.some((p: { detected: boolean; alreadyConfigured: boolean }) => p.detected && p.alreadyConfigured);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Guard process helpers
// ---------------------------------------------------------------------------

function isGuardRunning(): { running: boolean; pid?: number } {
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
// Status panel with box border
// ---------------------------------------------------------------------------

function renderStatusPanel(): void {
  const guardStatus = isGuardRunning();
  const modulesValue = moduleCountDisplay(currentLang);

  const guardLine = guardStatus.running
    ? `${c.safe('PROTECTED')} ${c.dim(`(PID: ${guardStatus.pid})`)}`
    : c.dim('Inactive');

  const lines =
    currentLang === 'zh-TW'
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

  const title =
    currentLang === 'zh-TW'
      ? '\u7CFB\u7D71\u72C0\u614B / System Status'
      : 'System Status';

  console.log(box(lines.join('\n'), { borderColor: c.sage, title }));
}

// ---------------------------------------------------------------------------
// Menu rendering
// ---------------------------------------------------------------------------

function renderMenu(): void {
  const titleText =
    currentLang === 'zh-TW'
      ? '\u4E3B\u9078\u55AE / Main Menu'
      : 'Main Menu';
  console.log(`         ${theme.title(titleText)}`);
  console.log('');

  for (const def of MENU_DEFS) {
    const name = currentLang === 'zh-TW' ? def.zh : def.en;
    const desc = currentLang === 'zh-TW' ? def.zhDesc : def.enDesc;
    const badge = def.tierBadge ? ` ${c.dim(def.tierBadge)}` : '';
    const iconStr = def.icon === '\u2713' ? c.safe(def.icon) : c.dim(def.icon);

    console.log(
      `  ${iconStr}  ${c.sage(`[${def.number}]`)}  ${name}${badge}`
    );
    console.log(`           ${c.dim(desc)}`);
    console.log('');
  }
}

// ---------------------------------------------------------------------------
// Footer shortcuts
// ---------------------------------------------------------------------------

function renderFooter(): void {
  const quit = currentLang === 'zh-TW' ? '\u9000\u51FA' : 'Quit';
  const help = currentLang === 'zh-TW' ? '\u8AAA\u660E' : 'Help';
  const langToggle = currentLang === 'zh-TW' ? '\u4E2D/EN' : '\u4E2D/EN';

  console.log(
    `${c.dim(`[q] ${quit}   [h] ${help}   [b] ${langToggle}`)}`
  );
  console.log('');
}

// ---------------------------------------------------------------------------
// Help display
// ---------------------------------------------------------------------------

function showHelp(): void {
  console.log('');
  const title =
    currentLang === 'zh-TW' ? '\u6307\u4EE4\u8AAA\u660E' : 'Available Commands';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const menuTitle = currentLang === 'zh-TW' ? '\u4E3B\u9078\u55AE' : 'Main Menu';
  console.log(`  ${c.sage(menuTitle)}`);
  console.log(
    c.dim(
      currentLang === 'zh-TW'
        ? '  [0]-[8]  \u6309\u6578\u5B57\u9375\u5373\u523B\u9078\u64C7\uFF08\u4E0D\u9700\u6309 Enter\uFF09'
        : '  [0]-[8]  Press number key to select instantly (no Enter needed)'
    )
  );
  console.log('');

  const promptTitle = currentLang === 'zh-TW' ? '\u6587\u5B57\u6307\u4EE4' : 'Text Commands';
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
    const desc = currentLang === 'zh-TW' ? zh : en;
    console.log(`  ${c.sage(cmd.padEnd(14))} ${c.dim(desc)}`);
  }

  const shortcutTitle =
    currentLang === 'zh-TW' ? '\u5FEB\u6377\u9375' : 'Shortcuts';
  console.log('');
  console.log(`  ${c.sage(shortcutTitle)}`);
  console.log(c.dim(`  [q] ${currentLang === 'zh-TW' ? '\u9000\u51FA' : 'Quit'}   [h] ${currentLang === 'zh-TW' ? '\u8AAA\u660E' : 'Help'}   [b] ${currentLang === 'zh-TW' ? '\u5207\u63DB\u8A9E\u8A00' : 'Toggle language'}`));
  console.log('');
}

// ---------------------------------------------------------------------------
// Startup screen
// ---------------------------------------------------------------------------

function renderStartup(): void {
  console.clear();

  // Brand logo
  renderLogo();
  console.log('');

  // Tagline + version
  const tagline = c.dim('  AI-Powered Security Platform');
  console.log(tagline);
  console.log('');

  // Status panel
  renderStatusPanel();
  console.log('');

  // Menu
  renderMenu();

  // Footer
  renderFooter();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function startInteractive(lang?: string): Promise<void> {
  currentLang = lang === 'en' ? 'en' : lang === 'zh-TW' ? 'zh-TW' : detectLang();

  const exit = () => {
    cleanupTerminal();
    const msg = currentLang === 'zh-TW' ? '\u611F\u8B1D\u4F7F\u7528 Panguard AI\uFF01' : 'Goodbye!';
    console.log(`\n  ${c.sage(msg)}\n`);
    process.exit(0);
  };
  process.on('SIGINT', exit);
  process.on('SIGTERM', exit);

  renderStartup();

  // First-time user hint — detect MCP status and guide user
  const mcpConfigured = await isMCPConfigured();
  if (!existsSync(CONFIG_PATH)) {
    console.log(
      currentLang === 'zh-TW'
        ? `  ${c.sage('\u25C6')} \u9996\u6B21\u4F7F\u7528\uFF1F\u5EFA\u8B70\u6D41\u7A0B\uFF1A`
        : `  ${c.sage('\u25C6')} First time? Recommended flow:`
    );
    console.log(
      currentLang === 'zh-TW'
        ? `    ${c.sage('[0]')} \u521D\u59CB\u8A2D\u5B9A \u2192 \u81EA\u52D5\u9023\u63A5 AI \u4EE3\u7406 + \u6280\u80FD\u5BE9\u8A08 + \u6383\u63CF`
        : `    ${c.sage('[0]')} Setup Wizard \u2192 auto-connect AI agents + skill audit + scan`
    );
    console.log(
      currentLang === 'zh-TW'
        ? `    ${c.sage('[8]')} \u6280\u80FD\u5BE9\u8A08 \u2192 \u5BE9\u8A08\u5DF2\u5B89\u88DD AI \u6280\u80FD\u7684\u5B89\u5168\u554F\u984C`
        : `    ${c.sage('[8]')} Skill Auditor \u2192 check installed AI skills for security issues`
    );
    console.log('');
  } else if (!mcpConfigured) {
    console.log(
      currentLang === 'zh-TW'
        ? `  ${c.sage('\u25C6')} AI \u4EE3\u7406\u5C1A\u672A\u9023\u63A5\u3002\u57F7\u884C ${c.sage('panguard setup')} \u6216\u6309 ${c.sage('[0]')} \u9023\u63A5 Claude Code\u3001Cursor \u7B49\u5E73\u53F0\u3002`
        : `  ${c.sage('\u25C6')} AI agents not connected. Run ${c.sage('panguard setup')} or press ${c.sage('[0]')} to connect Claude Code, Cursor, etc.`
    );
    console.log('');
  }

  // Main loop
  while (true) {
    const promptLabel = c.sage('panguard >') + ' ';
    process.stdout.write(promptLabel);

    const input = await waitForMainInput();

    switch (input.type) {
      case 'quit':
        exit();
        return;

      case 'help':
        showHelp();
        continue;

      case 'lang_toggle':
        currentLang = currentLang === 'zh-TW' ? 'en' : 'zh-TW';
        saveLang(currentLang);
        renderStartup();
        continue;

      case 'number': {
        const def = MENU_DEFS[input.index];
        if (!def) continue;

        // Feature gate check
        if (!checkFeatureAccess(def.featureKey)) {
          showUpgradePrompt(def.featureKey, currentLang);
          await new Promise((r) => setTimeout(r, 500));
          renderStartup();
          continue;
        }

        console.clear();
        try {
          await dispatch(def.key);
        } catch (err) {
          console.log('');
          console.log(
            formatError(
              err instanceof Error ? err.message : String(err),
              `${currentLang === 'zh-TW' ? '\u57F7\u884C' : 'Running'} ${def.key}`,
              currentLang === 'zh-TW'
                ? '\u8ACB\u67E5\u770B\u65E5\u8A8C\u6216\u91CD\u8A66'
                : 'Check logs or retry'
            )
          );
        }

        await new Promise((r) => setTimeout(r, 500));
        renderStartup();
        continue;
      }

      case 'command': {
        const text = input.text.toLowerCase();

        if (!text) continue;

        // Handle text commands
        const handled = await dispatchCommand(text);
        if (!handled) {
          console.log(
            c.dim(
              currentLang === 'zh-TW'
                ? `  \u672A\u77E5\u6307\u4EE4\u3002\u8F38\u5165 help \u67E5\u770B\u53EF\u7528\u6307\u4EE4\u3002`
                : `  Unknown command. Type 'help' for available commands.`
            )
          );
          console.log('');
        }
        continue;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Prompt command dispatch
// ---------------------------------------------------------------------------

async function dispatchCommand(text: string): Promise<boolean> {
  switch (text) {
    case 'status':
      console.clear();
      await actionStatus();
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;

    case 'login':
    case 'logout': {
      console.clear();
      console.log('');
      console.log('  Authentication removed. All features are free and open source.');
      console.log('');
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;
    }

    case 'config':
      console.clear();
      await actionConfig();
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;

    case 'upgrade': {
      console.clear();
      console.log('');
      console.log('  All features are free and open source.');
      console.log('');
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;
    }

    case 'hardening':
      console.clear();
      await actionHardening();
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;

    case 'doctor':
      console.clear();
      try {
        const { runDoctor } = await import('./commands/doctor.js');
        await runDoctor(currentLang);
      } catch (err) {
        console.log(
          formatError(
            err instanceof Error ? err.message : String(err),
            currentLang === 'zh-TW' ? '\u57F7\u884C\u5065\u5EB7\u8A3A\u65B7' : 'Running diagnostics',
            currentLang === 'zh-TW' ? '\u8ACB\u91CD\u8A66' : 'Please retry'
          )
        );
      }
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;

    case 'whoami': {
      console.clear();
      console.log('');
      console.log('  All features available (no login required).');
      console.log('');
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;
    }

    case 'audit':
      console.clear();
      await actionAudit();
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;

    case 'setup': {
      console.clear();
      await actionMCPSetup();
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;
    }

    case 'help':
      showHelp();
      return true;

    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Action dispatch (from numbered menu)
// ---------------------------------------------------------------------------

async function dispatch(key: string): Promise<void> {
  switch (key) {
    case 'setup':
      await actionInit();
      break;
    case 'scan':
      await actionScan();
      break;
    case 'report':
      await actionReport();
      break;
    case 'guard':
      await actionGuard();
      break;
    case 'trap':
      await actionTrap();
      break;
    case 'notify':
      await actionChat();
      break;
    case 'threat-cloud':
      await actionThreat();
      break;
    case 'demo':
      await actionDemo();
      break;
    case 'audit':
      await actionAudit();
      break;
  }
}

// ---------------------------------------------------------------------------
// [0] Setup Wizard
// ---------------------------------------------------------------------------

async function actionInit(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u521D\u59CB\u8A2D\u5B9A' : 'Setup']);
  const { runInitWizard } = await import('../init/index.js');
  await runInitWizard(currentLang);
}

// ---------------------------------------------------------------------------
// Text command: setup (MCP-only, for users who already have config)
// ---------------------------------------------------------------------------

async function actionMCPSetup(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? 'MCP \u8A2D\u5B9A' : 'MCP Setup']);
  const title = currentLang === 'zh-TW' ? 'AI \u4EE3\u7406\u9023\u63A5 (MCP)' : 'AI Agent Connection (MCP)';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const { spinner: sp } = await import('@panguard-ai/core');

  const detectSp = sp(
    currentLang === 'zh-TW'
      ? '\u6B63\u5728\u5075\u6E2C AI \u4EE3\u7406\u5E73\u53F0...'
      : 'Detecting AI agent platforms...'
  );

  try {
    const mcpConfig = await import('@panguard-ai/panguard-mcp/config');
    const platforms = await mcpConfig.detectPlatforms();
    const detected = platforms.filter((p: { detected: boolean }) => p.detected);
    const unconfigured = detected.filter((p: { alreadyConfigured: boolean }) => !p.alreadyConfigured);

    if (detected.length === 0) {
      detectSp.warn(
        currentLang === 'zh-TW'
          ? '\u672A\u5075\u6E2C\u5230\u4EFB\u4F55 AI \u4EE3\u7406\u5E73\u53F0'
          : 'No AI agent platforms detected'
      );
      console.log('');
      console.log(c.dim(
        currentLang === 'zh-TW'
          ? '  \u652F\u63F4\u5E73\u53F0: Claude Code, Cursor, OpenClaw, Codex, WorkBuddy, NemoClaw, Claude Desktop'
          : '  Supported: Claude Code, Cursor, OpenClaw, Codex, WorkBuddy, NemoClaw, Claude Desktop'
      ));
      return;
    }

    detectSp.succeed(
      currentLang === 'zh-TW'
        ? `\u5075\u6E2C\u5230 ${detected.length} \u500B\u5E73\u53F0`
        : `Found ${detected.length} platform(s)`
    );
    console.log('');

    // Show all platforms
    for (const p of platforms) {
      const status = p.detected
        ? p.alreadyConfigured
          ? c.safe('\u2713 configured')
          : c.caution('~ not configured')
        : c.dim('- not found');
      console.log(`  ${p.detected ? c.bold(p.name) : c.dim(p.name)}  ${status}`);
    }
    console.log('');

    if (unconfigured.length === 0) {
      console.log(c.safe(
        currentLang === 'zh-TW'
          ? `  \u2713 \u6240\u6709\u5E73\u53F0\u5DF2\u8A2D\u5B9A\u5B8C\u6210\uFF01`
          : '  \u2713 All platforms already configured!'
      ));
      console.log('');
      console.log(c.dim(
        currentLang === 'zh-TW'
          ? '  \u91CD\u555F AI \u4EE3\u7406\u5F8C\uFF0C\u8ACB\u6C42\u300Cpanguard_status\u300D\u5373\u53EF\u9A57\u8B49\u3002'
          : '  Restart your AI agent, then ask "panguard_status" to verify.'
      ));
      return;
    }

    // Configure unconfigured platforms
    const configSp = sp(
      currentLang === 'zh-TW'
        ? `\u6B63\u5728\u8A2D\u5B9A ${unconfigured.length} \u500B\u5E73\u53F0...`
        : `Configuring ${unconfigured.length} platform(s)...`
    );

    let successCount = 0;
    for (const p of unconfigured) {
      const result = mcpConfig.injectMCPConfig(p.id);
      if (result.success) successCount++;
    }

    if (successCount === unconfigured.length) {
      configSp.succeed(
        currentLang === 'zh-TW'
          ? `${successCount} \u500B\u5E73\u53F0\u8A2D\u5B9A\u5B8C\u6210`
          : `${successCount} platform(s) configured`
      );
    } else {
      configSp.warn(
        currentLang === 'zh-TW'
          ? `${successCount}/${unconfigured.length} \u5E73\u53F0\u8A2D\u5B9A\u6210\u529F`
          : `${successCount}/${unconfigured.length} platform(s) configured`
      );
    }

    console.log('');
    console.log(c.dim(
      currentLang === 'zh-TW'
        ? '  \u91CD\u555F AI \u4EE3\u7406\u5F8C\u5373\u53EF\u4F7F\u7528 11 \u500B panguard_* MCP \u5DE5\u5177\uFF1A'
        : '  Restart your AI agent to use 11 panguard_* MCP tools:'
    ));

    // Platform-specific restart instructions
    const restartHints: Record<string, { en: string; zh: string }> = {
      'claude-code': { en: 'Close and reopen your terminal', zh: '\u95DC\u9589\u4E26\u91CD\u65B0\u958B\u555F\u7D42\u7AEF\u6A5F' },
      'claude-desktop': { en: 'Quit and reopen Claude Desktop', zh: '\u9000\u51FA\u4E26\u91CD\u65B0\u958B\u555F Claude Desktop' },
      cursor: { en: 'Cmd+Shift+P (or Ctrl+Shift+P) > "Reload Window"', zh: 'Cmd+Shift+P > "Reload Window"' },
      openclaw: { en: 'Close and reopen OpenClaw', zh: '\u95DC\u9589\u4E26\u91CD\u65B0\u958B\u555F OpenClaw' },
      codex: { en: 'Restart the Codex CLI session', zh: '\u91CD\u65B0\u555F\u52D5 Codex CLI' },
      workbuddy: { en: 'Close and reopen WorkBuddy', zh: '\u95DC\u9589\u4E26\u91CD\u65B0\u958B\u555F WorkBuddy' },
      nemoclaw: { en: 'Close and reopen NemoClaw', zh: '\u95DC\u9589\u4E26\u91CD\u65B0\u958B\u555F NemoClaw' },
    };
    for (const p of unconfigured) {
      const hint = restartHints[p.id];
      const text = hint
        ? (currentLang === 'zh-TW' ? hint.zh : hint.en)
        : (currentLang === 'zh-TW' ? '\u91CD\u65B0\u555F\u52D5\u61C9\u7528\u7A0B\u5F0F' : 'Restart the application');
      console.log(c.dim(`    ${p.name}: ${text}`));
    }

    console.log('');
    console.log(c.dim(
      currentLang === 'zh-TW'
        ? '  \u8A66\u8A66\u554F AI: \u300C\u5BE9\u8A08\u9019\u500B\u5C08\u6848\u7684\u6280\u80FD\u300D\u6216\u300C\u6383\u63CF\u6211\u7684\u7CFB\u7D71\u300D'
        : '  Try asking your AI: "audit the skills in this project" or "scan my system"'
    ));
  } catch (err) {
    detectSp.fail(
      currentLang === 'zh-TW'
        ? 'MCP \u8A2D\u5B9A\u5931\u6557'
        : 'MCP setup failed'
    );
    console.log(
      formatError(
        err instanceof Error ? err.message : String(err),
        'MCP Setup',
        currentLang === 'zh-TW' ? '\u8ACB\u91CD\u8A66' : 'Please retry'
      )
    );
  }
}

// ---------------------------------------------------------------------------
// [1] Security Scan
// ---------------------------------------------------------------------------

async function actionScan(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Security Scan']);
  const scanTitle = currentLang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Security Scan';
  console.log(`  ${theme.brandBold(scanTitle)}`);
  console.log('');

  const depthItems: MenuItem[] = [
    {
      key: '1',
      label:
        currentLang === 'zh-TW'
          ? '\u5FEB\u901F\u6383\u63CF (~30 \u79D2)'
          : 'Quick Scan (~30 seconds)',
    },
    {
      key: '2',
      label: currentLang === 'zh-TW' ? '\u5B8C\u6574\u6383\u63CF' : 'Full Scan',
    },
  ];

  renderCompactMenu(currentLang === 'zh-TW' ? '\u6383\u63CF\u6A21\u5F0F' : 'Scan Mode', depthItems);

  const choice = await waitForCompactChoice(depthItems, currentLang);
  if (!choice) return;

  const depth = choice.key === '1' ? 'quick' : 'full';
  console.log('');

  const { runScan } = await import('@panguard-ai/panguard-scan');
  const sp = spinner(
    currentLang === 'zh-TW'
      ? '\u6B63\u5728\u6383\u63CF\u7CFB\u7D71\u5B89\u5168...'
      : 'Scanning system...'
  );
  const result = await runScan({ depth, lang: currentLang, verbose: false });
  sp.succeed(
    currentLang === 'zh-TW'
      ? `\u6383\u63CF\u5B8C\u6210 ${c.dim(`(${formatDuration(result.scanDuration)})`)}`
      : `Scan complete ${c.dim(`(${formatDuration(result.scanDuration)})`)}`
  );

  const safetyScore = Math.max(0, 100 - result.riskScore);
  const grade =
    safetyScore >= 90
      ? 'A'
      : safetyScore >= 75
        ? 'B'
        : safetyScore >= 60
          ? 'C'
          : safetyScore >= 40
            ? 'D'
            : 'F';

  console.log('');
  const scoreLabel = currentLang === 'zh-TW' ? '\u6383\u63CF\u5B8C\u6210' : 'Scan Complete';
  console.log(
    `  ${theme.title(scoreLabel)}${' '.repeat(30)}Score: ${c.bold(`${safetyScore}/100`)} (${grade})`
  );
  console.log('');

  const { tier } = getLicense();
  let fixableCount = 0;

  if (result.findings.length > 0) {
    for (const f of result.findings) {
      const sev = colorSeverity(f.severity).padEnd(10);
      console.log(`  ${sev} ${f.title}`);

      // Show description if available
      if (f.description) {
        console.log(c.dim(`          ${f.description}`));
      }

      if (f.manualFix && f.manualFix.length > 0) {
        const fixLabel = currentLang === 'zh-TW' ? '\u4FEE\u5FA9:' : 'Fix:';
        console.log(c.dim(`          ${fixLabel}`));
        for (const cmd of f.manualFix) {
          console.log(c.dim(`          $ ${cmd}`));
        }
        fixableCount++;
      } else if (f.remediation) {
        // Show recommendation even if no auto-fix command
        const recLabel = currentLang === 'zh-TW' ? '\u5EFA\u8B70:' : 'Recommendation:';
        console.log(c.dim(`          ${recLabel} ${f.remediation}`));
      }
    }
    console.log('');

    const issuesText =
      currentLang === 'zh-TW'
        ? `${result.findings.length} \u500B\u554F\u984C`
        : `${result.findings.length} issue(s) found`;
    console.log(c.dim(`  ${issuesText}`));

    if (fixableCount > 0) {
      const upgradeLines =
        currentLang === 'zh-TW'
          ? [
              `\u53EF\u81EA\u52D5\u4FEE\u5FA9:`,
              `$ panguard scan --fix`,
            ]
          : [`Auto-fix available:`, `$ panguard scan --fix`];
      console.log('');
      console.log(box(upgradeLines.join('\n'), { borderColor: c.sage }));
    }
  } else {
    const noIssues =
      currentLang === 'zh-TW'
        ? '\u672A\u767C\u73FE\u5B89\u5168\u554F\u984C'
        : 'No security issues found';
    console.log(`  ${c.safe(noIssues)}`);
  }

  // Agent auto-suggestion: offer to activate Guard if not running
  const guardRunning = isGuardRunning().running;
  if (!guardRunning) {
    console.log('');
    const agentMsg = currentLang === 'zh-TW'
      ? `${c.sage('\u25C6')} \u5373\u6642\u9632\u8B77\u5C1A\u672A\u555F\u52D5\u3002\u8981\u73FE\u5728\u555F\u7528\u55CE\uFF1F`
      : `${c.sage('\u25C6')} Real-time protection is not active. Enable now?`;
    console.log(`  ${agentMsg}`);

    const guardItems: MenuItem[] = [
      { key: '1', label: currentLang === 'zh-TW' ? '\u662F\uFF0C\u555F\u52D5 Guard \u9632\u8B77' : 'Yes, start Guard protection' },
      { key: '2', label: currentLang === 'zh-TW' ? '\u5BE9\u8A08\u5DF2\u5B89\u88DD\u6280\u80FD\u7684\u5B89\u5168\u5A01\u8105' : 'Audit installed skills for threats' },
      { key: '3', label: currentLang === 'zh-TW' ? '\u4E0D\u7528\uFF0C\u56DE\u4E3B\u9078\u55AE' : 'No, return to main menu' },
    ];
    renderCompactMenu('', guardItems);
    const guardChoice = await waitForCompactChoice(guardItems, currentLang);
    if (guardChoice?.key === '1') {
      await actionGuard();
      return;
    }
    if (guardChoice?.key === '2') {
      await actionAudit();
      return;
    }
  } else {
    nextSteps(
      currentLang === 'zh-TW'
        ? [
            { cmd: '[8] \u6280\u80FD\u5BE9\u8A08', desc: '\u5BE9\u8A08\u5DF2\u5B89\u88DD\u6280\u80FD\u7684\u5B89\u5168\u5A01\u8105' },
            { cmd: 'scan --full', desc: '\u57F7\u884C\u5B8C\u6574\u6383\u63CF' },
            { cmd: 'guard start', desc: '\u555F\u52D5\u5373\u6642\u9632\u8B77' },
          ]
        : [
            { cmd: '[8] Skill Auditor', desc: 'Audit installed skills for threats' },
            { cmd: 'scan --full', desc: 'Run a comprehensive scan' },
            { cmd: 'guard start', desc: 'Enable real-time protection' },
          ],
      currentLang
    );
  }
}

// ---------------------------------------------------------------------------
// [2] Compliance Report
// ---------------------------------------------------------------------------

async function actionReport(): Promise<void> {
  breadcrumb([
    'Panguard',
    currentLang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Compliance Report',
  ]);
  console.log('');
  if (currentLang === 'zh-TW') {
    console.log('  \u5408\u898F\u5831\u544A \u2014 \u5373\u5C07\u63A8\u51FA');
    console.log('');
    console.log('  ISO 27001\u3001SOC 2\u3001\u8CC7\u5B89\u7BA1\u7406\u6CD5\u5408\u898F\u5831\u544A\u529F\u80FD\u958B\u767C\u4E2D\u3002');
    console.log('  \u8FFD\u8E64\u9032\u5EA6: https://github.com/panguard-ai/panguard-ai');
  } else {
    console.log('  Compliance Report \u2014 Coming Soon');
    console.log('');
    console.log('  ISO 27001, SOC 2, and TW Cyber Security Act compliance');
    console.log('  reports are under active development.');
    console.log('  Follow progress: https://github.com/panguard-ai/panguard-ai');
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// [3] Guard Engine
// ---------------------------------------------------------------------------

async function actionGuard(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine']);
  const title = currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine';
  console.log(`  ${theme.brandBold(title)}`);

  const guardInfo = isGuardRunning();
  const guardRunning = guardInfo.running;
  const statusText = guardRunning
    ? c.safe(currentLang === 'zh-TW' ? '\u904B\u884C\u4E2D' : 'Running')
    : c.caution(currentLang === 'zh-TW' ? '\u672A\u904B\u884C' : 'Not running');
  console.log(`  ${c.dim(currentLang === 'zh-TW' ? '\u72C0\u614B' : 'Status')} ${statusText}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: currentLang === 'zh-TW' ? '\u555F\u52D5\u5F15\u64CE  Start' : 'Start' },
    { key: '2', label: currentLang === 'zh-TW' ? '\u505C\u6B62\u5F15\u64CE  Stop' : 'Stop' },
    { key: '3', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u72C0\u614B  Status' : 'Status' },
    { key: '4', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u65E5\u8A8C  Logs' : 'Logs' },
  ];

  renderCompactMenu(currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine', items);

  const choice = await waitForCompactChoice(items, currentLang);
  if (!choice) return;

  console.log('');
  const { runCLI } = await import('@panguard-ai/panguard-guard');

  switch (choice.key) {
    case '1': {
      // Start guard engine
      if (guardRunning) {
        console.log(
          `  ${c.safe('\u2713')} ${currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE\u5DF2\u5728\u904B\u884C\u4E2D' : 'Guard engine is already running'} ${c.dim(`(PID: ${guardInfo.pid})`)}`
        );
        nextSteps(
          currentLang === 'zh-TW'
            ? [
                { cmd: 'guard > \u67E5\u770B\u72C0\u614B', desc: '\u67E5\u770B\u8A73\u7D30\u72C0\u614B' },
                { cmd: 'guard > \u505C\u6B62\u5F15\u64CE', desc: '\u505C\u6B62\u9632\u8B77' },
              ]
            : [
                { cmd: 'guard > Status', desc: 'View detailed status' },
                { cmd: 'guard > Stop', desc: 'Stop protection' },
              ],
          currentLang
        );
        break;
      }

      // Show Guard capabilities
      console.log(`  ${c.sage('\u25C6')} Guard active${' '.repeat(30)}All Layers \u00B7 Free`);
      console.log('');
      if (currentLang === 'zh-TW') {
        console.log(`  ${c.safe('\u2713')} \u5DF2\u77E5\u653B\u64CA\u6A21\u5F0F\u81EA\u52D5\u5C01\u9396`);
        console.log(`  ${c.safe('\u2713')} Threat Cloud \u5A01\u8105\u60C5\u5831`);
        console.log(`  ${c.safe('\u2713')} AI \u5206\u6790`);
        console.log(`  ${c.safe('\u2713')} \u901A\u77E5\u7CFB\u7D71`);
        console.log(`  ${c.safe('\u2713')} \u65E5\u8A8C\u4FDD\u7559`);
      } else {
        console.log(`  ${c.safe('\u2713')} Auto-blocking for known attack patterns`);
        console.log(`  ${c.safe('\u2713')} Threat Cloud intelligence`);
        console.log(`  ${c.safe('\u2713')} AI analysis`);
        console.log(`  ${c.safe('\u2713')} Notifications`);
        console.log(`  ${c.safe('\u2713')} Log retention`);
      }
      console.log('');

      // Spawn guard as background process
      const { spawn: spawnProcess } = await import('node:child_process');
      const { fileURLToPath: toPath } = await import('node:url');

      const guardMainUrl = import.meta.resolve('@panguard-ai/panguard-guard');
      const guardCliScript = join(toPath(guardMainUrl), '..', 'cli', 'index.js');

      const guardDataDir = join(homedir(), '.panguard-guard');
      if (!existsSync(guardDataDir)) mkdirSync(guardDataDir, { recursive: true });
      const logPath = join(guardDataDir, 'guard.log');
      const logFd = openSync(logPath, 'a');

      const guardSp = spinner(
        currentLang === 'zh-TW'
          ? '\u6B63\u5728\u555F\u52D5\u5B88\u8B77\u5F15\u64CE...'
          : 'Starting guard engine...'
      );

      const child = spawnProcess(process.execPath, [guardCliScript, 'start'], {
        detached: true,
        stdio: ['ignore', logFd, logFd],
        env: { ...process.env },
      });
      child.unref();
      closeSync(logFd);

      // Wait for PID file to confirm startup
      const pidPath = join(guardDataDir, 'panguard-guard.pid');
      let started = false;
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        if (existsSync(pidPath)) {
          try {
            const newPid = parseInt(readFileSync(pidPath, 'utf-8').trim(), 10);
            process.kill(newPid, 0);
            started = true;
            break;
          } catch {
            /* not yet */
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 300));
      }

      if (started) {
        const newPid = parseInt(readFileSync(pidPath, 'utf-8').trim(), 10);
        guardSp.succeed(
          currentLang === 'zh-TW'
            ? '\u5B88\u8B77\u5F15\u64CE\u5DF2\u555F\u52D5'
            : 'Guard engine started'
        );
        console.log('');
        console.log(
          `  ${c.safe('\u2713')} ${currentLang === 'zh-TW' ? '\u7CFB\u7D71\u5DF2\u53D7\u4FDD\u8B77' : 'System is now protected'} ${c.dim(`(PID: ${newPid})`)}`
        );
        console.log(
          `  ${c.dim(currentLang === 'zh-TW' ? '  \u65E5\u8A8C: ~/.panguard-guard/guard.log' : '  Logs: ~/.panguard-guard/guard.log')}`
        );
      } else {
        guardSp.fail(
          currentLang === 'zh-TW'
            ? '\u5B88\u8B77\u5F15\u64CE\u555F\u52D5\u5931\u6557'
            : 'Failed to start guard engine'
        );
        console.log(
          `  ${c.dim(currentLang === 'zh-TW' ? '  \u67E5\u770B\u65E5\u8A8C: ~/.panguard-guard/guard.log' : '  Check logs: ~/.panguard-guard/guard.log')}`
        );
      }

      nextSteps(
        currentLang === 'zh-TW'
          ? [
              { cmd: 'scan', desc: '\u57F7\u884C\u5B89\u5168\u6383\u63CF' },
              { cmd: 'status', desc: '\u67E5\u770B\u7CFB\u7D71\u72C0\u614B' },
            ]
          : [
              { cmd: 'scan', desc: 'Run a security scan' },
              { cmd: 'status', desc: 'Check system status' },
            ],
        currentLang
      );
      break;
    }
    case '2': {
      const confirmed = await confirmDestructive(
        currentLang === 'zh-TW'
          ? '\u78BA\u5B9A\u8981\u505C\u6B62\u5373\u6642\u9632\u8B77\uFF1F'
          : 'Stop real-time protection?',
        currentLang
      );
      if (confirmed) {
        await runCLI(['stop']);
      } else {
        console.log(c.dim(currentLang === 'zh-TW' ? '  \u5DF2\u53D6\u6D88' : '  Cancelled'));
      }
      break;
    }
    case '3':
      await runCLI(['status']);
      break;
    case '4': {
      const logFilePath = join(homedir(), '.panguard-guard', 'guard.log');
      if (existsSync(logFilePath)) {
        const content = readFileSync(logFilePath, 'utf-8');
        const lines = content.trim().split('\n').slice(-30);
        console.log(c.dim(currentLang === 'zh-TW' ? '  \u6700\u8FD1 30 \u884C\u65E5\u8A8C:' : '  Last 30 log lines:'));
        console.log('');
        for (const line of lines) {
          console.log(`  ${c.dim(line)}`);
        }
      } else {
        console.log(c.dim(currentLang === 'zh-TW' ? '  \u5C1A\u7121\u65E5\u8A8C\u6A94\u6848' : '  No log file found'));
      }
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// [4] Honeypot System
// ---------------------------------------------------------------------------

async function actionTrap(): Promise<void> {
  breadcrumb([
    'Panguard',
    currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Honeypot System',
  ]);
  console.log('');
  if (currentLang === 'zh-TW') {
    console.log('  \u871C\u7F50\u7CFB\u7D71 \u2014 \u5373\u5C07\u63A8\u51FA');
    console.log('');
    console.log('  \u8A98\u990C\u670D\u52D9\uFF08SSH\u3001HTTP\u3001FTP\uFF09\u5075\u6E2C\u8207\u5206\u6790\u653B\u64CA\u8005\u529F\u80FD\u958B\u767C\u4E2D\u3002');
    console.log('  \u8FFD\u8E64\u9032\u5EA6: https://github.com/panguard-ai/panguard-ai');
  } else {
    console.log('  Honeypot System \u2014 Coming Soon');
    console.log('');
    console.log('  Decoy services (SSH, HTTP, FTP) to detect and profile');
    console.log('  attackers are under active development.');
    console.log('  Follow progress: https://github.com/panguard-ai/panguard-ai');
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// [5] Notifications
// ---------------------------------------------------------------------------

async function actionChat(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notifications']);
  const title = currentLang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notifications';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: currentLang === 'zh-TW' ? '\u8A2D\u5B9A\u901A\u77E5\u7BA1\u9053' : 'Setup Channels' },
    { key: '2', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u72C0\u614B' : 'Status' },
    { key: '3', label: currentLang === 'zh-TW' ? '\u6E2C\u8A66\u767C\u9001' : 'Test Send' },
  ];

  renderCompactMenu(currentLang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notifications', items);
  const choice = await waitForCompactChoice(items, currentLang);
  if (!choice) return;

  console.log('');
  const { runCLI: chatRunCLI } = await import('@panguard-ai/panguard-chat');

  switch (choice.key) {
    case '1':
      await chatRunCLI(['setup', '--lang', currentLang]);
      break;
    case '2':
      await chatRunCLI(['status']);
      break;
    case '3':
      await chatRunCLI(['config']);
      break;
  }
}

// ---------------------------------------------------------------------------
// [6] Threat Cloud
// ---------------------------------------------------------------------------

async function actionThreat(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u5A01\u8105\u60C5\u5831' : 'Threat Cloud']);
  const title = currentLang === 'zh-TW' ? '\u5A01\u8105\u60C5\u5831' : 'Threat Cloud';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const port = 8080;
  const net = await import('node:net');
  const portAvailable = await new Promise<boolean>((resolve) => {
    const tester = net.createServer();
    tester.once('error', () => resolve(false));
    tester.once('listening', () => {
      tester.close(() => resolve(true));
    });
    tester.listen(port, '127.0.0.1');
  });

  if (!portAvailable) {
    console.log(
      formatError(
        currentLang === 'zh-TW'
          ? `\u9023\u63A5\u57E0 ${port} \u5DF2\u88AB\u4F54\u7528`
          : `Port ${port} is already in use`,
        `Port ${port}`,
        currentLang === 'zh-TW'
          ? `\u91CB\u653E\u9023\u63A5\u57E0 ${port} \u5F8C\u518D\u8A66`
          : `Free port ${port} and try again`
      )
    );
    return;
  }

  console.log(
    c.dim(
      currentLang === 'zh-TW'
        ? `  \u5373\u5C07\u555F\u52D5\u5A01\u8105\u60C5\u5831 REST API \u4F3A\u670D\u5668 (port ${port})`
        : `  Starting Threat Cloud REST API server (port ${port})...`
    )
  );
  console.log('');

  let ThreatCloudServer: any;
  try {
    const mod = '@panguard-ai/threat-cloud';
    const tc = await import(/* webpackIgnore: true */ mod);
    ThreatCloudServer = tc.ThreatCloudServer;
  } catch {
    console.log(c.red('  Threat Cloud server package is not available.'));
    console.log(c.dim('  Your Guard client connects to Threat Cloud automatically.'));
    return;
  }
  const sp = spinner(
    currentLang === 'zh-TW'
      ? '\u6B63\u5728\u555F\u52D5 Threat Cloud API...'
      : 'Starting Threat Cloud API server...'
  );

  const server = new ThreatCloudServer({
    port: 8080,
    host: '127.0.0.1',
    dbPath: './threat-cloud.db',
    apiKeyRequired: false,
    apiKeys: [],
    rateLimitPerMinute: 120,
  });

  try {
    await server.start();
    sp.succeed(
      currentLang === 'zh-TW' ? 'Threat Cloud API \u5DF2\u555F\u52D5' : 'Threat Cloud API started'
    );

    console.log('');
    console.log(`  URL       ${c.underline('http://127.0.0.1:8080')}`);
    console.log(`  Health    ${c.sage('http://127.0.0.1:8080/health')}`);
    console.log(`  API       ${c.sage('http://127.0.0.1:8080/api/stats')}`);
    console.log('');

    console.log(
      c.dim(
        currentLang === 'zh-TW'
          ? '  \u6309\u4EFB\u610F\u9375\u505C\u6B62\u4F3A\u670D\u5668...'
          : '  Press any key to stop...'
      )
    );

    await pressAnyKey(currentLang);
    await server.stop();
    console.log(
      `  ${c.safe(
        currentLang === 'zh-TW' ? 'Threat Cloud \u5DF2\u505C\u6B62' : 'Threat Cloud stopped'
      )}`
    );
  } catch (err) {
    sp.fail(`${err instanceof Error ? err.message : String(err)}`);
  }
}

// ---------------------------------------------------------------------------
// [7] Auto Demo
// ---------------------------------------------------------------------------

async function actionDemo(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u529F\u80FD\u5C55\u793A' : 'Feature Demo']);
  const { runScan } = await import('@panguard-ai/panguard-scan');
  const title = currentLang === 'zh-TW' ? '\u529F\u80FD\u5C55\u793A' : 'Feature Demo';
  console.log(`  ${theme.brandBold(title)}`);
  console.log(
    c.dim(
      currentLang === 'zh-TW'
        ? '  \u6B63\u5728\u57F7\u884C\u6240\u6709\u5B89\u5168\u6A21\u7D44...'
        : '  Running through all security modules...'
    )
  );
  console.log('');

  type DemoResult = 'ok' | 'warn' | 'fail';
  const results: { name: string; status: DemoResult }[] = [];

  // 1. Security Scan
  console.log(
    c.dim(currentLang === 'zh-TW' ? '  1. \u5B89\u5168\u6383\u63CF' : '  1. Security Scan')
  );
  console.log('');

  const scanSp = spinner(
    currentLang === 'zh-TW'
      ? '\u6B63\u5728\u57F7\u884C\u5FEB\u901F\u6383\u63CF...'
      : 'Running quick scan...'
  );
  try {
    const result = await runScan({ depth: 'quick', lang: currentLang, verbose: false });
    scanSp.succeed(
      `${currentLang === 'zh-TW' ? '\u6383\u63CF\u5B8C\u6210' : 'Scan complete'} ${c.dim(`(${formatDuration(result.scanDuration)})`)}`
    );

    const safetyScore = Math.max(0, 100 - result.riskScore);
    const grade =
      safetyScore >= 90
        ? 'A'
        : safetyScore >= 75
          ? 'B'
          : safetyScore >= 60
            ? 'C'
            : safetyScore >= 40
              ? 'D'
              : 'F';
    console.log(
      `  Score: ${c.bold(`${safetyScore}/100`)} (${grade}) | Findings: ${result.findings.length}`
    );
    results.push({
      name: currentLang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Scan',
      status: 'ok',
    });
  } catch (err) {
    scanSp.fail(`${err instanceof Error ? err.message : err}`);
    results.push({
      name: currentLang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Scan',
      status: 'fail',
    });
  }
  console.log('');

  // 2. Compliance Report (Coming Soon)
  console.log(
    c.dim(
      currentLang === 'zh-TW'
        ? '  2. \u5408\u898F\u5831\u544A \u2014 \u5373\u5C07\u63A8\u51FA'
        : '  2. Compliance Report \u2014 Coming Soon'
    )
  );
  results.push({
    name: currentLang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Report',
    status: 'warn',
  });
  console.log('');

  // 3. Guard Engine
  console.log(
    c.dim(currentLang === 'zh-TW' ? '  3. \u5B88\u8B77\u5F15\u64CE' : '  3. Guard Engine')
  );
  console.log('');

  try {
    const { runCLI: guardCLI } = await import('@panguard-ai/panguard-guard');
    await guardCLI(['status']);
    results.push({
      name: currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard',
      status: 'ok',
    });
  } catch {
    console.log(
      c.dim(
        currentLang === 'zh-TW'
          ? '  \u5B88\u8B77\u5F15\u64CE: \u672A\u904B\u884C (\u5C55\u793A\u6B63\u5E38)'
          : '  Guard engine: not running (normal for demo)'
      )
    );
    results.push({
      name: currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard',
      status: 'warn',
    });
  }
  console.log('');

  // 4. Honeypot (Coming Soon)
  console.log(
    c.dim(
      currentLang === 'zh-TW'
        ? '  4. \u871C\u7F50\u7CFB\u7D71 \u2014 \u5373\u5C07\u63A8\u51FA'
        : '  4. Honeypot System \u2014 Coming Soon'
    )
  );
  results.push({
    name: currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Trap',
    status: 'warn',
  });
  console.log('');

  // 5. Notifications
  console.log(
    c.dim(currentLang === 'zh-TW' ? '  5. \u901A\u77E5\u7CFB\u7D71' : '  5. Notification System')
  );
  console.log('');

  try {
    const { runCLI: chatCLI } = await import('@panguard-ai/panguard-chat');
    await chatCLI(['status']);
    results.push({
      name: currentLang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notify',
      status: 'ok',
    });
  } catch {
    console.log(
      c.dim(
        currentLang === 'zh-TW'
          ? '  \u901A\u77E5\u7CFB\u7D71: \u5C1A\u672A\u914D\u7F6E'
          : '  Notification system: not configured'
      )
    );
    results.push({
      name: currentLang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notify',
      status: 'warn',
    });
  }
  console.log('');

  // Summary
  console.log(
    `  ${theme.brandBold(currentLang === 'zh-TW' ? '\u5C55\u793A\u5B8C\u6210' : 'Demo Complete')}`
  );
  console.log('');
  for (const r of results) {
    const icon =
      r.status === 'ok'
        ? c.safe('\u2713')
        : r.status === 'warn'
          ? c.caution('~')
          : c.critical('\u2717');
    console.log(`  ${icon} ${r.name}`);
  }

  nextSteps(
    currentLang === 'zh-TW'
      ? [
          { cmd: 'init', desc: '\u521D\u59CB\u8A2D\u5B9A\u60A8\u7684\u74B0\u5883' },
          { cmd: 'scan', desc: '\u57F7\u884C\u5B89\u5168\u6383\u63CF' },
          { cmd: 'guard start', desc: '\u555F\u52D5\u5373\u6642\u9632\u8B77' },
        ]
      : [
          { cmd: 'init', desc: 'Set up your environment' },
          { cmd: 'scan', desc: 'Run a security scan' },
          { cmd: 'guard start', desc: 'Enable real-time protection' },
        ],
    currentLang
  );
}

// ---------------------------------------------------------------------------
// [8] Skill Auditor
// ---------------------------------------------------------------------------

async function actionAudit(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u6280\u80FD\u5BE9\u8A08' : 'Skill Auditor']);
  const title = currentLang === 'zh-TW' ? '\u6280\u80FD\u5BE9\u8A08' : 'Skill Auditor';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');
  console.log(
    c.dim(
      currentLang === 'zh-TW'
        ? '  \u6383\u63CF AI \u4EE3\u7406\u6280\u80FD\u76EE\u9304\uFF08\u5305\u542B SKILL.md\uFF09\u4EE5\u5075\u6E2C\u5B89\u5168\u554F\u984C\u3002'
        : '  Scan an AI agent skill directory (containing SKILL.md) for security issues.'
    )
  );
  console.log('');

  // Ask for path to audit
  const pathItems: MenuItem[] = [
    {
      key: '1',
      label:
        currentLang === 'zh-TW'
          ? '\u5BE9\u8A08\u7576\u524D\u76EE\u9304 (.)'
          : 'Audit current directory (.)',
    },
    {
      key: '2',
      label:
        currentLang === 'zh-TW'
          ? '\u8F38\u5165\u81EA\u5B9A\u8DEF\u5F91'
          : 'Enter custom path',
    },
  ];

  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u9078\u64C7\u76EE\u6A19' : 'Select target',
    pathItems
  );

  const choice = await waitForCompactChoice(pathItems, currentLang);
  if (!choice) return;

  let targetPath = process.cwd();

  if (choice.key === '2') {
    // Read a custom path from the user via text prompt
    const readline = await import('node:readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    targetPath = await new Promise<string>((resolve) => {
      const prompt = currentLang === 'zh-TW' ? '  \u8DEF\u5F91: ' : '  Path: ';
      rl.question(prompt, (answer) => {
        rl.close();
        resolve(answer.trim() || process.cwd());
      });
    });
  }

  const path = await import('node:path');
  const resolvedPath = path.resolve(targetPath);

  console.log('');
  const sp = spinner(
    currentLang === 'zh-TW'
      ? `\u6B63\u5728\u5BE9\u8A08 ${resolvedPath}...`
      : `Auditing ${resolvedPath}...`
  );

  try {
    const { auditSkill } = await import('@panguard-ai/panguard-skill-auditor');
    const report = await auditSkill(resolvedPath);
    sp.succeed(
      currentLang === 'zh-TW' ? '\u5BE9\u8A08\u5B8C\u6210' : 'Audit complete'
    );

    // Display results
    const levelColors: Record<string, (s: string) => string> = {
      LOW: c.safe,
      MEDIUM: c.caution,
      HIGH: c.critical,
      CRITICAL: (s: string) => c.bold(c.critical(s)),
    };
    const colorFn = levelColors[report.riskLevel] ?? c.dim;

    console.log('');
    console.log(
      box(
        [
          `${c.bold(currentLang === 'zh-TW' ? '\u6280\u80FD\u5BE9\u8A08\u5831\u544A' : 'Skill Audit Report')}`,
          '',
          `${currentLang === 'zh-TW' ? '\u6280\u80FD' : 'Skill'}:      ${report.manifest?.name ?? 'Unknown'}${report.manifest?.metadata?.version ? ` v${report.manifest.metadata.version}` : ''}`,
          `${currentLang === 'zh-TW' ? '\u4F5C\u8005' : 'Author'}:     ${report.manifest?.metadata?.author ?? 'Unknown'}`,
          `${currentLang === 'zh-TW' ? '\u98A8\u96AA\u5206\u6578' : 'Risk Score'}: ${colorFn(`${report.riskScore}/100 (${report.riskLevel})`)}`,
          `${currentLang === 'zh-TW' ? '\u6642\u9593' : 'Duration'}:   ${report.durationMs}ms`,
        ].join('\n'),
        { borderColor: c.sage }
      )
    );

    console.log('');

    for (const check of report.checks) {
      const icon =
        check.status === 'pass'
          ? c.safe('\u2713')
          : check.status === 'fail'
            ? c.critical('\u2717')
            : check.status === 'warn'
              ? c.caution('~')
              : c.dim('i');
      const statusLabel =
        check.status === 'pass'
          ? 'PASS'
          : check.status === 'fail'
            ? 'FAIL'
            : check.status === 'warn'
              ? 'WARN'
              : 'INFO';
      console.log(`  ${icon} [${statusLabel}] ${check.label}`);
    }

    console.log('');

    if (report.findings.length > 0) {
      console.log(
        c.bold(
          currentLang === 'zh-TW'
            ? `  \u767C\u73FE ${report.findings.length} \u500B\u554F\u984C:`
            : `  ${report.findings.length} finding(s):`
        )
      );
      console.log('');
      for (const finding of report.findings) {
        const sevColor =
          finding.severity === 'critical'
            ? c.critical
            : finding.severity === 'high'
              ? c.caution
              : c.dim;
        console.log(
          `  ${sevColor(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`
        );
        console.log(`    ${c.dim(finding.description)}`);
        if (finding.location) console.log(`    ${c.dim(`at ${finding.location}`)}`);
        console.log('');
      }
    }

    nextSteps(
      currentLang === 'zh-TW'
        ? [
            { cmd: 'scan', desc: '\u57F7\u884C\u7CFB\u7D71\u5B89\u5168\u6383\u63CF' },
            { cmd: 'guard start', desc: '\u555F\u52D5 24/7 \u5B88\u8B77\u9632\u8B77' },
          ]
        : [
            { cmd: 'scan', desc: 'Run a system security scan' },
            { cmd: 'guard start', desc: 'Start 24/7 guard protection' },
          ],
      currentLang
    );
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const isNoSkill = errMsg.toLowerCase().includes('skill.md') || errMsg.toLowerCase().includes('not found') || errMsg.toLowerCase().includes('enoent');

    if (isNoSkill) {
      sp.warn(
        currentLang === 'zh-TW'
          ? '\u6B64\u76EE\u9304\u672A\u627E\u5230 AI \u6280\u80FD (SKILL.md)'
          : 'No AI skills (SKILL.md) found in this directory'
      );
      console.log('');
      console.log(c.dim(
        currentLang === 'zh-TW'
          ? '  Skill Auditor \u6383\u63CF\u5305\u542B SKILL.md \u7684 AI \u6280\u80FD\u76EE\u9304\u3002'
          : '  Skill Auditor scans AI skill directories containing a SKILL.md file.'
      ));
      console.log('');
      console.log(c.dim(
        currentLang === 'zh-TW'
          ? '  \u5E38\u898B\u6280\u80FD\u4F4D\u7F6E\uFF1A'
          : '  Common skill locations:'
      ));
      console.log(c.dim('    ~/.claude/skills/'));
      console.log(c.dim('    ./.claude/skills/'));
      console.log(c.dim('    ./.mcp/'));
      console.log(c.dim('    ./skills/'));
      console.log('');

      // Auto-scan known skill directories
      const fs = await import('node:fs');
      const path = await import('node:path');
      const skillDirs = [
        path.join(homedir(), '.claude', 'skills'),
        path.join(process.cwd(), '.claude', 'skills'),
        path.join(process.cwd(), '.mcp'),
        path.join(process.cwd(), 'skills'),
      ];
      const foundDirs: string[] = [];
      for (const dir of skillDirs) {
        if (fs.existsSync(dir)) {
          // Check for subdirectories that might have SKILL.md
          try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
              if (entry.isDirectory()) {
                const skillMdPath = path.join(dir, entry.name, 'SKILL.md');
                if (fs.existsSync(skillMdPath)) {
                  foundDirs.push(path.join(dir, entry.name));
                }
              }
            }
            // Also check the directory itself
            if (fs.existsSync(path.join(dir, 'SKILL.md'))) {
              foundDirs.push(dir);
            }
          } catch {
            /* skip inaccessible dirs */
          }
        }
      }

      if (foundDirs.length > 0) {
        console.log(c.sage(
          currentLang === 'zh-TW'
            ? `  \u5728\u7CFB\u7D71\u4E2D\u627E\u5230 ${foundDirs.length} \u500B\u6280\u80FD\uFF1A`
            : `  Found ${foundDirs.length} skill(s) on your system:`
        ));
        for (const dir of foundDirs) {
          console.log(c.dim(`    ${dir}`));
        }
        console.log('');
        console.log(c.dim(
          currentLang === 'zh-TW'
            ? `  \u57F7\u884C\uFF1Apanguard audit skill <path> \u4F86\u5BE9\u8A08\u7279\u5B9A\u6280\u80FD`
            : `  Run: panguard audit skill <path> to audit a specific skill`
        ));
      } else {
        console.log(c.dim(
          currentLang === 'zh-TW'
            ? '  \u7CFB\u7D71\u4E2D\u672A\u627E\u5230\u5DF2\u5B89\u88DD\u7684 AI \u6280\u80FD\u3002'
            : '  No installed AI skills found on your system.'
        ));
        console.log(c.dim(
          currentLang === 'zh-TW'
            ? '  \u5728\u5305\u542B AI \u6280\u80FD\u7684\u5C08\u6848\u76EE\u9304\u4E2D\u57F7\u884C\u6B64\u6307\u4EE4\u3002'
            : '  Run this command inside a project directory that contains AI skills.'
        ));
      }
    } else {
      sp.fail(
        currentLang === 'zh-TW' ? '\u5BE9\u8A08\u5931\u6557' : 'Audit failed'
      );
      console.log(
        formatError(
          errMsg,
          currentLang === 'zh-TW' ? '\u6280\u80FD\u5BE9\u8A08' : 'Skill Auditor',
          currentLang === 'zh-TW' ? '\u8ACB\u91CD\u8A66\u6216\u6AA2\u67E5\u65E5\u8A8C' : 'Please retry or check logs'
        )
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Prompt commands: Hardening
// ---------------------------------------------------------------------------

async function actionHardening(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u5B89\u5168\u52A0\u56FA' : 'Security Hardening']);
  const title = currentLang === 'zh-TW' ? '\u5B89\u5168\u52A0\u56FA' : 'Security Hardening';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: currentLang === 'zh-TW' ? '\u57F7\u884C\u52A0\u56FA\u6383\u63CF' : 'Run hardening audit' },
    { key: '2', label: currentLang === 'zh-TW' ? '\u81EA\u52D5\u4FEE\u5FA9' : 'Auto-fix issues' },
    { key: '3', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u5831\u544A' : 'View report' },
  ];

  renderCompactMenu(currentLang === 'zh-TW' ? '\u5B89\u5168\u52A0\u56FA' : 'Hardening', items);
  const choice = await waitForCompactChoice(items, currentLang);
  if (!choice) return;

  console.log('');
  const { hardeningCommand } = await import('./commands/hardening.js');
  const cmd = hardeningCommand();

  switch (choice.key) {
    case '1':
      await cmd.parseAsync(['hardening', 'audit'], { from: 'user' });
      break;
    case '2':
      await cmd.parseAsync(['hardening', 'fix'], { from: 'user' });
      break;
    case '3':
      await cmd.parseAsync(['hardening', 'report'], { from: 'user' });
      break;
  }
}

// ---------------------------------------------------------------------------
// Prompt commands: Status
// ---------------------------------------------------------------------------

async function actionStatus(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u7CFB\u7D71\u72C0\u614B' : 'Status']);
  const { statusCommand } = await import('./commands/status.js');
  const cmd = statusCommand();
  await cmd.parseAsync(['status'], { from: 'user' });
}

// ---------------------------------------------------------------------------
// Prompt commands: Config
// ---------------------------------------------------------------------------

async function actionConfig(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u8A2D\u5B9A\u7BA1\u7406' : 'Settings']);
  const { configCommand } = await import('./commands/config.js');
  const cmd = configCommand();
  await cmd.parseAsync(['config'], { from: 'user' });
}
