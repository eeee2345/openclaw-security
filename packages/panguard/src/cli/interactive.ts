/**
 * Panguard AI - Interactive CLI Mode
 *
 * Number-key menu [0]-[7] with panguard > prompt for text commands.
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
import { checkFeatureAccess, showUpgradePrompt, getLicense, FEATURE_TIER } from './auth-guard.js';
import { tierDisplayName } from './credentials.js';
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
// Menu definitions — 8 core items matching the redesigned UI
// ---------------------------------------------------------------------------

interface MenuDef {
  key: string;
  icon: string;
  number: number;
  en: string;
  zh: string;
  enDesc: string;
  zhDesc: string;
  tierBadge: string; // Display badge: '', '[STARTER]', '[PRO]', '[ENT]'
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
    en: 'Compliance Report',
    zh: '\u5408\u898F\u5831\u544A',
    enDesc: 'Generate ISO 27001, SOC 2, TW Cyber Security Act reports',
    zhDesc: '\u7522\u751F ISO 27001\u3001SOC 2\u3001\u8CC7\u5B89\u7BA1\u7406\u6CD5\u5408\u898F\u5831\u544A',
    tierBadge: '[PRO]',
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
    en: 'Honeypot System',
    zh: '\u871C\u7F50\u7CFB\u7D71',
    enDesc: 'Detect and profile attackers with decoy services',
    zhDesc: '\u5373\u770B\u5373\u8B58\u99ED\u5BA2\uFF0C\u5206\u6790\u653B\u64CA\u8005\u884C\u70BA',
    tierBadge: '[PRO]',
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
    tierBadge: '[STARTER]',
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
    tierBadge: '[ENT]',
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
];

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
        ? '  [0]-[7]  \u6309\u6578\u5B57\u9375\u5373\u523B\u9078\u64C7\uFF08\u4E0D\u9700\u6309 Enter\uFF09'
        : '  [0]-[7]  Press number key to select instantly (no Enter needed)'
    )
  );
  console.log('');

  const promptTitle = currentLang === 'zh-TW' ? '\u6587\u5B57\u6307\u4EE4' : 'Text Commands';
  console.log(`  ${c.sage(promptTitle)}`);

  const cmds = [
    { cmd: 'status', en: 'System status overview', zh: '\u7CFB\u7D71\u72C0\u614B\u7E3D\u89BD' },
    { cmd: 'login', en: 'Account login', zh: '\u5E33\u865F\u767B\u5165' },
    { cmd: 'logout', en: 'Account logout', zh: '\u767B\u51FA' },
    { cmd: 'config', en: 'Settings management', zh: '\u8A2D\u5B9A\u7BA1\u7406' },
    { cmd: 'upgrade', en: 'Upgrade plan', zh: '\u5347\u7D1A\u65B9\u6848' },
    { cmd: 'hardening', en: 'Security hardening', zh: '\u5B89\u5168\u52A0\u56FA' },
    { cmd: 'doctor', en: 'Health diagnostics', zh: '\u5065\u5EB7\u8A3A\u65B7' },
    { cmd: 'whoami', en: 'Current account info', zh: '\u986F\u793A\u7576\u524D\u5E33\u865F' },
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

  // First-time user hint
  if (!existsSync(CONFIG_PATH)) {
    const hint =
      currentLang === 'zh-TW'
        ? `  ${c.sage('\u25C6')} \u9996\u6B21\u4F7F\u7528\uFF1F\u5EFA\u8B70\u6309 [0] \u57F7\u884C\u521D\u59CB\u8A2D\u5B9A\u6216\u6309 [7] \u529F\u80FD\u5C55\u793A`
        : `  ${c.sage('\u25C6')} First time? Press [0] for Setup Wizard or [7] for Auto Demo`;
    console.log(hint);
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
      console.clear();
      await actionLogin();
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;

    case 'logout': {
      console.clear();
      const { logoutCommand } = await import('./commands/logout.js');
      const cmd = logoutCommand();
      await cmd.parseAsync(['logout'], { from: 'user' });
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

    case 'upgrade':
      console.clear();
      await actionUpgrade();
      await new Promise((r) => setTimeout(r, 500));
      renderStartup();
      return true;

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
      const { whoamiCommand } = await import('./commands/whoami.js');
      const cmd = whoamiCommand();
      await cmd.parseAsync(['whoami'], { from: 'user' });
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

      if (tier === 'community' && f.manualFix && f.manualFix.length > 0) {
        const fixLabel = currentLang === 'zh-TW' ? '\u624B\u52D5\u4FEE\u5FA9:' : 'Manual fix:';
        console.log(c.dim(`          ${fixLabel}`));
        for (const cmd of f.manualFix) {
          console.log(c.dim(`          $ ${cmd}`));
        }
        fixableCount++;
      }
    }
    console.log('');

    const issuesText =
      currentLang === 'zh-TW'
        ? `${result.findings.length} \u500B\u554F\u984C`
        : `${result.findings.length} issue(s) found`;
    console.log(c.dim(`  ${issuesText}`));

    if (tier === 'community' && fixableCount > 0) {
      const upgradeLines =
        currentLang === 'zh-TW'
          ? [
              `\u5347\u7D1A\u5230 Solo ($9/\u6708) \u5373\u53EF\u4E00\u9375\u4FEE\u5FA9:`,
              `$ panguard scan --fix`,
            ]
          : [`Upgrade to Solo ($9/mo) to auto-fix all:`, `$ panguard scan --fix`];
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
      { key: '2', label: currentLang === 'zh-TW' ? '\u4E0D\u7528\uFF0C\u56DE\u4E3B\u9078\u55AE' : 'No, return to main menu' },
    ];
    renderCompactMenu('', guardItems);
    const guardChoice = await waitForCompactChoice(guardItems, currentLang);
    if (guardChoice?.key === '1') {
      await actionGuard();
      return;
    }
  } else {
    nextSteps(
      currentLang === 'zh-TW'
        ? [
            { cmd: 'scan --full', desc: '\u57F7\u884C\u5B8C\u6574\u6383\u63CF' },
            { cmd: 'report', desc: '\u7522\u751F\u5408\u898F\u5831\u544A' },
          ]
        : [
            { cmd: 'scan --full', desc: 'Run a comprehensive scan' },
            { cmd: 'report', desc: 'Generate compliance report' },
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
  const title = currentLang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Compliance Report';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const frameworkItems: MenuItem[] = [
    { key: '1', label: 'ISO 27001' },
    { key: '2', label: 'SOC 2' },
    {
      key: '3',
      label:
        currentLang === 'zh-TW'
          ? '\u8CC7\u901A\u5B89\u5168\u7BA1\u7406\u6CD5'
          : 'TW Cyber Security Act',
    },
  ];

  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u9078\u64C7\u5408\u898F\u6846\u67B6' : 'Select Framework',
    frameworkItems
  );

  const fwChoice = await waitForCompactChoice(frameworkItems, currentLang);
  if (!fwChoice) return;

  const frameworkMap: Record<string, string> = {
    '1': 'iso27001',
    '2': 'soc2',
    '3': 'tw_cyber_security_act',
  };
  const framework = frameworkMap[fwChoice.key] ?? 'iso27001';

  const langItems: MenuItem[] = [
    {
      key: '1',
      label: currentLang === 'zh-TW' ? '\u7E41\u9AD4\u4E2D\u6587 (zh-TW)' : 'Chinese (zh-TW)',
    },
    { key: '2', label: currentLang === 'zh-TW' ? '\u82F1\u6587 (en)' : 'English (en)' },
  ];

  console.log('');
  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u5831\u544A\u8A9E\u8A00' : 'Report Language',
    langItems
  );
  const langChoice = await waitForCompactChoice(langItems, currentLang);
  if (!langChoice) return;

  const reportLang = langChoice.key === '1' ? 'zh-TW' : 'en';
  console.log('');

  const { executeCli } = await import('@panguard-ai/panguard-report');
  await executeCli(['generate', '--framework', framework, '--language', reportLang]);

  nextSteps(
    currentLang === 'zh-TW'
      ? [
          { cmd: 'scan', desc: '\u57F7\u884C\u5B89\u5168\u6383\u63CF' },
          { cmd: 'guard start', desc: '\u555F\u52D5\u5373\u6642\u9632\u8B77' },
        ]
      : [
          { cmd: 'scan', desc: 'Run a security scan' },
          { cmd: 'guard start', desc: 'Enable real-time protection' },
        ],
    currentLang
  );
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

      // Free tier — show positive capabilities first
      const { tier } = getLicense();
      if (tier === 'community') {
        console.log(`  ${c.sage('\u25C6')} Guard active${' '.repeat(30)}Layer 1 \u00B7 Community`);
        console.log('');
        if (currentLang === 'zh-TW') {
          console.log(`  ${c.safe('\u2713')} \u5DF2\u77E5\u653B\u64CA\u6A21\u5F0F\u81EA\u52D5\u5C01\u9396`);
          console.log(`  ${c.safe('\u2713')} Threat Cloud \u5A01\u8105\u60C5\u5831`);
          console.log(`  ${c.dim('\u2500')} AI \u5206\u6790 ${c.dim('(Solo $9/\u6708)')}`);
          console.log(`  ${c.dim('\u2500')} \u901A\u77E5\u7CFB\u7D71 ${c.dim('(Solo $9/\u6708)')}`);
          console.log(`  ${c.dim('\u2500')} \u65E5\u8A8C\u4FDD\u7559 7 \u5929+ ${c.dim('(Solo $9/\u6708)')}`);
        } else {
          console.log(`  ${c.safe('\u2713')} Auto-blocking for known attack patterns`);
          console.log(`  ${c.safe('\u2713')} Threat Cloud intelligence`);
          console.log(`  ${c.dim('\u2500')} AI analysis ${c.dim('(Solo $9/mo)')}`);
          console.log(`  ${c.dim('\u2500')} Notifications ${c.dim('(Solo $9/mo)')}`);
          console.log(`  ${c.dim('\u2500')} Log retention 7d+ ${c.dim('(Solo $9/mo)')}`);
        }
        console.log('');
      }

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
  const title = currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Honeypot System';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const items: MenuItem[] = [
    {
      key: '1',
      label:
        currentLang === 'zh-TW' ? '\u57FA\u672C\u914D\u7F6E (SSH + HTTP)' : 'Config (SSH + HTTP)',
    },
    {
      key: '2',
      label:
        currentLang === 'zh-TW'
          ? '\u5B8C\u6574\u914D\u7F6E (8 \u7A2E\u670D\u52D9)'
          : 'Config (All 8 Services)',
    },
    { key: '3', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u72C0\u614B' : 'Status' },
    {
      key: '4',
      label: currentLang === 'zh-TW' ? '\u653B\u64CA\u8005\u5206\u6790' : 'Attacker Profiles',
    },
  ];

  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Honeypot System',
    items
  );
  const choice = await waitForCompactChoice(items, currentLang);
  if (!choice) return;

  console.log('');
  const { executeCli } = await import('@panguard-ai/panguard-trap');

  switch (choice.key) {
    case '1':
      await executeCli(['config', '--services', 'ssh,http']);
      break;
    case '2':
      await executeCli(['config', '--services', 'ssh,http,ftp,telnet,mysql,redis,smb,rdp']);
      break;
    case '3':
      await executeCli(['status']);
      break;
    case '4':
      await executeCli(['profiles']);
      break;
  }
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

  const { ThreatCloudServer } = await import('@panguard-ai/threat-cloud');
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
  const { generateComplianceReport, generateSummaryText } =
    await import('@panguard-ai/panguard-report');

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

  // 2. Compliance Report
  console.log(
    c.dim(
      currentLang === 'zh-TW'
        ? '  2. \u5408\u898F\u5831\u544A (ISO 27001)'
        : '  2. Compliance Report (ISO 27001)'
    )
  );
  console.log('');

  const reportSp = spinner(
    currentLang === 'zh-TW'
      ? '\u6B63\u5728\u7522\u751F ISO 27001 \u5831\u544A...'
      : 'Generating ISO 27001 report...'
  );
  try {
    const findings = [
      {
        findingId: 'DEMO-001',
        severity: 'high' as const,
        title: 'Missing information security policy',
        description: 'No formal information security policy document found.',
        category: 'policy',
        timestamp: new Date(),
        source: 'panguard-scan' as const,
      },
      {
        findingId: 'DEMO-002',
        severity: 'medium' as const,
        title: 'Unencrypted data at rest',
        description: 'Database storage does not use encryption at rest.',
        category: 'encryption',
        timestamp: new Date(),
        source: 'panguard-scan' as const,
      },
    ];

    const report = generateComplianceReport(findings, 'iso27001', 'en', {
      includeRecommendations: true,
    });
    const summary = generateSummaryText(report);
    reportSp.succeed(
      currentLang === 'zh-TW'
        ? 'ISO 27001 \u5831\u544A\u5DF2\u7522\u751F'
        : 'ISO 27001 report generated'
    );

    const summaryLines = summary.split('\n').slice(0, 10);
    for (const line of summaryLines) {
      console.log(`  ${c.dim(line)}`);
    }
    console.log(c.dim('  ...'));
    results.push({
      name: currentLang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Report',
      status: 'ok',
    });
  } catch (err) {
    reportSp.fail(`${err instanceof Error ? err.message : err}`);
    results.push({
      name: currentLang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Report',
      status: 'fail',
    });
  }
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

  // 4. Honeypot
  console.log(
    c.dim(currentLang === 'zh-TW' ? '  4. \u871C\u7F50\u7CFB\u7D71' : '  4. Honeypot System')
  );
  console.log('');

  try {
    const { executeCli: trapCLI } = await import('@panguard-ai/panguard-trap');
    await trapCLI(['config', '--services', 'ssh,http']);
    results.push({
      name: currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Trap',
      status: 'ok',
    });
  } catch (err) {
    console.log(`  ${c.critical(err instanceof Error ? err.message : String(err))}`);
    results.push({
      name: currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Trap',
      status: 'fail',
    });
  }
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
// Prompt commands: Upgrade
// ---------------------------------------------------------------------------

async function actionUpgrade(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u5347\u7D1A\u65B9\u6848' : 'Upgrade Plan']);
  const { upgradeCommand } = await import('./commands/upgrade.js');
  const cmd = upgradeCommand();
  await cmd.parseAsync(['upgrade', '--lang', currentLang], { from: 'user' });
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
// Prompt commands: Login
// ---------------------------------------------------------------------------

async function actionLogin(): Promise<void> {
  breadcrumb(['Panguard', currentLang === 'zh-TW' ? '\u5E33\u865F\u767B\u5165' : 'Login']);
  const { loginCommand } = await import('./commands/login.js');
  const cmd = loginCommand();
  await cmd.parseAsync(['login'], { from: 'user' });
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
