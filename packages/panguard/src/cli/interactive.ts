/**
 * Panguard AI - Interactive CLI Mode
 *
 * Minimalist arrow-key menu interface inspired by Claude Code / Vercel CLI.
 * Single-language display, no box borders, brand sage green theme.
 *
 * @module @panguard-ai/panguard/cli/interactive
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import {
  c, spinner, colorSeverity,
} from '@panguard-ai/core';
import { PANGUARD_VERSION } from '../index.js';
import { renderLogo, theme } from './theme.js';
import {
  runArrowMenu, pressAnyKey, cleanupTerminal,
  renderCompactMenu, waitForCompactChoice,
} from './menu.js';
import type { MenuItem, Lang } from './menu.js';
import { checkFeatureAccess, showUpgradePrompt, getLicense } from './auth-guard.js';
import { tierDisplayName } from './credentials.js';

// ---------------------------------------------------------------------------
// Language management
// ---------------------------------------------------------------------------

const CONFIG_DIR = join(homedir(), '.panguard');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

function detectLang(): Lang {
  // 1. Read saved preference
  if (existsSync(CONFIG_PATH)) {
    try {
      const data = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
      if (data.lang === 'zh-TW' || data.lang === 'en') return data.lang;
    } catch { /* ignore */ }
  }
  // 2. Detect from system locale
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
  } catch { /* best effort */ }
}

let currentLang: Lang = 'en';

// ---------------------------------------------------------------------------
// Menu data
// ---------------------------------------------------------------------------

interface MenuDef {
  key: string;
  en: string;
  zh: string;
  tier: string;
}

const MENU_DEFS: MenuDef[] = [
  { key: 'scan',         en: 'Security scan',                         zh: '\u5B89\u5168\u6383\u63CF',                     tier: 'free' },
  { key: 'guard',        en: 'Real-time protection',                  zh: '\u5373\u6642\u9632\u8B77',                     tier: 'free' },
  { key: 'report',       en: 'Compliance report (ISO 27001, SOC 2)',  zh: '\u5408\u898F\u5831\u544A (ISO 27001, SOC 2)',   tier: 'pro' },
  { key: 'trap',         en: 'Honeypot system',                       zh: '\u871C\u7F50\u7CFB\u7D71',                     tier: 'pro' },
  { key: 'notify',       en: 'Notifications (LINE, Telegram, Slack)', zh: '\u901A\u77E5\u7CFB\u7D71 (LINE, Telegram, Slack)', tier: 'solo' },
  { key: 'threat-cloud', en: 'Threat intelligence API',               zh: '\u5A01\u8105\u60C5\u5831 API',                 tier: 'enterprise' },
  { key: '__sep__',      en: '',                                       zh: '',                                             tier: '' },
  { key: 'setup',        en: 'Initial configuration',                 zh: '\u521D\u59CB\u8A2D\u5B9A',                     tier: 'free' },
  { key: 'demo',         en: 'Feature demo',                          zh: '\u529F\u80FD\u5C55\u793A',                     tier: 'free' },
];

function buildMenuItems(lang: Lang): MenuItem[] {
  return MENU_DEFS.map((def) => {
    if (def.key === '__sep__') return { key: '__sep__', label: '', separator: true };
    return {
      key: def.key,
      label: lang === 'zh-TW' ? def.zh : def.en,
      tier: def.tier || undefined,
    };
  });
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
  const tagline = c.dim('  Headless Defense Platform');
  const version = c.dim(`v${PANGUARD_VERSION}`);
  // Right-align version
  // eslint-disable-next-line no-control-regex
  const tagLen = tagline.replace(/\x1b\[[0-9;]*m/g, '').length;
  // eslint-disable-next-line no-control-regex
  const verLen = version.replace(/\x1b\[[0-9;]*m/g, '').length;
  const totalWidth = Math.max(60, (process.stdout.columns ?? 60));
  const gap = Math.max(2, totalWidth - tagLen - verLen - 4);
  console.log(`${tagline}${' '.repeat(gap)}${version}`);
  console.log('');

  // Status info
  const { tier } = getLicense();
  const tierName = tierDisplayName(tier);
  const tierColor = tier === 'free' ? c.caution : c.safe;

  const statusLabel = currentLang === 'zh-TW' ? '\u72C0\u614B' : 'Status';
  const licenseLabel = currentLang === 'zh-TW' ? '\u6388\u6B0A' : 'License';
  const modulesLabel = currentLang === 'zh-TW' ? '\u6A21\u7D44' : 'Modules';
  const modulesValue = currentLang === 'zh-TW' ? '6 \u500B\u53EF\u7528' : '6 available';

  console.log(`  ${c.dim(statusLabel.padEnd(10))} ${c.safe('Ready')}`);
  console.log(`  ${c.dim(licenseLabel.padEnd(10))} ${tierColor(tierName)}`);
  console.log(`  ${c.dim(modulesLabel.padEnd(10))} ${modulesValue}`);
  console.log('');
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function startInteractive(lang?: string): Promise<void> {
  currentLang = lang === 'en' ? 'en' : lang === 'zh-TW' ? 'zh-TW' : detectLang();

  const exit = () => {
    cleanupTerminal();
    const msg = currentLang === 'zh-TW'
      ? '\u611F\u8B1D\u4F7F\u7528 Panguard AI\uFF01'
      : 'Goodbye!';
    console.log(`\n  ${c.sage(msg)}\n`);
    process.exit(0);
  };
  process.on('SIGINT', exit);
  process.on('SIGTERM', exit);

  renderStartup();

  // Main loop
  while (true) {
    const title = currentLang === 'zh-TW' ? '  \u6307\u4EE4' : '  Commands';
    console.log(theme.title(title));
    console.log('');

    const items = buildMenuItems(currentLang);
    const choice = await runArrowMenu(items, { lang: currentLang });

    if (!choice) {
      exit();
      return;
    }

    if (choice.key === '__lang__') {
      currentLang = currentLang === 'zh-TW' ? 'en' : 'zh-TW';
      saveLang(currentLang);
      renderStartup();
      continue;
    }

    // Feature gate check
    if (!checkFeatureAccess(choice.key)) {
      showUpgradePrompt(choice.key, currentLang);
      await pressAnyKey(currentLang);
      renderStartup();
      continue;
    }

    console.clear();
    try {
      await dispatch(choice.key);
    } catch (err) {
      console.log('');
      console.log(`  ${c.critical('Error:')} ${err instanceof Error ? err.message : String(err)}`);
    }

    await pressAnyKey(currentLang);
    renderStartup();
  }
}

// ---------------------------------------------------------------------------
// Action dispatch
// ---------------------------------------------------------------------------

async function dispatch(key: string): Promise<void> {
  switch (key) {
    case 'scan': await actionScan(); break;
    case 'guard': await actionGuard(); break;
    case 'report': await actionReport(); break;
    case 'trap': await actionTrap(); break;
    case 'notify': await actionChat(); break;
    case 'threat-cloud': await actionThreat(); break;
    case 'setup': await actionInit(); break;
    case 'demo': await actionDemo(); break;
  }
}

// ---------------------------------------------------------------------------
// 0. Setup Wizard
// ---------------------------------------------------------------------------

async function actionInit(): Promise<void> {
  const { runInitWizard } = await import('../init/index.js');
  await runInitWizard(currentLang);
}

// ---------------------------------------------------------------------------
// 1. Security Scan
// ---------------------------------------------------------------------------

async function actionScan(): Promise<void> {
  const scanTitle = currentLang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Security Scan';
  console.log(`  ${theme.brandBold(scanTitle)}`);
  console.log('');

  // Scan depth selection
  const depthItems: MenuItem[] = [
    {
      key: '1',
      label: currentLang === 'zh-TW' ? '\u5FEB\u901F\u6383\u63CF (~30 \u79D2)' : 'Quick Scan (~30 seconds)',
    },
    {
      key: '2',
      label: currentLang === 'zh-TW' ? '\u5B8C\u6574\u6383\u63CF' : 'Full Scan',
    },
  ];

  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u6383\u63CF\u6A21\u5F0F' : 'Scan Mode',
    depthItems,
  );

  const choice = await waitForCompactChoice(depthItems, currentLang);
  if (!choice) return;

  const depth = choice.key === '1' ? 'quick' : 'full';
  console.log('');

  const { runScan } = await import('@panguard-ai/panguard-scan');
  const sp = spinner(currentLang === 'zh-TW'
    ? '\u6B63\u5728\u6383\u63CF\u7CFB\u7D71\u5B89\u5168...'
    : 'Scanning system...');
  const result = await runScan({ depth, lang: currentLang, verbose: false });
  sp.succeed(currentLang === 'zh-TW'
    ? `\u6383\u63CF\u5B8C\u6210 ${c.dim(`(${formatDuration(result.scanDuration)})`)}`
    : `Scan complete ${c.dim(`(${formatDuration(result.scanDuration)})`)}`);

  const safetyScore = Math.max(0, 100 - result.riskScore);
  const grade = safetyScore >= 90 ? 'A' : safetyScore >= 75 ? 'B' : safetyScore >= 60 ? 'C' : safetyScore >= 40 ? 'D' : 'F';

  // Compact score display
  console.log('');
  const scoreLabel = currentLang === 'zh-TW' ? '\u6383\u63CF\u5B8C\u6210' : 'Scan Complete';
  console.log(`  ${theme.title(scoreLabel)}${' '.repeat(30)}Score: ${c.bold(`${safetyScore}/100`)} (${grade})`);
  console.log('');

  const { tier } = getLicense();
  let fixableCount = 0;

  if (result.findings.length > 0) {
    for (const f of result.findings) {
      const sev = colorSeverity(f.severity).padEnd(10);
      console.log(`  ${sev} ${f.title}`);

      // Show manual fix commands for free tier
      if (tier === 'free' && f.manualFix && f.manualFix.length > 0) {
        const fixLabel = currentLang === 'zh-TW' ? '\u624B\u52D5\u4FEE\u5FA9:' : 'Manual fix:';
        console.log(c.dim(`          ${fixLabel}`));
        for (const cmd of f.manualFix) {
          console.log(c.dim(`          $ ${cmd}`));
        }
        fixableCount++;
      }
    }
    console.log('');

    const issuesText = currentLang === 'zh-TW'
      ? `${result.findings.length} \u500B\u554F\u984C`
      : `${result.findings.length} issue(s) found`;
    console.log(c.dim(`  ${issuesText}`));

    // Upgrade prompt for free tier
    if (tier === 'free' && fixableCount > 0) {
      console.log('');
      const W = 49;
      const TL = '\u250C'; const TR = '\u2510'; const BL = '\u2514'; const BR = '\u2518';
      const H = '\u2500'; const V = '\u2502';
      console.log(`  ${c.sage(TL + H.repeat(W) + TR)}`);
      if (currentLang === 'zh-TW') {
        console.log(`  ${c.sage(V)}  \u26A1 \u5347\u7D1A\u5230 Solo ($9/\u6708) \u5373\u53EF\u4E00\u9375\u4FEE\u5FA9:${' '.repeat(W - 29)}${c.sage(V)}`);
        console.log(`  ${c.sage(V)}     $ panguard scan --fix${' '.repeat(W - 26)}${c.sage(V)}`);
      } else {
        console.log(`  ${c.sage(V)}  \u26A1 Upgrade to Solo ($9/mo) to auto-fix all:${' '.repeat(W - 43)}${c.sage(V)}`);
        console.log(`  ${c.sage(V)}     $ panguard scan --fix${' '.repeat(W - 26)}${c.sage(V)}`);
      }
      console.log(`  ${c.sage(BL + H.repeat(W) + BR)}`);
    }
  } else {
    const noIssues = currentLang === 'zh-TW'
      ? '\u672A\u767C\u73FE\u5B89\u5168\u554F\u984C'
      : 'No security issues found';
    console.log(`  ${c.safe(noIssues)}`);
  }
}

// ---------------------------------------------------------------------------
// 2. Compliance Report
// ---------------------------------------------------------------------------

async function actionReport(): Promise<void> {
  const title = currentLang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Compliance Report';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const frameworkItems: MenuItem[] = [
    { key: '1', label: 'ISO 27001' },
    { key: '2', label: 'SOC 2' },
    { key: '3', label: currentLang === 'zh-TW' ? '\u8CC7\u901A\u5B89\u5168\u7BA1\u7406\u6CD5' : 'TW Cyber Security Act' },
  ];

  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u9078\u64C7\u5408\u898F\u6846\u67B6' : 'Select Framework',
    frameworkItems,
  );

  const fwChoice = await waitForCompactChoice(frameworkItems, currentLang);
  if (!fwChoice) return;

  const frameworkMap: Record<string, string> = { '1': 'iso27001', '2': 'soc2', '3': 'tw_cyber_security_act' };
  const framework = frameworkMap[fwChoice.key] ?? 'iso27001';

  const langItems: MenuItem[] = [
    { key: '1', label: currentLang === 'zh-TW' ? '\u7E41\u9AD4\u4E2D\u6587 (zh-TW)' : 'Chinese (zh-TW)' },
    { key: '2', label: currentLang === 'zh-TW' ? '\u82F1\u6587 (en)' : 'English (en)' },
  ];

  console.log('');
  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u5831\u544A\u8A9E\u8A00' : 'Report Language',
    langItems,
  );
  const langChoice = await waitForCompactChoice(langItems, currentLang);
  if (!langChoice) return;

  const reportLang = langChoice.key === '1' ? 'zh-TW' : 'en';
  console.log('');

  const { executeCli } = await import('@panguard-ai/panguard-report');
  await executeCli(['generate', '--framework', framework, '--language', reportLang]);
}

// ---------------------------------------------------------------------------
// 3. Guard Engine
// ---------------------------------------------------------------------------

async function actionGuard(): Promise<void> {
  const title = currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u72C0\u614B' : 'Status' },
    { key: '2', label: currentLang === 'zh-TW' ? '\u555F\u52D5\u5F15\u64CE' : 'Start' },
    { key: '3', label: currentLang === 'zh-TW' ? '\u505C\u6B62\u5F15\u64CE' : 'Stop' },
    { key: '4', label: currentLang === 'zh-TW' ? '\u7522\u751F\u6E2C\u8A66\u91D1\u9470' : 'Generate Test Key' },
  ];

  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine',
    items,
  );

  const choice = await waitForCompactChoice(items, currentLang);
  if (!choice) return;

  console.log('');
  const { runCLI } = await import('@panguard-ai/panguard-guard');

  switch (choice.key) {
    case '1': await runCLI(['status']); break;
    case '2': {
      // Free tier hint
      const { tier } = getLicense();
      if (tier === 'free') {
        console.log(`  ${c.sage('\u25C6')} Guard active${' '.repeat(30)}Layer 1 \u00B7 Free`);
        console.log('');
        if (currentLang === 'zh-TW') {
          console.log(`  ${c.safe('\u2713')} \u5DF2\u77E5\u653B\u64CA\u6A21\u5F0F\u81EA\u52D5\u5C01\u9396`);
          console.log(`  ${c.critical('\u2717')} AI \u5206\u6790\u5DF2\u505C\u7528 ${c.dim('(Solo \u65B9\u6848)')}`);
          console.log(`  ${c.critical('\u2717')} \u901A\u77E5\u5DF2\u505C\u7528 ${c.dim('(Solo \u65B9\u6848)')}`);
          console.log(`  ${c.critical('\u2717')} \u65E5\u8A8C\u4FDD\u7559: \u50C5\u7576\u6B21 session`);
        } else {
          console.log(`  ${c.safe('\u2713')} Auto-blocking enabled for known attack patterns`);
          console.log(`  ${c.critical('\u2717')} AI analysis disabled ${c.dim('(Solo plan)')}`);
          console.log(`  ${c.critical('\u2717')} Notifications disabled ${c.dim('(Solo plan)')}`);
          console.log(`  ${c.critical('\u2717')} Log retention: this session only`);
        }
        console.log('');
      }
      await runCLI(['start']);
      break;
    }
    case '3': await runCLI(['stop']); break;
    case '4': await runCLI(['generate-key', 'pro']); break;
  }
}

// ---------------------------------------------------------------------------
// 4. Honeypot System
// ---------------------------------------------------------------------------

async function actionTrap(): Promise<void> {
  const title = currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Honeypot System';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: currentLang === 'zh-TW' ? '\u57FA\u672C\u914D\u7F6E (SSH + HTTP)' : 'Config (SSH + HTTP)' },
    { key: '2', label: currentLang === 'zh-TW' ? '\u5B8C\u6574\u914D\u7F6E (8 \u7A2E\u670D\u52D9)' : 'Config (All 8 Services)' },
    { key: '3', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u72C0\u614B' : 'Status' },
    { key: '4', label: currentLang === 'zh-TW' ? '\u653B\u64CA\u8005\u5206\u6790' : 'Attacker Profiles' },
  ];

  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Honeypot System',
    items,
  );
  const choice = await waitForCompactChoice(items, currentLang);
  if (!choice) return;

  console.log('');
  const { executeCli } = await import('@panguard-ai/panguard-trap');

  switch (choice.key) {
    case '1': await executeCli(['config', '--services', 'ssh,http']); break;
    case '2': await executeCli(['config', '--services', 'ssh,http,ftp,telnet,mysql,redis,smb,rdp']); break;
    case '3': await executeCli(['status']); break;
    case '4': await executeCli(['profiles']); break;
  }
}

// ---------------------------------------------------------------------------
// 5. Notifications
// ---------------------------------------------------------------------------

async function actionChat(): Promise<void> {
  const title = currentLang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notifications';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: currentLang === 'zh-TW' ? '\u8A2D\u5B9A\u901A\u77E5' : 'Setup' },
    { key: '2', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u72C0\u614B' : 'Status' },
    { key: '3', label: currentLang === 'zh-TW' ? '\u67E5\u770B\u914D\u7F6E' : 'Config' },
  ];

  renderCompactMenu(
    currentLang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notifications',
    items,
  );
  const choice = await waitForCompactChoice(items, currentLang);
  if (!choice) return;

  console.log('');
  const { runCLI } = await import('@panguard-ai/panguard-chat');

  switch (choice.key) {
    case '1': await runCLI(['setup', '--lang', currentLang]); break;
    case '2': await runCLI(['status']); break;
    case '3': await runCLI(['config']); break;
  }
}

// ---------------------------------------------------------------------------
// 6. Threat Cloud
// ---------------------------------------------------------------------------

async function actionThreat(): Promise<void> {
  const title = currentLang === 'zh-TW' ? '\u5A01\u8105\u60C5\u5831' : 'Threat Cloud';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  console.log(c.dim(currentLang === 'zh-TW'
    ? '  \u5373\u5C07\u555F\u52D5\u5A01\u8105\u60C5\u5831 REST API \u4F3A\u670D\u5668 (port 8080)'
    : '  Starting Threat Cloud REST API server (port 8080)...'));
  console.log('');

  const { ThreatCloudServer } = await import('@panguard-ai/threat-cloud');
  const sp = spinner(currentLang === 'zh-TW'
    ? '\u6B63\u5728\u555F\u52D5 Threat Cloud API...'
    : 'Starting Threat Cloud API server...');

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
    sp.succeed(currentLang === 'zh-TW'
      ? 'Threat Cloud API \u5DF2\u555F\u52D5'
      : 'Threat Cloud API started');

    console.log('');
    console.log(`  URL       ${c.underline('http://127.0.0.1:8080')}`);
    console.log(`  Health    ${c.sage('http://127.0.0.1:8080/health')}`);
    console.log(`  API       ${c.sage('http://127.0.0.1:8080/api/stats')}`);
    console.log('');

    console.log(c.dim(currentLang === 'zh-TW'
      ? '  \u6309\u4EFB\u610F\u9375\u505C\u6B62\u4F3A\u670D\u5668...'
      : '  Press any key to stop...'));

    await pressAnyKey(currentLang);
    await server.stop();
    console.log(`  ${c.safe(currentLang === 'zh-TW'
      ? 'Threat Cloud \u5DF2\u505C\u6B62'
      : 'Threat Cloud stopped')}`);
  } catch (err) {
    sp.fail(`${err instanceof Error ? err.message : String(err)}`);
  }
}

// ---------------------------------------------------------------------------
// 7. Auto Demo
// ---------------------------------------------------------------------------

async function actionDemo(): Promise<void> {
  const { runScan } = await import('@panguard-ai/panguard-scan');
  const { generateComplianceReport, generateSummaryText } = await import('@panguard-ai/panguard-report');

  const title = currentLang === 'zh-TW' ? '\u529F\u80FD\u5C55\u793A' : 'Feature Demo';
  console.log(`  ${theme.brandBold(title)}`);
  console.log(c.dim(currentLang === 'zh-TW'
    ? '  \u6B63\u5728\u57F7\u884C\u6240\u6709\u5B89\u5168\u6A21\u7D44...'
    : '  Running through all security modules...'));
  console.log('');

  // 1. Security Scan
  console.log(c.dim(currentLang === 'zh-TW' ? '  1. \u5B89\u5168\u6383\u63CF' : '  1. Security Scan'));
  console.log('');

  const scanSp = spinner(currentLang === 'zh-TW'
    ? '\u6B63\u5728\u57F7\u884C\u5FEB\u901F\u6383\u63CF...'
    : 'Running quick scan...');
  try {
    const result = await runScan({ depth: 'quick', lang: currentLang, verbose: false });
    scanSp.succeed(`${currentLang === 'zh-TW' ? '\u6383\u63CF\u5B8C\u6210' : 'Scan complete'} ${c.dim(`(${formatDuration(result.scanDuration)})`)}`);

    const safetyScore = Math.max(0, 100 - result.riskScore);
    const grade = safetyScore >= 90 ? 'A' : safetyScore >= 75 ? 'B' : safetyScore >= 60 ? 'C' : safetyScore >= 40 ? 'D' : 'F';
    console.log(`  Score: ${c.bold(`${safetyScore}/100`)} (${grade}) | Findings: ${result.findings.length}`);
  } catch (err) {
    scanSp.fail(`${err instanceof Error ? err.message : err}`);
  }
  console.log('');

  // 2. Compliance Report
  console.log(c.dim(currentLang === 'zh-TW' ? '  2. \u5408\u898F\u5831\u544A (ISO 27001)' : '  2. Compliance Report (ISO 27001)'));
  console.log('');

  const reportSp = spinner(currentLang === 'zh-TW'
    ? '\u6B63\u5728\u7522\u751F ISO 27001 \u5831\u544A...'
    : 'Generating ISO 27001 report...');
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
    reportSp.succeed(currentLang === 'zh-TW'
      ? 'ISO 27001 \u5831\u544A\u5DF2\u7522\u751F'
      : 'ISO 27001 report generated');

    const summaryLines = summary.split('\n').slice(0, 10);
    for (const line of summaryLines) {
      console.log(`  ${c.dim(line)}`);
    }
    console.log(c.dim('  ...'));
  } catch (err) {
    reportSp.fail(`${err instanceof Error ? err.message : err}`);
  }
  console.log('');

  // 3. Guard Engine
  console.log(c.dim(currentLang === 'zh-TW' ? '  3. \u5B88\u8B77\u5F15\u64CE' : '  3. Guard Engine'));
  console.log('');

  try {
    const { runCLI: guardCLI } = await import('@panguard-ai/panguard-guard');
    await guardCLI(['status']);
  } catch {
    console.log(c.dim(currentLang === 'zh-TW'
      ? '  \u5B88\u8B77\u5F15\u64CE: \u672A\u904B\u884C (\u5C55\u793A\u6B63\u5E38)'
      : '  Guard engine: not running (normal for demo)'));
  }
  console.log('');

  // 4. Honeypot
  console.log(c.dim(currentLang === 'zh-TW' ? '  4. \u871C\u7F50\u7CFB\u7D71' : '  4. Honeypot System'));
  console.log('');

  try {
    const { executeCli: trapCLI } = await import('@panguard-ai/panguard-trap');
    await trapCLI(['config', '--services', 'ssh,http']);
  } catch (err) {
    console.log(`  ${c.critical(err instanceof Error ? err.message : String(err))}`);
  }
  console.log('');

  // 5. Notifications
  console.log(c.dim(currentLang === 'zh-TW' ? '  5. \u901A\u77E5\u7CFB\u7D71' : '  5. Notification System'));
  console.log('');

  try {
    const { runCLI: chatCLI } = await import('@panguard-ai/panguard-chat');
    await chatCLI(['status']);
  } catch {
    console.log(c.dim(currentLang === 'zh-TW'
      ? '  \u901A\u77E5\u7CFB\u7D71: \u5C1A\u672A\u914D\u7F6E'
      : '  Notification system: not configured'));
  }
  console.log('');

  // Summary
  console.log(`  ${theme.brandBold(currentLang === 'zh-TW' ? '\u5C55\u793A\u5B8C\u6210' : 'Demo Complete')}`);
  console.log('');
  const modules = [
    currentLang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Scan',
    currentLang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Report',
    currentLang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard',
    currentLang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Trap',
    currentLang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notify',
  ];
  for (const m of modules) {
    console.log(`  ${c.safe('\u2713')} ${m}`);
  }
}
