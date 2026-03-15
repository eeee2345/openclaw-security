/**
 * Panguard AI - Interactive CLI Mode
 *
 * Number-key menu [0]-[8] with panguard > prompt for text commands.
 * Box-bordered status panel, breadcrumb navigation, no "press any key" interrupts.
 *
 * @module @panguard-ai/panguard/cli/interactive
 */

import { existsSync } from 'node:fs';
import { c } from '@panguard-ai/core';
import { waitForMainInput, cleanupTerminal } from './menu.js';
import { checkFeatureAccess, showUpgradePrompt } from './auth-guard.js';
import { formatError } from './ux-helpers.js';

import { getLang, setLang, getConfigPath, detectLang, saveLang } from './interactive/lang.js';
import { MENU_DEFS } from './interactive/menu-defs.js';
import { renderStartup, showHelp, isMCPConfigured } from './interactive/render.js';

import { actionInit, actionMCPSetup } from './interactive/actions/setup.js';
import { actionScan } from './interactive/actions/scan.js';
import { actionGuard } from './interactive/actions/guard.js';
import { actionDemo } from './interactive/actions/demo.js';
import { actionAudit } from './interactive/actions/audit.js';
import {
  actionReport,
  actionTrap,
  actionChat,
  actionThreat,
  actionHardening,
  actionStatus,
  actionConfig,
} from './interactive/actions/misc.js';

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function startInteractive(lang?: string): Promise<void> {
  setLang(lang === 'en' ? 'en' : lang === 'zh-TW' ? 'zh-TW' : detectLang());

  const exit = () => {
    cleanupTerminal();
    const msg = getLang() === 'zh-TW' ? '\u611F\u8B1D\u4F7F\u7528 Panguard AI\uFF01' : 'Goodbye!';
    console.log(`\n  ${c.sage(msg)}\n`);
    process.exit(0);
  };
  process.on('SIGINT', exit);
  process.on('SIGTERM', exit);

  renderStartup(getLang());

  // First-time user hint
  const mcpConfigured = await isMCPConfigured();
  if (!existsSync(getConfigPath())) {
    console.log(
      getLang() === 'zh-TW'
        ? `  ${c.sage('\u25C6')} \u9996\u6B21\u4F7F\u7528\uFF1F\u5EFA\u8B70\u6D41\u7A0B\uFF1A`
        : `  ${c.sage('\u25C6')} First time? Recommended flow:`
    );
    console.log(
      getLang() === 'zh-TW'
        ? `    ${c.sage('[0]')} \u521D\u59CB\u8A2D\u5B9A \u2192 \u81EA\u52D5\u9023\u63A5 AI \u4EE3\u7406 + \u6280\u80FD\u5BE9\u8A08 + \u6383\u63CF`
        : `    ${c.sage('[0]')} Setup Wizard \u2192 auto-connect AI agents + skill audit + scan`
    );
    console.log(
      getLang() === 'zh-TW'
        ? `    ${c.sage('[8]')} \u6280\u80FD\u5BE9\u8A08 \u2192 \u5BE9\u8A08\u5DF2\u5B89\u88DD AI \u6280\u80FD\u7684\u5B89\u5168\u554F\u984C`
        : `    ${c.sage('[8]')} Skill Auditor \u2192 check installed AI skills for security issues`
    );
    console.log('');
  } else if (!mcpConfigured) {
    console.log(
      getLang() === 'zh-TW'
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
        showHelp(getLang());
        continue;

      case 'lang_toggle':
        setLang(getLang() === 'zh-TW' ? 'en' : 'zh-TW');
        saveLang(getLang());
        renderStartup(getLang());
        continue;

      case 'number': {
        const def = MENU_DEFS[input.index];
        if (!def) continue;

        if (!checkFeatureAccess(def.featureKey)) {
          showUpgradePrompt(def.featureKey, getLang());
          await new Promise((r) => setTimeout(r, 500));
          renderStartup(getLang());
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
              `${getLang() === 'zh-TW' ? '\u57F7\u884C' : 'Running'} ${def.key}`,
              getLang() === 'zh-TW' ? '\u8ACB\u67E5\u770B\u65E5\u8A8C\u6216\u91CD\u8A66' : 'Check logs or retry'
            )
          );
        }

        await new Promise((r) => setTimeout(r, 500));
        renderStartup(getLang());
        continue;
      }

      case 'command': {
        const text = input.text.toLowerCase();
        if (!text) continue;

        const handled = await dispatchCommand(text);
        if (!handled) {
          console.log(
            c.dim(
              getLang() === 'zh-TW'
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
  const lang = getLang();

  switch (text) {
    case 'status':
      console.clear();
      await actionStatus(lang);
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'login':
    case 'logout':
      console.clear();
      console.log('');
      console.log('  Authentication removed. All features are free and open source.');
      console.log('');
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'config':
      console.clear();
      await actionConfig(lang);
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'upgrade':
      console.clear();
      console.log('');
      console.log('  All features are free and open source.');
      console.log('');
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'hardening':
      console.clear();
      await actionHardening(lang);
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'doctor':
      console.clear();
      try {
        const { runDoctor } = await import('./commands/doctor.js');
        await runDoctor(lang);
      } catch (err) {
        console.log(
          formatError(
            err instanceof Error ? err.message : String(err),
            lang === 'zh-TW' ? '\u57F7\u884C\u5065\u5EB7\u8A3A\u65B7' : 'Running diagnostics',
            lang === 'zh-TW' ? '\u8ACB\u91CD\u8A66' : 'Please retry'
          )
        );
      }
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'whoami':
      console.clear();
      console.log('');
      console.log('  All features available (no login required).');
      console.log('');
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'audit':
      console.clear();
      await actionAudit(lang);
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'setup':
      console.clear();
      await actionMCPSetup(lang);
      await new Promise((r) => setTimeout(r, 500));
      renderStartup(lang);
      return true;

    case 'help':
      showHelp(lang);
      return true;

    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Action dispatch (from numbered menu)
// ---------------------------------------------------------------------------

async function dispatch(key: string): Promise<void> {
  const lang = getLang();

  switch (key) {
    case 'setup':
      await actionInit(lang);
      break;
    case 'scan':
      await actionScan(lang, () => actionGuard(lang), () => actionAudit(lang));
      break;
    case 'report':
      await actionReport(lang);
      break;
    case 'guard':
      await actionGuard(lang);
      break;
    case 'trap':
      await actionTrap(lang);
      break;
    case 'notify':
      await actionChat(lang);
      break;
    case 'threat-cloud':
      await actionThreat(lang);
      break;
    case 'demo':
      await actionDemo(lang);
      break;
    case 'audit':
      await actionAudit(lang);
      break;
  }
}
