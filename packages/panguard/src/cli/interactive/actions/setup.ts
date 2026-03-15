/**
 * Setup & MCP connection actions
 * @module @panguard-ai/panguard/cli/interactive/actions/setup
 */

import { c, spinner } from '@panguard-ai/core';
import { theme } from '../../theme.js';
import { breadcrumb, formatError } from '../../ux-helpers.js';
import type { Lang } from '../../menu.js';

export async function actionInit(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u521D\u59CB\u8A2D\u5B9A' : 'Setup']);
  const { runInitWizard } = await import('../../../init/index.js');
  await runInitWizard(lang);
}

export async function actionMCPSetup(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? 'MCP \u8A2D\u5B9A' : 'MCP Setup']);
  const title = lang === 'zh-TW' ? 'AI \u4EE3\u7406\u9023\u63A5 (MCP)' : 'AI Agent Connection (MCP)';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const detectSp = spinner(
    lang === 'zh-TW'
      ? '\u6B63\u5728\u5075\u6E2C AI \u4EE3\u7406\u5E73\u53F0...'
      : 'Detecting AI agent platforms...'
  );

  try {
    const mcpConfig = await import('@panguard-ai/panguard-mcp/config');
    const platforms = await mcpConfig.detectPlatforms();
    const detected = platforms.filter((p: { detected: boolean }) => p.detected);
    const unconfigured = detected.filter(
      (p: { alreadyConfigured: boolean }) => !p.alreadyConfigured
    );

    if (detected.length === 0) {
      detectSp.warn(
        lang === 'zh-TW'
          ? '\u672A\u5075\u6E2C\u5230\u4EFB\u4F55 AI \u4EE3\u7406\u5E73\u53F0'
          : 'No AI agent platforms detected'
      );
      console.log('');
      console.log(
        c.dim(
          lang === 'zh-TW'
            ? '  \u652F\u63F4\u5E73\u53F0: Claude Code, Cursor, OpenClaw, Codex, WorkBuddy, NemoClaw, Claude Desktop'
            : '  Supported: Claude Code, Cursor, OpenClaw, Codex, WorkBuddy, NemoClaw, Claude Desktop'
        )
      );
      return;
    }

    detectSp.succeed(
      lang === 'zh-TW'
        ? `\u5075\u6E2C\u5230 ${detected.length} \u500B\u5E73\u53F0`
        : `Found ${detected.length} platform(s)`
    );
    console.log('');

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
      console.log(
        c.safe(
          lang === 'zh-TW'
            ? `  \u2713 \u6240\u6709\u5E73\u53F0\u5DF2\u8A2D\u5B9A\u5B8C\u6210\uFF01`
            : '  \u2713 All platforms already configured!'
        )
      );
      console.log('');
      console.log(
        c.dim(
          lang === 'zh-TW'
            ? '  \u91CD\u555F AI \u4EE3\u7406\u5F8C\uFF0C\u8ACB\u6C42\u300Cpanguard_status\u300D\u5373\u53EF\u9A57\u8B49\u3002'
            : '  Restart your AI agent, then ask "panguard_status" to verify.'
        )
      );
      return;
    }

    const configSp = spinner(
      lang === 'zh-TW'
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
        lang === 'zh-TW'
          ? `${successCount} \u500B\u5E73\u53F0\u8A2D\u5B9A\u5B8C\u6210`
          : `${successCount} platform(s) configured`
      );
    } else {
      configSp.warn(
        lang === 'zh-TW'
          ? `${successCount}/${unconfigured.length} \u5E73\u53F0\u8A2D\u5B9A\u6210\u529F`
          : `${successCount}/${unconfigured.length} platform(s) configured`
      );
    }

    console.log('');
    console.log(
      c.dim(
        lang === 'zh-TW'
          ? '  \u91CD\u555F AI \u4EE3\u7406\u5F8C\u5373\u53EF\u4F7F\u7528 11 \u500B panguard_* MCP \u5DE5\u5177\uFF1A'
          : '  Restart your AI agent to use 11 panguard_* MCP tools:'
      )
    );

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
        ? lang === 'zh-TW' ? hint.zh : hint.en
        : lang === 'zh-TW' ? '\u91CD\u65B0\u555F\u52D5\u61C9\u7528\u7A0B\u5F0F' : 'Restart the application';
      console.log(c.dim(`    ${p.name}: ${text}`));
    }

    console.log('');
    console.log(
      c.dim(
        lang === 'zh-TW'
          ? '  \u8A66\u8A66\u554F AI: \u300C\u5BE9\u8A08\u9019\u500B\u5C08\u6848\u7684\u6280\u80FD\u300D\u6216\u300C\u6383\u63CF\u6211\u7684\u7CFB\u7D71\u300D'
          : '  Try asking your AI: "audit the skills in this project" or "scan my system"'
      )
    );
  } catch (err) {
    detectSp.fail(lang === 'zh-TW' ? 'MCP \u8A2D\u5B9A\u5931\u6557' : 'MCP setup failed');
    console.log(
      formatError(
        err instanceof Error ? err.message : String(err),
        'MCP Setup',
        lang === 'zh-TW' ? '\u8ACB\u91CD\u8A66' : 'Please retry'
      )
    );
  }
}
