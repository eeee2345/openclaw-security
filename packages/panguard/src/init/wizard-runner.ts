/**
 * Init Wizard Runner - Orchestrates the full onboarding flow
 * 初始設定精靈執行器 - 編排完整的設定流程
 *
 * @module @panguard-ai/panguard/init/wizard-runner
 */

import {
  banner,
  box,
  c,
  symbols,
  statusPanel,
  divider,
  spinner,
  guardSpinner,
  setLogLevel,
  WizardEngine,
  promptConfirm,
} from '@panguard-ai/core';
import type { WizardAnswers as CoreWizardAnswers } from '@panguard-ai/core';
import { getWizardSteps, getQuickSteps } from './steps.js';
import { hasExistingConfig, getEnvironmentInfo, getEnhancedEnvironment } from './environment.js';
import { buildPanguardConfig, buildQuickConfig, writeConfig } from './config-writer.js';
import type {
  WizardAnswers,
  PanguardConfig,
  Lang,
  OrgSize,
  DeployEnv,
  AiPreference,
  ProtectionLevel,
  UsageProfile,
} from './types.js';
import { PANGUARD_VERSION } from '../index.js';

/**
 * Run the init wizard.
 * Default: quick 3-step flow. Pass advanced=true for full 10-step wizard.
 * Returns the path to the generated config, or null if cancelled.
 */
export async function runInitWizard(
  langOverride?: string,
  advanced = false
): Promise<string | null> {
  const initialLang: Lang = langOverride === 'en' ? 'en' : 'zh-TW';

  // ── Welcome screen ──────────────────────────────────────────
  console.clear();
  console.log(banner(PANGUARD_VERSION));
  console.log('');
  console.log(
    box(
      [
        initialLang === 'zh-TW'
          ? 'Panguard AI Setup Wizard / \u8A2D\u5B9A\u7CBE\u9748'
          : 'Panguard AI Setup Wizard',
        '',
        advanced
          ? initialLang === 'zh-TW'
            ? '\u901A\u904E\u5E7E\u500B\u554F\u984C\u4E86\u89E3\u4F60\u7684\u74B0\u5883\uFF0C\u81EA\u52D5\u914D\u7F6E\u6240\u6709\u5B89\u5168\u6A21\u7D44\u3002'
            : 'A few questions to understand your environment and auto-configure all security modules.'
          : initialLang === 'zh-TW'
            ? '\u5FEB\u901F\u8A2D\u5B9A\uFF1A\u9078\u64C7\u8A9E\u8A00\u548C\u4F7F\u7528\u60C5\u5883\uFF0C\u5176\u4ED6\u5168\u90E8\u81EA\u52D5\u5075\u6E2C\u3002'
            : 'Quick setup: pick your language and usage profile, we auto-detect the rest.',
      ].join('\n'),
      { borderColor: c.sage }
    )
  );
  console.log('');

  // ── Check for existing config ───────────────────────────────
  if (hasExistingConfig()) {
    const overwrite = await promptConfirm({
      message: {
        en: 'An existing config was found. Overwrite it?',
        'zh-TW': '\u767C\u73FE\u5DF2\u6709\u914D\u7F6E\u3002\u8981\u8986\u5BEB\u55CE\uFF1F',
      },
      defaultValue: false,
      lang: initialLang,
    });

    if (!overwrite) {
      console.log(
        `\n  ${symbols.info} ${initialLang === 'zh-TW' ? '\u5DF2\u53D6\u6D88\u3002' : 'Cancelled.'}\n`
      );
      return null;
    }
  }

  // ── Run wizard steps ────────────────────────────────────────
  const steps = advanced ? getWizardSteps() : getQuickSteps();
  const engine = new WizardEngine(steps, initialLang);
  const rawAnswers = await engine.run();

  if (!rawAnswers) {
    console.log(
      `\n  ${symbols.info} ${initialLang === 'zh-TW' ? '\u5DF2\u53D6\u6D88\u8A2D\u5B9A\u3002' : 'Setup cancelled.'}\n`
    );
    return null;
  }

  // ── Build config from answers ─────────────────────────────
  const lang = engine.getLang();

  let config: PanguardConfig;
  if (advanced) {
    const envInfo = getEnvironmentInfo();
    const answers = parseAnswers(rawAnswers, envInfo);
    config = buildPanguardConfig(answers);
  } else {
    const profile = (rawAnswers['usageProfile'] as UsageProfile) ?? 'personal';
    const env = getEnhancedEnvironment();
    config = buildQuickConfig(profile, lang, env);
  }

  // ── Show configuration summary ──────────────────────────────
  console.log('');
  console.log(divider(lang === 'zh-TW' ? '\u914D\u7F6E\u6458\u8981' : 'Configuration Summary'));
  console.log('');

  const summaryItems = [
    {
      label: lang === 'zh-TW' ? '\u7D44\u7E54' : 'Organization',
      value: `${config.organization.name} (${config.organization.size})`,
      status: 'safe' as const,
    },
    {
      label: lang === 'zh-TW' ? '\u74B0\u5883' : 'Environment',
      value: config.environment.os,
    },
    {
      label: lang === 'zh-TW' ? '\u9632\u8B77\u6A21\u5F0F' : 'Protection',
      value: config.security.protectionLevel,
      status:
        config.security.protectionLevel === 'aggressive' ? ('alert' as const) : ('safe' as const),
    },
    {
      label: 'AI',
      value:
        config.ai.preference === 'cloud_ai'
          ? 'Cloud AI (Claude/OpenAI)'
          : config.ai.preference === 'local_ai'
            ? 'Local AI (Ollama)'
            : lang === 'zh-TW'
              ? '\u50C5\u898F\u5247'
              : 'Rules Only',
    },
    {
      label: lang === 'zh-TW' ? '\u901A\u77E5' : 'Notifications',
      value:
        config.notifications.channel === 'none'
          ? lang === 'zh-TW'
            ? '\u672A\u8A2D\u5B9A'
            : 'Not configured'
          : config.notifications.channel.toUpperCase(),
    },
  ];

  // Show enabled modules
  const enabledModules = Object.entries(config.modules)
    .filter(([, v]) => v)
    .map(([k]) => k)
    .join(', ');

  summaryItems.push({
    label: lang === 'zh-TW' ? '\u555F\u7528\u6A21\u7D44' : 'Modules',
    value: enabledModules,
  });

  console.log(
    statusPanel(
      lang === 'zh-TW' ? 'Panguard AI \u914D\u7F6E' : 'Panguard AI Configuration',
      summaryItems
    )
  );

  // ── Confirm and write ──────────────────────────────────────
  const confirm = await promptConfirm({
    message: {
      en: 'Save this configuration?',
      'zh-TW': '\u5132\u5B58\u9019\u500B\u914D\u7F6E\uFF1F',
    },
    defaultValue: true,
    lang,
  });

  if (!confirm) {
    console.log(
      `\n  ${symbols.info} ${lang === 'zh-TW' ? '\u5DF2\u53D6\u6D88\u3002' : 'Cancelled.'}\n`
    );
    return null;
  }

  // Suppress JSON logs during config write and scan
  setLogLevel('silent');

  // Write config
  const sp = spinner(lang === 'zh-TW' ? '\u5BEB\u5165\u914D\u7F6E...' : 'Writing configuration...');
  const configPath = writeConfig(config);
  sp.succeed(
    lang === 'zh-TW'
      ? `\u914D\u7F6E\u5DF2\u5BEB\u5165 ${configPath}`
      : `Config saved to ${configPath}`
  );

  // ── Post-setup actions ─────────────────────────────────────
  console.log('');

  // Offer to run quick scan
  const runScan = await promptConfirm({
    message: {
      en: 'Run a quick security scan now?',
      'zh-TW': '\u73FE\u5728\u57F7\u884C\u5FEB\u901F\u5B89\u5168\u6383\u63CF\uFF1F',
    },
    defaultValue: true,
    lang,
  });

  if (runScan) {
    console.log('');
    const scanSp = guardSpinner(lang === 'zh-TW' ? '\u6383\u63CF\u4E2D...' : 'Scanning...');
    try {
      const { runScan: execScan } = await import('@panguard-ai/panguard-scan');
      const result = await execScan({ depth: 'quick', lang });
      scanSp.succeed(
        lang === 'zh-TW'
          ? `\u6383\u63CF\u5B8C\u6210\uFF01\u98A8\u96AA\u5206\u6578: ${result.riskScore}/100\uFF0C${result.findings.length} \u500B\u767C\u73FE`
          : `Scan complete! Risk score: ${result.riskScore}/100, ${result.findings.length} finding(s)`
      );
    } catch {
      scanSp.warn(
        lang === 'zh-TW'
          ? '\u6383\u63CF\u5931\u6557\uFF08\u53EF\u7A0D\u5F8C\u7528 panguard scan \u57F7\u884C\uFF09'
          : 'Scan failed (run panguard scan later)'
      );
    }
  }

  // ── Auto-run MCP setup ──────────────────────────────────────
  console.log('');
  const runMCPSetup = await promptConfirm({
    message: {
      en: 'Connect to AI agents (Claude Code, Cursor, etc.) via MCP?',
      'zh-TW':
        '\u8981\u900F\u904E MCP \u9023\u63A5 AI \u4EE3\u7406\uFF08Claude Code\u3001Cursor \u7B49\uFF09\u55CE\uFF1F',
    },
    defaultValue: true,
    lang,
  });

  if (runMCPSetup) {
    console.log('');
    const mcpSp = spinner(
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

      if (unconfigured.length > 0) {
        mcpSp.succeed(
          lang === 'zh-TW'
            ? `\u5075\u6E2C\u5230 ${detected.length} \u500B\u5E73\u53F0\uFF0C\u6B63\u5728\u8A2D\u5B9A ${unconfigured.length} \u500B...`
            : `Found ${detected.length} platform(s), configuring ${unconfigured.length}...`
        );

        let successCount = 0;
        for (const p of unconfigured) {
          const result = mcpConfig.injectMCPConfig(p.id);
          if (result.success) {
            console.log(`  ${c.safe(symbols.pass)} ${p.name}`);
            successCount++;
          } else {
            console.log(`  ${c.critical(symbols.fail)} ${p.name}: ${result.error}`);
          }
        }

        if (successCount > 0) {
          console.log('');
          console.log(
            c.dim(
              lang === 'zh-TW'
                ? '  \u91CD\u555F AI \u4EE3\u7406\u5F8C\u5373\u53EF\u4F7F\u7528 panguard_* MCP \u5DE5\u5177\uFF1A'
                : '  Restart your AI agent to use panguard_* MCP tools:'
            )
          );
          // Platform-specific restart guidance
          const restartMap: Record<string, { en: string; zh: string }> = {
            'claude-code': {
              en: 'Close and reopen your terminal',
              zh: '\u95DC\u9589\u4E26\u91CD\u65B0\u958B\u555F\u7D42\u7AEF\u6A5F',
            },
            'claude-desktop': {
              en: 'Quit and reopen Claude Desktop',
              zh: '\u9000\u51FA\u4E26\u91CD\u65B0\u958B\u555F Claude Desktop',
            },
            cursor: { en: 'Cmd+Shift+P > "Reload Window"', zh: 'Cmd+Shift+P > "Reload Window"' },
            openclaw: {
              en: 'Close and reopen OpenClaw',
              zh: '\u95DC\u9589\u4E26\u91CD\u65B0\u958B\u555F OpenClaw',
            },
            codex: {
              en: 'Restart the Codex CLI session',
              zh: '\u91CD\u65B0\u555F\u52D5 Codex CLI',
            },
            workbuddy: {
              en: 'Close and reopen WorkBuddy',
              zh: '\u95DC\u9589\u4E26\u91CD\u65B0\u958B\u555F WorkBuddy',
            },
            nemoclaw: {
              en: 'Close and reopen NemoClaw',
              zh: '\u95DC\u9589\u4E26\u91CD\u65B0\u958B\u555F NemoClaw',
            },
          };
          for (const p of unconfigured) {
            const hint = restartMap[p.id];
            if (hint) {
              console.log(c.dim(`    ${p.name}: ${lang === 'zh-TW' ? hint.zh : hint.en}`));
            }
          }
        }
      } else if (detected.length > 0) {
        mcpSp.succeed(
          lang === 'zh-TW'
            ? `${detected.length} \u500B\u5E73\u53F0\u5DF2\u8A2D\u5B9A\u5B8C\u6210`
            : `${detected.length} platform(s) already configured`
        );
      } else {
        mcpSp.warn(
          lang === 'zh-TW'
            ? '\u672A\u5075\u6E2C\u5230 AI \u4EE3\u7406\u5E73\u53F0\u3002\u7A0D\u5F8C\u57F7\u884C panguard setup \u5373\u53EF\u3002'
            : 'No AI agent platforms detected. Run panguard setup later.'
        );
      }
    } catch {
      mcpSp.warn(
        lang === 'zh-TW'
          ? 'MCP \u8A2D\u5B9A\u5931\u6557\uFF0C\u7A0D\u5F8C\u57F7\u884C panguard setup'
          : 'MCP setup failed. Run panguard setup later.'
      );
    }
  }

  // ── Offer skill audit ──────────────────────────────────────
  console.log('');
  const runAudit = await promptConfirm({
    message: {
      en: 'Audit current directory for AI skill security issues?',
      'zh-TW':
        '\u8981\u5BE9\u8A08\u7576\u524D\u76EE\u9304\u7684 AI \u6280\u80FD\u5B89\u5168\u554F\u984C\u55CE\uFF1F',
    },
    defaultValue: true,
    lang,
  });

  if (runAudit) {
    console.log('');
    const auditSp = spinner(lang === 'zh-TW' ? '\u6B63\u5728\u5BE9\u8A08...' : 'Auditing...');
    try {
      const { auditSkill } = await import('@panguard-ai/panguard-skill-auditor');
      const report = await auditSkill(process.cwd());
      auditSp.succeed(
        lang === 'zh-TW'
          ? `\u5BE9\u8A08\u5B8C\u6210\uFF01\u98A8\u96AA: ${report.riskScore}/100 (${report.riskLevel})\uFF0C${report.findings.length} \u500B\u767C\u73FE`
          : `Audit complete! Risk: ${report.riskScore}/100 (${report.riskLevel}), ${report.findings.length} finding(s)`
      );
    } catch {
      auditSp.warn(
        lang === 'zh-TW'
          ? '\u6B64\u76EE\u9304\u672A\u627E\u5230 AI \u6280\u80FD (SKILL.md)\u3002\u5728\u5305\u542B\u6280\u80FD\u7684\u5C08\u6848\u76EE\u9304\u4E2D\u57F7\u884C panguard audit skill <path>'
          : 'No AI skills (SKILL.md) found here. Run panguard audit skill <path> in a project with skills.'
      );
    }
  }

  // ── Guard AI layer configuration ──────────────────────────
  // Check if AI layer is already configured
  const aiPref = config.ai?.preference ?? 'rules_only';
  if (aiPref === 'rules_only') {
    console.log('');
    const configureAI = await promptConfirm({
      message: {
        en: 'Configure AI detection layer for Guard? (Ollama or Claude API)',
        'zh-TW':
          '\u8981\u8A2D\u5B9A Guard \u7684 AI \u5075\u6E2C\u5C64\u55CE\uFF1F\uFF08Ollama \u6216 Claude API\uFF09',
      },
      defaultValue: false,
      lang,
    });

    if (configureAI) {
      console.log('');
      try {
        const { guardCommand } = await import('../cli/commands/guard.js');
        const guardCmd = guardCommand();
        await guardCmd.parseAsync(['guard', 'setup-ai'], { from: 'user' });
      } catch {
        console.log(
          c.dim(
            lang === 'zh-TW'
              ? '  AI \u8A2D\u5B9A\u5931\u6557\u3002\u7A0D\u5F8C\u57F7\u884C panguard guard setup-ai'
              : '  AI setup failed. Run panguard guard setup-ai later.'
          )
        );
      }
    }
  }

  // ── Final guidance ─────────────────────────────────────────
  console.log('');
  console.log(
    box(
      lang === 'zh-TW'
        ? [
            `${symbols.pass} Panguard AI \u8A2D\u5B9A\u5B8C\u6210\uFF01`,
            '',
            '\u63A5\u4E0B\u4F86\u4F60\u53EF\u4EE5\uFF1A',
            '',
            `  ${c.sage('panguard setup')}      \u9023\u63A5 AI \u4EE3\u7406 (MCP)`,
            `  ${c.sage('panguard audit skill .')} \u5BE9\u8A08 AI \u6280\u80FD\u5B89\u5168`,
            `  ${c.sage('panguard scan')}       \u57F7\u884C\u5B8C\u6574\u5B89\u5168\u6383\u63CF`,
            `  ${c.sage('panguard guard start --dashboard')} \u555F\u52D5 Guard + Dashboard`,
          ].join('\n')
        : [
            `${symbols.pass} Panguard AI setup complete!`,
            '',
            'Next steps:',
            '',
            `  ${c.sage('panguard setup')}       Connect AI agents (MCP)`,
            `  ${c.sage('panguard audit skill .')} Audit AI skill security`,
            `  ${c.sage('panguard scan')}        Run a full security scan`,
            `  ${c.sage('panguard guard start --dashboard')} Start Guard + Dashboard`,
          ].join('\n'),
      { borderColor: c.safe }
    )
  );
  console.log('');

  return configPath;
}

// ── Parse raw wizard answers ───────────────────────────────

function parseAnswers(
  raw: CoreWizardAnswers,
  envInfo: { os: string; hostname: string }
): WizardAnswers {
  return {
    language: (raw['language'] as Lang) ?? 'zh-TW',
    orgName: raw['orgName'] ?? '',
    orgSize: (raw['orgSize'] as OrgSize) ?? 'individual',
    industry: raw['industry'] ?? 'tech',
    environment: {
      os: raw['environment_os'] ?? envInfo.os,
      hostname: envInfo.hostname,
      deployType: (raw['deployType'] as DeployEnv) ?? 'cloud',
      serverCount: parseInt(raw['serverCount'] ?? '1', 10) || 1,
    },
    securityGoals: raw['securityGoals'] ?? 'all',
    compliance: raw['compliance'] ?? 'none',
    notification: {
      channel: raw['notification'] ?? 'none',
      config: {},
    },
    aiPreference: (raw['aiPreference'] as AiPreference) ?? 'rules_only',
    protectionLevel: (raw['protectionLevel'] as ProtectionLevel) ?? 'balanced',
  };
}
