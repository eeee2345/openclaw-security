/**
 * Init Wizard Runner - Orchestrates the full onboarding flow
 * 初始設定精靈執行器 - 編排完整的設定流程
 *
 * @module @panguard-ai/panguard/init/wizard-runner
 */

import {
  banner, box, c, symbols, statusPanel, divider, spinner,
  WizardEngine, promptConfirm,
} from '@panguard-ai/core';
import type { WizardAnswers as CoreWizardAnswers } from '@panguard-ai/core';
import { getWizardSteps } from './steps.js';
import { hasExistingConfig, getEnvironmentInfo } from './environment.js';
import { buildPanguardConfig, writeConfig } from './config-writer.js';
import type { WizardAnswers, Lang, OrgSize, DeployEnv, AiPreference, ProtectionLevel } from './types.js';

/**
 * Run the full init wizard.
 * Returns the path to the generated config, or null if cancelled.
 */
export async function runInitWizard(langOverride?: string): Promise<string | null> {
  const initialLang: Lang = langOverride === 'en' ? 'en' : 'zh-TW';

  // ── Welcome screen ──────────────────────────────────────────
  console.clear();
  console.log(banner());
  console.log('');
  console.log(box(
    [
      initialLang === 'zh-TW'
        ? 'Panguard AI Setup Wizard / \u8A2D\u5B9A\u7CBE\u9748'
        : 'Panguard AI Setup Wizard',
      '',
      initialLang === 'zh-TW'
        ? '\u901A\u904E\u5E7E\u500B\u554F\u984C\u4E86\u89E3\u4F60\u7684\u74B0\u5883\uFF0C\u81EA\u52D5\u914D\u7F6E\u6240\u6709\u5B89\u5168\u6A21\u7D44\u3002'
        : 'A few questions to understand your environment and auto-configure all security modules.',
    ].join('\n'),
    { borderColor: c.sage },
  ));
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
      console.log(`\n  ${symbols.info} ${initialLang === 'zh-TW' ? '\u5DF2\u53D6\u6D88\u3002' : 'Cancelled.'}\n`);
      return null;
    }
  }

  // ── Run wizard steps ────────────────────────────────────────
  const steps = getWizardSteps();
  const engine = new WizardEngine(steps, initialLang);
  const rawAnswers = await engine.run();

  if (!rawAnswers) {
    console.log(`\n  ${symbols.info} ${initialLang === 'zh-TW' ? '\u5DF2\u53D6\u6D88\u8A2D\u5B9A\u3002' : 'Setup cancelled.'}\n`);
    return null;
  }

  // ── Parse raw answers into typed structure ──────────────────
  const lang = engine.getLang();
  const envInfo = getEnvironmentInfo();
  const answers = parseAnswers(rawAnswers, envInfo);

  // ── Show configuration summary ──────────────────────────────
  console.log('');
  console.log(divider(lang === 'zh-TW' ? '\u914D\u7F6E\u6458\u8981' : 'Configuration Summary'));
  console.log('');

  const config = buildPanguardConfig(answers);

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
      status: config.security.protectionLevel === 'aggressive' ? 'alert' as const : 'safe' as const,
    },
    {
      label: 'AI',
      value: config.ai.preference === 'cloud_ai' ? 'Cloud AI (Claude/OpenAI)'
        : config.ai.preference === 'local_ai' ? 'Local AI (Ollama)'
        : lang === 'zh-TW' ? '\u50C5\u898F\u5247' : 'Rules Only',
    },
    {
      label: lang === 'zh-TW' ? '\u901A\u77E5' : 'Notifications',
      value: config.notifications.channel === 'none'
        ? (lang === 'zh-TW' ? '\u672A\u8A2D\u5B9A' : 'Not configured')
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

  console.log(statusPanel(
    lang === 'zh-TW' ? 'Panguard AI \u914D\u7F6E' : 'Panguard AI Configuration',
    summaryItems,
  ));

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
    console.log(`\n  ${symbols.info} ${lang === 'zh-TW' ? '\u5DF2\u53D6\u6D88\u3002' : 'Cancelled.'}\n`);
    return null;
  }

  // Write config
  const sp = spinner(lang === 'zh-TW' ? '\u5BEB\u5165\u914D\u7F6E...' : 'Writing configuration...');
  const configPath = writeConfig(config);
  sp.succeed(lang === 'zh-TW' ? `\u914D\u7F6E\u5DF2\u5BEB\u5165 ${configPath}` : `Config saved to ${configPath}`);

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
    const scanSp = spinner(lang === 'zh-TW' ? '\u6383\u63CF\u4E2D...' : 'Scanning...');
    try {
      const { runScan: execScan } = await import('@panguard-ai/panguard-scan');
      const result = await execScan({ depth: 'quick', lang });
      scanSp.succeed(
        lang === 'zh-TW'
          ? `\u6383\u63CF\u5B8C\u6210\uFF01\u98A8\u96AA\u5206\u6578: ${result.riskScore}/100\uFF0C${result.findings.length} \u500B\u767C\u73FE`
          : `Scan complete! Risk score: ${result.riskScore}/100, ${result.findings.length} finding(s)`,
      );
    } catch {
      scanSp.warn(lang === 'zh-TW' ? '\u6383\u63CF\u5931\u6557\uFF08\u53EF\u7A0D\u5F8C\u7528 panguard scan \u57F7\u884C\uFF09' : 'Scan failed (run panguard scan later)');
    }
  }

  // ── Final guidance ─────────────────────────────────────────
  console.log('');
  console.log(box(
    lang === 'zh-TW' ? [
      `${symbols.pass} Panguard AI \u8A2D\u5B9A\u5B8C\u6210\uFF01`,
      '',
      '\u63A5\u4E0B\u4F86\u4F60\u53EF\u4EE5\uFF1A',
      '',
      `  ${c.sage('panguard deploy')}     \u90E8\u7F72\u5DF2\u914D\u7F6E\u7684\u670D\u52D9`,
      `  ${c.sage('panguard scan')}       \u57F7\u884C\u5B8C\u6574\u5B89\u5168\u6383\u63CF`,
      `  ${c.sage('panguard status')}     \u67E5\u770B\u7CFB\u7D71\u72C0\u614B`,
      `  ${c.sage('panguard guard start')}\u555F\u52D5\u5373\u6642\u9632\u8B77`,
      `  ${c.sage('panguard')}            \u958B\u555F\u4E92\u52D5\u6A21\u5F0F`,
    ].join('\n') : [
      `${symbols.pass} Panguard AI setup complete!`,
      '',
      'Next steps:',
      '',
      `  ${c.sage('panguard deploy')}      Deploy configured services`,
      `  ${c.sage('panguard scan')}        Run a full security scan`,
      `  ${c.sage('panguard status')}      Check system status`,
      `  ${c.sage('panguard guard start')} Start real-time protection`,
      `  ${c.sage('panguard')}             Open interactive mode`,
    ].join('\n'),
    { borderColor: c.safe },
  ));
  console.log('');

  return configPath;
}

// ── Parse raw wizard answers ───────────────────────────────

function parseAnswers(
  raw: CoreWizardAnswers,
  envInfo: { os: string; hostname: string },
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
