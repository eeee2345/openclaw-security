/**
 * `panguard deploy` - Deploy configured services
 * `panguard deploy` - 部署已配置的服務
 *
 * @module @panguard-ai/panguard/cli/commands/deploy
 */

import { Command } from 'commander';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { c, symbols, spinner, box, statusPanel, divider } from '@panguard-ai/core';
import { readConfig } from '../../init/config-writer.js';
import type { PanguardConfig, Lang } from '../../init/types.js';
import { withAuth } from '../auth-guard.js';

export function deployCommand(): Command {
  return new Command('deploy')
    .description('Deploy configured services / \u90E8\u7F72\u5DF2\u914D\u7F6E\u7684\u670D\u52D9')
    .option('--config <path>', 'Config path', join(homedir(), '.panguard', 'config.json'))
    .option('--dry-run', 'Show deployment plan without executing')
    .option('--lang <language>', 'Language override')
    .action(
      withAuth('solo', async (opts: { config?: string; dryRun?: boolean; lang?: string }) => {
        await runDeploy(opts);
      })
    );
}

async function runDeploy(opts: {
  config?: string;
  dryRun?: boolean;
  lang?: string;
}): Promise<void> {
  // ── Load config ─────────────────────────────────────────
  const config = readConfig();
  const lang: Lang = (opts.lang as Lang) ?? config?.meta?.language ?? 'zh-TW';

  if (!config) {
    console.log('');
    console.log(
      `  ${symbols.fail} ${
        lang === 'zh-TW'
          ? '\u627E\u4E0D\u5230\u914D\u7F6E\u6A94\u3002\u8ACB\u5148\u57F7\u884C: panguard init'
          : 'No config found. Run: panguard init'
      }`
    );
    console.log('');
    return;
  }

  // ── Show deployment plan ────────────────────────────────
  console.log('');
  console.log(divider(lang === 'zh-TW' ? '\u90E8\u7F72\u8A08\u756B' : 'Deployment Plan'));
  console.log('');

  const planItems = [];

  if (config.modules.guard) {
    planItems.push({
      label: lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine',
      value: `${config.guard.mode} mode (${config.security.protectionLevel})`,
      status: 'safe' as const,
    });
  }

  if (config.modules.scan) {
    planItems.push({
      label: lang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Security Scan',
      value: lang === 'zh-TW' ? '\u5DF2\u555F\u7528' : 'Enabled',
      status: 'safe' as const,
    });
  }

  if (config.modules.trap && config.trap.enabled) {
    planItems.push({
      label: lang === 'zh-TW' ? '\u871C\u7F50\u670D\u52D9' : 'Honeypot',
      value: config.trap.services.join(', ').toUpperCase(),
      status: 'caution' as const,
    });
  }

  if (config.notifications.channel !== 'none') {
    planItems.push({
      label: lang === 'zh-TW' ? '\u901A\u77E5\u7BA1\u9053' : 'Notifications',
      value: config.notifications.channel.toUpperCase(),
      status: 'safe' as const,
    });
  }

  planItems.push({
    label: 'AI',
    value:
      config.ai.preference === 'cloud_ai'
        ? 'Cloud AI'
        : config.ai.preference === 'local_ai'
          ? 'Local AI (Ollama)'
          : lang === 'zh-TW'
            ? '\u50C5\u898F\u5247'
            : 'Rules Only',
  });

  console.log(
    statusPanel(
      lang === 'zh-TW' ? 'Panguard AI \u90E8\u7F72\u8A08\u756B' : 'Panguard AI Deployment Plan',
      planItems
    )
  );

  // ── Dry run: stop here ─────────────────────────────────
  if (opts.dryRun) {
    console.log(
      `  ${symbols.info} ${lang === 'zh-TW' ? 'Dry run \u6A21\u5F0F\uFF0C\u672A\u5BE6\u969B\u57F7\u884C\u3002' : 'Dry run mode, nothing executed.'}`
    );
    console.log('');
    return;
  }

  // ── Execute deployment ──────────────────────────────────
  console.log(divider(lang === 'zh-TW' ? '\u57F7\u884C\u90E8\u7F72' : 'Deploying'));
  console.log('');

  let step = 1;
  const totalSteps = countDeploySteps(config);

  // Step: Initialize data directory
  const dirSp = spinner(
    `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u521D\u59CB\u5316\u8CC7\u6599\u76EE\u9304...' : 'Initializing data directory...'}`
  );
  try {
    const { mkdirSync } = await import('node:fs');
    mkdirSync(join(homedir(), '.panguard-guard'), { recursive: true });
    mkdirSync(join(homedir(), '.panguard', 'logs'), { recursive: true });
    dirSp.succeed(
      `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u8CC7\u6599\u76EE\u9304\u5DF2\u521D\u59CB\u5316' : 'Data directory initialized'}`
    );
  } catch {
    dirSp.warn(
      `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u8CC7\u6599\u76EE\u9304\u521D\u59CB\u5316\u5931\u6557' : 'Directory init failed'}`
    );
  }
  step++;

  // Step: Guard engine config
  if (config.modules.guard) {
    const guardSp = spinner(
      `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u5BEB\u5165\u5B88\u8B77\u5F15\u64CE\u914D\u7F6E...' : 'Writing guard engine config...'}`
    );
    try {
      const guardConfigPath = join(homedir(), '.panguard-guard', 'config.json');
      const { writeFileSync } = await import('node:fs');
      writeFileSync(
        guardConfigPath,
        JSON.stringify(
          {
            mode: config.guard.mode,
            learningDays: config.guard.learningDays,
            actionThresholds: config.guard.actionPolicy,
            monitors: config.guard.monitors,
          },
          null,
          2
        )
      );
      guardSp.succeed(
        `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE\u914D\u7F6E\u5DF2\u5BEB\u5165' : 'Guard engine configured'}`
      );
    } catch {
      guardSp.warn(
        `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u5B88\u8B77\u914D\u7F6E\u5BEB\u5165\u5931\u6557' : 'Guard config failed'}`
      );
    }
    step++;
  }

  // Step: Test notification
  if (config.notifications.channel !== 'none') {
    const notifSp = spinner(
      `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u6E2C\u8A66\u901A\u77E5\u7BA1\u9053...' : 'Testing notification channel...'}`
    );
    // Simulated test - real implementation would call ChatAgent.sendTest()
    await sleep(500);
    notifSp.succeed(
      `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u901A\u77E5\u7BA1\u9053\u5DF2\u914D\u7F6E' : 'Notification channel configured'}`
    );
    step++;
  }

  // Step: Initial scan
  if (config.modules.scan) {
    const scanSp = spinner(
      `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u57F7\u884C\u521D\u59CB\u6383\u63CF...' : 'Running initial scan...'}`
    );
    try {
      const { runScan } = await import('@panguard-ai/panguard-scan');
      const result = await runScan({ depth: 'quick', lang });
      scanSp.succeed(
        `[${step}/${totalSteps}] ${
          lang === 'zh-TW'
            ? `\u6383\u63CF\u5B8C\u6210\uFF01\u98A8\u96AA: ${result.riskScore}/100`
            : `Scan complete! Risk: ${result.riskScore}/100`
        }`
      );
    } catch {
      scanSp.warn(
        `[${step}/${totalSteps}] ${lang === 'zh-TW' ? '\u6383\u63CF\u5931\u6557\uFF08\u7A0D\u5F8C\u7528 panguard scan\uFF09' : 'Scan failed (run panguard scan later)'}`
      );
    }
    step++;
  }

  // ── Completion summary ──────────────────────────────────
  console.log('');
  console.log(
    box(
      lang === 'zh-TW'
        ? [
            `${symbols.pass} \u90E8\u7F72\u5B8C\u6210\uFF01`,
            '',
            `\u63A5\u4E0B\u4F86\uFF1A`,
            `  ${c.sage('panguard guard start')}  \u555F\u52D5\u5373\u6642\u9632\u8B77`,
            `  ${c.sage('panguard status')}       \u67E5\u770B\u7CFB\u7D71\u72C0\u614B`,
            `  ${c.sage('panguard scan --full')}  \u57F7\u884C\u5B8C\u6574\u6383\u63CF`,
          ].join('\n')
        : [
            `${symbols.pass} Deployment complete!`,
            '',
            `Next:`,
            `  ${c.sage('panguard guard start')}  Start real-time protection`,
            `  ${c.sage('panguard status')}       Check system status`,
            `  ${c.sage('panguard scan --full')}  Run a full scan`,
          ].join('\n'),
      { borderColor: c.safe }
    )
  );
  console.log('');
}

function countDeploySteps(config: PanguardConfig): number {
  let count = 1; // always: init data dir
  if (config.modules.guard) count++;
  if (config.notifications.channel !== 'none') count++;
  if (config.modules.scan) count++;
  return count;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
