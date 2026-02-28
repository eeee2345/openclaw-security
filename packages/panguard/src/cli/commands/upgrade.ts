/**
 * `panguard upgrade` - Self-service plan upgrade via Lemon Squeezy
 * `panguard upgrade` - 透過 Lemon Squeezy 自助升級方案
 *
 * Shows current plan, lists available tiers, opens checkout in browser.
 * Also supports `panguard upgrade portal` for subscription management.
 *
 * @module @panguard-ai/panguard/cli/commands/upgrade
 */

import { Command } from 'commander';
import { exec } from 'node:child_process';
import { c, box, spinner, statusPanel } from '@panguard-ai/core';
import type { StatusItem } from '@panguard-ai/core';
import { loadCredentials, isTokenExpired, tierDisplayName, TIER_LEVEL } from '../credentials.js';
import type { Tier } from '../credentials.js';
import { PRICING_TIERS, refreshTierInBackground } from '../auth-guard.js';

const PLAN_ORDER: Tier[] = ['solo', 'pro', 'business'];

export function upgradeCommand(): Command {
  const cmd = new Command('upgrade')
    .description('Upgrade your plan / 升級方案')
    .option('--lang <language>', 'Language override')
    .action(async (opts: { lang?: string }) => {
      await runUpgrade(opts);
    });

  cmd
    .command('portal')
    .description('Open subscription management portal / 開啟訂閱管理')
    .action(async () => {
      await runPortal();
    });

  cmd
    .command('status')
    .description('Check billing status / 查看帳單狀態')
    .action(async () => {
      await runBillingStatus();
    });

  return cmd;
}

async function runUpgrade(opts: { lang?: string }): Promise<void> {
  const lang = opts.lang === 'en' ? 'en' : 'zh-TW';
  const creds = loadCredentials();

  if (!creds || isTokenExpired(creds)) {
    console.log('');
    console.log(
      box(
        lang === 'zh-TW'
          ? `\u9700\u8981\u5148\u767B\u5165\u3002\u8ACB\u57F7\u884C ${c.sage('panguard login')}`
          : `Please log in first. Run ${c.sage('panguard login')}`,
        { borderColor: c.caution, title: 'Panguard AI' }
      )
    );
    console.log('');
    process.exitCode = 1;
    return;
  }

  const currentLevel = TIER_LEVEL[creds.tier] ?? 0;
  const currentName = tierDisplayName(creds.tier);

  // Show current plan
  console.log('');
  const items: StatusItem[] = [
    {
      label: lang === 'zh-TW' ? '\u76EE\u524D\u65B9\u6848' : 'Current Plan',
      value: currentName,
      status: 'safe',
    },
    { label: lang === 'zh-TW' ? '\u4FE1\u7BB1' : 'Email', value: creds.email },
  ];
  console.log(statusPanel(lang === 'zh-TW' ? '\u65B9\u6848\u5347\u7D1A' : 'Plan Upgrade', items));
  console.log('');

  // List available upgrades
  const upgrades = PLAN_ORDER.filter((t) => (TIER_LEVEL[t] ?? 0) > currentLevel);

  if (upgrades.length === 0) {
    console.log(
      `  ${c.safe('\u2713')} ${
        lang === 'zh-TW'
          ? '\u60A8\u5DF2\u5728\u6700\u9AD8\u65B9\u6848\uFF01'
          : "You're already on the highest plan!"
      }`
    );
    console.log('');
    console.log(
      c.dim(
        lang === 'zh-TW'
          ? `  \u7BA1\u7406\u8A02\u95B1: ${c.sage('panguard upgrade portal')}`
          : `  Manage subscription: ${c.sage('panguard upgrade portal')}`
      )
    );
    console.log('');
    return;
  }

  console.log(`  ${lang === 'zh-TW' ? '\u53EF\u7528\u65B9\u6848:' : 'Available plans:'}`);
  console.log('');

  for (let i = 0; i < upgrades.length; i++) {
    const tier = upgrades[i]!;
    const pricing = PRICING_TIERS[tier];
    const name = tierDisplayName(tier);
    const price = pricing ? `$${pricing.price}${pricing.unit}` : '';
    const machines = pricing ? pricing.machines : '';
    console.log(
      `  ${c.sage(`${i + 1}.`)} ${c.bold(name)}  ${price}  ${c.dim(`${machines} ${lang === 'zh-TW' ? '\u53F0\u6A5F\u5668' : 'machine(s)'}`)}`
    );
  }

  console.log('');
  console.log(
    c.dim(
      lang === 'zh-TW'
        ? '  \u8F38\u5165\u7DE8\u865F\u9078\u64C7\u65B9\u6848 (Ctrl+C \u53D6\u6D88):'
        : '  Enter number to select plan (Ctrl+C to cancel):'
    )
  );

  // Read user selection from stdin
  const selection = await readLine();
  const idx = parseInt(selection.trim(), 10) - 1;

  if (isNaN(idx) || idx < 0 || idx >= upgrades.length) {
    console.log(c.dim(lang === 'zh-TW' ? '  \u5DF2\u53D6\u6D88' : '  Cancelled'));
    return;
  }

  const selectedTier = upgrades[idx]!;

  // Call billing checkout API
  const sp = spinner(
    lang === 'zh-TW'
      ? '\u6B63\u5728\u5EFA\u7ACB\u7D50\u5E33\u9023\u7D50...'
      : 'Creating checkout session...'
  );

  try {
    const res = await fetch(`${creds.apiUrl}/api/billing/checkout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${creds.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ tier: selectedTier }),
    });

    const data = (await res.json()) as { ok: boolean; data?: { url: string }; error?: string };

    if (!data.ok || !data.data?.url) {
      sp.fail(data.error ?? 'Failed to create checkout session');
      process.exitCode = 1;
      return;
    }

    sp.succeed(
      lang === 'zh-TW' ? '\u7D50\u5E33\u9023\u7D50\u5DF2\u5EFA\u7ACB' : 'Checkout session created'
    );

    console.log('');
    console.log(
      lang === 'zh-TW' ? `  \u6B63\u5728\u958B\u555F\u700F\u89BD\u5668...` : '  Opening browser...'
    );

    await openBrowser(data.data.url);

    console.log('');
    console.log(
      lang === 'zh-TW'
        ? `  ${c.sage('\u25C6')} \u8ACB\u5728\u700F\u89BD\u5668\u4E2D\u5B8C\u6210\u4ED8\u6B3E\u3002`
        : `  ${c.sage('\u25C6')} Please complete payment in the browser.`
    );
    console.log(
      c.dim(
        lang === 'zh-TW'
          ? '  \u4ED8\u6B3E\u5B8C\u6210\u5F8C\uFF0C\u60A8\u7684\u65B9\u6848\u5C07\u81EA\u52D5\u5347\u7D1A\u3002'
          : '  Your plan will be upgraded automatically after payment.'
      )
    );
    console.log('');

    // Trigger a background tier refresh so next CLI command picks up the new tier
    refreshTierInBackground();
  } catch (err) {
    sp.fail(`${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}

async function runPortal(): Promise<void> {
  const creds = loadCredentials();
  if (!creds || isTokenExpired(creds)) {
    console.log('');
    console.log(`  ${c.caution('Please log in first:')} ${c.sage('panguard login')}`);
    console.log('');
    process.exitCode = 1;
    return;
  }

  const sp = spinner('Opening subscription portal...');

  try {
    const res = await fetch(`${creds.apiUrl}/api/billing/portal`, {
      headers: { Authorization: `Bearer ${creds.token}` },
    });

    const data = (await res.json()) as { ok: boolean; data?: { url: string }; error?: string };

    if (!data.ok || !data.data?.url) {
      sp.fail(data.error ?? 'No active subscription found');
      if (!data.ok && data.error?.includes('No active subscription')) {
        console.log(c.dim(`  Run ${c.sage('panguard upgrade')} to subscribe.`));
      }
      return;
    }

    sp.succeed('Portal link ready');
    await openBrowser(data.data.url);
    console.log(c.dim('  Subscription portal opened in browser.'));
    console.log('');
  } catch (err) {
    sp.fail(`${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}

async function runBillingStatus(): Promise<void> {
  const creds = loadCredentials();
  if (!creds || isTokenExpired(creds)) {
    console.log('');
    console.log(`  ${c.caution('Please log in first:')} ${c.sage('panguard login')}`);
    console.log('');
    process.exitCode = 1;
    return;
  }

  const sp = spinner('Fetching billing status...');

  try {
    const res = await fetch(`${creds.apiUrl}/api/billing/status`, {
      headers: { Authorization: `Bearer ${creds.token}` },
    });

    const data = (await res.json()) as {
      ok: boolean;
      data?: {
        tier: string;
        subscription?: {
          status: string;
          renewsAt?: string;
          endsAt?: string;
        };
      };
    };

    if (!data.ok) {
      sp.fail('Failed to fetch billing status');
      return;
    }

    sp.succeed('Billing info loaded');
    console.log('');

    const d = data.data!;
    const statusItems: StatusItem[] = [
      { label: 'Plan', value: tierDisplayName(d.tier as Tier), status: 'safe' },
    ];

    if (d.subscription) {
      statusItems.push({ label: 'Status', value: d.subscription.status });
      if (d.subscription.renewsAt) {
        statusItems.push({
          label: 'Renews',
          value: new Date(d.subscription.renewsAt).toLocaleDateString(),
        });
      }
      if (d.subscription.endsAt) {
        statusItems.push({
          label: 'Ends',
          value: new Date(d.subscription.endsAt).toLocaleDateString(),
          status: 'caution',
        });
      }
    } else {
      statusItems.push({ label: 'Subscription', value: 'None (free tier)' });
    }

    console.log(statusPanel('Billing Status', statusItems));
    console.log('');
  } catch (err) {
    sp.fail(`${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}

// ── Helpers ─────────────────────────────────────────────────

function readLine(): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write('  > ');
    process.stdin.setEncoding('utf-8');
    process.stdin.resume();
    process.stdin.once('data', (data) => {
      process.stdin.pause();
      resolve(String(data));
    });
  });
}

function openBrowser(url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const platform = process.platform;
    let cmd: string;
    if (platform === 'darwin') {
      cmd = `open "${url}"`;
    } else if (platform === 'win32') {
      cmd = `start "" "${url}"`;
    } else {
      cmd = `xdg-open "${url}"`;
    }
    exec(cmd, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}
