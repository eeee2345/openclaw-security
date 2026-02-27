/**
 * `panguard status` - Enhanced system status dashboard
 * `panguard status` - 增強版系統狀態儀表板
 *
 * @module @panguard-ai/panguard/cli/commands/status
 */

import { Command } from 'commander';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import {
  c,
  symbols,
  divider,
  statusPanel,
  scoreDisplay,
  table,
  timeAgo,
  header,
} from '@panguard-ai/core';
import type { StatusItem, TableColumn } from '@panguard-ai/core';
import { readConfig } from '../../init/config-writer.js';
import type { Lang } from '../../init/types.js';

export function statusCommand(): Command {
  return new Command('status')
    .description(
      'Show system status dashboard / \u986F\u793A\u7CFB\u7D71\u72C0\u614B\u5100\u8868\u677F'
    )
    .option('--json', 'Output as JSON')
    .option('--lang <language>', 'Language override')
    .action(async (opts: { json?: boolean; lang?: string }) => {
      await showStatus(opts);
    });
}

interface SystemStatus {
  configLoaded: boolean;
  configPath: string;
  guard: {
    running: boolean;
    mode: string;
    pid?: number;
  } | null;
  lastScan: {
    timestamp: string;
    riskScore: number;
    findings: number;
    grade: string;
  } | null;
  notifications: {
    channel: string;
    configured: boolean;
  };
  trap: {
    enabled: boolean;
    services: string[];
  } | null;
  ai: {
    preference: string;
    provider?: string;
  };
  modules: Record<string, { enabled: boolean; status: string }>;
}

async function showStatus(opts: { json?: boolean; lang?: string }): Promise<void> {
  const config = readConfig();
  const lang: Lang = (opts.lang as Lang) ?? config?.meta?.language ?? 'zh-TW';

  const status = collectStatus(config);

  // JSON output
  if (opts.json) {
    console.log(JSON.stringify(status, null, 2));
    return;
  }

  // ── Banner ──────────────────────────────────────────────
  console.log('');
  console.log(
    header(
      lang === 'zh-TW' ? '\u7CFB\u7D71\u72C0\u614B\u5100\u8868\u677F' : 'System Status Dashboard'
    )
  );

  // ── No config message ──────────────────────────────────
  if (!status.configLoaded) {
    console.log(
      `  ${symbols.warn} ${
        lang === 'zh-TW'
          ? '\u672A\u627E\u5230\u914D\u7F6E\u3002\u57F7\u884C \u300Cpanguard init\u300D\u958B\u59CB\u8A2D\u5B9A\u3002'
          : 'No config found. Run "panguard init" to get started.'
      }`
    );
    console.log('');
    return;
  }

  // ── System Status ──────────────────────────────────────
  const systemItems: StatusItem[] = [];

  // Guard status
  if (status.guard) {
    systemItems.push({
      label: lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine',
      value: status.guard.running
        ? `${status.guard.mode} mode (PID: ${status.guard.pid})`
        : lang === 'zh-TW'
          ? '\u672A\u904B\u884C'
          : 'Not running',
      status: status.guard.running ? 'safe' : 'caution',
    });
  }

  // AI status
  systemItems.push({
    label: 'AI',
    value: status.ai.provider
      ? `${status.ai.provider} (${status.ai.preference})`
      : status.ai.preference === 'rules_only'
        ? lang === 'zh-TW'
          ? '\u50C5\u898F\u5247\u5F15\u64CE'
          : 'Rules only'
        : lang === 'zh-TW'
          ? '\u672A\u914D\u7F6E'
          : 'Not configured',
    status: status.ai.provider ? 'safe' : undefined,
  });

  // Notification status
  systemItems.push({
    label: lang === 'zh-TW' ? '\u901A\u77E5' : 'Notifications',
    value: status.notifications.configured
      ? status.notifications.channel.toUpperCase()
      : lang === 'zh-TW'
        ? '\u672A\u914D\u7F6E'
        : 'Not configured',
    status: status.notifications.configured ? 'safe' : 'caution',
  });

  // Trap status
  if (status.trap?.enabled) {
    systemItems.push({
      label: lang === 'zh-TW' ? '\u871C\u7F50' : 'Honeypot',
      value: status.trap.services.join(', ').toUpperCase(),
      status: 'safe',
    });
  }

  console.log(
    statusPanel(
      lang === 'zh-TW' ? '\u7CFB\u7D71\u72C0\u614B / System Status' : 'System Status',
      systemItems
    )
  );

  // ── Last Scan Results ──────────────────────────────────
  if (status.lastScan) {
    console.log(divider(lang === 'zh-TW' ? '\u4E0A\u6B21\u6383\u63CF' : 'Last Scan'));
    console.log(scoreDisplay(status.lastScan.riskScore, status.lastScan.grade));
    console.log(
      `  ${status.lastScan.findings} ${lang === 'zh-TW' ? '\u500B\u767C\u73FE' : 'finding(s)'} ${c.dim('\u00B7')} ${timeAgo(status.lastScan.timestamp)}`
    );
    console.log('');
  }

  // ── Module Status Table ─────────────────────────────────
  console.log(divider(lang === 'zh-TW' ? '\u6A21\u7D44\u72C0\u614B' : 'Module Status'));
  console.log('');

  const columns: TableColumn[] = [
    { header: '#', key: 'num', width: 3, align: 'right' },
    { header: lang === 'zh-TW' ? '\u6A21\u7D44' : 'Module', key: 'module', width: 22 },
    {
      header: lang === 'zh-TW' ? '\u72C0\u614B' : 'Status',
      key: 'status',
      width: 10,
      color: (v: string) => {
        if (v === 'active' || v === 'ready') return c.safe(v);
        if (v === 'disabled') return c.dim(v);
        return c.caution(v);
      },
    },
  ];

  const moduleNames: Record<string, Record<Lang, string>> = {
    guard: { en: 'Panguard Guard', 'zh-TW': 'Panguard Guard (\u5B88\u8B77)' },
    scan: { en: 'Panguard Scan', 'zh-TW': 'Panguard Scan (\u6383\u63CF)' },
    chat: { en: 'Panguard Chat', 'zh-TW': 'Panguard Chat (\u901A\u77E5)' },
    trap: { en: 'Panguard Trap', 'zh-TW': 'Panguard Trap (\u871C\u7F50)' },
    report: { en: 'Panguard Report', 'zh-TW': 'Panguard Report (\u5831\u544A)' },
    dashboard: { en: 'Dashboard', 'zh-TW': 'Dashboard (\u5100\u8868\u677F)' },
  };

  const rows = Object.entries(status.modules).map(([key, mod], i) => ({
    num: String(i + 1),
    module: moduleNames[key]?.[lang] ?? key,
    status: mod.status,
  }));

  console.log(table(columns, rows));
  console.log('');
}

function collectStatus(config: ReturnType<typeof readConfig>): SystemStatus {
  const configPath = join(homedir(), '.panguard', 'config.json');

  if (!config) {
    return {
      configLoaded: false,
      configPath,
      guard: null,
      lastScan: null,
      notifications: { channel: 'none', configured: false },
      trap: null,
      ai: { preference: 'rules_only' },
      modules: {},
    };
  }

  // Check if guard is running (PID file)
  const guardPidPath = join(homedir(), '.panguard-guard', 'panguard-guard.pid');
  let guardRunning = false;
  let guardPid: number | undefined;

  if (existsSync(guardPidPath)) {
    try {
      const pid = parseInt(readFileSync(guardPidPath, 'utf-8').trim(), 10);
      // Check if process is alive
      process.kill(pid, 0);
      guardRunning = true;
      guardPid = pid;
    } catch {
      guardRunning = false;
    }
  }

  // Check for last scan result
  let lastScan: SystemStatus['lastScan'] = null;
  const scanResultPath = join(homedir(), '.panguard', 'last-scan.json');
  if (existsSync(scanResultPath)) {
    try {
      const scanData = JSON.parse(readFileSync(scanResultPath, 'utf-8'));
      lastScan = {
        timestamp: scanData.scannedAt ?? new Date().toISOString(),
        riskScore: scanData.riskScore ?? 0,
        findings: scanData.findings?.length ?? 0,
        grade: scoreToGrade(scanData.riskScore ?? 0),
      };
    } catch {
      // ignore
    }
  }

  // Build module status
  const modules: Record<string, { enabled: boolean; status: string }> = {};
  for (const [key, enabled] of Object.entries(config.modules)) {
    modules[key] = {
      enabled,
      status: !enabled
        ? 'disabled'
        : key === 'guard'
          ? guardRunning
            ? 'active'
            : 'ready'
          : 'ready',
    };
  }

  return {
    configLoaded: true,
    configPath,
    guard: config.modules.guard
      ? {
          running: guardRunning,
          mode: config.guard.mode,
          pid: guardPid,
        }
      : null,
    lastScan,
    notifications: {
      channel: config.notifications.channel,
      configured: config.notifications.channel !== 'none',
    },
    trap: config.modules.trap
      ? {
          enabled: config.trap.enabled,
          services: config.trap.services,
        }
      : null,
    ai: {
      preference: config.ai.preference,
      provider: config.ai.provider,
    },
    modules,
  };
}

function scoreToGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
