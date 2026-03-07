/**
 * panguard guard - Guard engine management
 * panguard guard - 守護引擎管理
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { request as httpNodeRequest } from 'node:http';
import { execFileSync as nodeExecFileSync } from 'node:child_process';
import { Command } from 'commander';
import { runCLI } from '@panguard-ai/panguard-guard';
import { c, box, header } from '@panguard-ai/core';

export function guardCommand(): Command {
  const cmd = new Command('guard').description(
    'Guard engine management / \u5B88\u8B77\u5F15\u64CE\u7BA1\u7406'
  );

  cmd
    .command('start')
    .description('Start the guard engine / \u555F\u52D5\u5B88\u8B77\u5F15\u64CE')
    .option('--data-dir <path>', 'Data directory / \u8CC7\u6599\u76EE\u9304')
    .option('--verbose', 'Verbose output (show all event logs) / \u8A73\u7D30\u8F38\u51FA', false)
    .option(
      '--manager <url>',
      'Manager URL for agent mode / Manager \u7DB2\u5740\uFF08Agent \u6A21\u5F0F\uFF09'
    )
    .action(async (opts: { dataDir?: string; verbose: boolean; manager?: string }) => {
      const args = ['start'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      if (opts.verbose) args.push('--verbose');
      if (opts.manager) args.push('--manager', opts.manager);
      await runCLI(args);
    });

  cmd
    .command('stop')
    .description('Stop the guard engine / \u505C\u6B62\u5B88\u8B77\u5F15\u64CE')
    .option('--data-dir <path>', 'Data directory / \u8CC7\u6599\u76EE\u9304')
    .action(async (opts: { dataDir?: string }) => {
      const args = ['stop'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      await runCLI(args);
    });

  cmd
    .command('restart')
    .description('Restart the guard engine / 重啟守護引擎')
    .option('--data-dir <path>', 'Data directory / 資料目錄')
    .option('--verbose', 'Verbose output / 詳細輸出', false)
    .action(async (opts: { dataDir?: string; verbose: boolean }) => {
      const stopArgs = ['stop'];
      if (opts.dataDir) stopArgs.push('--data-dir', opts.dataDir);
      await runCLI(stopArgs);

      const startArgs = ['start'];
      if (opts.dataDir) startArgs.push('--data-dir', opts.dataDir);
      if (opts.verbose) startArgs.push('--verbose');
      await runCLI(startArgs);
    });

  cmd
    .command('status')
    .description('Show engine status / 顯示引擎狀態')
    .option('--data-dir <path>', 'Data directory / 資料目錄')
    .option('--detailed', 'Show 3-layer health check / 顯示三層健康檢查', false)
    .action(async (opts: { dataDir?: string; detailed: boolean }) => {
      if (opts.detailed) {
        await showDetailedStatus(opts.dataDir);
        return;
      }
      const args = ['status'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      await runCLI(args);
    });

  cmd
    .command('config')
    .description('Show current configuration / 顯示當前配置')
    .option('--data-dir <path>', 'Data directory / 資料目錄')
    .action(async (opts: { dataDir?: string }) => {
      const args = ['config'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      await runCLI(args);
    });

  cmd
    .command('generate-key [tier]')
    .description('Generate a test license key / 產生測試授權金鑰')
    .action(async (tier?: string) => {
      const args = ['generate-key'];
      if (tier) args.push(tier);
      await runCLI(args);
    });

  cmd
    .command('install')
    .description('Install as system service / 安裝為系統服務')
    .option('--data-dir <path>', 'Data directory / 資料目錄')
    .action(async (opts: { dataDir?: string }) => {
      const args = ['install'];
      if (opts.dataDir) args.push('--data-dir', opts.dataDir);
      await runCLI(args);
    });

  cmd
    .command('uninstall')
    .description('Remove system service / 移除系統服務')
    .action(async () => {
      await runCLI(['uninstall']);
    });

  return cmd;
}

// ---------------------------------------------------------------------------
// Detailed status helper — 3-layer health check
// 詳細狀態輔助函數 — 三層健康檢查
// ---------------------------------------------------------------------------

/** Read and parse a JSON file; returns null on any error */
function readJsonFile(filePath: string): Record<string, unknown> | null {
  try {
    if (!existsSync(filePath)) return null;
    return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Try to connect to the dashboard health endpoint with a 2-second timeout */
async function checkDashboardReachable(port: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const req = httpNodeRequest(
      { hostname: 'localhost', port, path: '/api/health', method: 'GET', timeout: 2000 },
      (res) => {
        resolve(res.statusCode !== undefined && res.statusCode < 500);
        res.resume();
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

/** Format uptime in seconds as a human-readable string */
function formatUptime(uptimeSeconds: number): string {
  const h = Math.floor(uptimeSeconds / 3600);
  const m = Math.floor((uptimeSeconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${uptimeSeconds}s`;
}

/**
 * Parse recent stats from the guard log file.
 * Scans the last 200 lines for the most recent status summary line emitted
 * by the engine's quiet-mode callback (format: "Events: N | Threats: N | Uploaded: N").
 */
function parseLogStats(logPath: string): { events: number; threats: number } {
  if (!existsSync(logPath)) return { events: 0, threats: 0 };
  try {
    const content = readFileSync(logPath, 'utf-8');
    const lines = content.split('\n');
    const recent = lines.slice(-200);
    for (let i = recent.length - 1; i >= 0; i--) {
      const line = recent[i] ?? '';
      const evMatch = line.match(/Events:\s*([\d,]+)/);
      const thMatch = line.match(/Threats:\s*([\d,]+)/);
      if (evMatch && thMatch) {
        return {
          events: parseInt((evMatch[1] ?? '0').replace(/,/g, ''), 10),
          threats: parseInt((thMatch[1] ?? '0').replace(/,/g, ''), 10),
        };
      }
    }
  } catch {
    // Ignore read errors
  }
  return { events: 0, threats: 0 };
}

/**
 * Show a 3-layer health check panel for the guard engine.
 *
 * Layer 1 — Process:   PID file + process.kill(pid, 0)
 * Layer 2 — Dashboard: HTTP health probe on configured port
 * Layer 3 — AI Layer:  AI provider/model from config
 *
 * 顯示守護引擎的三層健康檢查面板。
 */
async function showDetailedStatus(dataDirOverride?: string): Promise<void> {
  const dataDir = dataDirOverride ?? join(homedir(), '.panguard-guard');
  const pidPath = join(dataDir, 'panguard-guard.pid');
  const configPath = join(dataDir, 'config.json');
  const logPath = join(dataDir, 'panguard-guard.log');

  // ── Layer 1: Process ──────────────────────────────────────────────────────
  let pid: number | null = null;
  let processRunning = false;
  let uptimeStr = 'unknown';

  if (existsSync(pidPath)) {
    const raw = readFileSync(pidPath, 'utf-8').trim();
    const parsed = parseInt(raw, 10);
    if (!isNaN(parsed)) {
      pid = parsed;
      try {
        process.kill(pid, 0);
        processRunning = true;
      } catch {
        processRunning = false;
      }
    }
  }

  // Attempt to derive uptime from the process start time (macOS / Linux)
  if (processRunning && pid !== null) {
    try {
      const out = nodeExecFileSync('ps', ['-p', String(pid), '-o', 'etime='], {
        encoding: 'utf-8',
        timeout: 2000,
      }).trim();
      // ps etime format: [[DD-]HH:]MM:SS
      const parts = out.split(/[-:]/).map(Number);
      let seconds = 0;
      if (parts.length === 4) seconds = (parts[0] ?? 0) * 86400 + (parts[1] ?? 0) * 3600 + (parts[2] ?? 0) * 60 + (parts[3] ?? 0);
      else if (parts.length === 3) seconds = (parts[0] ?? 0) * 3600 + (parts[1] ?? 0) * 60 + (parts[2] ?? 0);
      else if (parts.length === 2) seconds = (parts[0] ?? 0) * 60 + (parts[1] ?? 0);
      else seconds = parts[0] ?? 0;
      if (seconds > 0) uptimeStr = formatUptime(seconds);
    } catch {
      // ps not available or failed — leave uptimeStr as 'unknown'
    }
  }

  // ── Layer 2: Dashboard + config ───────────────────────────────────────────
  const config = readJsonFile(configPath);
  const dashboardPort = typeof config?.['dashboardPort'] === 'number'
    ? config['dashboardPort']
    : 3100;
  const dashboardEnabled = config?.['dashboardEnabled'] !== false;
  const mode = typeof config?.['mode'] === 'string' ? config['mode'] : 'unknown';
  const cloudEndpoint = typeof config?.['threatCloudEndpoint'] === 'string'
    ? config['threatCloudEndpoint']
    : 'tc.panguard.ai';

  let dashboardStatus: string;
  if (!dashboardEnabled) {
    dashboardStatus = c.dim('disabled');
  } else if (!processRunning) {
    dashboardStatus = c.caution('not checked (engine stopped)');
  } else {
    const reachable = await checkDashboardReachable(dashboardPort);
    dashboardStatus = reachable
      ? c.safe(`http://localhost:${dashboardPort} (reachable)`)
      : c.caution(`http://localhost:${dashboardPort} (unreachable)`);
  }

  // ── Layer 3: AI provider ──────────────────────────────────────────────────
  let aiStatus: string;
  const aiConfig = config?.['ai'] as Record<string, unknown> | undefined;
  if (!aiConfig?.['provider']) {
    aiStatus = c.dim('not configured');
  } else {
    const provider = String(aiConfig['provider']);
    const model = typeof aiConfig['model'] === 'string' ? aiConfig['model'] : 'default';
    aiStatus = c.sage(`${provider} connected (${model})`);
  }

  // ── Log stats ─────────────────────────────────────────────────────────────
  const { events, threats } = parseLogStats(logPath);

  // ── Render ────────────────────────────────────────────────────────────────
  const processLine = processRunning
    ? c.safe(`running`) +
      c.dim(` (PID: ${pid ?? '?'}, uptime: ${uptimeStr})`)
    : c.critical('stopped');

  const cloudHost = cloudEndpoint.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  const lines = [
    `${c.bold('Process:   ')} ${processLine}`,
    `${c.bold('Dashboard: ')} ${dashboardStatus}`,
    `${c.bold('AI Layer:  ')} ${aiStatus}`,
    `${c.bold('Events:    ')} ${c.sage(events.toLocaleString())} processed | ${threats > 0 ? c.caution(String(threats)) : c.dim(String(threats))} threats`,
    `${c.bold('Mode:      ')} ${c.sage(mode)}`,
    `${c.bold('Cloud:     ')} ${processRunning ? c.safe(`connected to ${cloudHost}`) : c.dim(cloudHost)}`,
  ].join('\n');

  process.stdout.write('\n');
  process.stdout.write(header('Guard Engine Status'));
  process.stdout.write(
    box(lines, {
      title: 'Guard Engine Status',
      borderColor: processRunning ? c.sage : c.caution,
    })
  );
  process.stdout.write('\n\n');
}
