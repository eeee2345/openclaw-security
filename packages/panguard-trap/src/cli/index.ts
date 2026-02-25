#!/usr/bin/env node
/**
 * PanguardTrap CLI
 * PanguardTrap 命令列介面
 *
 * @module @openclaw/panguard-trap/cli
 */

import type { TrapConfig, TrapServiceType, TrapStatistics } from '../types.js';
import { DEFAULT_TRAP_CONFIG, DEFAULT_SERVICE_CONFIGS } from '../types.js';
import { TrapEngine } from '../trap-engine.js';

/** Available CLI commands / 可用的 CLI 命令 */
export type TrapCliCommand = 'start' | 'stop' | 'status' | 'deploy' | 'profiles' | 'intel' | 'config' | 'help';

/** CLI options / CLI 選項 */
export interface TrapCliOptions {
  command: TrapCliCommand;
  services?: TrapServiceType[];
  port?: number;
  dataDir?: string;
  noCloud?: boolean;
  verbose?: boolean;
}

/**
 * Parse CLI arguments
 * 解析 CLI 參數
 */
export function parseCliArgs(args: string[]): TrapCliOptions {
  const command = (args[0] as TrapCliCommand) || 'help';
  const options: TrapCliOptions = { command };

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--services' && args[i + 1]) {
      options.services = args[i + 1]!.split(',') as TrapServiceType[];
      i++;
    } else if (arg === '--port' && args[i + 1]) {
      options.port = parseInt(args[i + 1]!, 10);
      i++;
    } else if (arg === '--data-dir' && args[i + 1]) {
      options.dataDir = args[i + 1];
      i++;
    } else if (arg === '--no-cloud') {
      options.noCloud = true;
    } else if (arg === '--verbose' || arg === '-v') {
      options.verbose = true;
    }
  }

  return options;
}

/**
 * Build trap config from CLI options
 * 從 CLI 選項建立蜜罐配置
 */
export function buildConfigFromOptions(options: TrapCliOptions): TrapConfig {
  const config = { ...DEFAULT_TRAP_CONFIG };

  if (options.dataDir) {
    config.dataDir = options.dataDir;
  }

  if (options.noCloud) {
    config.feedThreatCloud = false;
  }

  // Enable only specified services
  if (options.services && options.services.length > 0) {
    config.services = options.services.map((type) => ({
      ...DEFAULT_SERVICE_CONFIGS[type],
      enabled: true,
    }));
  }

  return config;
}

/**
 * Format statistics for display
 * 格式化統計資料以供顯示
 */
export function formatStatistics(stats: TrapStatistics): string {
  const lines: string[] = [];

  lines.push('=== PanguardTrap Status / PanguardTrap 狀態 ===');
  lines.push('');
  lines.push(`Total Sessions / 總連線數: ${stats.totalSessions}`);
  lines.push(`Active Sessions / 活動中連線: ${stats.activeSessions}`);
  lines.push(`Unique Source IPs / 不重複 IP: ${stats.uniqueSourceIPs}`);
  lines.push(`Credential Attempts / 認證嘗試: ${stats.totalCredentialAttempts}`);
  lines.push(`Commands Captured / 捕獲指令: ${stats.totalCommandsCaptured}`);
  lines.push(`Uptime / 運作時間: ${formatDuration(stats.uptimeMs)}`);
  lines.push('');

  // Sessions by service
  lines.push('--- Sessions by Service / 依服務分類 ---');
  for (const [service, count] of Object.entries(stats.sessionsByService)) {
    if (count > 0) {
      lines.push(`  ${service}: ${count}`);
    }
  }
  lines.push('');

  // Top attacker IPs
  if (stats.topAttackerIPs.length > 0) {
    lines.push('--- Top Attacker IPs / 前幾名攻擊者 ---');
    for (const entry of stats.topAttackerIPs.slice(0, 5)) {
      lines.push(`  ${entry.ip}: ${entry.sessions} sessions (risk=${entry.riskScore})`);
    }
    lines.push('');
  }

  // Top credentials
  if (stats.topUsernames.length > 0) {
    lines.push('--- Top Usernames / 前幾名使用者名稱 ---');
    for (const entry of stats.topUsernames.slice(0, 5)) {
      lines.push(`  ${entry.username}: ${entry.count}`);
    }
    lines.push('');
  }

  // Skill distribution
  lines.push('--- Attacker Skill Distribution / 攻擊者技術分布 ---');
  for (const [skill, count] of Object.entries(stats.skillDistribution)) {
    if (count > 0) {
      lines.push(`  ${skill}: ${count}`);
    }
  }

  return lines.join('\n');
}

/**
 * Get help text
 * 取得說明文字
 */
export function getHelpText(): string {
  return `
PanguardTrap - Smart Honeypot System / 智慧蜜罐系統
Panguard AI (https://panguard.ai)

Usage / 用法:
  panguard-trap <command> [options]

Commands / 命令:
  start       Start honeypot services / 啟動蜜罐服務
  stop        Stop honeypot services / 停止蜜罐服務
  status      Show current status and statistics / 顯示目前狀態和統計
  deploy      Deploy specific trap services / 部署特定蜜罐服務
  profiles    Show attacker profiles / 顯示攻擊者 profiles
  intel       Show threat intelligence summary / 顯示威脅情報摘要
  config      Show current configuration / 顯示目前配置
  help        Show this help message / 顯示此說明

Options / 選項:
  --services <types>   Comma-separated service types / 逗號分隔的服務類型
                       (ssh,http,ftp,telnet,mysql,redis,smb,rdp)
  --port <number>      Override port for single service / 覆寫單一服務的埠
  --data-dir <path>    Data directory for logs / 日誌資料目錄
  --no-cloud           Disable Threat Cloud upload / 停用 Threat Cloud 上傳
  --verbose, -v        Verbose output / 詳細輸出

Examples / 範例:
  panguard-trap start --services ssh,http
  panguard-trap status
  panguard-trap profiles
  panguard-trap intel
`.trim();
}

/** Format duration / 格式化持續時間 */
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

/** Singleton engine instance for the running process */
let activeEngine: TrapEngine | null = null;

/**
 * Execute CLI command
 * 執行 CLI 命令
 */
export async function executeCli(args: string[]): Promise<void> {
  const options = parseCliArgs(args);

  switch (options.command) {
    case 'help':
      console.log(getHelpText());
      break;

    case 'config': {
      const config = buildConfigFromOptions(options);
      console.log('=== PanguardTrap Configuration / PanguardTrap 配置 ===');
      console.log('');
      console.log(`Data Directory / 資料目錄: ${config.dataDir}`);
      console.log(`Threat Cloud / 威脅雲端: ${config.feedThreatCloud ? 'enabled / 啟用' : 'disabled / 停用'}`);
      console.log(`Fake Access / 假存取: ${config.grantFakeAccess ? `after ${config.fakeAccessAfterAttempts} attempts` : 'disabled'}`);
      console.log('');
      console.log('Enabled Services / 已啟用服務:');
      for (const svc of config.services.filter((s) => s.enabled)) {
        console.log(`  ${svc.type}: port ${svc.port}`);
      }
      break;
    }

    case 'start': {
      const config = buildConfigFromOptions(options);
      console.log('Starting PanguardTrap... / 啟動 PanguardTrap...');

      const engine = new TrapEngine(config);
      activeEngine = engine;

      // Register session handler for verbose output
      engine.onSession((session) => {
        console.log(
          `[Session] ${session.sourceIP}:${session.sourcePort} -> ${session.serviceType} ` +
          `(creds=${session.credentials.length}, cmds=${session.commands.length})`,
        );
      });

      await engine.start();

      const running = engine.getRunningServices();
      console.log(`Services running / 已啟動服務: ${running.join(', ') || '(none)'}`);
      console.log('Press Ctrl+C to stop / 按 Ctrl+C 停止');

      // Graceful shutdown
      const shutdown = async () => {
        console.log('\nStopping PanguardTrap... / 停止 PanguardTrap...');
        await engine.stop();
        console.log('PanguardTrap stopped / PanguardTrap 已停止');
        process.exit(0);
      };

      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);

      // Keep process alive
      await new Promise(() => {});
      break;
    }

    case 'stop':
      if (activeEngine) {
        await activeEngine.stop();
        activeEngine = null;
        console.log('PanguardTrap stopped / PanguardTrap 已停止');
      } else {
        console.log('PanguardTrap is not running. / PanguardTrap 未運行。');
      }
      break;

    case 'status':
      if (activeEngine && activeEngine.status === 'running') {
        const stats = activeEngine.getStatistics();
        console.log(formatStatistics(stats));
      } else {
        console.log('PanguardTrap is not running. Use panguard-trap start to begin.');
        console.log('PanguardTrap 未運行。使用 panguard-trap start 開始。');
      }
      break;

    case 'deploy': {
      const deployConfig = buildConfigFromOptions(options);
      console.log('Deploying trap services... / 部署蜜罐服務...');
      const deployEngine = new TrapEngine(deployConfig);
      await deployEngine.start();
      const deployRunning = deployEngine.getRunningServices();
      console.log(`Deployed services / 已部署服務: ${deployRunning.join(', ') || '(none)'}`);
      await deployEngine.stop();
      console.log('Deploy test complete / 部署測試完成');
      break;
    }

    case 'profiles':
      if (activeEngine) {
        const profiler = activeEngine.getProfiler();
        const profiles = profiler.getAllProfiles();
        if (profiles.length === 0) {
          console.log('No attacker profiles yet. / 尚無攻擊者 profiles。');
        } else {
          console.log(`=== Attacker Profiles (${profiles.length}) / 攻擊者分析 ===`);
          for (const p of profiles) {
            console.log(`  [${p.profileId}] ${p.skillLevel} / ${p.intent} (risk=${p.riskScore})`);
          }
        }
      } else {
        console.log('PanguardTrap is not running. Start it first.');
        console.log('PanguardTrap 未運行。請先啟動。');
      }
      break;

    case 'intel':
      if (activeEngine) {
        const reports = activeEngine.getIntelReports();
        if (reports.length === 0) {
          console.log('No intel reports yet. / 尚無情報報告。');
        } else {
          console.log(`=== Intel Reports (${reports.length}) / 情報報告 ===`);
          for (const r of reports) {
            console.log(`  [${r.serviceType}] ${r.sourceIP} - ${r.attackType} (${r.skillLevel}/${r.intent})`);
          }
        }
      } else {
        console.log('PanguardTrap is not running. Start it first.');
        console.log('PanguardTrap 未運行。請先啟動。');
      }
      break;

    default:
      console.log(`Unknown command: ${options.command}`);
      console.log(getHelpText());
  }
}

// ---------------------------------------------------------------------------
// CLI entry point (when run directly)
// CLI 進入點（直接執行時）
// ---------------------------------------------------------------------------

const isDirectRun = process.argv[1] &&
  (process.argv[1].endsWith('/panguard-trap') ||
   process.argv[1].includes('panguard-trap/dist/cli'));

if (isDirectRun) {
  executeCli(process.argv.slice(2)).catch((err) => {
    console.error('Error:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
