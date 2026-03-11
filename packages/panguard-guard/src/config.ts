/**
 * GuardConfig loader and defaults
 * GuardConfig 載入器與預設值
 * @module @panguard-ai/panguard-guard/config
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createLogger } from '@panguard-ai/core';
import type { GuardConfig } from './types.js';
import { DEFAULT_ACTION_POLICY } from './types.js';

const logger = createLogger('panguard-guard:config');

/** Default data directory / 預設資料目錄 */
export const DEFAULT_DATA_DIR = join(homedir(), '.panguard-guard');

/**
 * Resolve the bundled rules directory.
 * Search order:
 * 1. bundled-rules/ inside the package (npm install scenario)
 * 2. config/ in monorepo root (development scenario)
 * 從安裝包或 monorepo 解析內建規則目錄。
 */
function findBundledDir(subdir: string): string | undefined {
  const thisDir = dirname(fileURLToPath(import.meta.url));

  // 1. Check for bundled-rules/ inside the package (npm install)
  //    thisDir = .../dist/ or .../dist/src/ → package root is 1-2 levels up
  let pkgDir = thisDir;
  for (let i = 0; i < 3; i++) {
    const bundled = join(pkgDir, 'bundled-rules', subdir);
    if (existsSync(bundled)) {
      return bundled;
    }
    pkgDir = dirname(pkgDir);
  }

  // 2. Walk up to find monorepo root (development — contains config/)
  let dir = thisDir;
  for (let i = 0; i < 8; i++) {
    const candidate = join(dir, 'config', subdir);
    if (existsSync(candidate)) {
      return candidate;
    }
    dir = dirname(dir);
  }
  return undefined;
}

/** Default configuration / 預設配置 */
export const DEFAULT_GUARD_CONFIG: GuardConfig = {
  lang: 'zh-TW',
  mode: 'learning',
  learningDays: 7,
  actionPolicy: DEFAULT_ACTION_POLICY,
  notifications: {},
  dataDir: DEFAULT_DATA_DIR,
  yaraRulesDir: join(DEFAULT_DATA_DIR, 'yara-rules'),
  bundledSigmaDir: findBundledDir('sigma-rules'),
  bundledYaraDir: findBundledDir('yara-rules'),
  dashboardPort: 3100,
  dashboardEnabled: true,
  verbose: false,
  monitors: {
    logMonitor: true,
    networkMonitor: true,
    processMonitor: true,
    fileMonitor: true,
    networkPollInterval: 30000,
    processPollInterval: 15000,
  },
  watchdogEnabled: true,
  watchdogInterval: 60000,
  threatCloudEndpoint: 'https://tc.panguard.ai/api',
};

/** Master config path written by `panguard init` / `panguard init` 寫入的主配置路徑 */
const MASTER_CONFIG_DIR = join(homedir(), '.panguard');
const MASTER_CONFIG_PATH = join(MASTER_CONFIG_DIR, 'config.json');

/**
 * Load configuration from JSON file / 從 JSON 檔案載入配置
 *
 * Resolution order:
 * 1. Explicit configPath (if provided)
 * 2. ~/.panguard-guard/config.json (guard-specific config)
 * 3. ~/.panguard/config.json (master config from `panguard init`, auto-converted)
 * 4. Built-in defaults
 */
export function loadConfig(configPath?: string): GuardConfig {
  const guardPath = configPath ?? join(DEFAULT_DATA_DIR, 'config.json');

  // Try guard-specific config first
  if (existsSync(guardPath)) {
    return loadGuardConfigFile(guardPath);
  }

  // Fall back to master config from `panguard init`
  if (existsSync(MASTER_CONFIG_PATH)) {
    logger.info(
      `No guard config at ${guardPath}, loading from master config / ` +
        `未找到守護配置，從主配置載入`
    );
    return loadFromMasterConfig(MASTER_CONFIG_PATH);
  }

  logger.info(`No config file found, using defaults / 找不到配置檔，使用預設值`);
  return { ...DEFAULT_GUARD_CONFIG };
}

/**
 * Load and merge a guard-specific config file.
 */
function loadGuardConfigFile(path: string): GuardConfig {
  try {
    const raw = readFileSync(path, 'utf-8');
    const parsed = JSON.parse(raw) as Partial<GuardConfig> & { actionThresholds?: Partial<GuardConfig['actionPolicy']> };
    // Support legacy `actionThresholds` key from older deploy writes
    const policySource = parsed.actionPolicy ?? parsed.actionThresholds ?? {};
    const merged: GuardConfig = {
      ...DEFAULT_GUARD_CONFIG,
      ...parsed,
      actionPolicy: { ...DEFAULT_ACTION_POLICY, ...policySource },
      notifications: { ...DEFAULT_GUARD_CONFIG.notifications, ...(parsed.notifications ?? {}) },
      monitors: { ...DEFAULT_GUARD_CONFIG.monitors, ...(parsed.monitors ?? {}) },
    };
    logger.info(`Loaded config from ${path} / 已從 ${path} 載入配置`);
    return merged;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to load config: ${msg} / 載入配置失敗: ${msg}`);
    return { ...DEFAULT_GUARD_CONFIG };
  }
}

/**
 * Convert master PanguardConfig (from `panguard init`) to GuardConfig.
 * 將 `panguard init` 的主配置轉換為 GuardConfig。
 */
function loadFromMasterConfig(masterPath: string): GuardConfig {
  try {
    const raw = readFileSync(masterPath, 'utf-8');
    const master = JSON.parse(raw) as Record<string, unknown>;

    const guard = (master['guard'] ?? {}) as Record<string, unknown>;
    const ai = (master['ai'] ?? {}) as Record<string, unknown>;
    const notifications = (master['notifications'] ?? {}) as Record<string, unknown>;
    const meta = (master['meta'] ?? {}) as Record<string, unknown>;
    const monitors = (guard['monitors'] ?? {}) as Record<string, boolean>;
    const policy = (guard['actionPolicy'] ?? {}) as Record<string, number>;

    // Map notification channel config from master format to guard format
    const notifConfig = buildNotificationConfig(
      notifications['channel'] as string | undefined,
      (notifications['config'] ?? {}) as Record<string, string>
    );

    const config: GuardConfig = {
      ...DEFAULT_GUARD_CONFIG,
      lang: (meta['language'] as GuardConfig['lang']) ?? DEFAULT_GUARD_CONFIG.lang,
      mode: (guard['mode'] as GuardConfig['mode']) ?? DEFAULT_GUARD_CONFIG.mode,
      learningDays: (guard['learningDays'] as number) ?? DEFAULT_GUARD_CONFIG.learningDays,
      actionPolicy: {
        ...DEFAULT_ACTION_POLICY,
        ...policy,
      },
      notifications: notifConfig,
      monitors: {
        ...DEFAULT_GUARD_CONFIG.monitors,
        ...monitors,
      },
    };

    // Map threat cloud API key from master config or env
    const tcKey = (master['threatCloudApiKey'] as string | undefined)
      ?? process.env['TC_API_KEY'];
    if (tcKey) {
      config.threatCloudApiKey = tcKey;
    }

    // Map AI settings
    if (ai['provider']) {
      config.ai = {
        provider: ai['provider'] as 'ollama' | 'claude' | 'openai',
        model: (ai['model'] as string) ?? 'default',
        endpoint: ai['endpoint'] as string | undefined,
        apiKey: ai['apiKey'] as string | undefined,
      };
    }

    logger.info(
      `Loaded and converted master config from ${masterPath} / ` +
        `已從 ${masterPath} 載入並轉換主配置`
    );
    return config;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to load master config: ${msg} / 載入主配置失敗: ${msg}`);
    return { ...DEFAULT_GUARD_CONFIG };
  }
}

/**
 * Build NotificationConfig from master config channel/config pair.
 */
function buildNotificationConfig(
  channel: string | undefined,
  cfg: Record<string, string>
): GuardConfig['notifications'] {
  if (!channel || channel === 'none') return {};

  switch (channel) {
    case 'telegram':
      return cfg['botToken'] && cfg['chatId']
        ? { telegram: { botToken: cfg['botToken'], chatId: cfg['chatId'] } }
        : {};
    case 'slack':
      return cfg['webhookUrl']
        ? { slack: { webhookUrl: cfg['webhookUrl'] } }
        : {};
    case 'email':
      return cfg['host']
        ? {
            email: {
              host: cfg['host'],
              port: Number(cfg['port'] ?? 587),
              secure: cfg['secure'] === 'true',
              auth: { user: cfg['user'] ?? '', pass: cfg['pass'] ?? '' },
              from: cfg['from'] ?? '',
              to: (cfg['to'] ?? '').split(',').filter(Boolean),
            },
          }
        : {};
    case 'webhook':
      return cfg['url']
        ? { webhook: { url: cfg['url'], secret: cfg['secret'] } }
        : {};
    case 'line':
      return cfg['accessToken']
        ? { line: { accessToken: cfg['accessToken'] } }
        : {};
    default:
      return {};
  }
}

/**
 * Save configuration to JSON file / 儲存配置到 JSON 檔案
 */
export function saveConfig(config: GuardConfig, configPath?: string): void {
  const path = configPath ?? join(config.dataDir, 'config.json');
  const dir = join(path, '..');

  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  writeFileSync(path, JSON.stringify(config, null, 2), 'utf-8');
  logger.info(`Saved config to ${path} / 已儲存配置到 ${path}`);
}

/**
 * Ensure data directory exists / 確保資料目錄存在
 */
export function ensureDataDir(dataDir: string): void {
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
    logger.info(`Created data directory: ${dataDir} / 已建立資料目錄: ${dataDir}`);
  }
}
