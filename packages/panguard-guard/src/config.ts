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
 * Resolve the bundled rules directory from the installation root.
 * Walks up from this file's location to find the monorepo config/ directory.
 * 從安裝根目錄解析內建規則目錄。
 */
function findBundledDir(subdir: string): string | undefined {
  const thisDir = dirname(fileURLToPath(import.meta.url));
  // Walk up to find the monorepo root (contains config/)
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

/**
 * Load configuration from JSON file / 從 JSON 檔案載入配置
 */
export function loadConfig(configPath?: string): GuardConfig {
  const path = configPath ?? join(DEFAULT_DATA_DIR, 'config.json');

  if (!existsSync(path)) {
    logger.info(`No config file found at ${path}, using defaults / 找不到配置檔，使用預設值`);
    return { ...DEFAULT_GUARD_CONFIG };
  }

  try {
    const raw = readFileSync(path, 'utf-8');
    const parsed = JSON.parse(raw) as Partial<GuardConfig>;
    const merged: GuardConfig = {
      ...DEFAULT_GUARD_CONFIG,
      ...parsed,
      actionPolicy: { ...DEFAULT_ACTION_POLICY, ...(parsed.actionPolicy ?? {}) },
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
