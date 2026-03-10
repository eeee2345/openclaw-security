/**
 * MCP Config Injector - Write Panguard MCP config to AI agent platforms
 * MCP 設定注入器 - 將 Panguard MCP 設定寫入 AI Agent 平台
 *
 * Supports Claude Code, Claude Desktop, Cursor, OpenClaw, Codex, Workbuddy.
 *
 * @module @panguard-ai/panguard-mcp/config/mcp-injector
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type { PlatformId } from './platform-detector.js';
import { getConfigPath } from './platform-detector.js';

const logger = createLogger('panguard-mcp:injector');

export interface InjectionResult {
  platformId: PlatformId;
  success: boolean;
  configPath: string;
  backupPath?: string;
  error?: string;
}

/** The MCP server entry Panguard adds to config files. */
const PANGUARD_MCP_ENTRY = {
  command: 'npx',
  args: ['-y', '@panguard-ai/panguard-mcp'],
};

/**
 * Read an existing JSON config file, or return empty object.
 * 讀取現有 JSON 設定檔，或回傳空物件。
 */
function readJsonSafe(filePath: string): Record<string, unknown> {
  if (!existsSync(filePath)) return {};
  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return {};
  } catch {
    return {};
  }
}

/**
 * Back up a config file before modifying it.
 * 修改前備份設定檔。
 */
function backupFile(filePath: string): string | undefined {
  if (!existsSync(filePath)) return undefined;
  const backupPath = `${filePath}.bak.${Date.now()}`;
  copyFileSync(filePath, backupPath);
  logger.info(`Backed up ${filePath} -> ${backupPath}`);
  return backupPath;
}

/**
 * Ensure parent directory exists.
 * 確保父目錄存在。
 */
function ensureDir(filePath: string): void {
  const dir = dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

/**
 * Inject Panguard MCP config for Claude Desktop.
 * Claude Desktop uses: { "mcpServers": { "panguard": { "command": "...", "args": [...] } } }
 */
function injectClaudeDesktop(configPath: string): void {
  const config = readJsonSafe(configPath);
  const servers = (config['mcpServers'] as Record<string, unknown>) ?? {};
  servers['panguard'] = { ...PANGUARD_MCP_ENTRY };
  config['mcpServers'] = servers;
  writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
}

/**
 * Inject Panguard MCP config for Claude Code.
 * Claude Code uses: { "mcpServers": { "panguard": { "command": "...", "args": [...] } } }
 * in ~/.claude/settings.local.json
 */
function injectClaudeCode(configPath: string): void {
  const config = readJsonSafe(configPath);
  const servers = (config['mcpServers'] as Record<string, unknown>) ?? {};
  servers['panguard'] = { ...PANGUARD_MCP_ENTRY };
  config['mcpServers'] = servers;
  writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
}

/**
 * Inject Panguard MCP config for Cursor.
 * Cursor uses: { "mcpServers": { "panguard": { "command": "...", "args": [...] } } }
 * in ~/.cursor/mcp.json
 */
function injectCursor(configPath: string): void {
  const config = readJsonSafe(configPath);
  const servers = (config['mcpServers'] as Record<string, unknown>) ?? {};
  servers['panguard'] = { ...PANGUARD_MCP_ENTRY };
  config['mcpServers'] = servers;
  writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
}

/**
 * Inject Panguard MCP config for OpenClaw/Codex/Workbuddy.
 * Generic MCP JSON format: { "mcpServers": { "panguard": { ... } } }
 */
function injectGenericMCP(configPath: string): void {
  const config = readJsonSafe(configPath);
  const servers = (config['mcpServers'] as Record<string, unknown>) ?? {};
  servers['panguard'] = { ...PANGUARD_MCP_ENTRY };
  config['mcpServers'] = servers;
  writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
}

/**
 * Inject Panguard MCP config into a specific platform.
 * 將 Panguard MCP 設定注入特定平台。
 *
 * @param platformId - Target platform / 目標平台
 * @returns Injection result with success status and paths.
 */
export function injectMCPConfig(platformId: PlatformId): InjectionResult {
  const configPath = getConfigPath(platformId);
  const result: InjectionResult = { platformId, success: false, configPath };

  try {
    ensureDir(configPath);
    result.backupPath = backupFile(configPath);

    switch (platformId) {
      case 'claude-desktop':
        injectClaudeDesktop(configPath);
        break;
      case 'claude-code':
        injectClaudeCode(configPath);
        break;
      case 'cursor':
        injectCursor(configPath);
        break;
      case 'openclaw':
      case 'codex':
      case 'workbuddy':
        injectGenericMCP(configPath);
        break;
    }

    // Verify the write succeeded
    const verify = readJsonSafe(configPath);
    const servers = verify['mcpServers'] as Record<string, unknown> | undefined;
    if (servers && servers['panguard']) {
      result.success = true;
      logger.info(`Injected Panguard MCP config into ${platformId} at ${configPath}`);
    } else {
      result.error = 'Verification failed: panguard entry not found after write';
      logger.error(result.error);
    }
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to inject ${platformId}: ${result.error}`);
  }

  return result;
}

/**
 * Remove Panguard MCP config from a specific platform.
 * 從特定平台移除 Panguard MCP 設定。
 */
export function removeMCPConfig(platformId: PlatformId): InjectionResult {
  const configPath = getConfigPath(platformId);
  const result: InjectionResult = { platformId, success: false, configPath };

  try {
    if (!existsSync(configPath)) {
      result.success = true;
      return result;
    }

    result.backupPath = backupFile(configPath);
    const config = readJsonSafe(configPath);
    const servers = config['mcpServers'] as Record<string, unknown> | undefined;
    if (servers) {
      delete servers['panguard'];
      config['mcpServers'] = servers;
    }
    writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
    result.success = true;
    logger.info(`Removed Panguard MCP config from ${platformId}`);
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to remove from ${platformId}: ${result.error}`);
  }

  return result;
}

/**
 * Inject Panguard MCP config into all detected platforms.
 * 將 Panguard MCP 設定注入所有偵測到的平台。
 */
export async function injectAll(platformIds: PlatformId[]): Promise<InjectionResult[]> {
  return platformIds.map((id) => injectMCPConfig(id));
}

/**
 * Get the one-liner install command for display.
 * 取得用於顯示的一行安裝指令。
 */
export function getInstallCommand(): string {
  return 'npx panguard setup';
}
