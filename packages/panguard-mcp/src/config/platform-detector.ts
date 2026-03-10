/**
 * Platform Detector - Detect installed AI agent runtimes
 * 平台偵測器 - 偵測已安裝的 AI Agent 執行環境
 *
 * Detects Claude Code, Cursor, OpenClaw, Codex, and Workbuddy.
 * 偵測 Claude Code、Cursor、OpenClaw、Codex 和 Workbuddy。
 *
 * @module @panguard-ai/panguard-mcp/config/platform-detector
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { execFile } from 'node:child_process';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-mcp:platform-detector');

export type PlatformId =
  | 'claude-code'
  | 'claude-desktop'
  | 'cursor'
  | 'openclaw'
  | 'codex'
  | 'workbuddy';

export interface DetectedPlatform {
  id: PlatformId;
  name: string;
  configPath: string;
  detected: boolean;
  alreadyConfigured: boolean;
}

/** Check if a command exists on PATH. */
function commandExists(cmd: string): Promise<boolean> {
  if (!/^[a-zA-Z0-9_.-]+$/.test(cmd)) return Promise.resolve(false);
  return new Promise((resolve) => {
    const bin = platform() === 'win32' ? 'where' : 'which';
    execFile(bin, [cmd], (err) => resolve(!err));
  });
}

/** Check if a JSON file contains a panguard MCP entry. */
function hasPanguardEntry(filePath: string): boolean {
  if (!existsSync(filePath)) return false;
  try {
    const content = readFileSync(filePath, 'utf-8');
    return content.includes('panguard');
  } catch {
    return false;
  }
}

/** Get the MCP config path for Claude Desktop based on OS. */
function getClaudeDesktopConfigPath(): string {
  const home = homedir();
  switch (platform()) {
    case 'darwin':
      return join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    case 'win32':
      return join(process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json');
    default:
      return join(home, '.config', 'claude', 'claude_desktop_config.json');
  }
}

/** Get the MCP settings path for Claude Code. */
function getClaudeCodeConfigPath(): string {
  return join(homedir(), '.claude', 'settings.local.json');
}

/** Get the MCP config path for Cursor. */
function getCursorConfigPath(): string {
  return join(homedir(), '.cursor', 'mcp.json');
}

/** Get the MCP config path for OpenClaw. */
function getOpenClawConfigPath(): string {
  return join(homedir(), '.openclaw', 'mcp.json');
}

/** Get the MCP config path for Codex. */
function getCodexConfigPath(): string {
  return join(homedir(), '.codex', 'mcp.json');
}

/** Get the MCP config path for Workbuddy. */
function getWorkbuddyConfigPath(): string {
  return join(homedir(), '.workbuddy', 'mcp.json');
}

/**
 * Detect all supported AI agent platforms.
 * 偵測所有支援的 AI Agent 平台。
 *
 * @returns Array of detected platforms with their config paths and status.
 */
export async function detectPlatforms(): Promise<DetectedPlatform[]> {
  const platforms: DetectedPlatform[] = [];

  // Claude Code
  const claudeCodePath = getClaudeCodeConfigPath();
  const claudeCodeDetected = await commandExists('claude') || existsSync(join(homedir(), '.claude'));
  platforms.push({
    id: 'claude-code',
    name: 'Claude Code',
    configPath: claudeCodePath,
    detected: claudeCodeDetected,
    alreadyConfigured: hasPanguardEntry(claudeCodePath),
  });

  // Claude Desktop
  const claudeDesktopPath = getClaudeDesktopConfigPath();
  const claudeDesktopDetected = existsSync(claudeDesktopPath) ||
    (platform() === 'darwin' && existsSync('/Applications/Claude.app'));
  platforms.push({
    id: 'claude-desktop',
    name: 'Claude Desktop',
    configPath: claudeDesktopPath,
    detected: claudeDesktopDetected,
    alreadyConfigured: hasPanguardEntry(claudeDesktopPath),
  });

  // Cursor
  const cursorPath = getCursorConfigPath();
  const cursorDetected = await commandExists('cursor') ||
    existsSync(join(homedir(), '.cursor')) ||
    (platform() === 'darwin' && existsSync('/Applications/Cursor.app'));
  platforms.push({
    id: 'cursor',
    name: 'Cursor',
    configPath: cursorPath,
    detected: cursorDetected,
    alreadyConfigured: hasPanguardEntry(cursorPath),
  });

  // OpenClaw
  const openclawPath = getOpenClawConfigPath();
  const openclawDetected = await commandExists('openclaw') || existsSync(join(homedir(), '.openclaw'));
  platforms.push({
    id: 'openclaw',
    name: 'OpenClaw',
    configPath: openclawPath,
    detected: openclawDetected,
    alreadyConfigured: hasPanguardEntry(openclawPath),
  });

  // Codex
  const codexPath = getCodexConfigPath();
  const codexDetected = await commandExists('codex') || existsSync(join(homedir(), '.codex'));
  platforms.push({
    id: 'codex',
    name: 'Codex CLI',
    configPath: codexPath,
    detected: codexDetected,
    alreadyConfigured: hasPanguardEntry(codexPath),
  });

  // Workbuddy
  const workbuddyPath = getWorkbuddyConfigPath();
  const workbuddyDetected = await commandExists('workbuddy') || existsSync(join(homedir(), '.workbuddy'));
  platforms.push({
    id: 'workbuddy',
    name: 'Workbuddy',
    configPath: workbuddyPath,
    detected: workbuddyDetected,
    alreadyConfigured: hasPanguardEntry(workbuddyPath),
  });

  const detected = platforms.filter((p) => p.detected);
  logger.info(`Detected ${detected.length} platform(s): ${detected.map((p) => p.name).join(', ') || 'none'}`);
  return platforms;
}

/**
 * Get the MCP config path for a specific platform.
 * 取得特定平台的 MCP 設定路徑。
 */
export function getConfigPath(platformId: PlatformId): string {
  switch (platformId) {
    case 'claude-code': return getClaudeCodeConfigPath();
    case 'claude-desktop': return getClaudeDesktopConfigPath();
    case 'cursor': return getCursorConfigPath();
    case 'openclaw': return getOpenClawConfigPath();
    case 'codex': return getCodexConfigPath();
    case 'workbuddy': return getWorkbuddyConfigPath();
  }
}
