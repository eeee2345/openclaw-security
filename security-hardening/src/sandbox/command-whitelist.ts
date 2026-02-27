/**
 * Command whitelist for safe execution
 * 安全執行的命令白名單
 *
 * Prevents Skills from executing arbitrary commands.
 * 防止 Skills 執行任意命令。
 *
 * @module @panguard-ai/security-hardening/sandbox/command-whitelist
 */

import { createLogger } from '@panguard-ai/core';

const logger = createLogger('sandbox:command-whitelist');

/**
 * Default allowed commands (safe, read-only utilities)
 * 預設允許的命令（安全、唯讀工具）
 */
export const DEFAULT_ALLOWED_COMMANDS: readonly string[] = [
  'ls',
  'cat',
  'grep',
  'find',
  'head',
  'tail',
  'wc',
  'echo',
  'pwd',
  'date',
  'whoami',
  'uname',
  'node',
  'git',
] as const;

/**
 * Extract base command name from a command string
 * 從命令字串中提取基礎命令名稱
 *
 * @param command - Full command string / 完整命令字串
 * @returns Base command name / 基礎命令名稱
 */
export function extractBaseCommand(command: string): string {
  const trimmed = command.trim();
  // Get first token (before any spaces/args)
  const firstToken = trimmed.split(/\s+/)[0] ?? trimmed;
  // Get basename (after last /)
  const basename = firstToken.split('/').pop() ?? firstToken;
  return basename;
}

/**
 * Check if a command is in the whitelist
 * 檢查命令是否在白名單中
 *
 * @param command - Command to check / 要檢查的命令
 * @param whitelist - Allowed commands / 允許的命令
 * @returns true if command is allowed / 命令被允許則回傳 true
 */
export function isCommandAllowed(
  command: string,
  whitelist: readonly string[] = DEFAULT_ALLOWED_COMMANDS
): boolean {
  const base = extractBaseCommand(command);
  const allowed = whitelist.includes(base);

  if (!allowed) {
    logger.warn('Command blocked: not in whitelist', { command, baseCommand: base });
  } else {
    logger.info('Command allowed', { command, baseCommand: base });
  }

  return allowed;
}

/**
 * Create a command validator function
 * 建立命令驗證器函式
 *
 * Returns a function that throws if a command is not whitelisted.
 * 回傳一個在命令未列入白名單時拋出錯誤的函式。
 *
 * @param whitelist - Allowed commands / 允許的命令
 * @returns Validator function / 驗證器函式
 */
export function createCommandValidator(whitelist: readonly string[] = DEFAULT_ALLOWED_COMMANDS) {
  return (command: string): void => {
    if (!isCommandAllowed(command, whitelist)) {
      throw new Error(
        `Command execution denied: '${extractBaseCommand(command)}' is not whitelisted / ` +
          `命令執行拒絕：'${extractBaseCommand(command)}' 未列入白名單`
      );
    }
  };
}
