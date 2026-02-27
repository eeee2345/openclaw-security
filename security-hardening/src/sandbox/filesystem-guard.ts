/**
 * Filesystem access control for Skills
 * Skills 的檔案系統存取控制
 *
 * Restricts file access to whitelisted directories only.
 * 限制檔案存取僅限白名單目錄。
 *
 * @module @panguard-ai/security-hardening/sandbox/filesystem-guard
 */

import { resolve, normalize } from 'path';
import { createLogger, validateFilePath } from '@panguard-ai/core';

const logger = createLogger('sandbox:filesystem-guard');

/**
 * Check if a file path is within allowed directories
 * 檢查檔案路徑是否在允許的目錄內
 *
 * @param filePath - File path to check / 要檢查的檔案路徑
 * @param allowedDirs - Allowed directories / 允許的目錄
 * @returns true if path is allowed / 路徑被允許則回傳 true
 */
export function isPathAllowed(filePath: string, allowedDirs: string[]): boolean {
  if (allowedDirs.length === 0) {
    logger.warn('No allowed directories configured, blocking all access');
    return false;
  }

  try {
    // Use core's validateFilePath to check for traversal attacks
    const sanitized = validateFilePath(filePath);
    const absolutePath = normalize(resolve(sanitized));

    for (const dir of allowedDirs) {
      const allowedAbsolute = normalize(resolve(dir));
      if (absolutePath.startsWith(allowedAbsolute + '/') || absolutePath === allowedAbsolute) {
        logger.info('Path access allowed', { filePath, allowedDir: dir });
        return true;
      }
    }

    logger.warn('Path access denied: not in allowed directories', { filePath });
    return false;
  } catch (error) {
    // validateFilePath throws on traversal attempts
    logger.error('Path validation failed (possible traversal attack)', {
      filePath,
      error: String(error),
    });
    return false;
  }
}

/**
 * Create a filesystem guard function
 * 建立檔案系統守衛函式
 *
 * Returns a function that throws if a path is not allowed.
 * 回傳一個在路徑不被允許時拋出錯誤的函式。
 *
 * @param allowedDirs - Allowed directories / 允許的目錄
 * @returns Guard function / 守衛函式
 */
export function createFilesystemGuard(allowedDirs: string[]) {
  return (filePath: string): void => {
    if (!isPathAllowed(filePath, allowedDirs)) {
      throw new Error(
        `Filesystem access denied: ${filePath} is not in allowed directories / ` +
          `檔案系統存取拒絕：${filePath} 不在允許的目錄中`
      );
    }
  };
}
