/**
 * Context Memory Module
 * Context Memory 模組
 *
 * Environment behavior baseline management with learning period support.
 * Tracks normal system behavior during learning mode and detects
 * deviations once in protection mode.
 * 環境行為基線管理，支援學習期。在學習模式中追蹤正常系統行為，
 * 進入防護模式後偵測偏離。
 *
 * @module @panguard-ai/panguard-guard/memory
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type { EnvironmentBaseline } from '../types.js';
import { createEmptyBaseline } from './baseline.js';

const logger = createLogger('panguard-guard:memory');

export { createEmptyBaseline, checkDeviation, updateBaseline } from './baseline.js';

export {
  isLearningComplete,
  getLearningProgress,
  getRemainingDays,
  switchToProtectionMode,
  getBaselineSummary,
} from './learning.js';

/**
 * Load baseline from a JSON file, or create empty if not found
 * 從 JSON 檔案載入基線，找不到則建立空白基線
 *
 * @param filePath - Path to the baseline JSON file / 基線 JSON 檔案路徑
 * @returns The loaded or newly created baseline / 載入或新建的基線
 */
export function loadBaseline(filePath: string): EnvironmentBaseline {
  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw) as EnvironmentBaseline;
    logger.info(`Baseline loaded from ${filePath} / 已從 ${filePath} 載入基線`);
    return parsed;
  } catch {
    logger.info(
      `No existing baseline at ${filePath}, creating empty / ` +
        `${filePath} 無現有基線，建立空白基線`
    );
    return createEmptyBaseline();
  }
}

/**
 * Save baseline to a JSON file
 * 將基線儲存至 JSON 檔案
 *
 * @param filePath - Path to save the baseline / 儲存基線的路徑
 * @param baseline - The baseline to save / 要儲存的基線
 */
export function saveBaseline(filePath: string, baseline: EnvironmentBaseline): void {
  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(baseline, null, 2), 'utf-8');
    logger.info(`Baseline saved to ${filePath} / 基線已儲存至 ${filePath}`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to save baseline: ${msg} / 儲存基線失敗: ${msg}`);
  }
}
