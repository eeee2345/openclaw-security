/**
 * Sigma rule filesystem loader
 * Sigma 規則檔案系統載入器
 *
 * Loads Sigma rules from directories and supports watching for changes.
 * 從目錄載入 Sigma 規則並支援監視變更。
 *
 * @module @panguard-ai/core/rules/rule-loader
 */

import fs from 'node:fs';
import path from 'node:path';
import { createLogger } from '../utils/logger.js';
import { parseSigmaFile } from './sigma-parser.js';
import type { SigmaRule } from './types.js';

const logger = createLogger('rule-loader');

/** Supported Sigma rule file extensions / 支援的 Sigma 規則檔案副檔名 */
const SIGMA_EXTENSIONS = new Set(['.yml', '.yaml']);

/**
 * Load all Sigma rules from a directory
 * 從目錄載入所有 Sigma 規則
 *
 * Reads all .yml and .yaml files in the given directory (non-recursive),
 * parses each one, and returns the successfully parsed rules.
 * 讀取指定目錄中所有 .yml 和 .yaml 檔案（非遞迴），
 * 解析每一個，並回傳成功解析的規則。
 *
 * @param dir - Directory path containing Sigma rule files / 包含 Sigma 規則檔案的目錄路徑
 * @returns Array of successfully parsed Sigma rules / 成功解析的 Sigma 規則陣列
 */
export function loadRulesFromDirectory(dir: string): SigmaRule[] {
  const rules: SigmaRule[] = [];

  if (!fs.existsSync(dir)) {
    logger.error(`Rules directory does not exist: ${dir} / 規則目錄不存在: ${dir}`);
    return rules;
  }

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to read rules directory: ${dir} / 讀取規則目錄失敗: ${dir}`, {
      error: message,
    });
    return rules;
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;

    const ext = path.extname(entry.name).toLowerCase();
    if (!SIGMA_EXTENSIONS.has(ext)) continue;

    const filePath = path.join(dir, entry.name);
    const rule = parseSigmaFile(filePath);

    if (rule !== null) {
      rules.push(rule);
      logger.debug(`Loaded rule from file: ${entry.name} / 從檔案載入規則: ${entry.name}`, {
        ruleId: rule.id,
        title: rule.title,
      });
    }
  }

  logger.info(
    `Loaded ${rules.length} rules from directory: ${dir} / 從目錄載入 ${rules.length} 條規則: ${dir}`
  );

  return rules;
}

/**
 * Recursively load Sigma rules from a directory tree
 * 從目錄樹遞迴載入 Sigma 規則
 *
 * Walks subdirectories to find all .yml/.yaml files.
 * Optionally tags each rule with a source label.
 * 遍歷子目錄尋找所有 .yml/.yaml 檔案。
 * 可選擇性地為每條規則標記來源標籤。
 *
 * @param dir - Root directory to scan recursively / 要遞迴掃描的根目錄
 * @param source - Optional source tag for loaded rules / 可選的規則來源標記
 * @returns Array of successfully parsed Sigma rules / 成功解析的 Sigma 規則陣列
 */
export function loadRulesRecursive(dir: string, source?: SigmaRule['source']): SigmaRule[] {
  if (!fs.existsSync(dir)) {
    logger.warn(`Rules directory does not exist, skipping: ${dir} / 規則目錄不存在，跳過: ${dir}`);
    return [];
  }

  const rules: SigmaRule[] = [];

  function walk(currentDir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!SIGMA_EXTENSIONS.has(ext)) continue;
        const rule = parseSigmaFile(fullPath);
        if (rule !== null) {
          if (source !== undefined) {
            rule.source = source;
          }
          rules.push(rule);
        }
      }
    }
  }

  walk(dir);

  logger.info(
    `Loaded ${rules.length} rules recursively from: ${dir} (source: ${source ?? 'unset'}) / 從 ${dir} 遞迴載入 ${rules.length} 條規則`
  );

  return rules;
}

/**
 * Watch a directory for Sigma rule file changes
 * 監視目錄中的 Sigma 規則檔案變更
 *
 * Uses fs.watch to monitor the directory. When any .yml/.yaml file changes,
 * reloads all rules from the directory and invokes the callback.
 * Returns a cleanup function that stops the watcher.
 * 使用 fs.watch 監視目錄。當任何 .yml/.yaml 檔案變更時，
 * 從目錄重新載入所有規則並呼叫回調。
 * 回傳停止監視的清理函式。
 *
 * @param dir - Directory path to watch / 要監視的目錄路徑
 * @param callback - Called with reloaded rules on file changes / 檔案變更時以重新載入的規則呼叫
 * @returns Cleanup function to stop the watcher / 停止監視的清理函式
 */
export function watchRulesDirectory(
  dir: string,
  callback: (rules: SigmaRule[]) => void
): () => void {
  if (!fs.existsSync(dir)) {
    logger.error(`Cannot watch non-existent directory: ${dir} / 無法監視不存在的目錄: ${dir}`);
    return () => {
      /* noop */
    };
  }

  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  const DEBOUNCE_MS = 300;

  const watcher = fs.watch(dir, (eventType, filename) => {
    // Filter for Sigma rule files only / 僅篩選 Sigma 規則檔案
    if (filename !== null && filename !== undefined) {
      const ext = path.extname(filename).toLowerCase();
      if (!SIGMA_EXTENSIONS.has(ext)) return;
    }

    // Debounce rapid changes / 防止快速連續變更
    if (debounceTimer !== null) {
      clearTimeout(debounceTimer);
    }

    debounceTimer = setTimeout(() => {
      logger.info(
        `Detected rule file change (${eventType}${filename ? `: ${filename}` : ''}), reloading rules / 偵測到規則檔案變更，重新載入規則`
      );
      const rules = loadRulesFromDirectory(dir);
      callback(rules);
      debounceTimer = null;
    }, DEBOUNCE_MS);
  });

  logger.info(`Watching rules directory for changes: ${dir} / 正在監視規則目錄的變更: ${dir}`);

  // Return cleanup function / 回傳清理函式
  return () => {
    if (debounceTimer !== null) {
      clearTimeout(debounceTimer);
    }
    watcher.close();
    logger.info(`Stopped watching rules directory: ${dir} / 停止監視規則目錄: ${dir}`);
  };
}
