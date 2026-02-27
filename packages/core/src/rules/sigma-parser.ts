/**
 * Sigma YAML rule parser
 * Sigma YAML 規則解析器
 *
 * Parses Sigma rules from YAML format into typed SigmaRule objects.
 * Validates required fields and logs warnings for missing optional fields.
 * 將 Sigma 規則從 YAML 格式解析為型別化的 SigmaRule 物件。
 * 驗證必要欄位並對缺少的可選欄位記錄警告。
 *
 * @module @panguard-ai/core/rules/sigma-parser
 */

import fs from 'node:fs';
import yaml from 'js-yaml';
import { createLogger } from '../utils/logger.js';
import type { Severity } from '../types.js';
import type { SigmaRule, SigmaDetection, SigmaLogSource } from './types.js';

const logger = createLogger('sigma-parser');

/** Valid Sigma rule status values / 有效的 Sigma 規則狀態值 */
const VALID_STATUSES = new Set(['experimental', 'test', 'stable']);

/** Valid severity levels / 有效的嚴重等級 */
const VALID_LEVELS = new Set(['info', 'low', 'medium', 'high', 'critical']);

/**
 * Parse a Sigma rule from a YAML string
 * 從 YAML 字串解析 Sigma 規則
 *
 * Validates required fields (title, detection, level) and normalizes
 * optional fields with sensible defaults.
 * 驗證必要欄位（title、detection、level）並以合理預設值標準化可選欄位。
 *
 * @param yamlContent - Raw YAML string content / 原始 YAML 字串內容
 * @returns Parsed SigmaRule or null if validation fails / 解析後的 SigmaRule，驗證失敗則回傳 null
 */
export function parseSigmaYaml(yamlContent: string): SigmaRule | null {
  let parsed: unknown;

  try {
    parsed = yaml.load(yamlContent);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error('Failed to parse YAML content / 解析 YAML 內容失敗', { error: message });
    return null;
  }

  if (parsed === null || parsed === undefined || typeof parsed !== 'object') {
    logger.error('YAML content is not an object / YAML 內容不是物件');
    return null;
  }

  const doc = parsed as Record<string, unknown>;

  // --- Validate required fields / 驗證必要欄位 ---

  if (typeof doc['title'] !== 'string' || doc['title'].trim() === '') {
    logger.error('Missing or invalid required field: title / 缺少或無效的必要欄位: title');
    return null;
  }

  if (
    doc['detection'] === undefined ||
    doc['detection'] === null ||
    typeof doc['detection'] !== 'object'
  ) {
    logger.error('Missing or invalid required field: detection / 缺少或無效的必要欄位: detection');
    return null;
  }

  const rawDetection = doc['detection'] as Record<string, unknown>;
  if (typeof rawDetection['condition'] !== 'string') {
    logger.error(
      'Missing or invalid required field: detection.condition / 缺少或無效的必要欄位: detection.condition'
    );
    return null;
  }

  const levelStr = typeof doc['level'] === 'string' ? doc['level'].toLowerCase() : '';
  if (!VALID_LEVELS.has(levelStr)) {
    logger.error(
      `Invalid or missing level: "${String(doc['level'])}" / 無效或缺少嚴重等級: "${String(doc['level'])}"`,
      {
        validLevels: [...VALID_LEVELS],
      }
    );
    return null;
  }

  // --- Parse optional fields with warnings / 解析可選欄位並記錄警告 ---

  if (doc['id'] === undefined) {
    logger.warn(
      'Missing optional field: id - a unique identifier is recommended / 缺少可選欄位: id - 建議提供唯一識別碼'
    );
  }

  if (doc['author'] === undefined) {
    logger.warn('Missing optional field: author / 缺少可選欄位: author');
  }

  if (doc['date'] === undefined) {
    logger.warn('Missing optional field: date / 缺少可選欄位: date');
  }

  if (doc['tags'] === undefined) {
    logger.warn('Missing optional field: tags / 缺少可選欄位: tags');
  }

  if (doc['falsepositives'] === undefined) {
    logger.warn('Missing optional field: falsepositives / 缺少可選欄位: falsepositives');
  }

  if (doc['references'] === undefined) {
    logger.warn('Missing optional field: references / 缺少可選欄位: references');
  }

  // --- Build logsource / 建立日誌來源 ---

  const rawLogSource =
    typeof doc['logsource'] === 'object' && doc['logsource'] !== null
      ? (doc['logsource'] as Record<string, unknown>)
      : {};

  const logsource: SigmaLogSource = {};
  if (typeof rawLogSource['category'] === 'string') logsource.category = rawLogSource['category'];
  if (typeof rawLogSource['product'] === 'string') logsource.product = rawLogSource['product'];
  if (typeof rawLogSource['service'] === 'string') logsource.service = rawLogSource['service'];

  // --- Build detection / 建立偵測區塊 ---

  const detection: SigmaDetection = {
    condition: rawDetection['condition'] as string,
  };

  for (const [key, value] of Object.entries(rawDetection)) {
    if (key === 'condition') continue;

    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const selectionMap: Record<string, string | string[]> = {};
      for (const [fieldName, fieldValue] of Object.entries(value as Record<string, unknown>)) {
        if (typeof fieldValue === 'string') {
          selectionMap[fieldName] = fieldValue;
        } else if (Array.isArray(fieldValue)) {
          selectionMap[fieldName] = fieldValue.map(String);
        } else {
          selectionMap[fieldName] = String(fieldValue);
        }
      }
      detection[key] = selectionMap;
    }
  }

  // --- Normalize status / 標準化狀態 ---

  const statusStr =
    typeof doc['status'] === 'string' ? doc['status'].toLowerCase() : 'experimental';
  const status = VALID_STATUSES.has(statusStr)
    ? (statusStr as 'experimental' | 'test' | 'stable')
    : 'experimental';

  if (!VALID_STATUSES.has(typeof doc['status'] === 'string' ? doc['status'].toLowerCase() : '')) {
    logger.warn(
      `Invalid or missing status "${String(doc['status'])}", defaulting to "experimental" / 無效或缺少狀態，預設為 "experimental"`
    );
  }

  // --- Build tags and falsepositives arrays / 建立標籤和誤報陣列 ---

  const tags = Array.isArray(doc['tags']) ? doc['tags'].map(String) : undefined;
  const falsepositives = Array.isArray(doc['falsepositives'])
    ? doc['falsepositives'].map(String)
    : undefined;
  const references = Array.isArray(doc['references']) ? doc['references'].map(String) : undefined;

  const rule: SigmaRule = {
    id: typeof doc['id'] === 'string' ? doc['id'] : `auto-${Date.now()}`,
    title: doc['title'] as string,
    status,
    description: typeof doc['description'] === 'string' ? doc['description'] : '',
    logsource,
    detection,
    level: levelStr as Severity,
    ...(typeof doc['author'] === 'string' ? { author: doc['author'] } : {}),
    ...(doc['date'] !== undefined ? { date: String(doc['date']) } : {}),
    ...(tags !== undefined ? { tags } : {}),
    ...(falsepositives !== undefined ? { falsepositives } : {}),
    ...(references !== undefined ? { references } : {}),
  };

  logger.info(
    `Successfully parsed Sigma rule: "${rule.title}" (${rule.id}) / 成功解析 Sigma 規則: "${rule.title}" (${rule.id})`
  );
  return rule;
}

/**
 * Parse a Sigma rule from a YAML file on disk
 * 從磁碟上的 YAML 檔案解析 Sigma 規則
 *
 * Reads the file contents and delegates to parseSigmaYaml.
 * 讀取檔案內容並委派給 parseSigmaYaml。
 *
 * @param filePath - Absolute or relative path to the YAML file / YAML 檔案的絕對或相對路徑
 * @returns Parsed SigmaRule or null if file read or parsing fails / 解析後的 SigmaRule，讀取或解析失敗則回傳 null
 */
export function parseSigmaFile(filePath: string): SigmaRule | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const rule = parseSigmaYaml(content);
    if (rule === null) {
      logger.error(`Failed to parse Sigma file: ${filePath} / 解析 Sigma 檔案失敗: ${filePath}`);
    }
    return rule;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to read Sigma file: ${filePath} / 讀取 Sigma 檔案失敗: ${filePath}`, {
      error: message,
    });
    return null;
  }
}
