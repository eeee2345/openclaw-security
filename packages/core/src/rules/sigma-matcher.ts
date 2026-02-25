/**
 * Sigma rule event matcher
 * Sigma 規則事件比對器
 *
 * Matches SecurityEvent instances against Sigma rules by evaluating
 * detection selections and condition expressions.
 * Supports wildcards (*), the |contains modifier, and simple AND/OR/NOT logic.
 * 將 SecurityEvent 實例與 Sigma 規則比對，透過評估偵測選擇項和條件表達式。
 * 支援萬用字元（*）、|contains 修飾符，以及簡單的 AND/OR/NOT 邏輯。
 *
 * @module @openclaw/core/rules/sigma-matcher
 */

import { createLogger } from '../utils/logger.js';
import type { SecurityEvent } from '../types.js';
import type { SigmaRule, RuleMatch } from './types.js';

const logger = createLogger('sigma-matcher');

/**
 * Convert a Sigma wildcard pattern to a RegExp
 * 將 Sigma 萬用字元模式轉換為正規表達式
 *
 * Sigma uses `*` as a wildcard matching zero or more characters.
 * Sigma 使用 `*` 作為比對零個或多個字元的萬用字元。
 *
 * @param pattern - Sigma pattern string possibly containing `*` wildcards / 可能包含 `*` 萬用字元的 Sigma 模式字串
 * @returns Compiled RegExp for the pattern / 模式的編譯正規表達式
 */
function wildcardToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  const withWildcards = escaped.replace(/\*/g, '.*');
  return new RegExp(`^${withWildcards}$`, 'i');
}

/**
 * Retrieve a field value from a SecurityEvent by name
 * 依名稱從 SecurityEvent 取得欄位值
 *
 * Looks in the event's top-level properties first, then in metadata.
 * 先在事件的頂層屬性中查找，然後在 metadata 中查找。
 *
 * @param event - The security event / 安全事件
 * @param fieldName - Field name to look up / 要查找的欄位名稱
 * @returns The field value as a string, or undefined if not found / 欄位值的字串，找不到則回傳 undefined
 */
function getEventFieldValue(event: SecurityEvent, fieldName: string): string | undefined {
  // Check top-level event properties first / 先檢查事件頂層屬性
  const topLevelKeys: ReadonlyArray<keyof SecurityEvent> = [
    'id', 'source', 'severity', 'category', 'description', 'host',
  ];

  for (const key of topLevelKeys) {
    if (key === fieldName) {
      const val = event[key];
      if (typeof val === 'string') return val;
      if (val instanceof Date) return val.toISOString();
      return String(val);
    }
  }

  // Then check metadata / 然後檢查 metadata
  const metaValue = event.metadata[fieldName];
  if (metaValue === undefined || metaValue === null) return undefined;
  return String(metaValue);
}

/**
 * Parse a field name and extract the base name and modifier
 * 解析欄位名稱並擷取基礎名稱和修飾符
 *
 * Sigma field names can include modifiers like `|contains`, `|endswith`, `|startswith`.
 * Sigma 欄位名稱可包含修飾符如 `|contains`、`|endswith`、`|startswith`。
 *
 * @param fieldName - Full field name possibly with modifier / 可能帶有修飾符的完整欄位名稱
 * @returns Tuple of [baseName, modifier] / [基礎名稱, 修飾符] 的元組
 */
function parseFieldModifier(fieldName: string): [string, string | null] {
  const pipeIndex = fieldName.indexOf('|');
  if (pipeIndex === -1) return [fieldName, null];
  return [fieldName.substring(0, pipeIndex), fieldName.substring(pipeIndex + 1)];
}

/**
 * Check whether a single field value matches an expected value with modifier support
 * 檢查單一欄位值是否與預期值比對（支援修飾符）
 *
 * @param actual - The actual event field value / 事件的實際欄位值
 * @param expected - The expected value from the rule / 規則中的預期值
 * @param modifier - Optional modifier (contains, endswith, startswith) / 可選修飾符
 * @returns True if the value matches / 值比對時回傳 true
 */
function matchValue(actual: string, expected: string, modifier: string | null): boolean {
  const actualLower = actual.toLowerCase();
  const expectedLower = expected.toLowerCase();

  // Handle chained modifiers (e.g., "contains|all") — use first modifier
  const primaryModifier = modifier?.split('|')[0] ?? null;

  switch (primaryModifier) {
    case 'contains':
      return actualLower.includes(expectedLower);
    case 'endswith':
      return actualLower.endsWith(expectedLower);
    case 'startswith':
      return actualLower.startsWith(expectedLower);
    case 're':
      try {
        return new RegExp(expected, 'i').test(actual);
      } catch {
        logger.warn(`Invalid regex pattern: "${expected}" / 無效的正規表達式: "${expected}"`);
        return false;
      }
    case 'base64':
    case 'base64offset': {
      // Check if the actual value contains the expected value in base64 form
      try {
        const decoded = Buffer.from(actual, 'base64').toString('utf-8');
        return decoded.toLowerCase().includes(expectedLower);
      } catch {
        return false;
      }
    }
    case 'cidr': {
      // Basic CIDR matching for IP addresses
      return matchCIDR(actual, expected);
    }
    case 'gt':
      return Number(actual) > Number(expected);
    case 'gte':
      return Number(actual) >= Number(expected);
    case 'lt':
      return Number(actual) < Number(expected);
    case 'lte':
      return Number(actual) <= Number(expected);
    case 'utf8':
    case 'wide':
      // Encoding modifiers — perform basic string matching
      return actualLower.includes(expectedLower);
    default: {
      // Default: exact match or wildcard match / 預設：精確比對或萬用字元比對
      if (expected.includes('*')) {
        return wildcardToRegex(expected).test(actual);
      }
      return actualLower === expectedLower;
    }
  }
}

/**
 * Basic CIDR matching for IP addresses
 * 基本的 CIDR IP 位址比對
 */
function matchCIDR(ip: string, cidr: string): boolean {
  const parts = cidr.split('/');
  if (parts.length !== 2) return ip === cidr;

  const cidrIP = parts[0]!;
  const prefixLen = parseInt(parts[1]!, 10);
  if (isNaN(prefixLen)) return false;

  const ipNum = ipToNumber(ip);
  const cidrNum = ipToNumber(cidrIP);
  if (ipNum === null || cidrNum === null) return false;

  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  return (ipNum & mask) === (cidrNum & mask);
}

function ipToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    const val = parseInt(part, 10);
    if (isNaN(val) || val < 0 || val > 255) return null;
    num = (num << 8) | val;
  }
  return num >>> 0;
}

/**
 * Evaluate a single detection selection against an event
 * 評估單一偵測選擇項與事件的比對
 *
 * All fields in the selection must match (AND logic within a selection).
 * For array values, any value matching counts as a match (OR logic for arrays).
 * 選擇項中的所有欄位都必須比對（選擇項內為 AND 邏輯）。
 * 對於陣列值，任一值比對即算比對成功（陣列為 OR 邏輯）。
 *
 * @param event - The security event to test / 要測試的安全事件
 * @param selection - The selection fields and values / 選擇項欄位和值
 * @returns Object with match result and list of matched field names / 比對結果和比對到的欄位名稱列表
 */
function evaluateSelection(
  event: SecurityEvent,
  selection: Record<string, string | string[]>,
): { matched: boolean; fields: string[] } {
  const matchedFields: string[] = [];

  for (const [rawFieldName, expectedValues] of Object.entries(selection)) {
    const [baseName, modifier] = parseFieldModifier(rawFieldName);
    const actual = getEventFieldValue(event, baseName);

    if (actual === undefined) {
      return { matched: false, fields: [] };
    }

    const values = Array.isArray(expectedValues) ? expectedValues : [expectedValues];
    const fieldMatched = values.some((expected) => matchValue(actual, expected, modifier));

    if (!fieldMatched) {
      return { matched: false, fields: [] };
    }

    matchedFields.push(baseName);
  }

  return { matched: true, fields: matchedFields };
}

/**
 * Tokenize a condition expression into tokens
 * 將條件表達式分詞為 token
 *
 * Splits the condition string into identifiers, operators (AND, OR, NOT),
 * and parentheses.
 * 將條件字串拆分為識別碼、運算子（AND、OR、NOT）和括號。
 *
 * @param condition - The condition string / 條件字串
 * @returns Array of token strings / token 字串陣列
 */
function tokenize(condition: string): string[] {
  const tokens: string[] = [];
  let current = '';

  for (let i = 0; i < condition.length; i++) {
    const ch = condition[i]!;
    if (ch === '(' || ch === ')') {
      if (current.trim()) tokens.push(current.trim());
      tokens.push(ch);
      current = '';
    } else if (ch === ' ' || ch === '\t') {
      if (current.trim()) tokens.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) tokens.push(current.trim());

  return tokens;
}

/**
 * Resolve aggregation expressions like "1 of them", "all of them", "1 of selection*"
 * 解析聚合表達式如 "1 of them"、"all of them"、"1 of selection*"
 *
 * Pre-processes the condition string to expand these into explicit OR/AND expressions.
 *
 * @param condition - The condition string / 條件字串
 * @param selectionNames - Available selection names / 可用的選擇項名稱
 * @returns Expanded condition string / 展開的條件字串
 */
function expandAggregations(condition: string, selectionNames: string[]): string {
  let result = condition;

  // "all of them" → (sel1 AND sel2 AND ...)
  result = result.replace(/\ball\s+of\s+them\b/gi, () => {
    if (selectionNames.length === 0) return 'false';
    return '(' + selectionNames.join(' AND ') + ')';
  });

  // "1 of them" → (sel1 OR sel2 OR ...)
  result = result.replace(/\b1\s+of\s+them\b/gi, () => {
    if (selectionNames.length === 0) return 'false';
    return '(' + selectionNames.join(' OR ') + ')';
  });

  // "<N> of them" → at least N selections match (expand as OR of AND combos is complex,
  // so we treat as "1 of them" for simplicity — covers most real-world rules)
  result = result.replace(/\b\d+\s+of\s+them\b/gi, () => {
    if (selectionNames.length === 0) return 'false';
    return '(' + selectionNames.join(' OR ') + ')';
  });

  // "all of <pattern>*" → AND of matching selections
  result = result.replace(/\ball\s+of\s+(\w+)\*/gi, (_match, prefix: string) => {
    const matching = selectionNames.filter(n => n.startsWith(prefix));
    if (matching.length === 0) return 'false';
    return '(' + matching.join(' AND ') + ')';
  });

  // "1 of <pattern>*" → OR of matching selections
  result = result.replace(/\b1\s+of\s+(\w+)\*/gi, (_match, prefix: string) => {
    const matching = selectionNames.filter(n => n.startsWith(prefix));
    if (matching.length === 0) return 'false';
    return '(' + matching.join(' OR ') + ')';
  });

  return result;
}

/**
 * Evaluate a condition expression given selection results
 * 根據選擇項結果評估條件表達式
 *
 * Supports AND/OR/NOT with parentheses, plus Sigma aggregation expressions:
 * "1 of them", "all of them", "1 of selection*", "all of filter*"
 * 支援 AND/OR/NOT 搭配括號，以及 Sigma 聚合表達式。
 *
 * @param condition - The condition expression / 條件表達式
 * @param selectionResults - Map of selection name to match result / 選擇項名稱到比對結果的映射
 * @returns True if the condition is satisfied / 條件滿足時回傳 true
 */
function evaluateCondition(
  condition: string,
  selectionResults: Map<string, boolean>,
): boolean {
  // Expand aggregation expressions / 展開聚合表達式
  const selectionNames = Array.from(selectionResults.keys());
  const expanded = expandAggregations(condition, selectionNames);

  const tokens = tokenize(expanded);

  // Simple case: single selection name / 簡單情況：單一選擇項名稱
  if (tokens.length === 1) {
    const name = tokens[0]!;
    if (name === 'false') return false;
    if (name === 'true') return true;
    return selectionResults.get(name) ?? false;
  }

  // Recursive descent parser for AND/OR/NOT with parentheses
  // 遞迴下降解析器，處理 AND/OR/NOT 和括號
  let pos = 0;

  function peek(): string | undefined {
    return tokens[pos];
  }

  function consume(): string {
    const tok = tokens[pos]!;
    pos++;
    return tok;
  }

  /**
   * Parse primary: NOT, parenthesized expression, or selection name
   * 解析主要項：NOT、括號表達式或選擇項名稱
   */
  function parsePrimary(): boolean {
    const tok = peek();

    if (tok === undefined) return false;

    if (tok.toUpperCase() === 'NOT') {
      consume();
      return !parsePrimary();
    }

    if (tok === '(') {
      consume(); // consume '('
      const result = parseOr();
      if (peek() === ')') consume(); // consume ')'
      return result;
    }

    // It is a selection name / 是選擇項名稱
    consume();
    if (tok === 'false') return false;
    if (tok === 'true') return true;
    return selectionResults.get(tok) ?? false;
  }

  /**
   * Parse AND expressions / 解析 AND 表達式
   */
  function parseAnd(): boolean {
    let result = parsePrimary();
    while (peek()?.toUpperCase() === 'AND') {
      consume();
      const right = parsePrimary();
      result = result && right;
    }
    return result;
  }

  /**
   * Parse OR expressions (lowest precedence) / 解析 OR 表達式（最低優先權）
   */
  function parseOr(): boolean {
    let result = parseAnd();
    while (peek()?.toUpperCase() === 'OR') {
      consume();
      const right = parseAnd();
      result = result || right;
    }
    return result;
  }

  return parseOr();
}

/**
 * Match a single security event against a single Sigma rule
 * 比對單一安全事件與單一 Sigma 規則
 *
 * Evaluates all selections in the rule's detection block, then checks
 * whether the condition expression is satisfied.
 * 評估規則偵測區塊中的所有選擇項，然後檢查條件表達式是否滿足。
 *
 * @param event - The security event to test / 要測試的安全事件
 * @param rule - The Sigma rule to match against / 要比對的 Sigma 規則
 * @returns A RuleMatch if the event matches, or null / 事件比對時回傳 RuleMatch，否則回傳 null
 */
export function matchEvent(event: SecurityEvent, rule: SigmaRule): RuleMatch | null {
  const detection = rule.detection;
  const selectionResults = new Map<string, boolean>();
  const allMatchedFields: string[] = [];

  // Evaluate each selection in the detection block / 評估偵測區塊中的每個選擇項
  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;
    if (typeof value === 'string') continue; // skip condition-like entries / 跳過條件類條目

    const result = evaluateSelection(event, value as Record<string, string | string[]>);
    selectionResults.set(key, result.matched);
    if (result.matched) {
      allMatchedFields.push(...result.fields);
    }
  }

  // Evaluate the condition expression / 評估條件表達式
  const conditionMet = evaluateCondition(detection.condition, selectionResults);

  if (!conditionMet) {
    return null;
  }

  // Deduplicate matched fields / 去重比對到的欄位
  const uniqueFields = [...new Set(allMatchedFields)];

  const match: RuleMatch = {
    rule,
    event,
    matchedFields: uniqueFields,
    timestamp: new Date().toISOString(),
  };

  logger.info(
    `Event matched rule "${rule.title}" (${rule.id}) / 事件比對到規則 "${rule.title}" (${rule.id})`,
    { eventId: event.id, matchedFields: uniqueFields },
  );

  return match;
}

/**
 * Match a single security event against multiple Sigma rules
 * 比對單一安全事件與多個 Sigma 規則
 *
 * Tests the event against every rule and returns all matches.
 * 將事件與每個規則測試並回傳所有比對結果。
 *
 * @param event - The security event to test / 要測試的安全事件
 * @param rules - Array of Sigma rules to match against / 要比對的 Sigma 規則陣列
 * @returns Array of RuleMatch for all matching rules / 所有比對規則的 RuleMatch 陣列
 */
export function matchEventAgainstRules(event: SecurityEvent, rules: SigmaRule[]): RuleMatch[] {
  const matches: RuleMatch[] = [];

  for (const rule of rules) {
    const result = matchEvent(event, rule);
    if (result !== null) {
      matches.push(result);
    }
  }

  return matches;
}
