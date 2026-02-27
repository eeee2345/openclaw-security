/**
 * LLM response parsing utilities
 * LLM 回應解析工具
 *
 * Parses raw LLM text responses into structured data objects.
 * Supports JSON extraction from markdown code blocks and plain text fallback.
 * 將原始 LLM 文字回應解析為結構化資料物件。
 * 支援從 Markdown 程式碼區塊提取 JSON 以及純文字回退。
 *
 * @module @panguard-ai/core/ai/response-parser
 */

import type { Severity } from '../types.js';
import type { AnalysisResult, ThreatClassification } from './types.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('ai:response-parser');

/**
 * Valid severity values for validation
 * 用於驗證的有效嚴重等級值
 * @internal
 */
const VALID_SEVERITIES: ReadonlySet<string> = new Set([
  'info',
  'low',
  'medium',
  'high',
  'critical',
]);

/**
 * Attempt to extract a JSON object from a raw string
 * 嘗試從原始字串中提取 JSON 物件
 *
 * Tries in order: direct JSON.parse, markdown code block extraction, brace extraction.
 * 依序嘗試：直接 JSON.parse、Markdown 程式碼區塊提取、大括號提取。
 *
 * @param raw - Raw LLM response text / 原始 LLM 回應文字
 * @returns Parsed object or null if parsing fails / 解析的物件，或解析失敗時回傳 null
 * @internal
 */
function extractJson(raw: string): Record<string, unknown> | null {
  const trimmed = raw.trim();

  // Strategy 1: Direct JSON.parse
  // 策略 1：直接 JSON.parse
  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed;
    }
  } catch {
    // Not pure JSON, try next strategy
    // 非純 JSON，嘗試下一個策略
  }

  // Strategy 2: Extract from markdown code block (```json ... ``` or ``` ... ```)
  // 策略 2：從 Markdown 程式碼區塊提取
  const codeBlockMatch = trimmed.match(/```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/);
  if (codeBlockMatch?.[1]) {
    try {
      const parsed = JSON.parse(codeBlockMatch[1].trim()) as Record<string, unknown>;
      if (typeof parsed === 'object' && parsed !== null) {
        return parsed;
      }
    } catch {
      // Code block content is not valid JSON
      // 程式碼區塊內容非有效 JSON
    }
  }

  // Strategy 3: Find first { ... } block (greedy inner match)
  // 策略 3：尋找第一個 { ... } 區塊
  const braceStart = trimmed.indexOf('{');
  const braceEnd = trimmed.lastIndexOf('}');
  if (braceStart !== -1 && braceEnd > braceStart) {
    try {
      const jsonCandidate = trimmed.slice(braceStart, braceEnd + 1);
      const parsed = JSON.parse(jsonCandidate) as Record<string, unknown>;
      if (typeof parsed === 'object' && parsed !== null) {
        return parsed;
      }
    } catch {
      // Brace extraction failed
      // 大括號提取失敗
    }
  }

  return null;
}

/**
 * Validate and coerce a severity string
 * 驗證並強制轉換嚴重等級字串
 *
 * @param value - Raw severity value / 原始嚴重等級值
 * @returns Valid Severity or 'medium' as default / 有效嚴重等級或預設 'medium'
 * @internal
 */
function coerceSeverity(value: unknown): Severity {
  if (typeof value === 'string' && VALID_SEVERITIES.has(value.toLowerCase())) {
    return value.toLowerCase() as Severity;
  }
  return 'medium';
}

/**
 * Validate and coerce a confidence value
 * 驗證並強制轉換信心值
 *
 * @param value - Raw confidence value / 原始信心值
 * @returns Number between 0 and 1, default 0.5 / 0 到 1 之間的數字，預設 0.5
 * @internal
 */
function coerceConfidence(value: unknown): number {
  if (typeof value === 'number' && isFinite(value)) {
    return Math.max(0, Math.min(1, value));
  }
  if (typeof value === 'string') {
    const num = parseFloat(value);
    if (isFinite(num)) {
      return Math.max(0, Math.min(1, num));
    }
  }
  return 0.5;
}

/**
 * Parse a raw LLM response into an AnalysisResult
 * 將原始 LLM 回應解析為 AnalysisResult
 *
 * Attempts JSON parsing first, then falls back to treating the entire
 * response as a text summary.
 * 首先嘗試 JSON 解析，然後回退到將整個回應視為文字摘要。
 *
 * @param raw - Raw LLM response text / 原始 LLM 回應文字
 * @returns Parsed analysis result / 解析的分析結果
 */
export function parseAnalysisResponse(raw: string): AnalysisResult {
  const json = extractJson(raw);

  if (json) {
    logger.debug('Successfully parsed analysis response as JSON', {
      keys: Object.keys(json),
    });

    const recommendations = Array.isArray(json['recommendations'])
      ? (json['recommendations'] as unknown[]).map(String)
      : typeof json['recommendations'] === 'string'
        ? [json['recommendations'] as string]
        : [];

    return {
      summary: typeof json['summary'] === 'string' ? json['summary'] : raw.slice(0, 500),
      severity: coerceSeverity(json['severity']),
      confidence: coerceConfidence(json['confidence']),
      recommendations,
      rawResponse: raw,
    };
  }

  // Fallback: treat the entire response as a text summary
  // 回退：將整個回應視為文字摘要
  logger.debug('JSON parsing failed, using text fallback for analysis response');

  return {
    summary: raw.slice(0, 2000),
    severity: 'medium',
    confidence: 0.3,
    recommendations: [],
    rawResponse: raw,
  };
}

/**
 * Parse a raw LLM response into a ThreatClassification
 * 將原始 LLM 回應解析為 ThreatClassification
 *
 * Attempts JSON parsing first, then falls back to a generic classification.
 * 首先嘗試 JSON 解析，然後回退到通用分類。
 *
 * @param raw - Raw LLM response text / 原始 LLM 回應文字
 * @returns Parsed threat classification / 解析的威脅分類
 */
export function parseClassificationResponse(raw: string): ThreatClassification {
  const json = extractJson(raw);

  if (json) {
    logger.debug('Successfully parsed classification response as JSON', {
      keys: Object.keys(json),
    });

    return {
      category: typeof json['category'] === 'string' ? json['category'] : 'Unknown',
      technique: typeof json['technique'] === 'string' ? json['technique'] : 'T0000',
      severity: coerceSeverity(json['severity']),
      confidence: coerceConfidence(json['confidence']),
      description:
        typeof json['description'] === 'string' ? json['description'] : raw.slice(0, 500),
    };
  }

  // Fallback: generic unclassified threat
  // 回退：通用未分類威脅
  logger.debug('JSON parsing failed, using text fallback for classification response');

  return {
    category: 'Unknown',
    technique: 'T0000',
    severity: 'medium',
    confidence: 0.2,
    description: raw.slice(0, 500),
  };
}
