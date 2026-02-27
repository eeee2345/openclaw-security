/**
 * Threat analysis prompt templates
 * 威脅分析提示詞範本
 *
 * Generates prompts for AI-powered security threat analysis.
 * Supports bilingual output (English and Traditional Chinese).
 * 產生 AI 驅動的安全威脅分析提示詞。支援雙語輸出（英文和繁體中文）。
 *
 * @module @panguard-ai/core/ai/prompts/threat-analyzer
 */

import type { Language } from '../../types.js';

/**
 * Generate a threat analysis prompt
 * 產生威脅分析提示詞
 *
 * Creates a prompt that instructs the LLM to analyze a security threat
 * and return structured JSON with summary, severity, confidence, and recommendations.
 * 建立一個提示詞，指示 LLM 分析安全威脅並回傳包含摘要、嚴重等級、信心分數和建議的結構化 JSON。
 *
 * @param prompt - The primary analysis prompt or question / 主要分析提示詞或問題
 * @param context - Optional additional context (logs, environment info) / 可選的額外上下文（日誌、環境資訊）
 * @param lang - Output language / 輸出語言
 * @returns Formatted prompt string / 格式化的提示詞字串
 */
export function getThreatAnalysisPrompt(
  prompt: string,
  context: string | undefined,
  lang: Language
): string {
  const contextSection = context
    ? lang === 'zh-TW'
      ? `\n額外上下文資訊：\n${context}\n`
      : `\nAdditional Context:\n${context}\n`
    : '';

  if (lang === 'zh-TW') {
    return `你是一位專業的資安威脅分析師。請分析以下安全相關資訊並提供專業評估。

分析需求：
${prompt}
${contextSection}
請以 JSON 格式回應，包含以下欄位：
{
  "summary": "威脅分析摘要，清楚描述發現的問題和潛在影響",
  "severity": "嚴重等級：info、low、medium、high 或 critical",
  "confidence": "信心分數，0 到 1 之間的數字",
  "recommendations": ["建議措施 1", "建議措施 2", "建議措施 3"]
}

評估標準：
- info：一般資訊性事件，無安全疑慮
- low：輕微安全疑慮，可列入觀察
- medium：中等威脅，建議進一步調查
- high：嚴重威脅，需要立即處理
- critical：極度嚴重，系統可能已遭入侵

只回傳 JSON，不要包含其他文字。`;
  }

  return `You are a professional cybersecurity threat analyst. Analyze the following security information and provide a professional assessment.

Analysis Request:
${prompt}
${contextSection}
Respond in JSON format with the following fields:
{
  "summary": "threat analysis summary, clearly describing findings and potential impact",
  "severity": "severity level: info, low, medium, high, or critical",
  "confidence": "confidence score, a number between 0 and 1",
  "recommendations": ["recommendation 1", "recommendation 2", "recommendation 3"]
}

Assessment Criteria:
- info: General informational event, no security concern
- low: Minor security concern, can be monitored
- medium: Moderate threat, further investigation recommended
- high: Serious threat, immediate action required
- critical: Extremely severe, system may already be compromised

Return only JSON, no additional text.`;
}
