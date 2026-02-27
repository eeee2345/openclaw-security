/**
 * Event classification prompt templates
 * 事件分類提示詞範本
 *
 * Generates prompts for classifying security events using
 * the MITRE ATT&CK framework. Supports bilingual output.
 * 產生使用 MITRE ATT&CK 框架分類安全事件的提示詞。支援雙語輸出。
 *
 * @module @panguard-ai/core/ai/prompts/event-classifier
 */

import type { Language, SecurityEvent } from '../../types.js';

/**
 * MITRE ATT&CK tactic categories for reference in prompts
 * MITRE ATT&CK 戰術分類（供提示詞參考）
 * @internal
 */
const MITRE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const;

/**
 * Generate an event classification prompt for the given security event
 * 為指定的安全事件產生事件分類提示詞
 *
 * The prompt instructs the LLM to classify the event according to
 * MITRE ATT&CK framework and return structured JSON output.
 * 提示詞指示 LLM 根據 MITRE ATT&CK 框架分類事件並回傳結構化 JSON 輸出。
 *
 * @param event - The security event to classify / 要分類的安全事件
 * @param lang - Output language / 輸出語言
 * @returns Formatted prompt string / 格式化的提示詞字串
 */
export function getEventClassifierPrompt(event: SecurityEvent, lang: Language): string {
  const eventData = JSON.stringify(
    {
      id: event.id,
      timestamp: event.timestamp instanceof Date ? event.timestamp.toISOString() : event.timestamp,
      source: event.source,
      severity: event.severity,
      category: event.category,
      description: event.description,
      host: event.host,
      metadata: event.metadata,
    },
    null,
    2
  );

  if (lang === 'zh-TW') {
    return `你是一位專業的資安分析師。請根據 MITRE ATT&CK 框架分析以下安全事件。

安全事件資料：
${eventData}

可用的 MITRE ATT&CK 戰術分類：
${MITRE_TACTICS.join(', ')}

請以 JSON 格式回應，包含以下欄位：
{
  "category": "MITRE ATT&CK 戰術分類（從上方清單中選擇）",
  "technique": "MITRE ATT&CK 技術 ID（例如 T1059、T1548）",
  "severity": "嚴重等級：info、low、medium、high 或 critical",
  "confidence": "信心分數，0 到 1 之間的數字",
  "description": "此分類的簡短說明"
}

只回傳 JSON，不要包含其他文字。`;
  }

  return `You are a professional cybersecurity analyst. Analyze the following security event according to the MITRE ATT&CK framework.

Security Event Data:
${eventData}

Available MITRE ATT&CK Tactic Categories:
${MITRE_TACTICS.join(', ')}

Respond in JSON format with the following fields:
{
  "category": "MITRE ATT&CK tactic category (choose from the list above)",
  "technique": "MITRE ATT&CK technique ID (e.g., T1059, T1548)",
  "severity": "severity level: info, low, medium, high, or critical",
  "confidence": "confidence score, a number between 0 and 1",
  "description": "brief explanation of this classification"
}

Return only JSON, no additional text.`;
}
