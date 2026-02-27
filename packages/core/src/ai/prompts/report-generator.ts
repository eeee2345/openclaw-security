/**
 * Report generation prompt templates
 * 報告產生提示詞範本
 *
 * Generates prompts for summarizing multiple security events
 * into structured security reports.
 * 產生將多個安全事件摘要為結構化安全報告的提示詞。
 *
 * @module @panguard-ai/core/ai/prompts/report-generator
 */

import type { Language, SecurityEvent } from '../../types.js';

/**
 * Maximum number of events to include in the prompt to avoid token limits
 * 提示詞中包含的最大事件數量，以避免超出 Token 限制
 * @internal
 */
const MAX_EVENTS_IN_PROMPT = 50;

/**
 * Serialize a security event for inclusion in the prompt
 * 序列化安全事件以包含在提示詞中
 *
 * @param event - Security event to serialize / 要序列化的安全事件
 * @returns Compact string representation / 精簡的字串表示
 * @internal
 */
function serializeEvent(event: SecurityEvent): string {
  const ts =
    event.timestamp instanceof Date ? event.timestamp.toISOString() : String(event.timestamp);
  return `[${ts}] [${event.severity.toUpperCase()}] [${event.source}] ${event.host}: ${event.description}`;
}

/**
 * Generate a severity distribution summary
 * 產生嚴重等級分布摘要
 *
 * @param events - Array of security events / 安全事件陣列
 * @returns Distribution string / 分布字串
 * @internal
 */
function getSeverityDistribution(events: SecurityEvent[]): string {
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const event of events) {
    const key = event.severity.toLowerCase();
    if (key in counts) {
      counts[key] = (counts[key] ?? 0) + 1;
    }
  }
  return Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([level, count]) => `${level}: ${count}`)
    .join(', ');
}

/**
 * Generate a report summarization prompt for multiple security events
 * 為多個安全事件產生報告摘要提示詞
 *
 * If the number of events exceeds MAX_EVENTS_IN_PROMPT, only the most
 * severe events are included with a statistical summary of the rest.
 * 若事件數量超過 MAX_EVENTS_IN_PROMPT，僅包含最嚴重的事件，並附上其餘事件的統計摘要。
 *
 * @param events - Array of security events to summarize / 要摘要的安全事件陣列
 * @param lang - Output language / 輸出語言
 * @returns Formatted prompt string / 格式化的提示詞字串
 */
export function getReportPrompt(events: SecurityEvent[], lang: Language): string {
  const total = events.length;
  const distribution = getSeverityDistribution(events);

  // Sort by severity (critical first) and take top N
  // 按嚴重等級排序（critical 優先）並取前 N 個
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  const sorted = [...events].sort((a, b) => {
    const aOrder = severityOrder[a.severity] ?? 5;
    const bOrder = severityOrder[b.severity] ?? 5;
    return aOrder - bOrder;
  });

  const included = sorted.slice(0, MAX_EVENTS_IN_PROMPT);
  const eventLines = included.map(serializeEvent).join('\n');

  const truncationNote =
    total > MAX_EVENTS_IN_PROMPT
      ? lang === 'zh-TW'
        ? `\n(注意：共有 ${total} 個事件，以下僅顯示最嚴重的 ${MAX_EVENTS_IN_PROMPT} 個)\n`
        : `\n(Note: ${total} total events, showing the ${MAX_EVENTS_IN_PROMPT} most severe below)\n`
      : '';

  if (lang === 'zh-TW') {
    return `你是一位專業的資安報告撰寫者。請根據以下安全事件產生一份結構化的安全摘要報告。

事件統計：
- 總事件數量：${total}
- 嚴重等級分布：${distribution}
${truncationNote}
安全事件清單：
${eventLines}

請產生一份結構化的安全摘要報告，包含以下章節：

1. 總體概述：整體安全狀態的簡要描述
2. 關鍵發現：列出最重要的安全發現（最多 5 項）
3. 威脅趨勢：觀察到的威脅模式或趨勢
4. 建議措施：具體的改善建議（最多 5 項）
5. 風險評級：整體風險等級（低/中/高/極高）及理由

請使用繁體中文撰寫，語氣專業簡潔。直接回傳報告文字內容。`;
  }

  return `You are a professional cybersecurity report writer. Generate a structured security summary report based on the following security events.

Event Statistics:
- Total events: ${total}
- Severity distribution: ${distribution}
${truncationNote}
Security Events:
${eventLines}

Generate a structured security summary report with the following sections:

1. Executive Summary: Brief description of the overall security posture
2. Key Findings: List the most important security findings (up to 5)
3. Threat Trends: Observed threat patterns or trends
4. Recommendations: Specific improvement recommendations (up to 5)
5. Risk Rating: Overall risk level (Low/Medium/High/Critical) with justification

Write in a professional and concise tone. Return the report text directly.`;
}
