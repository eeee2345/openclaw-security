/**
 * LLM-based Investigation Planner
 * 基於 LLM 的調查規劃器
 *
 * Uses an LLM provider to dynamically choose which investigation tools
 * to run and in what order, replacing hardcoded if/else heuristics.
 * 使用 LLM 供應商動態選擇要執行哪些調查工具及其順序，
 * 取代硬編碼的 if/else 啟發式邏輯。
 *
 * @module @panguard-ai/panguard-guard/investigation/llm-planner
 */

import { createLogger } from '@panguard-ai/core';
import type { LLMProvider } from '@panguard-ai/core';
import type { SecurityEvent } from '@panguard-ai/core';
import type { InvestigationTool, InvestigationStep } from '../types.js';
import { INVESTIGATION_TOOL_DESCRIPTIONS } from './tool-descriptions.js';

const logger = createLogger('panguard-guard:llm-planner');

/** Maximum investigation steps / 最大調查步驟數 */
const MAX_STEPS = 8;

/** All valid tool names for validation / 所有有效工具名稱供驗證用 */
const VALID_TOOL_NAMES: ReadonlySet<string> = new Set<string>([
  'checkIPHistory',
  'checkUserPrivilege',
  'checkTimeAnomaly',
  'checkGeoLocation',
  'checkRelatedEvents',
  'checkProcessTree',
  'checkFileReputation',
  'checkNetworkPattern',
]);

/**
 * LLM Investigation Planner interface
 * LLM 調查規劃器介面
 */
export interface LLMInvestigationPlanner {
  /**
   * Plan investigation steps using LLM reasoning
   * 使用 LLM 推理規劃調查步驟
   *
   * @param event - Security event to investigate / 要調查的安全事件
   * @returns Ordered list of investigation steps / 有序的調查步驟列表
   */
  planInvestigation(event: SecurityEvent): Promise<InvestigationStep[]>;
}

/**
 * Build the system prompt for the LLM security analyst role
 * 建構 LLM 安全分析師角色的系統提示詞
 */
function buildSystemPrompt(): string {
  const toolList = INVESTIGATION_TOOL_DESCRIPTIONS.map(
    (t) => `- ${t.name}: ${t.description}`
  ).join('\n');

  return [
    'You are a senior security analyst AI. Your task is to plan an investigation for a security event.',
    '你是資深安全分析師 AI。你的任務是為安全事件規劃調查計畫。',
    '',
    'Available investigation tools:',
    '可用的調查工具：',
    toolList,
    '',
    'Instructions:',
    '指示：',
    `1. Analyze the security event and select the most relevant tools to investigate it (max ${MAX_STEPS} tools).`,
    '2. Order them by priority - most critical checks first.',
    '3. Explain why each tool is selected.',
    '4. Do NOT select tools that are irrelevant to the event type.',
    '',
    'Respond ONLY with a JSON array of objects, each with "tool" (string) and "reason" (string).',
    'Do not include any text outside the JSON array.',
    '',
    'Example response:',
    '[',
    '  {"tool": "checkTimeAnomaly", "reason": "Check if activity occurred at unusual hours"},',
    '  {"tool": "checkIPHistory", "reason": "Verify IP reputation against threat intel"}',
    ']',
  ].join('\n');
}

/**
 * Build the event context prompt for the LLM
 * 建構事件上下文提示詞
 */
function buildEventPrompt(event: SecurityEvent): string {
  const metadataStr = event.metadata
    ? JSON.stringify(event.metadata, null, 2)
    : '{}';

  return [
    'Security Event to investigate:',
    '要調查的安全事件：',
    '',
    `ID: ${event.id}`,
    `Timestamp: ${event.timestamp instanceof Date ? event.timestamp.toISOString() : String(event.timestamp)}`,
    `Source: ${event.source}`,
    `Severity: ${event.severity}`,
    `Category: ${event.category}`,
    `Description: ${event.description}`,
    `Host: ${event.host}`,
    `Metadata: ${metadataStr}`,
    '',
    `Select the investigation tools (max ${MAX_STEPS}) and respond with the JSON array only.`,
  ].join('\n');
}

/**
 * Parse the LLM response into investigation steps
 * 解析 LLM 回應為調查步驟
 *
 * Extracts a JSON array from the response, validates tool names,
 * and enforces the MAX_STEPS limit.
 * 從回應中提取 JSON 陣列，驗證工具名稱，並強制執行 MAX_STEPS 限制。
 *
 * @param raw - Raw LLM response text / 原始 LLM 回應文字
 * @returns Validated investigation steps / 已驗證的調查步驟
 */
export function parseLLMResponse(raw: string): InvestigationStep[] {
  // Try to extract JSON array from the response
  // 嘗試從回應中提取 JSON 陣列
  const trimmed = raw.trim();

  // Find the first '[' and last ']' to extract JSON array
  // 找到第一個 '[' 和最後一個 ']' 以提取 JSON 陣列
  const startIdx = trimmed.indexOf('[');
  const endIdx = trimmed.lastIndexOf(']');

  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
    logger.warn('LLM response does not contain a valid JSON array / LLM 回應不含有效 JSON 陣列');
    return [];
  }

  const jsonStr = trimmed.slice(startIdx, endIdx + 1);

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    logger.warn('Failed to parse LLM response as JSON / 解析 LLM 回應為 JSON 失敗');
    return [];
  }

  if (!Array.isArray(parsed)) {
    logger.warn('LLM response is not an array / LLM 回應不是陣列');
    return [];
  }

  // Validate and transform each step / 驗證並轉換每個步驟
  const steps: InvestigationStep[] = [];
  const seenTools = new Set<string>();

  for (const item of parsed) {
    if (steps.length >= MAX_STEPS) break;

    if (
      typeof item !== 'object' ||
      item === null ||
      typeof (item as Record<string, unknown>)['tool'] !== 'string'
    ) {
      continue;
    }

    const toolName = (item as Record<string, unknown>)['tool'] as string;
    const reason =
      typeof (item as Record<string, unknown>)['reason'] === 'string'
        ? ((item as Record<string, unknown>)['reason'] as string)
        : `LLM selected ${toolName}`;

    // Skip invalid or duplicate tool names / 跳過無效或重複的工具名稱
    if (!VALID_TOOL_NAMES.has(toolName)) {
      logger.warn(`LLM suggested unknown tool: ${toolName} / LLM 建議了未知工具`);
      continue;
    }

    if (seenTools.has(toolName)) {
      continue;
    }

    seenTools.add(toolName);
    steps.push({
      tool: toolName as InvestigationTool,
      reason,
    });
  }

  return steps;
}

/**
 * Create an LLM-based investigation planner
 * 建立基於 LLM 的調查規劃器
 *
 * The planner sends the security event context to the LLM along with
 * tool descriptions, then parses the LLM's tool selections into
 * an ordered investigation plan.
 * 規劃器將安全事件上下文連同工具描述發送至 LLM，
 * 然後將 LLM 的工具選擇解析為有序的調查計畫。
 *
 * @param llm - LLM provider instance / LLM 供應商實例
 * @returns LLM investigation planner / LLM 調查規劃器
 */
export function createLLMPlanner(llm: LLMProvider): LLMInvestigationPlanner {
  const systemPrompt = buildSystemPrompt();

  return {
    async planInvestigation(event: SecurityEvent): Promise<InvestigationStep[]> {
      logger.info(
        `Planning investigation with LLM (${llm.providerType}/${llm.model}) for event ${event.id} / ` +
          `使用 LLM 為事件 ${event.id} 規劃調查`
      );

      try {
        // Use the LLM analyze method with system prompt as context
        // 使用 LLM analyze 方法，以系統提示詞作為上下文
        const eventPrompt = buildEventPrompt(event);
        const result = await llm.analyze(eventPrompt, systemPrompt);

        // The raw response contains the LLM's tool selection JSON
        // 原始回應包含 LLM 的工具選擇 JSON
        // We try rawResponse first, then fall back to summary
        const responseText = result.rawResponse ?? result.summary;
        const steps = parseLLMResponse(responseText);

        if (steps.length === 0) {
          logger.warn(
            'LLM returned no valid investigation steps, will fallback to heuristic / ' +
              'LLM 未回傳有效的調查步驟，將回退至啟發式方法'
          );
          return [];
        }

        logger.info(
          `LLM planned ${steps.length} investigation step(s): ` +
            `${steps.map((s) => s.tool).join(', ')} / ` +
            `LLM 規劃了 ${steps.length} 個調查步驟`
        );

        return steps;
      } catch (error) {
        logger.error(
          `LLM planning failed: ${error instanceof Error ? error.message : String(error)} / ` +
            'LLM 規劃失敗，將回退至啟發式方法'
        );
        return [];
      }
    },
  };
}
