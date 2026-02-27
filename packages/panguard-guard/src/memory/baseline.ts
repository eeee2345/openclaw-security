/**
 * Baseline Memory - Environment behavior baseline management
 * 基線記憶 - 環境行為基線管理
 *
 * Tracks normal system behavior patterns and detects deviations.
 * 追蹤正常系統行為模式並偵測偏離。
 *
 * @module @panguard-ai/panguard-guard/memory/baseline
 */

import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent } from '@panguard-ai/core';
import type {
  EnvironmentBaseline,
  DeviationResult,
  ProcessPattern,
  ConnectionPattern,
  LoginPattern,
} from '../types.js';

const logger = createLogger('panguard-guard:baseline');

/**
 * Create an empty baseline / 建立空白基線
 */
export function createEmptyBaseline(): EnvironmentBaseline {
  return {
    normalProcesses: [],
    normalConnections: [],
    normalLoginPatterns: [],
    normalServicePorts: [],
    learningStarted: new Date().toISOString(),
    learningComplete: false,
    confidenceLevel: 0,
    lastUpdated: new Date().toISOString(),
    eventCount: 0,
  };
}

/**
 * Check if a security event deviates from the environment baseline
 * 檢查安全事件是否偏離環境基線
 *
 * @param baseline - The current environment baseline / 當前環境基線
 * @param event - The security event to check / 要檢查的安全事件
 * @returns DeviationResult indicating whether a deviation was found / 偏離結果
 */
export function checkDeviation(
  baseline: EnvironmentBaseline,
  event: SecurityEvent
): DeviationResult {
  // Check for new process / 檢查新程序
  if (event.source === 'process') {
    const processName = extractProcessName(event);
    if (processName) {
      const known = baseline.normalProcesses.some((p: ProcessPattern) => p.name === processName);
      if (!known) {
        return {
          isDeviation: true,
          deviationType: 'new_process',
          confidence: 70,
          description:
            `New process detected: ${processName} (not in baseline) / ` +
            `偵測到新程序: ${processName} (不在基線中)`,
        };
      }
    }
  }

  // Check for new network destination / 檢查新網路目的地
  if (event.source === 'network') {
    const remoteAddr = extractRemoteAddress(event);
    if (remoteAddr) {
      const known = baseline.normalConnections.some(
        (c: ConnectionPattern) => c.remoteAddress === remoteAddr
      );
      if (!known) {
        return {
          isDeviation: true,
          deviationType: 'new_network_dest',
          confidence: 65,
          description:
            `New network destination: ${remoteAddr} (not in baseline) / ` +
            `偵測到新網路目的地: ${remoteAddr} (不在基線中)`,
        };
      }
    }
  }

  // Check for new user login pattern / 檢查新使用者登入模式
  const username = extractUsername(event);
  if (username) {
    const known = baseline.normalLoginPatterns.some((l: LoginPattern) => l.username === username);
    if (!known) {
      return {
        isDeviation: true,
        deviationType: 'new_user',
        confidence: 60,
        description:
          `New user activity: ${username} (not in baseline) / ` +
          `偵測到新使用者活動: ${username} (不在基線中)`,
      };
    }
  }

  // No deviation / 無偏離
  return {
    isDeviation: false,
    deviationType: 'none',
    confidence: 0,
    description: 'Event within normal baseline parameters / 事件在正常基線參數範圍內',
  };
}

/**
 * Update the baseline with a new event (learning mode)
 * 使用新事件更新基線（學習模式）
 *
 * @param baseline - The current baseline to update / 要更新的當前基線
 * @param event - The security event to learn from / 要學習的安全事件
 * @returns Updated baseline / 更新後的基線
 */
export function updateBaseline(
  baseline: EnvironmentBaseline,
  event: SecurityEvent
): EnvironmentBaseline {
  const now = new Date().toISOString();
  const updated: EnvironmentBaseline = {
    ...baseline,
    lastUpdated: now,
    eventCount: baseline.eventCount + 1,
  };

  // Update process patterns / 更新程序模式
  if (event.source === 'process') {
    const processName = extractProcessName(event);
    if (processName) {
      updated.normalProcesses = updateProcessPatterns(
        [...baseline.normalProcesses],
        processName,
        (event.metadata?.['processPath'] as string) ?? undefined,
        now
      );
    }
  }

  // Update connection patterns / 更新連線模式
  if (event.source === 'network') {
    const remoteAddr = extractRemoteAddress(event);
    if (remoteAddr) {
      updated.normalConnections = updateConnectionPatterns(
        [...baseline.normalConnections],
        remoteAddr,
        (event.metadata?.['remotePort'] as number) ?? 0,
        (event.metadata?.['protocol'] as string) ?? 'tcp',
        now
      );
    }
  }

  // Update login patterns / 更新登入模式
  const username = extractUsername(event);
  if (username) {
    const eventDate = event.timestamp instanceof Date ? event.timestamp : new Date(event.timestamp);
    updated.normalLoginPatterns = updateLoginPatterns(
      [...baseline.normalLoginPatterns],
      username,
      (event.metadata?.['sourceIP'] as string) ?? undefined,
      eventDate.getHours(),
      eventDate.getDay(),
      now
    );
  }

  // Recalculate confidence / 重新計算信心度
  updated.confidenceLevel = calculateConfidence(updated);

  logger.info(
    `Baseline updated: ${event.source}/${event.category} ` +
      `(events: ${updated.eventCount}, confidence: ${(updated.confidenceLevel * 100).toFixed(1)}%) / ` +
      `基線已更新`
  );

  return updated;
}

// ---------------------------------------------------------------------------
// Internal helpers / 內部輔助函數
// ---------------------------------------------------------------------------

/** Extract process name from event metadata / 從事件 metadata 提取程序名稱 */
function extractProcessName(event: SecurityEvent): string | undefined {
  return (event.metadata?.['processName'] as string) ?? undefined;
}

/** Extract remote address from event metadata / 從事件 metadata 提取遠端地址 */
function extractRemoteAddress(event: SecurityEvent): string | undefined {
  return (
    (event.metadata?.['remoteAddress'] as string) ??
    (event.metadata?.['destinationIP'] as string) ??
    (event.metadata?.['sourceIP'] as string) ??
    undefined
  );
}

/** Extract username from event metadata / 從事件 metadata 提取使用者名稱 */
function extractUsername(event: SecurityEvent): string | undefined {
  return (
    (event.metadata?.['user'] as string) ?? (event.metadata?.['username'] as string) ?? undefined
  );
}

/** Update process patterns list / 更新程序模式列表 */
function updateProcessPatterns(
  patterns: ProcessPattern[],
  name: string,
  path: string | undefined,
  now: string
): ProcessPattern[] {
  const existing = patterns.find((p) => p.name === name);
  if (existing) {
    existing.frequency += 1;
    existing.lastSeen = now;
  } else {
    patterns.push({
      name,
      path,
      frequency: 1,
      firstSeen: now,
      lastSeen: now,
    });
  }
  return patterns;
}

/** Update connection patterns list / 更新連線模式列表 */
function updateConnectionPatterns(
  patterns: ConnectionPattern[],
  remoteAddress: string,
  remotePort: number,
  protocol: string,
  now: string
): ConnectionPattern[] {
  const existing = patterns.find(
    (c) => c.remoteAddress === remoteAddress && c.remotePort === remotePort
  );
  if (existing) {
    existing.frequency += 1;
    existing.lastSeen = now;
  } else {
    patterns.push({
      remoteAddress,
      remotePort,
      protocol,
      frequency: 1,
      firstSeen: now,
      lastSeen: now,
    });
  }
  return patterns;
}

/** Update login patterns list / 更新登入模式列表 */
function updateLoginPatterns(
  patterns: LoginPattern[],
  username: string,
  sourceIP: string | undefined,
  hourOfDay: number,
  dayOfWeek: number,
  now: string
): LoginPattern[] {
  const existing = patterns.find((l) => l.username === username);
  if (existing) {
    existing.frequency += 1;
    existing.lastSeen = now;
  } else {
    patterns.push({
      username,
      sourceIP,
      hourOfDay,
      dayOfWeek,
      frequency: 1,
      firstSeen: now,
      lastSeen: now,
    });
  }
  return patterns;
}

/**
 * Calculate baseline confidence based on data volume
 * 根據數據量計算基線信心度
 *
 * Confidence grows logarithmically with event count, capping at 0.95
 * 信心度隨事件數量對數增長，上限為 0.95
 */
function calculateConfidence(baseline: EnvironmentBaseline): number {
  const minEvents = 100;
  const targetEvents = 10000;

  if (baseline.eventCount < minEvents) {
    return (baseline.eventCount / minEvents) * 0.3;
  }

  const logProgress =
    Math.log(baseline.eventCount / minEvents) / Math.log(targetEvents / minEvents);
  return Math.min(0.95, 0.3 + logProgress * 0.65);
}
