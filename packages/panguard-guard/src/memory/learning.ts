/**
 * Learning period management for Context Memory
 * Context Memory 的學習期管理
 * @module @panguard-ai/panguard-guard/memory/learning
 */

import { createLogger } from '@panguard-ai/core';
import type { EnvironmentBaseline } from '../types.js';

const logger = createLogger('panguard-guard:learning');

/**
 * Check if the learning period has completed / 檢查學習期是否已完成
 */
export function isLearningComplete(baseline: EnvironmentBaseline, learningDays: number): boolean {
  if (baseline.learningComplete) return true;
  const startTime = new Date(baseline.learningStarted).getTime();
  const elapsedDays = (Date.now() - startTime) / (1000 * 60 * 60 * 24);
  return elapsedDays >= learningDays;
}

/**
 * Get learning progress as a percentage (0-100) / 取得學習進度百分比
 */
export function getLearningProgress(baseline: EnvironmentBaseline, learningDays: number): number {
  if (baseline.learningComplete) return 100;
  const startTime = new Date(baseline.learningStarted).getTime();
  const elapsedDays = (Date.now() - startTime) / (1000 * 60 * 60 * 24);
  return Math.round(Math.min((elapsedDays / learningDays) * 100, 100));
}

/**
 * Get remaining learning days / 取得剩餘學習天數
 */
export function getRemainingDays(baseline: EnvironmentBaseline, learningDays: number): number {
  if (baseline.learningComplete) return 0;
  const startTime = new Date(baseline.learningStarted).getTime();
  const elapsedDays = (Date.now() - startTime) / (1000 * 60 * 60 * 24);
  return Math.ceil(Math.max(learningDays - elapsedDays, 0));
}

/**
 * Switch baseline to protection mode / 將基線切換到防護模式
 */
export function switchToProtectionMode(baseline: EnvironmentBaseline): EnvironmentBaseline {
  logger.info(
    `Switching to protection mode. Processes: ${baseline.normalProcesses.length}, ` +
      `Connections: ${baseline.normalConnections.length}, Login patterns: ${baseline.normalLoginPatterns.length} / 切換至防護模式`
  );
  return { ...baseline, learningComplete: true, lastUpdated: new Date().toISOString() };
}

/**
 * Get baseline summary for display / 取得基線摘要
 */
export function getBaselineSummary(baseline: EnvironmentBaseline): {
  processCount: number;
  connectionCount: number;
  loginPatternCount: number;
  portCount: number;
  eventCount: number;
  confidenceLevel: number;
  learningComplete: boolean;
} {
  return {
    processCount: baseline.normalProcesses.length,
    connectionCount: baseline.normalConnections.length,
    loginPatternCount: baseline.normalLoginPatterns.length,
    portCount: baseline.normalServicePorts.length,
    eventCount: baseline.eventCount,
    confidenceLevel: baseline.confidenceLevel,
    learningComplete: baseline.learningComplete,
  };
}
