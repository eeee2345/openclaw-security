/**
 * Panguard AI - Manager Package
 * Panguard 安全平台 - Manager 套件
 *
 * Central orchestration node for the distributed Guard agent architecture.
 * Manages agent registration, threat correlation, and policy distribution.
 *
 * 分散式 Guard 代理架構的中央協調節點。
 * 管理代理登錄、威脅關聯和策略分發。
 *
 * @module @panguard-ai/manager
 */

// Main orchestrator / 主協調器
export { Manager } from './manager.js';

// Components / 元件
export { AgentRegistry } from './agent-registry.js';
export { ThreatAggregator } from './threat-aggregator.js';
export { PolicyEngine } from './policy-engine.js';

// Utilities / 工具函式
export {
  generateAgentId,
  generateThreatId,
  generatePolicyId,
  generateAuthToken,
  extractSourceIP,
  extractFileHash,
} from './utils.js';

// Types / 型別
export type {
  AgentStatus,
  AgentPlatformInfo,
  AgentRegistration,
  AgentRegistrationRequest,
  AgentHeartbeat,
  ThreatEvent,
  ThreatReport,
  AggregatedThreat,
  CorrelationMatch,
  ThreatSummary,
  PolicyRule,
  PolicyUpdate,
  ManagerConfig,
  AgentOverview,
  ManagerOverview,
  PolicyBroadcastResult,
} from './types.js';

// Constants / 常數
export { DEFAULT_MANAGER_CONFIG } from './types.js';

/** Manager package version / Manager 套件版本 */
export const MANAGER_VERSION = '0.2.0';
