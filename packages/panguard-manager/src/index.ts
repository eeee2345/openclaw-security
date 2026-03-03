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

// HTTP Server / HTTP 伺服器
export { ManagerServer } from './server.js';

// Components / 元件
export { AgentRegistry } from './agent-registry.js';
export { ThreatAggregator } from './threat-aggregator.js';
export { PolicyEngine } from './policy-engine.js';
export { DashboardRelay } from './dashboard-relay.js';
export type { DashboardRelayConfig } from './dashboard-relay.js';

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
  AgentPushResult,
  PolicyBroadcastResult,
} from './types.js';

// Constants / 常數
export { DEFAULT_MANAGER_CONFIG } from './types.js';

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _pkg = _require('../package.json') as { version: string };

/** Manager package version / Manager 套件版本 */
export const MANAGER_VERSION: string = _pkg.version;
