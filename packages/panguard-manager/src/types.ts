/**
 * Manager type definitions for distributed Guard agent orchestration
 * Manager 分散式 Guard 代理協調型別定義
 *
 * @module @panguard-ai/manager/types
 */

import type { SecurityEvent, Severity } from '@panguard-ai/core';

// ===== Agent Registration =====

/** Agent status in the registry / 代理在登錄簿中的狀態 */
export type AgentStatus = 'online' | 'offline' | 'stale';

/** Agent platform information / 代理平台資訊 */
export interface AgentPlatformInfo {
  readonly os: string;
  readonly arch: string;
  readonly ip?: string;
}

/** Agent registration record / 代理登錄紀錄 */
export interface AgentRegistration {
  readonly agentId: string;
  readonly hostname: string;
  readonly platform: AgentPlatformInfo;
  readonly version: string;
  readonly registeredAt: string;
  readonly lastHeartbeat: string;
  readonly status: AgentStatus;
}

/** Incoming registration request from a Guard agent / 來自 Guard 代理的登錄請求 */
export interface AgentRegistrationRequest {
  readonly hostname: string;
  readonly os: string;
  readonly arch: string;
  readonly version: string;
  readonly ip?: string;
}

// ===== Agent Heartbeat =====

/** Heartbeat data sent by a Guard agent / Guard 代理發送的心跳資料 */
export interface AgentHeartbeat {
  readonly agentId: string;
  readonly timestamp: string;
  readonly cpuUsage: number;
  readonly memUsage: number;
  readonly activeMonitors: number;
  readonly threatCount: number;
  readonly eventsProcessed: number;
  readonly mode: string;
  readonly uptime: number;
}

// ===== Threat Reporting =====

/** Threat event from a Guard agent / 來自 Guard 代理的威脅事件 */
export interface ThreatEvent {
  readonly event: SecurityEvent;
  readonly verdict: {
    readonly conclusion: 'benign' | 'suspicious' | 'malicious';
    readonly confidence: number;
    readonly action: string;
  };
}

/** Threat report containing one or more threat events / 包含一或多個威脅事件的威脅報告 */
export interface ThreatReport {
  readonly agentId: string;
  readonly threats: readonly ThreatEvent[];
  readonly reportedAt: string;
}

/** Aggregated threat with source attribution and optional correlation / 帶有來源歸屬和可選關聯的聚合威脅 */
export interface AggregatedThreat {
  readonly id: string;
  readonly originalThreat: ThreatEvent;
  readonly sourceAgentId: string;
  readonly sourceHostname: string;
  readonly receivedAt: string;
  readonly correlatedWith: readonly string[];
}

/** Correlation match indicating related threats / 表示相關威脅的關聯比對 */
export interface CorrelationMatch {
  readonly threatIdA: string;
  readonly threatIdB: string;
  readonly correlationType: 'same_source_ip' | 'same_malware_hash' | 'same_attack_pattern';
  readonly sharedIndicator: string;
}

/** Threat summary for dashboard / 儀表板用威脅摘要 */
export interface ThreatSummary {
  readonly totalThreats: number;
  readonly criticalCount: number;
  readonly highCount: number;
  readonly suspiciousCount: number;
  readonly uniqueAttackers: number;
  readonly affectedAgents: number;
  readonly correlatedGroups: number;
}

// ===== Policy Management =====

/** Policy rule definition / 策略規則定義 */
export interface PolicyRule {
  readonly ruleId: string;
  readonly type: 'block_ip' | 'alert_threshold' | 'auto_respond' | 'custom';
  readonly condition: Record<string, unknown>;
  readonly action: string;
  readonly severity: Severity;
  readonly description: string;
}

/** Policy update payload / 策略更新內容 */
export interface PolicyUpdate {
  readonly policyId: string;
  readonly version: number;
  readonly rules: readonly PolicyRule[];
  readonly updatedAt: string;
  readonly appliedTo: readonly string[];
}

// ===== Manager Configuration =====

/** Manager server configuration / Manager 伺服器配置 */
export interface ManagerConfig {
  readonly port: number;
  readonly authToken: string;
  readonly heartbeatIntervalMs: number;
  readonly heartbeatTimeoutMs: number;
  readonly maxAgents: number;
  readonly correlationWindowMs: number;
  readonly threatRetentionMs: number;
}

/** Default manager configuration / 預設 Manager 配置 */
export const DEFAULT_MANAGER_CONFIG: ManagerConfig = {
  port: 8443,
  authToken: '',
  heartbeatIntervalMs: 30_000,
  heartbeatTimeoutMs: 90_000,
  maxAgents: 500,
  correlationWindowMs: 300_000, // 5 minutes
  threatRetentionMs: 86_400_000, // 24 hours
};

// ===== Manager Overview =====

/** Agent summary for overview display / 代理概覽摘要 */
export interface AgentOverview {
  readonly agentId: string;
  readonly hostname: string;
  readonly status: AgentStatus;
  readonly lastHeartbeat: string;
  readonly threatCount: number;
}

/** Full manager overview for dashboard / 儀表板用完整 Manager 概覽 */
export interface ManagerOverview {
  readonly totalAgents: number;
  readonly onlineAgents: number;
  readonly staleAgents: number;
  readonly offlineAgents: number;
  readonly agents: readonly AgentOverview[];
  readonly threatSummary: ThreatSummary;
  readonly activePolicyVersion: number;
  readonly uptimeMs: number;
}

/** Policy broadcast result / 策略廣播結果 */
export interface PolicyBroadcastResult {
  readonly policyId: string;
  readonly targetAgents: readonly string[];
  readonly queuedAt: string;
}
