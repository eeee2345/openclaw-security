/**
 * Manager - Central orchestrator for distributed Guard agent architecture
 * Manager - 分散式 Guard 代理架構的中央協調器
 *
 * Coordinates multiple Guard agents across endpoints:
 * - Agent registration and lifecycle management
 * - Heartbeat monitoring with stale agent detection
 * - Threat ingestion and cross-agent correlation
 * - Centralized policy creation and distribution
 *
 * @module @panguard-ai/manager/manager
 */

import { createLogger } from '@panguard-ai/core';
import { AgentRegistry } from './agent-registry.js';
import { ThreatAggregator } from './threat-aggregator.js';
import { PolicyEngine } from './policy-engine.js';
import type {
  ManagerConfig,
  AgentRegistrationRequest,
  AgentRegistration,
  AgentHeartbeat,
  ThreatReport,
  AggregatedThreat,
  PolicyUpdate,
  PolicyRule,
  ManagerOverview,
  AgentOverview,
  ThreatSummary,
  PolicyBroadcastResult,
} from './types.js';

const logger = createLogger('panguard-manager:core');

/**
 * Manager is the main orchestrator for the distributed Guard architecture.
 *
 * It composes AgentRegistry, ThreatAggregator, and PolicyEngine to provide
 * a unified API for managing the entire fleet of Guard agents.
 */
export class Manager {
  private readonly config: ManagerConfig;
  private readonly registry: AgentRegistry;
  private readonly aggregator: ThreatAggregator;
  private readonly policyEngine: PolicyEngine;

  private running: boolean;
  private startTime: number;
  private staleCheckTimer: ReturnType<typeof setInterval> | null;
  private purgeTimer: ReturnType<typeof setInterval> | null;

  // Policy broadcast queue / 策略廣播佇列
  private readonly broadcastQueue: PolicyBroadcastResult[];

  constructor(config: ManagerConfig) {
    this.config = config;
    this.registry = new AgentRegistry(config.maxAgents);
    this.aggregator = new ThreatAggregator(
      config.correlationWindowMs,
      config.threatRetentionMs
    );
    this.policyEngine = new PolicyEngine();

    this.running = false;
    this.startTime = 0;
    this.staleCheckTimer = null;
    this.purgeTimer = null;
    this.broadcastQueue = [];

    logger.info(
      `Manager initialized (maxAgents: ${config.maxAgents}, ` +
        `heartbeatTimeout: ${config.heartbeatTimeoutMs}ms) / ` +
        `Manager 已初始化`
    );
  }

  /**
   * Start the Manager service.
   * Begins periodic stale agent checking and threat purging.
   */
  start(): void {
    if (this.running) {
      logger.warn('Manager already running / Manager 已在執行中');
      return;
    }

    this.running = true;
    this.startTime = Date.now();

    // Periodic stale agent check / 定期檢查過期代理
    this.staleCheckTimer = setInterval(() => {
      this.checkStaleAgents();
    }, this.config.heartbeatIntervalMs);

    // Periodic threat data purge / 定期清除威脅資料
    const purgeIntervalMs = Math.min(
      this.config.threatRetentionMs / 4,
      3_600_000 // max 1 hour
    );
    this.purgeTimer = setInterval(() => {
      this.aggregator.purgeExpired();
    }, purgeIntervalMs);

    logger.info(
      `Manager started on port ${this.config.port} / ` +
        `Manager 已啟動於埠 ${this.config.port}`
    );
  }

  /**
   * Stop the Manager service.
   * Clears all periodic timers.
   */
  stop(): void {
    if (!this.running) return;

    if (this.staleCheckTimer) {
      clearInterval(this.staleCheckTimer);
      this.staleCheckTimer = null;
    }

    if (this.purgeTimer) {
      clearInterval(this.purgeTimer);
      this.purgeTimer = null;
    }

    this.running = false;

    logger.info(
      `Manager stopped (uptime: ${Date.now() - this.startTime}ms) / Manager 已停止`
    );
  }

  // ===== Agent Lifecycle / 代理生命週期 =====

  /**
   * Handle a new agent registration request.
   *
   * @param request - Registration data from the Guard agent
   * @returns Immutable copy of the registration record
   * @throws Error if max agents exceeded
   */
  handleRegistration(
    request: AgentRegistrationRequest
  ): AgentRegistration {
    const registration = this.registry.registerAgent(request);

    logger.info(
      `Agent joined: ${registration.agentId} from ${registration.hostname} / ` +
        `代理已加入: ${registration.agentId} 來自 ${registration.hostname}`
    );

    return registration;
  }

  /**
   * Handle a heartbeat from a Guard agent.
   * Updates the agent's status and last-seen timestamp.
   *
   * @param heartbeat - Heartbeat data from the agent
   * @returns Updated registration, or undefined if agent unknown
   */
  handleHeartbeat(
    heartbeat: AgentHeartbeat
  ): AgentRegistration | undefined {
    return this.registry.updateHeartbeat(heartbeat);
  }

  /**
   * Handle a threat report from a Guard agent.
   * Ingests threats into the aggregator and checks for cross-agent correlation.
   *
   * @param report - Threat report containing one or more events
   * @returns Array of aggregated threats, with correlation data if detected
   */
  handleThreatReport(
    report: ThreatReport
  ): readonly AggregatedThreat[] {
    const agent = this.registry.getAgent(report.agentId);
    const hostname = agent?.hostname ?? 'unknown';

    const aggregated = this.aggregator.ingestReport(report, hostname);

    // Log correlation detections
    const correlated = aggregated.filter(
      (t) => t.correlatedWith.length > 0
    );
    if (correlated.length > 0) {
      logger.warn(
        `ALERT: ${correlated.length} cross-agent correlations detected from ${hostname} / ` +
          `警報: 從 ${hostname} 偵測到 ${correlated.length} 個跨代理關聯`
      );
    }

    return aggregated;
  }

  /**
   * Remove an agent from the fleet.
   *
   * @param agentId - The agent's unique identifier
   * @returns true if the agent was found and removed
   */
  handleDeregistration(agentId: string): boolean {
    return this.registry.deregisterAgent(agentId);
  }

  // ===== Policy Management / 策略管理 =====

  /**
   * Create and optionally broadcast a new security policy.
   *
   * @param rules - Policy rules to include
   * @param broadcast - Whether to queue broadcast to all active agents
   * @returns The created policy
   */
  createPolicy(
    rules: readonly PolicyRule[],
    broadcast = true
  ): PolicyUpdate {
    const activeAgentIds = this.registry
      .getActiveAgents()
      .map((a) => a.agentId);

    const policy = this.policyEngine.createPolicy(rules, activeAgentIds);

    if (broadcast) {
      this.broadcastPolicy(policy);
    }

    return policy;
  }

  /**
   * Queue a policy update for broadcast to all active agents.
   *
   * @param policy - The policy to broadcast
   * @returns Broadcast result with target agent list
   */
  broadcastPolicy(policy: PolicyUpdate): PolicyBroadcastResult {
    const activeAgents = this.registry.getActiveAgents();
    const targetIds = activeAgents.map((a) => a.agentId);

    const result: PolicyBroadcastResult = {
      policyId: policy.policyId,
      targetAgents: [...targetIds],
      queuedAt: new Date().toISOString(),
    };

    this.broadcastQueue.push(result);

    logger.info(
      `Policy ${policy.policyId} queued for broadcast to ${targetIds.length} agents / ` +
        `策略 ${policy.policyId} 已排入佇列廣播至 ${targetIds.length} 個代理`
    );

    return {
      ...result,
      targetAgents: [...result.targetAgents],
    };
  }

  /**
   * Get the active global policy.
   *
   * @returns Active policy or null
   */
  getActivePolicy(): PolicyUpdate | null {
    return this.policyEngine.getActivePolicy();
  }

  /**
   * Get the policy applicable to a specific agent.
   *
   * @param agentId - The agent's unique identifier
   * @returns Policy for the agent, or null
   */
  getPolicyForAgent(agentId: string): PolicyUpdate | null {
    return this.policyEngine.getPolicyForAgent(agentId);
  }

  /**
   * Get pending policy broadcast results.
   *
   * @returns Immutable array of broadcast results
   */
  getPendingBroadcasts(): readonly PolicyBroadcastResult[] {
    return this.broadcastQueue.map((r) => ({
      ...r,
      targetAgents: [...r.targetAgents],
    }));
  }

  // ===== Monitoring / 監控 =====

  /**
   * Check for and handle stale agents.
   * Called periodically by the stale check timer.
   */
  private checkStaleAgents(): void {
    const stale = this.registry.getStaleAgents(
      this.config.heartbeatTimeoutMs
    );

    if (stale.length > 0) {
      logger.warn(
        `${stale.length} stale agent(s) detected / ` +
          `偵測到 ${stale.length} 個過期代理`
      );
    }
  }

  // ===== Dashboard / 儀表板 =====

  /**
   * Generate a comprehensive overview for the management dashboard.
   *
   * @returns Immutable manager overview object
   */
  getOverview(): ManagerOverview {
    const allAgents = this.registry.getAllAgents();
    const statusCounts = this.registry.getStatusCounts();
    const threatSummary = this.aggregator.getSummary();
    const policyVersion = this.policyEngine.getCurrentVersion();

    const agentOverviews: AgentOverview[] = allAgents.map((a) => {
      const agentThreats = this.aggregator.getThreatsByAgent(a.agentId);
      return {
        agentId: a.agentId,
        hostname: a.hostname,
        status: a.status,
        lastHeartbeat: a.lastHeartbeat,
        threatCount: agentThreats.length,
      };
    });

    return {
      totalAgents: allAgents.length,
      onlineAgents: statusCounts.online,
      staleAgents: statusCounts.stale,
      offlineAgents: statusCounts.offline,
      agents: agentOverviews,
      threatSummary,
      activePolicyVersion: policyVersion,
      uptimeMs: this.running ? Date.now() - this.startTime : 0,
    };
  }

  /**
   * Get threat summary from the aggregator.
   *
   * @returns Immutable threat summary
   */
  getThreatSummary(): ThreatSummary {
    return this.aggregator.getSummary();
  }

  /**
   * Get threats reported by a specific agent.
   *
   * @param agentId - The agent's unique identifier
   * @returns Array of aggregated threats
   */
  getThreatsByAgent(
    agentId: string
  ): readonly AggregatedThreat[] {
    return this.aggregator.getThreatsByAgent(agentId);
  }

  /**
   * Get recent threats across all agents.
   *
   * @param since - Date threshold
   * @returns Array of aggregated threats
   */
  getRecentThreats(since: Date): readonly AggregatedThreat[] {
    return this.aggregator.getRecentThreats(since);
  }

  /**
   * Get a specific agent's registration.
   *
   * @param agentId - The agent's unique identifier
   * @returns Agent registration or undefined
   */
  getAgent(agentId: string): AgentRegistration | undefined {
    return this.registry.getAgent(agentId);
  }

  /**
   * Check if the manager is currently running.
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Get the number of registered agents.
   */
  getAgentCount(): number {
    return this.registry.size;
  }
}
