/**
 * AgentRegistry - Manages connected Guard agent registrations
 * AgentRegistry - 管理已連線的 Guard 代理登錄
 *
 * Maintains an internal Map of registered agents, supports heartbeat updates,
 * and detects stale/offline agents. All returned data is immutable copies.
 *
 * @module @panguard-ai/manager/agent-registry
 */

import { createLogger } from '@panguard-ai/core';
import { generateAgentId } from './utils.js';
import type {
  AgentRegistration,
  AgentRegistrationRequest,
  AgentHeartbeat,
  AgentStatus,
} from './types.js';

const logger = createLogger('panguard-manager:registry');

/**
 * Registry that tracks all connected Guard agents.
 * Uses immutable return patterns - internal state is never exposed directly.
 */
export class AgentRegistry {
  private readonly agents: Map<string, AgentRegistration>;
  private readonly maxAgents: number;

  constructor(maxAgents: number) {
    this.agents = new Map();
    this.maxAgents = maxAgents;
  }

  /**
   * Register a new Guard agent.
   * Generates a unique agent ID and returns the registration record.
   *
   * @param request - Registration request from the agent
   * @returns Immutable copy of the registration record
   * @throws Error if maximum agent limit is reached
   */
  registerAgent(request: AgentRegistrationRequest): AgentRegistration {
    if (this.agents.size >= this.maxAgents) {
      throw new Error(
        `Maximum agent limit reached (${this.maxAgents}). ` +
          'Cannot register additional agents.'
      );
    }

    const agentId = generateAgentId();
    const now = new Date().toISOString();

    const registration: AgentRegistration = {
      agentId,
      hostname: request.hostname,
      platform: {
        os: request.os,
        arch: request.arch,
        ip: request.ip,
      },
      version: request.version,
      registeredAt: now,
      lastHeartbeat: now,
      status: 'online',
    };

    this.agents.set(agentId, registration);

    logger.info(
      `Agent registered: ${agentId} (${request.hostname}, ${request.os}) / ` +
        `代理已登錄: ${agentId} (${request.hostname}, ${request.os})`
    );

    return { ...registration, platform: { ...registration.platform } };
  }

  /**
   * Remove an agent from the registry.
   *
   * @param agentId - The agent's unique identifier
   * @returns true if the agent was found and removed
   */
  deregisterAgent(agentId: string): boolean {
    const agent = this.agents.get(agentId);
    if (!agent) {
      logger.warn(`Deregister failed: agent ${agentId} not found`);
      return false;
    }

    this.agents.delete(agentId);
    logger.info(
      `Agent deregistered: ${agentId} (${agent.hostname}) / ` +
        `代理已登出: ${agentId} (${agent.hostname})`
    );
    return true;
  }

  /**
   * Update the heartbeat timestamp and metrics for an agent.
   * Creates a new registration record with updated fields (immutable pattern).
   *
   * @param heartbeat - Heartbeat data from the agent
   * @returns Updated registration or undefined if agent not found
   */
  updateHeartbeat(heartbeat: AgentHeartbeat): AgentRegistration | undefined {
    const existing = this.agents.get(heartbeat.agentId);
    if (!existing) {
      logger.warn(`Heartbeat from unknown agent: ${heartbeat.agentId}`);
      return undefined;
    }

    const updated: AgentRegistration = {
      ...existing,
      platform: { ...existing.platform },
      lastHeartbeat: heartbeat.timestamp,
      status: 'online',
    };

    this.agents.set(heartbeat.agentId, updated);
    return { ...updated, platform: { ...updated.platform } };
  }

  /**
   * Get a single agent's registration record.
   *
   * @param agentId - The agent's unique identifier
   * @returns Immutable copy of the registration, or undefined
   */
  getAgent(agentId: string): AgentRegistration | undefined {
    const agent = this.agents.get(agentId);
    if (!agent) return undefined;
    return { ...agent, platform: { ...agent.platform } };
  }

  /**
   * Get all agents currently marked as online.
   *
   * @returns Array of immutable registration copies
   */
  getActiveAgents(): readonly AgentRegistration[] {
    return Array.from(this.agents.values())
      .filter((a) => a.status === 'online')
      .map((a) => ({ ...a, platform: { ...a.platform } }));
  }

  /**
   * Get all registered agents regardless of status.
   *
   * @returns Array of immutable registration copies
   */
  getAllAgents(): readonly AgentRegistration[] {
    return Array.from(this.agents.values()).map((a) => ({
      ...a,
      platform: { ...a.platform },
    }));
  }

  /**
   * Identify agents whose last heartbeat exceeds the timeout threshold.
   * Marks them as 'stale' in the internal registry.
   *
   * @param timeoutMs - Maximum allowed milliseconds since last heartbeat
   * @returns Array of agents that are now stale
   */
  getStaleAgents(timeoutMs: number): readonly AgentRegistration[] {
    const now = Date.now();
    const staleAgents: AgentRegistration[] = [];

    for (const [agentId, agent] of this.agents.entries()) {
      if (agent.status === 'offline') continue;

      const lastBeat = new Date(agent.lastHeartbeat).getTime();
      const elapsed = now - lastBeat;

      if (elapsed >= timeoutMs) {
        const updated: AgentRegistration = {
          ...agent,
          platform: { ...agent.platform },
          status: 'stale',
        };
        this.agents.set(agentId, updated);
        staleAgents.push({ ...updated, platform: { ...updated.platform } });

        logger.warn(
          `Agent ${agentId} (${agent.hostname}) is stale ` +
            `(last heartbeat ${Math.round(elapsed / 1000)}s ago) / ` +
            `代理 ${agentId} (${agent.hostname}) 已過期`
        );
      }
    }

    return staleAgents;
  }

  /**
   * Mark an agent as offline.
   *
   * @param agentId - The agent's unique identifier
   * @returns true if the agent was found and marked offline
   */
  markOffline(agentId: string): boolean {
    const existing = this.agents.get(agentId);
    if (!existing) return false;

    const updated: AgentRegistration = {
      ...existing,
      platform: { ...existing.platform },
      status: 'offline',
    };
    this.agents.set(agentId, updated);

    logger.info(
      `Agent marked offline: ${agentId} (${existing.hostname}) / ` +
        `代理已標記為離線: ${agentId}`
    );
    return true;
  }

  /**
   * Get the count of agents by status.
   *
   * @returns Object with counts for each status
   */
  getStatusCounts(): Record<AgentStatus, number> {
    const counts: Record<AgentStatus, number> = {
      online: 0,
      stale: 0,
      offline: 0,
    };

    for (const agent of this.agents.values()) {
      counts[agent.status]++;
    }

    return counts;
  }

  /**
   * Get the total number of registered agents.
   */
  get size(): number {
    return this.agents.size;
  }
}
