/**
 * PolicyEngine - Centralized security policy management
 * PolicyEngine - 集中式安全策略管理
 *
 * Manages security policies that are distributed to Guard agents.
 * Supports global policies and per-agent/group customization.
 *
 * @module @panguard-ai/manager/policy-engine
 */

import { createLogger } from '@panguard-ai/core';
import { generatePolicyId } from './utils.js';
import type { PolicyRule, PolicyUpdate } from './types.js';

const logger = createLogger('panguard-manager:policy');

/**
 * Agent group assignment for policy targeting.
 */
interface AgentGroup {
  readonly groupId: string;
  readonly name: string;
  readonly agentIds: readonly string[];
}

/**
 * Manages creation, versioning, and distribution of security policies.
 * All returned data is immutable copies.
 */
export class PolicyEngine {
  private activePolicy: PolicyUpdate | null;
  private readonly policyHistory: PolicyUpdate[];
  private readonly agentGroups: Map<string, AgentGroup>;
  private readonly agentOverrides: Map<string, PolicyUpdate>;

  constructor() {
    this.activePolicy = null;
    this.policyHistory = [];
    this.agentGroups = new Map();
    this.agentOverrides = new Map();
  }

  /**
   * Create a new global policy from a set of rules.
   * Increments the version number from the previous active policy.
   *
   * @param rules - Array of policy rules to include
   * @param targetAgentIds - Agent IDs this policy applies to (empty = all)
   * @returns Immutable copy of the new policy
   */
  createPolicy(
    rules: readonly PolicyRule[],
    targetAgentIds: readonly string[] = []
  ): PolicyUpdate {
    const previousVersion = this.activePolicy?.version ?? 0;

    const policy: PolicyUpdate = {
      policyId: generatePolicyId(),
      version: previousVersion + 1,
      rules: rules.map((r) => ({
        ...r,
        condition: { ...r.condition },
      })),
      updatedAt: new Date().toISOString(),
      appliedTo: [...targetAgentIds],
    };

    // Archive the previous policy / 歸檔先前的策略
    if (this.activePolicy) {
      this.policyHistory.push(this.activePolicy);
    }

    this.activePolicy = policy;

    logger.info(
      `Policy created: ${policy.policyId} v${policy.version} ` +
        `(${rules.length} rules, targets: ${targetAgentIds.length || 'all'}) / ` +
        `策略已建立: ${policy.policyId} v${policy.version}`
    );

    return this.copyPolicy(policy);
  }

  /**
   * Get the current active global policy.
   *
   * @returns Immutable copy of the active policy, or null if none set
   */
  getActivePolicy(): PolicyUpdate | null {
    if (!this.activePolicy) return null;
    return this.copyPolicy(this.activePolicy);
  }

  /**
   * Get the policy applicable to a specific agent.
   * Returns agent-specific override if one exists, otherwise the global policy.
   *
   * @param agentId - The agent's unique identifier
   * @returns Immutable copy of the applicable policy, or null
   */
  getPolicyForAgent(agentId: string): PolicyUpdate | null {
    // Check for agent-specific override first
    const override = this.agentOverrides.get(agentId);
    if (override) {
      return this.copyPolicy(override);
    }

    // Fall back to global policy / 回退至全域策略
    if (!this.activePolicy) return null;
    return this.copyPolicy(this.activePolicy);
  }

  /**
   * Set a policy override for a specific agent.
   * The agent will receive this policy instead of the global one.
   *
   * @param agentId - The agent's unique identifier
   * @param rules - Array of policy rules for this agent
   * @returns Immutable copy of the agent-specific policy
   */
  setAgentOverride(
    agentId: string,
    rules: readonly PolicyRule[]
  ): PolicyUpdate {
    const policy: PolicyUpdate = {
      policyId: generatePolicyId(),
      version: 1,
      rules: rules.map((r) => ({
        ...r,
        condition: { ...r.condition },
      })),
      updatedAt: new Date().toISOString(),
      appliedTo: [agentId],
    };

    this.agentOverrides.set(agentId, policy);

    logger.info(
      `Agent override set: ${agentId} -> ${policy.policyId} / ` +
        `代理覆寫策略已設定: ${agentId}`
    );

    return this.copyPolicy(policy);
  }

  /**
   * Remove a policy override for an agent, reverting to global policy.
   *
   * @param agentId - The agent's unique identifier
   * @returns true if an override was removed
   */
  removeAgentOverride(agentId: string): boolean {
    const removed = this.agentOverrides.delete(agentId);
    if (removed) {
      logger.info(
        `Agent override removed: ${agentId} / 代理覆寫策略已移除: ${agentId}`
      );
    }
    return removed;
  }

  /**
   * Create a named agent group for policy targeting.
   *
   * @param groupId - Unique group identifier
   * @param name - Human-readable group name
   * @param agentIds - Agent IDs in this group
   */
  createAgentGroup(
    groupId: string,
    name: string,
    agentIds: readonly string[]
  ): AgentGroup {
    const group: AgentGroup = {
      groupId,
      name,
      agentIds: [...agentIds],
    };
    this.agentGroups.set(groupId, group);

    logger.info(
      `Agent group created: ${groupId} (${name}, ${agentIds.length} agents) / ` +
        `代理群組已建立: ${groupId}`
    );

    return { ...group, agentIds: [...group.agentIds] };
  }

  /**
   * Get the policy version history.
   *
   * @returns Array of immutable historical policy copies
   */
  getPolicyHistory(): readonly PolicyUpdate[] {
    return this.policyHistory.map((p) => this.copyPolicy(p));
  }

  /**
   * Get the current policy version number.
   *
   * @returns Current version, or 0 if no policy exists
   */
  getCurrentVersion(): number {
    return this.activePolicy?.version ?? 0;
  }

  /**
   * Create a deep immutable copy of a PolicyUpdate.
   */
  private copyPolicy(policy: PolicyUpdate): PolicyUpdate {
    return {
      ...policy,
      rules: policy.rules.map((r) => ({
        ...r,
        condition: { ...r.condition },
      })),
      appliedTo: [...policy.appliedTo],
    };
  }
}
