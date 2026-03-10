/**
 * ATR Module System
 *
 * Extensible detection modules beyond regex pattern matching.
 * Inspired by YARA modules, adapted for AI agent threat detection.
 *
 * Built-in modules:
 * - session: Cross-event behavioral analysis using SessionTracker
 * - semantic: AI-driven semantic threat analysis using LLM-as-judge (v0.2)
 *
 * Reserved namespaces (planned):
 * - embedding: Vector similarity detection (v0.3)
 * - protocol: MCP/transport-level inspection (v0.3)
 * - entropy: Information-theoretic anomaly detection (v0.4)
 * - tokenizer: Token-level analysis for smuggling detection (v0.4)
 *
 * @module agent-threat-rules/modules
 */

import type { AgentEvent } from '../types.js';

/**
 * Condition defined by a module (used in rule YAML).
 *
 * Example in YAML:
 * ```yaml
 * detection:
 *   conditions:
 *     high_frequency:
 *       module: session
 *       function: call_frequency
 *       args:
 *         tool_name: "execute_code"
 *         window: "5m"
 *       operator: gt
 *       threshold: 10
 *   condition: "high_frequency"
 * ```
 */
export interface ModuleCondition {
  /** Module name (e.g., "session", "embedding") */
  module: string;
  /** Function within the module to call */
  function: string;
  /** Arguments passed to the module function */
  args: Record<string, unknown>;
  /** Comparison operator for the result */
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  /** Threshold value to compare against */
  threshold: number;
}

/**
 * Result returned by a module evaluation.
 */
export interface ModuleResult {
  /** Whether the condition was met */
  matched: boolean;
  /** Numeric value produced by the module (for threshold comparison) */
  value: number;
  /** Human-readable description of the result */
  description: string;
}

/**
 * Interface that all ATR detection modules must implement.
 *
 * Modules extend ATR's detection beyond regex by providing
 * custom evaluation logic (behavioral analysis, embedding
 * similarity, protocol inspection, etc.).
 */
export interface ATRModule {
  /** Unique module name (used in rule YAML) */
  readonly name: string;

  /** Human-readable description */
  readonly description: string;

  /** Module version */
  readonly version: string;

  /**
   * List of functions this module provides.
   * Each function can be referenced in rule conditions.
   */
  readonly functions: ReadonlyArray<{
    name: string;
    description: string;
    args: ReadonlyArray<{
      name: string;
      type: 'string' | 'number' | 'boolean';
      required: boolean;
      description: string;
    }>;
  }>;

  /**
   * Initialize the module. Called once when the engine starts.
   * Use for setup, connection pooling, model loading, etc.
   */
  initialize(): Promise<void>;

  /**
   * Evaluate a module condition against an agent event.
   *
   * @param event - The agent event being evaluated
   * @param condition - The module condition from the rule
   * @returns Module evaluation result
   */
  evaluate(event: AgentEvent, condition: ModuleCondition): Promise<ModuleResult>;

  /**
   * Clean up module resources. Called when the engine shuts down.
   */
  destroy(): Promise<void>;
}

/**
 * Registry for ATR detection modules.
 */
export class ModuleRegistry {
  private readonly modules = new Map<string, ATRModule>();

  /** Reserved module namespaces (cannot be registered by third parties) */
  private static readonly RESERVED = new Set([
    'session',
    'semantic',
    'embedding',
    'protocol',
    'entropy',
    'tokenizer',
  ]);

  /**
   * Register a detection module.
   * @throws if module name is already registered or reserved
   */
  register(module: ATRModule): void {
    if (this.modules.has(module.name)) {
      throw new Error(`Module "${module.name}" is already registered`);
    }
    this.modules.set(module.name, module);
  }

  /**
   * Check if a module name is reserved by the ATR core team.
   */
  isReserved(name: string): boolean {
    return ModuleRegistry.RESERVED.has(name);
  }

  /**
   * Get a registered module by name.
   */
  get(name: string): ATRModule | undefined {
    return this.modules.get(name);
  }

  /**
   * List all registered modules.
   */
  list(): ReadonlyArray<{ name: string; version: string; description: string }> {
    return Array.from(this.modules.values()).map(m => ({
      name: m.name,
      version: m.version,
      description: m.description,
    }));
  }

  /**
   * Initialize all registered modules.
   */
  async initializeAll(): Promise<void> {
    for (const module of this.modules.values()) {
      await module.initialize();
    }
  }

  /**
   * Destroy all registered modules.
   */
  async destroyAll(): Promise<void> {
    for (const module of this.modules.values()) {
      await module.destroy();
    }
  }
}
