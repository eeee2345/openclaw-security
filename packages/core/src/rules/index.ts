/**
 * Sigma/YARA Rules Engine
 * Sigma/YARA 規則引擎
 *
 * Provides the RuleEngine class for loading, managing, and matching
 * Sigma rules against security events. Supports filesystem loading,
 * hot-reloading, and custom rule injection.
 * 提供 RuleEngine 類別，用於載入、管理和比對 Sigma 規則與安全事件。
 * 支援檔案系統載入、熱載入和自訂規則注入。
 *
 * @module @panguard-ai/core/rules
 */

import { createLogger } from '../utils/logger.js';
import type { SecurityEvent } from '../types.js';
import type { SigmaRule, RuleMatch, RuleEngineConfig } from './types.js';
import { matchEventAgainstRules } from './sigma-matcher.js';
import { loadRulesRecursive, watchRulesDirectory } from './rule-loader.js';

const logger = createLogger('rule-engine');

/** Rules module version / 規則模組版本 */
export const RULES_VERSION = '0.1.0';

/**
 * Sigma rule engine for loading, managing, and matching security rules
 * Sigma 規則引擎，用於載入、管理和比對安全規則
 *
 * The RuleEngine is the primary entry point for working with Sigma rules.
 * It manages a collection of rules, supports hot-reloading from disk,
 * and provides matching against SecurityEvent instances.
 * RuleEngine 是使用 Sigma 規則的主要入口點。
 * 它管理規則集合、支援從磁碟熱載入，並提供與 SecurityEvent 實例的比對。
 *
 * @example
 * ```typescript
 * const engine = new RuleEngine({ rulesDir: './config/sigma-rules', hotReload: true });
 * await engine.loadRules();
 * const matches = engine.match(event);
 * engine.destroy();
 * ```
 */
export class RuleEngine {
  /** Internal rules collection / 內部規則集合 */
  private rules: SigmaRule[] = [];

  /** Cleanup function for the filesystem watcher / 檔案系統監視器的清理函式 */
  private cleanupWatcher?: () => void;

  /** Engine configuration / 引擎配置 */
  private config: RuleEngineConfig;

  /**
   * Create a new RuleEngine instance
   * 建立新的 RuleEngine 實例
   *
   * @param config - Optional configuration / 可選配置
   */
  constructor(config?: RuleEngineConfig) {
    this.config = config ?? {};

    // Add any pre-loaded custom rules / 新增預載入的自訂規則
    if (this.config.customRules !== undefined && this.config.customRules.length > 0) {
      this.rules.push(...this.config.customRules);
      logger.info(
        `Initialized with ${this.config.customRules.length} custom rules / 已初始化 ${this.config.customRules.length} 條自訂規則`
      );
    }
  }

  /**
   * Load rules from the configured directory
   * 從配置的目錄載入規則
   *
   * If a rulesDir is configured, loads all Sigma rules from that directory.
   * If hotReload is enabled, starts watching the directory for changes.
   * 如果配置了 rulesDir，從該目錄載入所有 Sigma 規則。
   * 如果啟用了 hotReload，開始監視目錄的變更。
   *
   * @returns Promise that resolves when rules are loaded / 規則載入完成後 resolve 的 Promise
   */
  async loadRules(): Promise<void> {
    const existingIds = new Set(this.rules.map((r) => r.id));

    // Load custom rules from rulesDir / 從 rulesDir 載入自訂規則
    if (this.config.rulesDir !== undefined) {
      const customDirRules = loadRulesRecursive(this.config.rulesDir, 'custom');
      for (const rule of customDirRules) {
        if (!existingIds.has(rule.id)) {
          this.rules.push(rule);
          existingIds.add(rule.id);
        } else {
          logger.warn(
            `Skipping duplicate rule id "${rule.id}" from custom directory / 跳過自訂目錄中重複的規則 id "${rule.id}"`
          );
        }
      }
    }

    // Load community rules from communityRulesDir / 從 communityRulesDir 載入社群規則
    if (this.config.communityRulesDir !== undefined) {
      const communityRules = loadRulesRecursive(this.config.communityRulesDir, 'community');
      for (const rule of communityRules) {
        if (!existingIds.has(rule.id)) {
          this.rules.push(rule);
          existingIds.add(rule.id);
        } else {
          logger.warn(
            `Skipping duplicate rule id "${rule.id}" from community directory / 跳過社群目錄中重複的規則 id "${rule.id}"`
          );
        }
      }
    }

    if (this.config.rulesDir === undefined && this.config.communityRulesDir === undefined) {
      logger.warn(
        'No rulesDir or communityRulesDir configured, skipping directory load / 未配置規則目錄，跳過載入'
      );
    }

    logger.info(`Total rules loaded: ${this.rules.length} / 已載入規則總數: ${this.rules.length}`);

    // Set up hot-reload watcher if configured / 如果配置了熱載入，設定監視器
    if (this.config.hotReload && this.config.rulesDir !== undefined) {
      if (this.cleanupWatcher !== undefined) {
        this.cleanupWatcher();
      }

      this.cleanupWatcher = watchRulesDirectory(this.config.rulesDir, (updatedRules) => {
        const customRules = this.config.customRules ?? [];
        const customIds = new Set(customRules.map((r) => r.id));

        this.rules = [...customRules];
        const loadedIds = new Set(customIds);

        for (const rule of updatedRules) {
          if (!loadedIds.has(rule.id)) {
            this.rules.push(rule);
            loadedIds.add(rule.id);
          }
        }

        // Re-load community rules after hot-reload / 熱載入後重新載入社群規則
        if (this.config.communityRulesDir !== undefined) {
          const communityRules = loadRulesRecursive(this.config.communityRulesDir, 'community');
          for (const rule of communityRules) {
            if (!loadedIds.has(rule.id)) {
              this.rules.push(rule);
              loadedIds.add(rule.id);
            }
          }
        }

        logger.info(
          `Hot-reloaded rules, total: ${this.rules.length} / 熱載入規則完成，總數: ${this.rules.length}`
        );
      });
    }
  }

  /**
   * Add a single rule to the engine
   * 新增單一規則到引擎
   *
   * @param rule - Sigma rule to add / 要新增的 Sigma 規則
   */
  addRule(rule: SigmaRule): void {
    const existingIndex = this.rules.findIndex((r) => r.id === rule.id);
    if (existingIndex !== -1) {
      this.rules[existingIndex] = rule;
      logger.info(
        `Updated existing rule: "${rule.title}" (${rule.id}) / 更新現有規則: "${rule.title}" (${rule.id})`
      );
    } else {
      this.rules.push(rule);
      logger.info(
        `Added new rule: "${rule.title}" (${rule.id}) / 新增規則: "${rule.title}" (${rule.id})`
      );
    }
  }

  /**
   * Remove a rule by its id
   * 依 id 移除規則
   *
   * @param id - The rule id to remove / 要移除的規則 id
   * @returns True if a rule was removed, false if not found / 移除成功回傳 true，找不到回傳 false
   */
  removeRule(id: string): boolean {
    const initialLength = this.rules.length;
    this.rules = this.rules.filter((r) => r.id !== id);
    const removed = this.rules.length < initialLength;

    if (removed) {
      logger.info(`Removed rule: ${id} / 已移除規則: ${id}`);
    } else {
      logger.warn(`Rule not found for removal: ${id} / 找不到要移除的規則: ${id}`);
    }

    return removed;
  }

  /**
   * Match a security event against all loaded rules
   * 比對安全事件與所有已載入的規則
   *
   * @param event - The security event to match / 要比對的安全事件
   * @returns Array of RuleMatch for all matching rules / 所有比對規則的 RuleMatch 陣列
   */
  match(event: SecurityEvent): RuleMatch[] {
    return matchEventAgainstRules(event, this.rules);
  }

  /**
   * Get a copy of all currently loaded rules
   * 取得所有已載入規則的副本
   *
   * @returns Array of Sigma rules (shallow copy) / Sigma 規則陣列（淺複製）
   */
  getRules(): SigmaRule[] {
    return [...this.rules];
  }

  /**
   * Reload all rules from the configured directory
   * 從配置的目錄重新載入所有規則
   *
   * Clears all existing rules (including custom rules) and reloads from scratch.
   * 清除所有現有規則（包含自訂規則）並從頭重新載入。
   *
   * @returns Promise that resolves when rules are reloaded / 規則重新載入完成後 resolve 的 Promise
   */
  async reload(): Promise<void> {
    logger.info('Reloading all rules / 重新載入所有規則');

    // Reset to custom rules only / 重設為僅有自訂規則
    this.rules = this.config.customRules ? [...this.config.customRules] : [];
    const existingIds = new Set(this.rules.map((r) => r.id));

    if (this.config.rulesDir !== undefined) {
      const customDirRules = loadRulesRecursive(this.config.rulesDir, 'custom');
      for (const rule of customDirRules) {
        if (!existingIds.has(rule.id)) {
          this.rules.push(rule);
          existingIds.add(rule.id);
        }
      }
    }

    if (this.config.communityRulesDir !== undefined) {
      const communityRules = loadRulesRecursive(this.config.communityRulesDir, 'community');
      for (const rule of communityRules) {
        if (!existingIds.has(rule.id)) {
          this.rules.push(rule);
          existingIds.add(rule.id);
        }
      }
    }

    logger.info(
      `Reload complete, total rules: ${this.rules.length} / 重新載入完成，規則總數: ${this.rules.length}`
    );
  }

  /**
   * Destroy the engine and clean up resources
   * 銷毀引擎並清理資源
   *
   * Stops the filesystem watcher if active and clears the rule set.
   * 停止檔案系統監視器（如果活動中）並清除規則集。
   */
  destroy(): void {
    if (this.cleanupWatcher !== undefined) {
      this.cleanupWatcher();
      this.cleanupWatcher = undefined;
    }
    this.rules = [];
    logger.info('RuleEngine destroyed / RuleEngine 已銷毀');
  }
}

// Re-export types / 重新匯出型別
export type {
  SigmaLogSource,
  SigmaDetection,
  SigmaRule,
  RuleMatch,
  RuleEngineConfig,
} from './types.js';

// Re-export parser functions / 重新匯出解析器函式
export { parseSigmaYaml, parseSigmaFile } from './sigma-parser.js';

// Re-export matcher functions / 重新匯出比對器函式
export { matchEvent, matchEventAgainstRules } from './sigma-matcher.js';

// Re-export loader functions / 重新匯出載入器函式
export { loadRulesFromDirectory, loadRulesRecursive, watchRulesDirectory } from './rule-loader.js';

// Re-export YARA scanner / 重新匯出 YARA 掃描器
export { YaraScanner, type YaraMatch, type YaraScanResult } from './yara-scanner.js';
