/**
 * Security adapter registry for auto-detection and management
 * 安全對接器註冊表，用於自動偵測和管理
 *
 * Provides centralized management of security tool adapters, including
 * manual registration, auto-detection from discovery results, and
 * unified alert collection across all registered adapters.
 * 提供安全工具對接器的集中管理，包括手動註冊、從偵察結果自動偵測，
 * 以及跨所有已註冊對接器的統一告警收集。
 *
 * @module @panguard-ai/core/adapters/adapter-registry
 */

import { createLogger } from '../utils/logger.js';
import type { SecurityEvent } from '../types.js';
import type { DiscoveryResult } from '../discovery/types.js';
import type { SecurityAdapter } from './types.js';
import { DefenderAdapter } from './defender-adapter.js';
import { WazuhAdapter } from './wazuh-adapter.js';
import { SyslogAdapter } from './syslog-adapter.js';

const logger = createLogger('adapter-registry');

/**
 * Centralized registry for security tool adapters
 * 安全工具對接器的集中註冊表
 *
 * The AdapterRegistry manages the lifecycle of security adapters:
 * - Manual registration of custom adapters
 * - Auto-detection of available adapters based on environment discovery
 * - Unified alert collection from all registered adapters
 * - Conversion of all alerts to the standardized SecurityEvent format
 *
 * AdapterRegistry 管理安全對接器的生命週期：
 * - 手動註冊自訂對接器
 * - 基於環境偵察的可用對接器自動偵測
 * - 從所有已註冊對接器統一收集告警
 * - 將所有告警轉換為標準化的 SecurityEvent 格式
 *
 * @example
 * ```typescript
 * const registry = new AdapterRegistry();
 *
 * // Auto-detect adapters from discovery results / 從偵察結果自動偵測對接器
 * await registry.autoDetect(discoveryResult);
 *
 * // Or register manually / 或手動註冊
 * registry.register(new WazuhAdapter({ enabled: true, endpoint: 'https://wazuh:55000' }));
 *
 * // Collect alerts from all adapters / 從所有對接器收集告警
 * const events = await registry.collectAlerts(new Date(Date.now() - 3600000));
 * ```
 */
export class AdapterRegistry {
  /**
   * Map of registered adapters keyed by adapter name
   * 以對接器名稱為鍵的已註冊對接器映射
   */
  private adapters: Map<string, SecurityAdapter> = new Map();

  /**
   * Create a new AdapterRegistry instance
   * 建立新的 AdapterRegistry 實例
   */
  constructor() {
    logger.info('AdapterRegistry initialized');
  }

  /**
   * Register an adapter manually
   * 手動註冊對接器
   *
   * Adds the adapter to the registry. If an adapter with the same name
   * is already registered, it will be replaced.
   * 將對接器新增到註冊表。若已有同名對接器，則會被取代。
   *
   * @param adapter - Security adapter to register / 要註冊的安全對接器
   */
  register(adapter: SecurityAdapter): void {
    const existing = this.adapters.has(adapter.name);
    this.adapters.set(adapter.name, adapter);

    if (existing) {
      logger.info(`Replaced existing adapter: ${adapter.name}`, { type: adapter.type });
    } else {
      logger.info(`Registered adapter: ${adapter.name}`, { type: adapter.type });
    }
  }

  /**
   * Remove a registered adapter by name
   * 依名稱移除已註冊的對接器
   *
   * @param name - Adapter name to remove / 要移除的對接器名稱
   * @returns True if the adapter was removed / 若對接器已移除則回傳 true
   */
  unregister(name: string): boolean {
    const removed = this.adapters.delete(name);
    if (removed) {
      logger.info(`Unregistered adapter: ${name}`);
    } else {
      logger.warn(`Adapter not found for removal: ${name}`);
    }
    return removed;
  }

  /**
   * Auto-detect and register available security adapters
   * 自動偵測並註冊可用的安全對接器
   *
   * Creates adapter instances based on detected security tools from
   * the discovery result. Each adapter is checked for availability
   * before being registered.
   *
   * Default adapters checked:
   * - Windows Defender (on Windows systems)
   * - Wazuh (if detected in discovery results)
   * - Syslog Receiver (always available as a generic receiver)
   *
   * 根據偵察結果中偵測到的安全工具建立對接器實例。
   * 每個對接器在註冊前都會檢查可用性。
   *
   * 檢查的預設對接器：
   * - Windows Defender（在 Windows 系統上）
   * - Wazuh（若在偵察結果中偵測到）
   * - Syslog 接收器（作為通用接收器始終可用）
   *
   * @param discoveryResult - Optional discovery result for context-aware detection / 可選的偵察結果，用於上下文感知偵測
   */
  async autoDetect(discoveryResult?: DiscoveryResult): Promise<void> {
    logger.info('Starting adapter auto-detection');

    const candidates: SecurityAdapter[] = [];

    // Always try Windows Defender / 總是嘗試 Windows Defender
    candidates.push(new DefenderAdapter({ enabled: true }));

    // Check discovery results for known security tools
    // 檢查偵察結果中的已知安全工具
    if (discoveryResult) {
      const tools = discoveryResult.security.existingTools;

      // Look for Wazuh in detected tools / 在偵測到的工具中尋找 Wazuh
      const wazuhTool = tools.find(
        (tool) =>
          tool.name.toLowerCase().includes('wazuh') || tool.vendor.toLowerCase().includes('wazuh')
      );

      if (wazuhTool) {
        logger.info('Wazuh detected in discovery results, adding adapter');
        candidates.push(new WazuhAdapter({ enabled: true }));
      }

      // Look for SIEM tools that might expose syslog
      // 尋找可能暴露 syslog 的 SIEM 工具
      const syslogCapable = tools.some(
        (tool) =>
          tool.type === 'siem' ||
          tool.type === 'ids' ||
          tool.name.toLowerCase().includes('syslog') ||
          tool.name.toLowerCase().includes('rsyslog') ||
          tool.name.toLowerCase().includes('syslog-ng')
      );

      if (syslogCapable) {
        logger.info('Syslog-capable tool detected, adding syslog adapter');
        candidates.push(new SyslogAdapter({ enabled: true }));
      }
    }

    // Check availability for each candidate and register if available
    // 檢查每個候選者的可用性，若可用則註冊
    let registered = 0;
    for (const candidate of candidates) {
      try {
        const available = await candidate.isAvailable();
        if (available) {
          this.register(candidate);
          registered++;
        } else {
          logger.debug(`Adapter not available: ${candidate.name}`);
        }
      } catch (err) {
        logger.warn(`Error checking adapter availability: ${candidate.name}`, {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    logger.info(`Auto-detection complete: ${registered} adapters registered`, {
      candidates: candidates.length,
      registered,
    });
  }

  /**
   * Get a registered adapter by name
   * 依名稱取得已註冊的對接器
   *
   * @param name - Adapter name / 對接器名稱
   * @returns The adapter instance, or undefined if not found / 對接器實例，若找不到則為 undefined
   */
  getAdapter(name: string): SecurityAdapter | undefined {
    return this.adapters.get(name);
  }

  /**
   * Get all registered (available) adapters
   * 取得所有已註冊（可用）的對接器
   *
   * @returns Array of registered security adapters / 已註冊的安全對接器陣列
   */
  getAvailableAdapters(): SecurityAdapter[] {
    return Array.from(this.adapters.values());
  }

  /**
   * Get the names of all registered adapters
   * 取得所有已註冊對接器的名稱
   *
   * @returns Array of adapter names / 對接器名稱陣列
   */
  getAdapterNames(): string[] {
    return Array.from(this.adapters.keys());
  }

  /**
   * Get the number of registered adapters
   * 取得已註冊對接器的數量
   *
   * @returns Number of registered adapters / 已註冊對接器的數量
   */
  get size(): number {
    return this.adapters.size;
  }

  /**
   * Collect alerts from all registered adapters and convert to SecurityEvents
   * 從所有已註冊對接器收集告警並轉換為 SecurityEvent
   *
   * Iterates over all registered adapters, retrieves their alerts,
   * converts them to the standardized SecurityEvent format, and
   * returns a merged array. Errors from individual adapters are
   * logged and do not prevent collection from other adapters.
   * 遍歷所有已註冊對接器，取得其告警，轉換為標準化的 SecurityEvent 格式，
   * 並回傳合併的陣列。個別對接器的錯誤會被記錄，不會阻止從其他對接器收集。
   *
   * @param since - Optional cutoff date for all adapters / 所有對接器的可選截止日期
   * @returns Merged array of SecurityEvents from all adapters / 來自所有對接器的合併 SecurityEvent 陣列
   */
  async collectAlerts(since?: Date): Promise<SecurityEvent[]> {
    const allEvents: SecurityEvent[] = [];
    const adapterNames = this.getAdapterNames();

    if (adapterNames.length === 0) {
      logger.debug('No adapters registered, no alerts to collect');
      return allEvents;
    }

    logger.info(`Collecting alerts from ${adapterNames.length} adapters`, {
      adapters: adapterNames,
      since: since?.toISOString(),
    });

    // Collect from all adapters in parallel for efficiency
    // 為了效率，同時從所有對接器收集
    const results = await Promise.allSettled(
      Array.from(this.adapters.entries()).map(async ([name, adapter]) => {
        try {
          const alerts = await adapter.getAlerts(since);
          const events = adapter.toSecurityEvents(alerts);

          logger.debug(`Collected ${events.length} events from ${name}`);
          return events;
        } catch (err) {
          logger.error(`Failed to collect alerts from ${name}`, {
            error: err instanceof Error ? err.message : String(err),
          });
          return [] as SecurityEvent[];
        }
      })
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        allEvents.push(...result.value);
      }
      // Rejected promises are already handled in the catch above
      // 被拒絕的 Promise 已在上面的 catch 中處理
    }

    logger.info(`Collected ${allEvents.length} total events from all adapters`);
    return allEvents;
  }

  /**
   * Clear all registered adapters
   * 清除所有已註冊的對接器
   */
  clear(): void {
    const count = this.adapters.size;
    this.adapters.clear();
    logger.info(`Cleared ${count} adapters from registry`);
  }
}
