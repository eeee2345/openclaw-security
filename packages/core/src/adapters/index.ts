/**
 * Security Tool Adapters
 * 資安工具對接器
 *
 * Integrates with existing security tools such as Windows Defender,
 * Wazuh, and syslog-based systems. Provides a unified adapter interface,
 * an auto-detection registry, and standard alert-to-SecurityEvent conversion.
 * 與現有資安工具整合，如 Windows Defender、Wazuh 和基於 syslog 的系統。
 * 提供統一的對接器介面、自動偵測註冊表和標準告警到 SecurityEvent 的轉換。
 *
 * @module @panguard-ai/core/adapters
 */

/** Adapters module version / 對接器模組版本 */
export const ADAPTERS_VERSION = '0.1.0';

// Types / 型別
export type { AdapterConfig, AdapterAlert, SecurityAdapter } from './types.js';

// Base adapter / 基底對接器
export { BaseAdapter, mapSeverity, mapEventSource } from './base-adapter.js';

// Concrete adapters / 具體對接器
export { DefenderAdapter } from './defender-adapter.js';
export { WazuhAdapter } from './wazuh-adapter.js';
export { SyslogAdapter, parseSyslogMessage } from './syslog-adapter.js';
export type { SyslogAlertCallback } from './syslog-adapter.js';

// Registry / 註冊表
export { AdapterRegistry } from './adapter-registry.js';
