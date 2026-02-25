/**
 * Environment Discovery Engine
 * 環境偵察引擎
 *
 * Provides system discovery capabilities including OS detection,
 * network scanning, service enumeration, and security tool detection.
 * 提供系統偵察功能，包括作業系統偵測、網路掃描、服務列舉和安全工具偵測。
 *
 * @module @openclaw/core/discovery
 */

/** Discovery engine version / 偵察引擎版本 */
export const DISCOVERY_VERSION = '0.1.0';

// Types
export type {
  DiscoveryConfig,
  OSInfo,
  NetworkInterface,
  PortInfo,
  ActiveConnection,
  NetworkInfo,
  ServiceInfo,
  SecurityToolType,
  SecurityTool,
  FirewallRule,
  FirewallStatus,
  UpdateStatus,
  UserInfo,
  RiskFactor,
  DiscoveryResult,
} from './types.js';

// OS Detection / 作業系統偵測
export { detectOS } from './os-detector.js';

// Network Scanning / 網路掃描
export {
  getNetworkInterfaces,
  scanOpenPorts,
  getActiveConnections,
  getGateway,
  getDnsServers,
  getDnsServersAsync,
} from './network-scanner.js';

// Service Detection / 服務偵測
export { detectServices } from './service-detector.js';

// Security Tool Detection / 安全工具偵測
export { detectSecurityTools } from './security-tools.js';

// Firewall Status / 防火牆狀態
export { checkFirewall } from './firewall-checker.js';

// User Audit / 使用者稽核
export { auditUsers } from './user-auditor.js';

// Risk Scoring / 風險評分
export { calculateRiskScore, getRiskLevel } from './risk-scorer.js';

// osquery Integration / osquery 整合
export { OsqueryProvider, createOsqueryProvider } from './osquery-provider.js';
export type { OsqueryProcess, OsqueryListeningPort, OsqueryLoggedInUser } from './osquery-provider.js';
