/**
 * Panguard AI - Core Package
 * Panguard 安全平台 - 核心套件
 *
 * Core shared modules for the Panguard AI platform.
 * Provides types, i18n, utilities, discovery, monitoring, rules, AI, and adapters.
 * 核心共用模組，提供類型、國際化、工具函式、偵察、監控、規則、AI 和對接器。
 *
 * @module @panguard-ai/core
 */

// Types / 型別
export type {
  Language,
  Severity,
  EventSource,
  BaseConfig,
  SecurityEvent,
  LogEntry,
} from './types.js';

// i18n / 國際化
export { initI18n, getI18n, changeLanguage, t, resetI18n } from './i18n/index.js';

// Utils / 工具函式
export {
  createLogger,
  setLogLevel,
  validateInput,
  sanitizeString,
  validateFilePath,
} from './utils/index.js';
export type { Logger } from './utils/index.js';

// Discovery engine / 偵察引擎
export {
  DISCOVERY_VERSION,
  detectOS,
  getNetworkInterfaces,
  scanOpenPorts,
  getActiveConnections,
  getGateway,
  getDnsServers,
  getDnsServersAsync,
  detectServices,
  detectSecurityTools,
  checkFirewall,
  auditUsers,
  calculateRiskScore,
  getRiskLevel,
  OsqueryProvider,
  createOsqueryProvider,
} from './discovery/index.js';
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
  OsqueryProcess,
  OsqueryListeningPort,
  OsqueryLoggedInUser,
} from './discovery/index.js';

// Rules engine / 規則引擎
export {
  RULES_VERSION,
  RuleEngine,
  parseSigmaYaml,
  parseSigmaFile,
  matchEvent,
  matchEventAgainstRules,
  loadRulesFromDirectory,
  watchRulesDirectory,
  YaraScanner,
} from './rules/index.js';
export type {
  SigmaLogSource,
  SigmaDetection,
  SigmaRule,
  RuleMatch,
  RuleEngineConfig,
  YaraMatch,
  YaraScanResult,
} from './rules/index.js';

// Monitor engine / 監控引擎
export {
  MONITOR_VERSION,
  MonitorEngine,
  LogMonitor,
  NetworkMonitor,
  ProcessMonitor,
  FileMonitor,
  checkThreatIntel,
  isPrivateIP,
  addThreatIntelEntry,
  getThreatIntelEntries,
  setFeedManager,
  getFeedManager,
  normalizeLogEvent,
  normalizeNetworkEvent,
  normalizeProcessEvent,
  normalizeFileEvent,
  DEFAULT_MONITOR_CONFIG,
  ThreatIntelFeedManager,
} from './monitor/index.js';
export type {
  MonitorConfig,
  MonitorStatus,
  ThreatIntelEntry,
  FileHashRecord,
  ProcessListEntry,
  IoC,
  FeedSource,
  FeedUpdateResult,
  FeedManagerConfig,
} from './monitor/index.js';

// Scoring / 安全分數
export {
  calculateSecurityScore,
  scoreToGrade,
  scoreToColor,
  generateScoreSummary,
  AchievementTracker,
  ACHIEVEMENTS,
} from './scoring/index.js';
export type {
  ScoreFactor,
  SecurityScoreSnapshot,
  ScoreInput,
  Achievement,
  AchievementStats,
  EarnedAchievement,
} from './scoring/index.js';

// AI / LLM interface / AI/LLM 介面
export { AI_VERSION, createLLM } from './ai/index.js';
export type {
  LLMConfig,
  LLMProvider,
  LLMProviderType,
  AnalysisResult,
  ThreatClassification,
} from './ai/index.js';

// Adapters / 對接器
export {
  ADAPTERS_VERSION,
  BaseAdapter,
  mapSeverity,
  mapEventSource,
  DefenderAdapter,
  WazuhAdapter,
  SyslogAdapter,
  parseSyslogMessage,
  AdapterRegistry,
} from './adapters/index.js';
export type {
  AdapterConfig,
  AdapterAlert,
  SecurityAdapter,
  SyslogAlertCallback,
} from './adapters/index.js';

// CLI utilities / CLI 工具
export {
  c,
  colorSeverity,
  colorScore,
  colorGrade,
  Spinner,
  spinner,
  ProgressBar,
  progressBar,
  table,
  box,
  banner,
  header,
  symbols,
  divider,
  scoreDisplay,
  statusPanel,
  stripAnsi,
  formatDuration,
  timeAgo,
  visLen,
  promptSelect,
  promptText,
  promptConfirm,
  WizardEngine,
} from './cli/index.js';
export type {
  ProgressBarOptions,
  TableColumn,
  BoxOptions,
  StatusItem,
  SelectOption,
  SelectConfig,
  TextConfig,
  ConfirmConfig,
  WizardStep,
  WizardAnswers,
} from './cli/index.js';

/** Core package version / 核心套件版本 */
export const CORE_VERSION = '0.1.0';
