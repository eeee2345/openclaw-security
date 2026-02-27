/**
 * PanguardGuard - AI Real-time Endpoint Monitoring & Auto-response
 * PanguardGuard - AI 即時端點監控與自動回應
 *
 * Main entry point for the PanguardGuard package.
 * Exports all public modules for programmatic use.
 * PanguardGuard 套件的主要入口點。匯出所有公開模組供程式化使用。
 *
 * @module @panguard-ai/panguard-guard
 */

/** Package version / 套件版本 */
export const PANGUARD_GUARD_VERSION = '0.1.0';
export const CLAWGUARD_NAME = 'PanguardGuard';

// Types / 型別
export type {
  InvestigationTool,
  InvestigationStep,
  InvestigationResult,
  InvestigationPlan,
  EvidenceSource,
  Evidence,
  ResponseAction,
  ThreatVerdict,
  ActionPolicy,
  ProcessPattern,
  ConnectionPattern,
  LoginPattern,
  PortPattern,
  EnvironmentBaseline,
  DeviationResult,
  DetectionResult,
  ResponseResult,
  LineNotifyConfig,
  TelegramConfig,
  SlackConfig,
  EmailConfig,
  NotificationConfig,
  NotificationResult,
  AnonymizedThreatData,
  ThreatCloudUpdate,
  ThreatCloudStatus,
  LicenseTier,
  LicenseInfo,
  LLMAnalysisResult,
  LLMClassificationResult,
  AnalyzeLLM,
  DashboardStatus,
  DashboardEvent,
  ThreatMapEntry,
  GuardMode,
  GuardConfig,
  GuardStatus,
} from './types.js';

export { DEFAULT_ACTION_POLICY, TIER_FEATURES } from './types.js';

// Config / 配置
export {
  loadConfig,
  saveConfig,
  ensureDataDir,
  DEFAULT_DATA_DIR,
  DEFAULT_GUARD_CONFIG,
} from './config.js';

// Guard Engine / 守護引擎
export { GuardEngine } from './guard-engine.js';

// Multi-Agent Pipeline / 多代理管線
export { DetectAgent, AnalyzeAgent, RespondAgent, ReportAgent } from './agent/index.js';
export type { ReportRecord } from './agent/index.js';

// Context Memory / 情境記憶
export {
  createEmptyBaseline,
  checkDeviation,
  updateBaseline,
  loadBaseline,
  saveBaseline,
  isLearningComplete,
  getLearningProgress,
  getRemainingDays,
  switchToProtectionMode,
  getBaselineSummary,
} from './memory/index.js';

// Investigation / Dynamic Reasoning / 調查/動態推理
export { InvestigationEngine } from './investigation/index.js';

// Notifications / 通知
export {
  sendNotifications,
  sendLineNotify,
  sendTelegramNotify,
  sendSlackNotify,
  sendEmailNotify,
} from './notify/index.js';

// Threat Cloud / 威脅雲
export { ThreatCloudClient } from './threat-cloud/index.js';

// Dashboard / 儀表板
export { DashboardServer } from './dashboard/index.js';

// License / 授權
export {
  validateLicense,
  hasFeature,
  getTierFeatures,
  generateTestLicenseKey,
} from './license/index.js';

// Daemon / 服務
export { PidFile, Watchdog, installService, uninstallService } from './daemon/index.js';

// Install / 安裝
export { generateInstallScript } from './install/index.js';

// CLI / 命令列
export { runCLI, CLI_VERSION } from './cli/index.js';
