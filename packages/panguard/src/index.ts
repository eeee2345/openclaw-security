/**
 * Panguard AI - Unified Security Platform
 * Panguard AI - 統一資安平台
 *
 * Single entry point for all Panguard security modules.
 * 所有 Panguard 資安模組的統一入口。
 *
 * @module @panguard-ai/panguard
 */

export const PANGUARD_VERSION = '0.1.0';

// Scanner
export { runScan, generatePdfReport } from '@panguard-ai/panguard-scan';
export type { ScanConfig, ScanResult, Finding } from '@panguard-ai/panguard-scan';

// Guard Engine
export { GuardEngine, DashboardServer, loadConfig } from '@panguard-ai/panguard-guard';

// Report Generator
export {
  generateComplianceReport,
  reportToJSON,
  generateSummaryText,
  getSupportedFrameworks,
} from '@panguard-ai/panguard-report';

// Chat / Notifications
export { ChatAgent, WebhookChannel } from '@panguard-ai/panguard-chat';

// Honeypot
export { TrapEngine } from '@panguard-ai/panguard-trap';

// Threat Intelligence
export { ThreatCloudServer, ThreatCloudDB } from '@panguard-ai/threat-cloud';

// Init / Config
export { runInitWizard, buildPanguardConfig, writeConfig, readConfig } from './init/index.js';
export type { WizardAnswers, PanguardConfig, Lang } from './init/types.js';
