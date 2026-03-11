/**
 * Panguard AI - Unified Security Platform
 * Panguard AI - 統一資安平台
 *
 * Single entry point for all Panguard security modules.
 * 所有 Panguard 資安模組的統一入口。
 *
 * @module @panguard-ai/panguard
 */

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _pkg = _require('../package.json') as { version: string };
export const PANGUARD_VERSION: string = _pkg.version;

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

// Threat Intelligence (server-side, not published — available only in monorepo)
// Use dynamic import: const tc = await import('@panguard-ai/threat-cloud');

// Bridges
export { scanFindingsToComplianceFindings } from './bridges/scan-to-report.js';
export type { ScanFinding } from './bridges/scan-to-report.js';

// Init / Config
export { runInitWizard, buildPanguardConfig, writeConfig, readConfig } from './init/index.js';
export type { WizardAnswers, PanguardConfig, Lang } from './init/types.js';
