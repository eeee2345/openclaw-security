/**
 * PanguardScan - Security Scanning CLI Tool
 * PanguardScan - 資安健檢命令列工具
 *
 * Performs comprehensive security scans and generates PDF reports.
 * 執行全面的安全掃描並產生 PDF 報告。
 *
 * @module @panguard-ai/panguard-scan
 */

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _pkg = _require('../package.json') as { version: string };
/** PanguardScan version / PanguardScan 版本 */
export const PANGUARD_SCAN_VERSION: string = _pkg.version;

/** PanguardScan product name / PanguardScan 產品名稱 */
export const CLAWSCAN_NAME = 'PanguardScan';

// Scanner exports / 掃描器匯出
export { runScan } from './scanners/index.js';
export type { ScanConfig, ScanResult, Finding } from './scanners/types.js';
export { sortBySeverity, SEVERITY_ORDER } from './scanners/types.js';

// Remote scanner exports / 遠端掃描器匯出
export { runRemoteScan } from './scanners/remote/index.js';
export type { RemoteScanConfig } from './scanners/remote/index.js';

// Report exports / 報告匯出
export { generatePdfReport } from './report/index.js';
