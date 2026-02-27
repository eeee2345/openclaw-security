/**
 * PanguardReport - AI Compliance Report Generator
 * PanguardReport - AI 合規報告產生器
 *
 * Generates compliance reports for:
 * - Taiwan Cyber Security Management Act (資通安全管理法)
 * - ISO/IEC 27001:2022
 * - SOC 2 Trust Services Criteria
 *
 * @module @panguard-ai/panguard-report
 */

export const PANGUARD_REPORT_VERSION = '0.1.0';
export const CLAWREPORT_NAME = 'PanguardReport';

// Types
export type {
  ComplianceFramework,
  ControlStatus,
  ComplianceControl,
  EvaluatedControl,
  ComplianceFinding,
  ReportType,
  ReportFormat,
  ReportLanguage,
  ReportMetadata,
  ComplianceReportData,
  ExecutiveSummary,
  ComplianceStatistics,
  ReportRecommendation,
  ReportConfig,
} from './types.js';
export { DEFAULT_REPORT_CONFIG } from './types.js';

// Frameworks
export {
  getFrameworkControls,
  getFrameworkName,
  getSupportedFrameworks,
  TW_CYBER_SECURITY_CONTROLS,
  ISO27001_CONTROLS,
  SOC2_CONTROLS,
} from './frameworks/index.js';

// Mapper
export {
  evaluateControls,
  generateExecutiveSummary,
  generateStatistics,
  generateRecommendations,
} from './mapper/index.js';

// Generator
export { generateComplianceReport, reportToJSON, generateSummaryText } from './generator/index.js';

// Templates
export {
  getSectionLabels,
  getStatusLabel,
  getSeverityLabel,
  getPriorityLabel,
  getFrameworkDescription,
} from './templates/index.js';
export type { ReportSectionLabels, FrameworkDescription } from './templates/index.js';

// CLI
export {
  parseCliArgs,
  buildConfigFromOptions,
  formatConfig,
  formatFrameworkList,
  getHelpText,
  executeCli,
} from './cli/index.js';
export type { ReportCliCommand, ReportCliOptions } from './cli/index.js';
