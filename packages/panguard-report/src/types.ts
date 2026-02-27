/**
 * PanguardReport type definitions
 * PanguardReport 型別定義
 * @module @panguard-ai/panguard-report/types
 */

// ---------------------------------------------------------------------------
// Compliance Frameworks
// 合規框架
// ---------------------------------------------------------------------------

/** Supported compliance frameworks / 支援的合規框架 */
export type ComplianceFramework = 'tw_cyber_security_act' | 'iso27001' | 'soc2';

/** Compliance control status / 合規控制狀態 */
export type ControlStatus = 'pass' | 'fail' | 'partial' | 'not_applicable';

/** A single compliance control / 單一合規控制項 */
export interface ComplianceControl {
  /** Control ID (e.g., "A.5.1", "CC6.1") / 控制項 ID */
  controlId: string;
  /** Category / 分類 */
  category: string;
  /** Title in English / 英文標題 */
  titleEn: string;
  /** Title in Traditional Chinese / 繁體中文標題 */
  titleZh: string;
  /** Description in English / 英文描述 */
  descriptionEn: string;
  /** Description in Traditional Chinese / 繁體中文描述 */
  descriptionZh: string;
  /** Related security categories for auto-mapping / 相關資安分類，用於自動映射 */
  relatedCategories: string[];
}

/** Evaluated compliance control with status / 已評估的合規控制項（含狀態） */
export interface EvaluatedControl extends ComplianceControl {
  /** Status / 狀態 */
  status: ControlStatus;
  /** Evidence supporting the evaluation / 支持評估的證據 */
  evidence: string[];
  /** Related findings / 相關發現 */
  relatedFindings: ComplianceFinding[];
  /** Remediation suggestions / 修復建議 */
  remediation?: string;
}

/** A finding that relates to compliance / 與合規相關的發現 */
export interface ComplianceFinding {
  /** Finding ID / 發現 ID */
  findingId: string;
  /** Severity / 嚴重度 */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Title / 標題 */
  title: string;
  /** Description / 描述 */
  description: string;
  /** Category for mapping / 分類（用於映射） */
  category: string;
  /** Timestamp / 時間戳 */
  timestamp: Date;
  /** Source (scan/guard/trap) / 來源 */
  source: 'panguard-scan' | 'panguard-guard' | 'panguard-trap' | 'manual';
}

// ---------------------------------------------------------------------------
// Report Types
// 報告類型
// ---------------------------------------------------------------------------

/** Report type / 報告類型 */
export type ReportType = 'compliance' | 'incident' | 'monthly' | 'quarterly' | 'annual';

/** Report format / 報告格式 */
export type ReportFormat = 'pdf' | 'json';

/** Report language / 報告語言 */
export type ReportLanguage = 'zh-TW' | 'en';

/** Report metadata / 報告元資料 */
export interface ReportMetadata {
  /** Report ID / 報告 ID */
  reportId: string;
  /** Report type / 報告類型 */
  type: ReportType;
  /** Compliance framework / 合規框架 */
  framework: ComplianceFramework;
  /** Language / 語言 */
  language: ReportLanguage;
  /** Report period / 報告期間 */
  period: {
    start: Date;
    end: Date;
  };
  /** Generation timestamp / 產生時間 */
  generatedAt: Date;
  /** Organization name / 組織名稱 */
  organizationName?: string;
  /** Report version / 報告版本 */
  version: string;
}

// ---------------------------------------------------------------------------
// Report Data
// 報告資料
// ---------------------------------------------------------------------------

/** Complete report data / 完整報告資料 */
export interface ComplianceReportData {
  /** Metadata / 元資料 */
  metadata: ReportMetadata;
  /** Executive summary / 執行摘要 */
  executiveSummary: ExecutiveSummary;
  /** Evaluated controls / 已評估的控制項 */
  controls: EvaluatedControl[];
  /** All findings / 所有發現 */
  findings: ComplianceFinding[];
  /** Statistics / 統計 */
  statistics: ComplianceStatistics;
  /** Recommendations / 建議 */
  recommendations: ReportRecommendation[];
}

/** Executive summary / 執行摘要 */
export interface ExecutiveSummary {
  /** Overall compliance score (0-100) / 整體合規分數 */
  overallScore: number;
  /** Total controls evaluated / 評估的控制項總數 */
  totalControls: number;
  /** Controls passed / 通過的控制項 */
  controlsPassed: number;
  /** Controls failed / 未通過的控制項 */
  controlsFailed: number;
  /** Controls partially met / 部分符合的控制項 */
  controlsPartial: number;
  /** Controls not applicable / 不適用的控制項 */
  controlsNA: number;
  /** Total findings / 發現總數 */
  totalFindings: number;
  /** Critical findings / 嚴重發現 */
  criticalFindings: number;
  /** High findings / 高風險發現 */
  highFindings: number;
  /** Key risks (human readable) / 主要風險（人類可讀） */
  keyRisks: string[];
  /** Key achievements / 主要成果 */
  keyAchievements: string[];
}

/** Compliance statistics / 合規統計 */
export interface ComplianceStatistics {
  /** By status / 依狀態分類 */
  byStatus: Record<ControlStatus, number>;
  /** By category / 依分類 */
  byCategory: Record<string, { total: number; passed: number; failed: number }>;
  /** By severity / 發現依嚴重度分類 */
  findingsBySeverity: Record<string, number>;
  /** Compliance percentage / 合規百分比 */
  compliancePercentage: number;
  /** Trend compared to last period / 與上期比較的趨勢 */
  trend?: {
    previousScore: number;
    change: number;
    direction: 'improving' | 'declining' | 'stable';
  };
}

/** Report recommendation / 報告建議 */
export interface ReportRecommendation {
  /** Priority / 優先級 */
  priority: 'immediate' | 'high' | 'medium' | 'low';
  /** Title / 標題 */
  title: string;
  /** Description / 描述 */
  description: string;
  /** Related control IDs / 相關控制項 ID */
  relatedControlIds: string[];
  /** Estimated effort / 預估工作量 */
  estimatedEffort?: string;
}

// ---------------------------------------------------------------------------
// Report Configuration
// 報告配置
// ---------------------------------------------------------------------------

/** Report generation config / 報告產生配置 */
export interface ReportConfig {
  /** Default language / 預設語言 */
  language: ReportLanguage;
  /** Default framework / 預設框架 */
  framework: ComplianceFramework;
  /** Organization name / 組織名稱 */
  organizationName?: string;
  /** Output directory / 輸出目錄 */
  outputDir: string;
  /** Include detailed findings / 包含詳細發現 */
  includeDetailedFindings: boolean;
  /** Include recommendations / 包含建議 */
  includeRecommendations: boolean;
  /** Report format / 報告格式 */
  format: ReportFormat;
}

/** Default report config / 預設報告配置 */
export const DEFAULT_REPORT_CONFIG: ReportConfig = {
  language: 'zh-TW',
  framework: 'tw_cyber_security_act',
  outputDir: './reports',
  includeDetailedFindings: true,
  includeRecommendations: true,
  format: 'json',
};
