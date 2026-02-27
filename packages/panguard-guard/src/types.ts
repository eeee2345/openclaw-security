/**
 * PanguardGuard type definitions
 * PanguardGuard 型別定義
 * @module @panguard-ai/panguard-guard/types
 */

import type { Language, Severity, SecurityEvent } from '@panguard-ai/core';

// ===== Investigation / Dynamic Reasoning =====

/** Investigation tool name / 調查工具名稱 */
export type InvestigationTool =
  | 'checkIPHistory'
  | 'checkUserPrivilege'
  | 'checkTimeAnomaly'
  | 'checkGeoLocation'
  | 'checkRelatedEvents'
  | 'checkProcessTree'
  | 'checkFileReputation'
  | 'checkNetworkPattern';

/** Single investigation step / 單一調查步驟 */
export interface InvestigationStep {
  tool: InvestigationTool;
  reason: string;
  result?: InvestigationResult;
  durationMs?: number;
}

/** Investigation result / 調查結果 */
export interface InvestigationResult {
  finding: string;
  riskContribution: number; // 0-100
  needsAdditionalInvestigation: boolean;
  data?: Record<string, unknown>;
}

/** Investigation plan from AI / AI 產生的調查計畫 */
export interface InvestigationPlan {
  steps: InvestigationStep[];
  reasoning: string;
}

// ===== Evidence & Verdict =====

/** Evidence source type / 證據來源類型 */
export type EvidenceSource =
  | 'rule_match'
  | 'ai_analysis'
  | 'baseline_deviation'
  | 'threat_intel'
  | 'investigation';

/** Evidence item / 證據項目 */
export interface Evidence {
  source: EvidenceSource;
  description: string;
  confidence: number; // 0-100
  data?: Record<string, unknown>;
}

/** Response action type / 回應動作類型 */
export type ResponseAction =
  | 'log_only'
  | 'notify'
  | 'block_ip'
  | 'kill_process'
  | 'disable_account'
  | 'isolate_file';

/** Threat verdict from Analyze Agent / 分析代理的威脅判決 */
export interface ThreatVerdict {
  /** Conclusion / 結論 */
  conclusion: 'benign' | 'suspicious' | 'malicious';
  /** Confidence score 0-100 / 信心分數 */
  confidence: number;
  /** AI reasoning chain / AI 推理鏈 */
  reasoning: string;
  /** Supporting evidence / 支持判斷的證據 */
  evidence: Evidence[];
  /** Recommended response action / 建議的回應動作 */
  recommendedAction: ResponseAction;
  /** MITRE ATT&CK technique ID / MITRE ATT&CK 技術 ID */
  mitreTechnique?: string;
  /** Investigation steps taken / 執行的調查步驟 */
  investigationSteps?: InvestigationStep[];
}

// ===== Confidence Scoring / Action Policy =====

/** Configurable action thresholds / 可配置的動作閾值 */
export interface ActionPolicy {
  /** Auto-respond threshold (default 85) / 自動回應閾值 */
  autoRespond: number;
  /** Notify-and-wait threshold (default 50) / 通知等待閾值 */
  notifyAndWait: number;
  /** Log-only threshold (default 0) / 僅記錄閾值 */
  logOnly: number;
}

/** Default action policy / 預設動作策略 */
export const DEFAULT_ACTION_POLICY: ActionPolicy = {
  autoRespond: 85,
  notifyAndWait: 50,
  logOnly: 0,
};

// ===== Context Memory =====

/** Process pattern for baseline / 基線程序模式 */
export interface ProcessPattern {
  name: string;
  path?: string;
  frequency: number;
  firstSeen: string;
  lastSeen: string;
}

/** Connection pattern for baseline / 基線連線模式 */
export interface ConnectionPattern {
  remoteAddress: string;
  remotePort: number;
  protocol: string;
  frequency: number;
  firstSeen: string;
  lastSeen: string;
}

/** Login pattern for baseline / 基線登入模式 */
export interface LoginPattern {
  username: string;
  sourceIP?: string;
  hourOfDay: number;
  dayOfWeek: number;
  frequency: number;
  firstSeen: string;
  lastSeen: string;
}

/** Port pattern for baseline / 基線埠模式 */
export interface PortPattern {
  port: number;
  service?: string;
  firstSeen: string;
  lastSeen: string;
}

/** Environment baseline built during learning / 學習期建立的環境基線 */
export interface EnvironmentBaseline {
  normalProcesses: ProcessPattern[];
  normalConnections: ConnectionPattern[];
  normalLoginPatterns: LoginPattern[];
  normalServicePorts: PortPattern[];
  learningStarted: string;
  learningComplete: boolean;
  confidenceLevel: number; // 0-1
  lastUpdated: string;
  eventCount: number;
}

/** Deviation check result / 偏離檢查結果 */
export interface DeviationResult {
  isDeviation: boolean;
  deviationType: string;
  confidence: number; // 0-100
  description: string;
}

// ===== Detection =====

/** Detection result from Detect Agent / 偵測代理的偵測結果 */
export interface DetectionResult {
  event: SecurityEvent;
  ruleMatches: Array<{ ruleId: string; ruleName: string; severity: Severity }>;
  threatIntelMatch?: { ip: string; threat: string };
  timestamp: string;
}

// ===== Response =====

/** Response execution result / 回應執行結果 */
export interface ResponseResult {
  action: ResponseAction;
  success: boolean;
  details: string;
  timestamp: string;
  target?: string;
}

// ===== Notification =====

/** LINE Notify config / LINE Notify 配置 */
export interface LineNotifyConfig {
  accessToken: string;
}

/** Telegram Bot config / Telegram Bot 配置 */
export interface TelegramConfig {
  botToken: string;
  chatId: string;
}

/** Slack Webhook config / Slack Webhook 配置 */
export interface SlackConfig {
  webhookUrl: string;
}

/** Email SMTP config / Email SMTP 配置 */
export interface EmailConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: { user: string; pass: string };
  from: string;
  to: string[];
}

/** Notification config combining all channels / 通知配置（所有通道） */
export interface NotificationConfig {
  line?: LineNotifyConfig;
  telegram?: TelegramConfig;
  slack?: SlackConfig;
  email?: EmailConfig;
}

/** Notification result / 通知結果 */
export interface NotificationResult {
  channel: 'line' | 'telegram' | 'slack' | 'email';
  success: boolean;
  error?: string;
}

// ===== Threat Cloud =====

/** Anonymized threat data for cloud upload / 匿名化威脅數據 */
export interface AnonymizedThreatData {
  attackSourceIP: string;
  attackType: string;
  mitreTechnique: string;
  sigmaRuleMatched: string;
  timestamp: string;
  industry?: string;
  region: string;
  /** Unique event identifier / 唯一事件識別碼 */
  eventId?: string;
  /** SHA-256 hash of threat pattern / 威脅模式的 SHA-256 雜湊 */
  patternHash?: string;
  /** Confidence score 0-100 / 信心分數 */
  confidence?: number;
  /** Severity level / 嚴重等級 */
  severity?: 'low' | 'medium' | 'high' | 'critical';
  /** Auto-response action taken / 自動回應動作 */
  autoResponseTaken?: string;
  /** Panguard client version / Panguard 客戶端版本 */
  panguardVersion?: string;
  /** OS type (darwin/linux/windows) / 作業系統類型 */
  osType?: string;
}

/** Threat cloud rule update / 威脅雲規則更新 */
export interface ThreatCloudUpdate {
  ruleId: string;
  ruleContent: string;
  publishedAt: string;
  source: string;
}

/** Threat cloud status / 威脅雲狀態 */
export type ThreatCloudStatus = 'connected' | 'disconnected' | 'offline';

// ===== License =====

/** License tier / 授權等級 */
export type LicenseTier = 'free' | 'pro' | 'enterprise';

/** License info / 授權資訊 */
export interface LicenseInfo {
  key: string;
  tier: LicenseTier;
  isValid: boolean;
  expiresAt?: string;
  maxEndpoints?: number;
  features: string[];
}

/** Feature gates per tier / 各等級功能閘 */
export const TIER_FEATURES: Record<LicenseTier, string[]> = {
  free: ['basic_monitoring', 'rule_matching', 'auto_respond', 'threat_cloud_upload'],
  pro: [
    'basic_monitoring',
    'rule_matching',
    'ai_analysis',
    'auto_respond',
    'auto_fix',
    'notifications',
    'context_memory',
    'threat_cloud_upload',
    'custom_rules',
  ],
  enterprise: [
    'basic_monitoring',
    'rule_matching',
    'ai_analysis',
    'auto_respond',
    'auto_fix',
    'notifications',
    'context_memory',
    'threat_cloud',
    'threat_cloud_upload',
    'multi_endpoint',
    'priority_support',
    'custom_rules',
    'webhook_api',
  ],
};

// ===== LLM interface for PanguardGuard =====

/** LLM analysis result / LLM 分析結果 */
export interface LLMAnalysisResult {
  summary: string;
  severity: string;
  confidence: number;
  recommendations: string[];
}

/** LLM classification result / LLM 分類結果 */
export interface LLMClassificationResult {
  technique: string;
  severity: string;
  confidence: number;
  description: string;
}

/** LLM provider interface for analysis / 分析用 LLM 供應商介面 */
export interface AnalyzeLLM {
  analyze(prompt: string, context?: string): Promise<LLMAnalysisResult>;
  classify(event: SecurityEvent): Promise<LLMClassificationResult>;
  isAvailable(): Promise<boolean>;
}

// ===== Dashboard =====

/** Dashboard status data / Dashboard 狀態資料 */
export interface DashboardStatus {
  mode: 'learning' | 'protection';
  uptime: number;
  eventsProcessed: number;
  threatsDetected: number;
  actionsExecuted: number;
  learningProgress: number;
  baselineConfidence: number;
  memoryUsageMB: number;
  cpuPercent: number;
  lastEvent?: SecurityEvent;
  recentVerdicts: ThreatVerdict[];
}

/** Dashboard event for WebSocket push / WebSocket 推送事件 */
export interface DashboardEvent {
  type: 'status_update' | 'new_event' | 'new_verdict' | 'action_executed' | 'learning_progress';
  data: unknown;
  timestamp: string;
}

/** Threat map entry / 威脅地圖條目 */
export interface ThreatMapEntry {
  sourceIP: string;
  country?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  attackType: string;
  count: number;
  lastSeen: string;
}

// ===== Guard Config =====

/** Guard engine operating mode / 守護引擎運作模式 */
export type GuardMode = 'learning' | 'protection';

/** Complete guard configuration / 完整守護配置 */
export interface GuardConfig {
  lang: Language;
  mode: GuardMode;
  learningDays: number;
  actionPolicy: ActionPolicy;
  notifications: NotificationConfig;
  ai?: {
    provider: 'ollama' | 'claude' | 'openai';
    model: string;
    endpoint?: string;
    apiKey?: string;
  };
  dataDir: string;
  threatCloudEndpoint?: string;
  licenseKey?: string;
  /** CLI tier from panguard credentials (overrides key-based license) */
  cliTier?: string;
  dashboardPort: number;
  dashboardEnabled: boolean;
  verbose: boolean;
  monitors: {
    logMonitor: boolean;
    networkMonitor: boolean;
    processMonitor: boolean;
    fileMonitor: boolean;
    networkPollInterval: number;
    processPollInterval: number;
  };
  watchdogEnabled: boolean;
  watchdogInterval: number;
}

/** Guard engine status / 守護引擎狀態 */
export interface GuardStatus {
  running: boolean;
  mode: GuardMode;
  uptime: number;
  eventsProcessed: number;
  threatsDetected: number;
  actionsExecuted: number;
  learningProgress: number;
  baselineConfidence: number;
  memoryUsageMB: number;
  licenseTier: LicenseTier;
}
