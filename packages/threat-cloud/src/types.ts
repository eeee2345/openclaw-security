/**
 * Threat Cloud API type definitions
 * 威脅雲 API 型別定義
 */

/** Anonymized threat data from clients / 客戶端匿名化威脅數據 */
export interface AnonymizedThreatData {
  attackSourceIP: string;
  attackType: string;
  mitreTechnique: string;
  sigmaRuleMatched: string;
  timestamp: string;
  industry?: string;
  region: string;
}

/** Community rule update / 社群規則更新 */
export interface ThreatCloudRule {
  ruleId: string;
  ruleContent: string;
  publishedAt: string;
  source: string;
}

/** API response envelope / API 回應封套 */
export interface ApiResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

/** Threat statistics / 威脅統計 */
export interface ThreatStats {
  totalThreats: number;
  totalRules: number;
  topAttackTypes: Array<{ type: string; count: number }>;
  topMitreTechniques: Array<{ technique: string; count: number }>;
  last24hThreats: number;
  proposalStats?: { pending: number; confirmed: number; rejected: number; total: number };
  skillThreatsTotal?: number;
}

/** ATR rule proposal from client / 客戶端 ATR 規則提案 */
export interface ATRProposal {
  patternHash: string;
  ruleContent: string;
  llmProvider: string;
  llmModel: string;
  selfReviewVerdict: string;
  clientId?: string;
  status?: string;
  confirmations?: number;
}

/** Skill threat submission from audit / 技能審計威脅提交 */
export interface SkillThreatSubmission {
  skillHash: string;
  skillName: string;
  riskScore: number;
  riskLevel: string;
  findingSummaries?: Array<{
    id: string;
    category: string;
    severity: string;
    title: string;
  }>;
  clientId?: string;
}

/** Server configuration / 伺服器配置 */
export interface ServerConfig {
  port: number;
  host: string;
  dbPath: string;
  apiKeyRequired: boolean;
  apiKeys: string[];
  rateLimitPerMinute: number;
}
