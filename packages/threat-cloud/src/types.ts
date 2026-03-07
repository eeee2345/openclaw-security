/**
 * Threat Cloud API type definitions
 * 威脅雲 API 型別定義
 */

// ---------------------------------------------------------------------------
// Existing types (backward compatible) / 既有型別（向後相容）
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Phase 1: IoC Management + Trap Intelligence / IoC 管理 + Trap 情報
// ---------------------------------------------------------------------------

/** IoC type categories / IoC 類型分類 */
export type IoCType = 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256';

/** IoC status / IoC 狀態 */
export type IoCStatus = 'active' | 'expired' | 'revoked' | 'under_review';

/** Stored IoC record / 儲存的 IoC 記錄 */
export interface IoCRecord {
  id: number;
  type: IoCType;
  value: string;
  normalizedValue: string;
  threatType: string;
  source: string;
  confidence: number;
  reputationScore: number;
  firstSeen: string;
  lastSeen: string;
  sightings: number;
  status: IoCStatus;
  tags: string[];
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

/** Input for creating/updating an IoC / 建立或更新 IoC 的輸入 */
export interface IoCInput {
  type: IoCType;
  value: string;
  threatType: string;
  source: string;
  confidence: number;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

/** IoC lookup result / IoC 查詢結果 */
export interface IoCLookupResult {
  found: boolean;
  ioc?: IoCRecord;
  relatedThreats: number;
}

/** TrapIntelligence payload from Trap agents / Trap 代理的情報資料 */
export interface TrapIntelligencePayload {
  timestamp: string;
  serviceType: string;
  sourceIP: string;
  attackType: string;
  mitreTechniques: string[];
  skillLevel: string;
  intent: string;
  tools: string[];
  topCredentials: Array<{ username: string; count: number }>;
  region?: string;
}

/** Enriched threat event (Guard + Trap unified) / 豐富化威脅事件 */
export interface EnrichedThreatEvent {
  id: number;
  sourceType: 'guard' | 'trap' | 'external_feed';
  attackSourceIP: string;
  attackType: string;
  mitreTechniques: string[];
  sigmaRuleMatched: string;
  timestamp: string;
  industry?: string;
  region: string;
  confidence: number;
  severity: string;
  serviceType?: string;
  skillLevel?: string;
  intent?: string;
  tools?: string[];
  eventHash: string;
  receivedAt: string;
  campaignId?: string;
}

/** Pagination parameters / 分頁參數 */
export interface PaginationParams {
  page: number;
  limit: number;
}

/** Paginated response / 分頁回應 */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
}

// ---------------------------------------------------------------------------
// Phase 2: Reputation + Correlation / 信譽評分 + 威脅關聯
// ---------------------------------------------------------------------------

/** Campaign record / 攻擊活動記錄 */
export interface Campaign {
  campaignId: string;
  name: string;
  campaignType: 'ip_cluster' | 'pattern_cluster' | 'manual';
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  uniqueIPs: number;
  attackTypes: string[];
  mitreTechniques: string[];
  regions: string[];
  severity: string;
  status: 'active' | 'resolved' | 'false_positive';
  createdAt: string;
  updatedAt: string;
}

/** Campaign scan result / 關聯掃描結果 */
export interface CampaignScanResult {
  newCampaigns: number;
  updatedCampaigns: number;
  eventsCorrelated: number;
  duration: number;
}

/** Campaign statistics / 攻擊活動統計 */
export interface CampaignStats {
  totalCampaigns: number;
  activeCampaigns: number;
  totalCorrelatedEvents: number;
  topAttackTypes: Array<{ type: string; count: number }>;
}

/** Reputation configuration / 信譽評分配置 */
export interface ReputationConfig {
  halfLifeDays: number;
  weights: {
    sighting: number;
    severity: number;
    recency: number;
    diversity: number;
    confidence: number;
  };
}

/** Correlation configuration / 關聯引擎配置 */
export interface CorrelationConfig {
  timeWindowMinutes: number;
  minEventsForCampaign: number;
  minIPsForPatternCampaign: number;
  scanWindowHours: number;
}

// ---------------------------------------------------------------------------
// Phase 3: Rule Generation / 自動規則產生
// ---------------------------------------------------------------------------

/** Detected pattern for rule generation / 偵測到的模式 */
export interface DetectedPattern {
  attackType: string;
  mitreTechniques: string[];
  patternHash: string;
  occurrences: number;
  distinctIPs: number;
  regions: string[];
  severityCounts: Record<string, number>;
  firstSeen: string;
  lastSeen: string;
}

/** Rule generation result / 規則產生結果 */
export interface RuleGenerationResult {
  patternsAnalyzed: number;
  rulesGenerated: number;
  rulesUpdated: number;
  duration: number;
}

/** Rule generator configuration / 規則產生器配置 */
export interface RuleGeneratorConfig {
  minOccurrences: number;
  analysisWindowHours: number;
  minDistinctIPs: number;
}

// ---------------------------------------------------------------------------
// Phase 4: Query API + Feed Distribution / 查詢 API + 情報分發
// ---------------------------------------------------------------------------

/** Time-series data point / 時間序列資料點 */
export interface TimeSeriesPoint {
  timestamp: string;
  count: number;
}

/** Geographic distribution entry / 地理分佈項目 */
export interface GeoDistributionEntry {
  region: string;
  count: number;
  topAttackTypes: Array<{ type: string; count: number }>;
  uniqueIPs: number;
}

/** Trend entry / 趨勢項目 */
export interface TrendEntry {
  attackType: string;
  currentCount: number;
  previousCount: number;
  changePercent: number;
  direction: 'rising' | 'falling' | 'stable';
}

/** MITRE ATT&CK heatmap entry / MITRE 熱力圖項目 */
export interface MitreHeatmapEntry {
  technique: string;
  count: number;
  severity: string;
}

/** Enhanced stats (extends ThreatStats) / 增強統計 */
export interface EnhancedStats extends ThreatStats {
  totalIoCs: number;
  iocsByType: Record<string, number>;
  activeCampaigns: number;
  autoGeneratedRules: number;
  trapEventsCount: number;
  guardEventsCount: number;
  topRegions: Array<{ region: string; count: number }>;
}

/** IoC feed entry / IoC feed 項目 */
export interface IoCFeedEntry {
  type: IoCType;
  value: string;
  threatType: string;
  reputation: number;
  confidence: number;
  lastSeen: string;
  tags: string[];
}

/** IoC feed response / IoC feed 回應 */
export interface IoCFeedResponse {
  generatedAt: string;
  totalEntries: number;
  entries: IoCFeedEntry[];
}

/** Agent update package / Agent 更新包 */
export interface AgentUpdatePackage {
  generatedAt: string;
  rules: ThreatCloudRule[];
  iocs: IoCFeedEntry[];
  stats: {
    newRules: number;
    newIoCs: number;
    totalActiveIoCs: number;
  };
}

/** Scheduler configuration / 排程器配置 */
export interface SchedulerConfig {
  reputationIntervalMs: number;
  correlationIntervalMs: number;
  ruleGenerationIntervalMs: number;
  threatRetentionDays: number;
  iocRetentionDays: number;
  aggregationIntervalMs: number;
}

// ---------------------------------------------------------------------------
// Phase A: Audit + Provenance + Security / 審計 + 溯源 + 資安強化
// ---------------------------------------------------------------------------

/**
 * Admiralty Scale source reliability rating.
 * A = Completely reliable, B = Usually reliable, C = Fairly reliable,
 * D = Not usually reliable, E = Unreliable, F = Cannot be judged
 */
export type SourceReliability = 'A' | 'B' | 'C' | 'D' | 'E' | 'F';

/** Sighting type / 觀測類型 */
export type SightingType = 'positive' | 'negative' | 'false_positive';

/** Sighting input / 觀測輸入 */
export interface SightingInput {
  iocId: number;
  type: SightingType;
  source: string;
  confidence?: number;
  details?: string;
}

/** Stored sighting record / 儲存的觀測記錄 */
export interface SightingRecord {
  id: number;
  iocId: number;
  type: SightingType;
  source: string;
  confidence: number;
  details: string;
  actorHash: string;
  createdAt: string;
}

/** Audit log action / 稽核日誌動作 */
export type AuditAction =
  | 'ioc_create'
  | 'ioc_update'
  | 'ioc_revoke'
  | 'sighting_create'
  | 'threat_upload'
  | 'trap_intel_upload'
  | 'rule_publish'
  | 'rule_generate'
  | 'campaign_create'
  | 'feed_access'
  | 'skill_threat_submit';

/** Audit log entry / 稽核日誌項目 */
export interface AuditLogEntry {
  id: number;
  action: AuditAction;
  entityType: string;
  entityId: string;
  actorHash: string;
  ipAddress: string;
  details: string;
  createdAt: string;
}

/** Audit log query params / 稽核日誌查詢參數 */
export interface AuditLogQuery {
  action?: AuditAction;
  entityType?: string;
  entityId?: string;
  since?: string;
  limit?: number;
}

// ---------------------------------------------------------------------------
// Phase B: Skill Threat Intelligence / AI Skill 威脅情報
// ---------------------------------------------------------------------------

/** Skill threat submission from Skill Auditor instances */
export interface SkillThreatSubmission {
  /** SHA-256 hash of the SKILL.md content */
  skillHash: string;
  /** Skill name (from manifest) */
  skillName: string;
  /** Risk score from auditor (0-100) */
  riskScore: number;
  /** Risk level */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /** Anonymized finding summaries (no raw content) */
  findingSummaries: SkillFindingSummary[];
  /** Skill source registry (e.g. "openclaw", "github", "local") */
  sourceRegistry?: string;
  /** Auditor version */
  auditorVersion?: string;
}

/** Anonymized finding summary for Threat Cloud sharing */
export interface SkillFindingSummary {
  id: string;
  category: string;
  severity: string;
  /** Generic title, no line-specific content */
  title: string;
}

/** Stored skill threat record in Threat Cloud */
export interface SkillThreatRecord {
  id: number;
  skillHash: string;
  skillName: string;
  /** Aggregate risk score (weighted average across submissions) */
  aggregateRiskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /** Number of times this skill has been scanned across all users */
  scanCount: number;
  /** Most common findings across all submissions */
  topFindings: SkillFindingSummary[];
  firstSeen: string;
  lastSeen: string;
  /** Community trust: positive scans / total scans */
  trustRatio: number;
  createdAt: string;
  updatedAt: string;
}

/** Skill threat lookup result */
export interface SkillThreatLookup {
  found: boolean;
  record?: SkillThreatRecord;
  /** "safe" | "suspicious" | "dangerous" | "unknown" */
  verdict: 'safe' | 'suspicious' | 'dangerous' | 'unknown';
}

/** Feed license info for compliance / Feed 授權資訊 */
export type FeedLicense =
  | 'public_domain'
  | 'cc0'
  | 'fair_use'
  | 'commercial_restricted'
  | 'unknown';

/** Source reliability mapping for known feeds / 已知 feed 的來源可靠度對映 */
export interface FeedSourceConfig {
  name: string;
  reliability: SourceReliability;
  license: FeedLicense;
  redistributable: boolean;
}
