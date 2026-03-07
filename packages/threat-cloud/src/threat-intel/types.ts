/**
 * Threat Intelligence Pipeline - Type Definitions
 * 威脅情報管線 - 型別定義
 *
 * @module @panguard-ai/threat-cloud/threat-intel/types
 */

// ---------------------------------------------------------------------------
// HackerOne Hacktivity types (matches actual API response)
// ---------------------------------------------------------------------------

/** Raw HackerOne hacktivity item from the API */
export interface HackerOneHacktivityItem {
  id: number;
  type: string;
  attributes: {
    title: string | null;
    substate: string | null;
    url: string | null;
    disclosed_at: string | null;
    vulnerability_information: string | null;
    cve_ids: string[] | null;
    cwe: string | null;
    severity_rating: string | null;
    votes: number;
    total_awarded_amount: number | null;
    latest_disclosable_action: string;
    latest_disclosable_activity_at: string;
    submitted_at: string;
    disclosed: boolean;
  };
  relationships?: {
    report_generated_content?: {
      data: {
        type: string;
        attributes: {
          hacktivity_summary: string;
        };
      } | null;
    };
    reporter?: {
      data: {
        type: string;
        attributes: { name: string; username: string };
      };
    };
    program?: {
      data: {
        type: string;
        attributes: { handle: string; name: string };
      };
    };
  };
}

/** Paginated response from HackerOne Hacktivity API */
export interface HackerOneHacktivityResponse {
  data: HackerOneHacktivityItem[];
  links: {
    self?: string;
    next?: string;
    prev?: string;
  };
}

/** Stored report after ingestion */
export interface StoredReport {
  id: string;
  title: string;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  cweId: string | null;
  cweName: string | null;
  cveIds: string[];
  summary: string | null;
  disclosedAt: string;
  programHandle: string | null;
  programName: string | null;
  reporterUsername: string | null;
  url: string;
  fetchedAt: string;
}

// ---------------------------------------------------------------------------
// Attack Pattern Extraction
// ---------------------------------------------------------------------------

/** Extracted attack pattern from NLP analysis */
export interface ExtractedAttackPattern {
  /** Attack type label (e.g. "SSRF", "XSS", "SQLi") */
  attackType: string;
  /** Affected endpoint patterns (e.g. "/api/v1/admin/*") */
  endpointPatterns: string[];
  /** Payload signatures for detection */
  payloadSignatures: string[];
  /** CWE classification */
  cweIds: string[];
  /** MITRE ATT&CK technique IDs */
  mitreTechniques: string[];
  /** Log source category for Sigma rule */
  logSourceCategory: string;
  /** Log source product */
  logSourceProduct: string;
  /** Confidence of extraction (0-100) */
  confidence: number;
  /** Brief description of the attack pattern */
  description: string;
}

/** Extraction result wrapping pattern + metadata */
export interface ExtractionResult {
  reportId: string;
  reportTitle: string;
  reportUrl: string;
  patterns: ExtractedAttackPattern[];
  extractedAt: string;
  model: string;
}

// ---------------------------------------------------------------------------
// Generated Rule
// ---------------------------------------------------------------------------

/** A generated Sigma rule with metadata */
export interface GeneratedRule {
  /** Auto-generated UUID */
  id: string;
  /** YAML content of the Sigma rule */
  yamlContent: string;
  /** Source report ID */
  sourceReportId: string;
  /** Source report URL */
  sourceReportUrl: string;
  /** Attack type this rule detects */
  attackType: string;
  /** Confidence score (0-100) */
  confidence: number;
  /** Rule status: draft if confidence < 70, experimental otherwise */
  status: 'draft' | 'experimental';
  /** Generation timestamp */
  generatedAt: string;
  /** Whether reviewed by human */
  reviewed: boolean;
  /** Review decision */
  reviewDecision: 'pending' | 'approved' | 'rejected' | null;
}

// ---------------------------------------------------------------------------
// Generated YARA Rule
// ---------------------------------------------------------------------------

/** A generated YARA rule with metadata */
export interface GeneratedYaraRule {
  /** Auto-generated rule name */
  id: string;
  /** YARA rule content */
  ruleContent: string;
  /** Source report ID */
  sourceReportId: string;
  /** Source report URL */
  sourceReportUrl: string;
  /** Attack type this rule detects */
  attackType: string;
  /** Confidence score (0-100) */
  confidence: number;
  /** Rule status: draft if confidence < 70, experimental otherwise */
  status: 'draft' | 'experimental';
  /** Generation timestamp */
  generatedAt: string;
  /** Whether reviewed by human */
  reviewed: boolean;
  /** Review decision */
  reviewDecision: 'pending' | 'approved' | 'rejected' | null;
}

// ---------------------------------------------------------------------------
// Rule Validation
// ---------------------------------------------------------------------------

/** Validation result for a generated Sigma rule */
export interface RuleValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  isDuplicate: boolean;
  duplicateOf: string | null;
}

// ---------------------------------------------------------------------------
// Pipeline Configuration
// ---------------------------------------------------------------------------

/** HackerOne adapter configuration */
export interface HackerOneConfig {
  /** Minimum severity to fetch (default: 'medium') */
  minSeverity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  /** Max reports per sync (default: 100) */
  maxReports: number;
  /** Request timeout in ms (default: 30000) */
  requestTimeoutMs: number;
  /** Rate limit: max requests per minute (default: 10) */
  rateLimitPerMinute: number;
}

/** Ollama extraction configuration */
export interface ExtractorConfig {
  /** Ollama API base URL (default: http://localhost:11434) */
  ollamaBaseUrl: string;
  /** Model name (default: 'llama3.2') */
  model: string;
  /** Request timeout in ms (default: 120000) */
  requestTimeoutMs: number;
  /** Minimum confidence to accept extraction (default: 40) */
  minConfidence: number;
}

/** Pipeline sync status */
export interface SyncStatus {
  lastSyncAt: string | null;
  totalReports: number;
  totalRulesGenerated: number;
  totalRulesApproved: number;
  totalRulesDraft: number;
  totalRulesRejected: number;
}

// ---------------------------------------------------------------------------
// Unified Threat Intelligence Types (multi-source)
// ---------------------------------------------------------------------------

/** All supported threat intel data sources */
export type ThreatSource =
  | 'hackerone'
  | 'nvd'
  | 'cisa-kev'
  | 'mitre-attack'
  | 'urlhaus'
  | 'malwarebazaar'
  | 'threatfox'
  | 'osv'
  | 'github-advisory'
  | 'alienvault-otx'
  | 'exploitdb';

/** Source reliability tier */
export type SourceReliability = 'authoritative' | 'high' | 'medium' | 'community';

/** Unified threat intel record normalized across all sources */
export interface ThreatIntelRecord {
  /** Unique ID (source-prefixed, e.g. "nvd:CVE-2024-1234") */
  id: string;
  /** Original source */
  source: ThreatSource;
  /** Record type */
  type: 'vulnerability' | 'ioc' | 'technique' | 'exploit' | 'malware';
  /** Title/name */
  title: string;
  /** Description/summary */
  description: string | null;
  /** Severity (normalized) */
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  /** CVSS score if available (0-10) */
  cvssScore: number | null;
  /** CVE IDs */
  cveIds: string[];
  /** CWE IDs */
  cweIds: string[];
  /** MITRE ATT&CK technique IDs */
  mitreTechniques: string[];
  /** IOC indicators (IPs, domains, URLs, hashes) */
  indicators: ThreatIndicator[];
  /** Affected products/packages */
  affectedProducts: AffectedProduct[];
  /** Reference URLs */
  references: string[];
  /** When the record was published/disclosed */
  publishedAt: string;
  /** When last modified at source */
  modifiedAt: string | null;
  /** When Panguard fetched it */
  fetchedAt: string;
  /** Source reliability */
  sourceReliability: SourceReliability;
  /** Data validation result */
  validation: ValidationStatus;
}

/** Threat indicator (IOC) */
export interface ThreatIndicator {
  type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'email' | 'filename';
  value: string;
  /** Indicator context (e.g. "c2_server", "phishing_url", "malware_hash") */
  context: string | null;
  /** First seen timestamp */
  firstSeen: string | null;
  /** Last seen timestamp */
  lastSeen: string | null;
}

/** Affected product/package */
export interface AffectedProduct {
  /** Product/package name */
  name: string;
  /** Vendor/ecosystem */
  vendor: string | null;
  /** Affected version range */
  versionRange: string | null;
  /** Fixed version */
  fixedVersion: string | null;
}

/** Validation status attached to every ingested record */
export interface ValidationStatus {
  /** Whether the record passed all validation checks */
  valid: boolean;
  /** Validation score (0-100) */
  score: number;
  /** Individual check results */
  checks: ValidationCheck[];
  /** Timestamp of validation */
  validatedAt: string;
}

/** Individual validation check */
export interface ValidationCheck {
  name: string;
  passed: boolean;
  message: string;
}

// ---------------------------------------------------------------------------
// NVD Types
// ---------------------------------------------------------------------------

/** NVD CVE API 2.0 response */
export interface NvdCveResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: NvdVulnerability[];
}

export interface NvdVulnerability {
  cve: {
    id: string;
    sourceIdentifier: string;
    published: string;
    lastModified: string;
    descriptions: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: { baseScore: number; baseSeverity: string; vectorString: string };
      }>;
      cvssMetricV2?: Array<{
        cvssData: { baseScore: number };
      }>;
    };
    weaknesses?: Array<{
      description: Array<{ lang: string; value: string }>;
    }>;
    configurations?: Array<{
      nodes: Array<{
        cpeMatch: Array<{
          vulnerable: boolean;
          criteria: string;
          versionStartIncluding?: string;
          versionEndExcluding?: string;
        }>;
      }>;
    }>;
    references?: Array<{ url: string; source?: string; tags?: string[] }>;
  };
}

// ---------------------------------------------------------------------------
// CISA KEV Types
// ---------------------------------------------------------------------------

export interface CisaKevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CisaKevEntry[];
}

export interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  notes: string;
}

// ---------------------------------------------------------------------------
// Abuse.ch URLhaus Types
// ---------------------------------------------------------------------------

export interface UrlhausRecentResponse {
  query_status: string;
  urls: UrlhausEntry[];
}

export interface UrlhausEntry {
  id: string;
  url: string;
  url_status: 'online' | 'offline';
  host: string;
  date_added: string;
  threat: string;
  tags: string[] | null;
  reporter: string;
}

// ---------------------------------------------------------------------------
// Abuse.ch MalwareBazaar Types
// ---------------------------------------------------------------------------

export interface MalwareBazaarResponse {
  query_status: string;
  data: MalwareBazaarEntry[] | null;
}

export interface MalwareBazaarEntry {
  sha256_hash: string;
  md5_hash: string;
  sha1_hash: string;
  first_seen: string;
  last_seen: string | null;
  file_name: string | null;
  file_type: string | null;
  file_size: number;
  signature: string | null;
  tags: string[] | null;
  intelligence?: {
    clamav?: string[] | null;
    yara_rules?: Array<{ rule_name: string }> | null;
  };
}

// ---------------------------------------------------------------------------
// Abuse.ch ThreatFox Types
// ---------------------------------------------------------------------------

export interface ThreatFoxResponse {
  query_status: string;
  data: ThreatFoxEntry[] | null;
}

export interface ThreatFoxEntry {
  id: string;
  ioc: string;
  ioc_type: string;
  threat_type: string;
  malware: string;
  confidence_level: number;
  first_seen: string;
  last_seen: string | null;
  tags: string[] | null;
  reference: string | null;
}

// ---------------------------------------------------------------------------
// AlienVault OTX Types
// ---------------------------------------------------------------------------

export interface OtxPulseResponse {
  results: OtxPulse[];
  count: number;
  next: string | null;
}

export interface OtxPulse {
  id: string;
  name: string;
  description: string;
  created: string;
  modified: string;
  indicators: OtxIndicator[];
  tags: string[];
  references: string[];
  tlp: string;
  adversary: string;
}

export interface OtxIndicator {
  type: string;
  indicator: string;
  created: string;
  title: string;
  description: string;
}

// ---------------------------------------------------------------------------
// OSV.dev Types
// ---------------------------------------------------------------------------

export interface OsvQueryResponse {
  vulns: OsvVulnerability[];
  next_page_token?: string;
}

export interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  modified: string;
  published: string;
  aliases: string[];
  severity: Array<{ type: string; score: string }>;
  affected: Array<{
    package: { ecosystem: string; name: string };
    ranges: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  references: Array<{ type: string; url: string }>;
}

// ---------------------------------------------------------------------------
// GitHub Advisory Types
// ---------------------------------------------------------------------------

export interface GhsaAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description: string;
  severity: string;
  cvss: { score: number; vector_string: string } | null;
  cwes: Array<{ cwe_id: string; name: string }>;
  published_at: string;
  updated_at: string;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    vulnerable_version_range: string;
    first_patched_version: string | null;
  }>;
  references: string[];
}

// ---------------------------------------------------------------------------
// Adapter Interface
// ---------------------------------------------------------------------------

/** Common configuration for all adapters */
export interface AdapterConfig {
  /** Request timeout in ms */
  requestTimeoutMs: number;
  /** Rate limit: max requests per minute */
  rateLimitPerMinute: number;
  /** Max records per sync */
  maxRecords: number;
}

/** Common interface for all threat intel source adapters */
export interface ThreatIntelAdapter {
  /** Source identifier */
  readonly source: ThreatSource;
  /** Fetch and validate records from the source */
  fetch(since?: string): Promise<ThreatIntelRecord[]>;
}
