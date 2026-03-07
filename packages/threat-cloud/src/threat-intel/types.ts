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
