/**
 * Threat Intelligence Pipeline - Public Exports
 * 威脅情報管線 - 公開匯出
 *
 * @module @panguard-ai/threat-cloud/threat-intel
 */

// Original adapters
export { HackerOneAdapter } from './hackerone-adapter.js';

// Multi-source adapters
export {
  NvdAdapter,
  CisaKevAdapter,
  MitreAttackAdapter,
  UrlhausAdapter,
  MalwareBazaarAdapter,
  ThreatFoxAdapter,
  OsvAdapter,
  GitHubAdvisoryAdapter,
  OtxAdapter,
  ExploitDbAdapter,
} from './adapters/index.js';

// Extraction & rule generation
export { AttackExtractor } from './attack-extractor.js';
export { SigmaRuleGenerator } from './sigma-rule-generator.js';
export { YaraRuleGenerator } from './yara-rule-generator.js';
export { RuleValidator } from './rule-validator.js';
export { DataValidator } from './data-validator.js';

// Types
export type {
  HackerOneHacktivityItem,
  HackerOneHacktivityResponse,
  StoredReport,
  ExtractedAttackPattern,
  ExtractionResult,
  GeneratedRule,
  GeneratedYaraRule,
  RuleValidationResult,
  HackerOneConfig,
  ExtractorConfig,
  SyncStatus,
  ThreatSource,
  SourceReliability,
  ThreatIntelRecord,
  ThreatIndicator,
  AffectedProduct,
  ValidationStatus,
  ValidationCheck,
  ThreatIntelAdapter,
  AdapterConfig,
} from './types.js';
