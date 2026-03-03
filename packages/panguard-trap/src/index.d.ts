/**
 * PanguardTrap - Smart Honeypot System
 * PanguardTrap - 智慧蜜罐系統
 *
 * Deploys fake services to lure and profile attackers,
 * recording their tools, techniques, and intentions.
 * 部署假服務來誘捕並分析攻擊者，記錄其工具、技術和意圖。
 *
 * @module @panguard-ai/panguard-trap
 */
export declare const PANGUARD_TRAP_VERSION: string;
export declare const CLAWTRAP_NAME = "PanguardTrap";
export type { TrapServiceType, TrapServiceStatus, TrapEngineStatus, TrapServiceConfig, TrapEvent, TrapEventType, TrapSession, CredentialAttempt, AttackerSkillLevel, AttackerIntent, AttackerProfile, TrapIntelligence, TrapConfig, TrapService, SessionHandler, TrapStatistics, } from './types.js';
export { DEFAULT_SERVICE_CONFIGS, DEFAULT_TRAP_CONFIG } from './types.js';
export { createTrapService, BaseTrapService, SSHTrapService, HTTPTrapService, MySQLTrapService, RedisTrapService, SMBTrapService, RDPTrapService, GenericTrapService, } from './services/index.js';
export { AttackerProfiler, estimateSkillLevel, classifyIntent, detectTools, } from './profiler/index.js';
export { buildTrapIntel, buildBatchIntel, generateIntelSummary } from './intel/index.js';
export type { IntelSummary } from './intel/index.js';
export { TrapEngine } from './trap-engine.js';
export { PidFile } from './pid-file.js';
export { ThreatCloudUploader } from './threat-cloud-uploader.js';
export { executeCli, parseCliArgs, buildConfigFromOptions, formatStatistics, getHelpText, } from './cli/index.js';
export type { TrapCliCommand, TrapCliOptions } from './cli/index.js';
//# sourceMappingURL=index.d.ts.map