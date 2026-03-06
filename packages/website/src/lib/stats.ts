/**
 * Single source of truth for all marketing statistics.
 *
 * Derived from (verified 2026-03-03):
 *   config/sigma-rules/       -> 3,155 YAML files (3,110 community + 45 custom)
 *   config/yara-rules/        -> 5,895 rule definitions across 926 files (923 community + 3 custom)
 *   packages/panguard-trap/src/types.ts        -> TrapServiceType union (8 protocols)
 *   packages/panguard-guard/src/types.ts       -> ResponseAction union (6 types)
 *   packages/core/src/ai/funnel-router.ts      -> 3 layers
 *   vitest run (142 test files)                -> 3,017 test cases
 *   packages/panguard/src/cli/index.ts         -> 21 top-level commands (incl. doctor, code)
 *   packages/panguard-report/src/frameworks/   -> 50 controls (ISO:30 + SOC2:10 + TCSA:10)
 *   packages/panguard-mcp/src/server.ts        -> 11 MCP tools
 *   packages/panguard-scan/src/scanners/sast-checker.ts -> 16 SAST patterns
 *   packages/panguard-guard/src/playbook/      -> 3 playbook templates
 *   packages/panguard-guard/src/collectors/     -> 4 log parsers
 *
 * When rules are added/removed, update the numbers here and the entire
 * site picks them up automatically.
 */
export const STATS = {
  /** Must match packages/panguard/package.json "version" */
  cliVersion: '0.3.0',
  sigmaRules: 3_155,
  yaraRules: 5_895,
  totalRules: 3_155 + 5_895,
  falcoConfigs: 1,
  testsPassing: 3_017,
  testFiles: 142,
  honeypotProtocols: 8,
  detectionLayers: 3,
  responseActions: 6,
  complianceControls: 50,
  cliCommands: 22,
  products: 8,
  aiAgents: 4,
  mcpTools: 11,
  /** 8 SAST code patterns + 8 secrets patterns */
  sastPatterns: 16,
  playbookTemplates: 3,
  logParsers: 4,
  license: 'MIT' as const,
  skillAuditChecks: 5,
  lastUpdated: '2026-03-06',
} as const;

export type Stats = typeof STATS;

/** Product maturity label */
export type MaturityLevel = 'GA' | 'Beta' | 'Roadmap';

/** Maturity status for each feature / product */
export const MATURITY: Record<string, MaturityLevel> = {
  scan: 'GA',
  guard: 'GA',
  chat: 'GA',
  trap: 'GA',
  report: 'GA',
  threatCloud: 'GA',
  manager: 'GA',
  skillAuditor: 'Beta',
  mcp: 'Beta',
  sast: 'Beta',
  soarPlaybooks: 'Beta',
  logCollectors: 'Beta',
  anomalyScoring: 'Beta',
  dashboardRelay: 'Beta',
  investigationLLM: 'Beta',
};
