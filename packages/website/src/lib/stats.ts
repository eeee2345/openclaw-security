/**
 * Single source of truth for all marketing statistics.
 *
 * Derived from:
 *   config/sigma-rules/  -> 3,155 YAML files
 *   config/yara-rules/   -> 5,895 rule definitions (926 files)
 *   packages/panguard-trap/src/types.ts -> TrapServiceType union (8 protocols)
 *   packages/panguard-guard/src/types.ts -> ResponseAction union (6 types)
 *   packages/core/src/ai/funnel-router.ts -> 3 layers
 *   vitest run -> 1,420 tests passing (87 test files)
 *   packages/panguard/src/cli/commands/ -> 25 unique subcommands
 *   packages/panguard-report/src/frameworks/ -> 50 controls (ISO:30 + SOC2:10 + TCSA:10)
 *
 * When rules are added/removed, update the numbers here and the entire
 * site picks them up automatically.
 */
export const STATS = {
  sigmaRules: 3_155,
  yaraRules: 5_895,
  totalRules: 3_155 + 5_895,
  falcoConfigs: 1,
  testsPassing: 1_420,
  honeypotProtocols: 8,
  detectionLayers: 3,
  responseActions: 6,
  complianceControls: 216,
  cliCommands: 25,
  products: 6,
  aiAgents: 4,
  license: 'MIT' as const,
} as const;

export type Stats = typeof STATS;
