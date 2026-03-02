/**
 * Config Writer - Generates PanguardConfig from wizard answers
 * 配置產生器 - 從精靈答案產生 PanguardConfig
 *
 * @module @panguard-ai/panguard/init/config-writer
 */

import { mkdirSync, writeFileSync, chmodSync, readFileSync } from 'node:fs';
import * as os from 'node:os';
import { join } from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type {
  WizardAnswers,
  PanguardConfig,
  ProtectionLevel,
  AiPreference,
  UsageProfile,
  EnhancedEnvironment,
  Lang,
} from './types.js';

const logger = createLogger('panguard:init:config');

/**
 * Build a PanguardConfig from wizard answers.
 */
export function buildPanguardConfig(answers: WizardAnswers): PanguardConfig {
  const goals = expandGoals(answers.securityGoals);
  const compliance = answers.compliance ? [answers.compliance] : [];
  const modules = deriveModules(goals);
  const guardPolicy = deriveGuardPolicy(answers.protectionLevel);
  const trapServices = deriveTrapServices(goals);

  return {
    version: '1.0.0',
    meta: {
      createdAt: new Date().toISOString(),
      language: answers.language,
    },
    organization: {
      name: answers.orgName,
      size: answers.orgSize,
      industry: answers.industry,
    },
    environment: {
      os: answers.environment.os,
      hostname: answers.environment.hostname,
      arch: os.arch(),
      deployType: answers.environment.deployType,
      serverCount: answers.environment.serverCount,
    },
    security: {
      goals,
      compliance,
      protectionLevel: answers.protectionLevel,
    },
    guard: {
      mode: guardPolicy.mode,
      learningDays: guardPolicy.learningDays,
      actionPolicy: {
        autoRespond: guardPolicy.autoRespond,
        notifyAndWait: guardPolicy.notifyAndWait,
      },
      monitors: {
        logMonitor: true,
        networkMonitor: true,
        processMonitor: true,
        fileMonitor: goals.includes('realtime'),
      },
    },
    ai: {
      preference: answers.aiPreference,
      provider: deriveAiProvider(answers.aiPreference),
    },
    notifications: {
      channel: answers.notification.channel,
      config: answers.notification.config,
    },
    trap: {
      enabled: goals.includes('honeypot'),
      services: trapServices,
    },
    modules,
  };
}

/**
 * Write config to ~/.panguard/config.json
 */
export function writeConfig(config: PanguardConfig): string {
  const configDir = join(os.homedir(), '.panguard');
  const configPath = join(configDir, 'config.json');

  // Create directory with restricted permissions (owner-only on Unix)
  mkdirSync(configDir, { recursive: true, mode: 0o700 });

  // Enforce directory permissions even if directory pre-existed
  try {
    chmodSync(configDir, 0o700);
  } catch {
    // Windows doesn't support chmod the same way
  }

  // Write config with restricted permissions
  const json = JSON.stringify(config, null, 2);
  writeFileSync(configPath, json, { encoding: 'utf-8' });

  // Set file permissions to owner-only (0600) on Unix
  try {
    chmodSync(configPath, 0o600);
  } catch {
    // Windows doesn't support chmod the same way
  }

  logger.info(`Config written to ${configPath}`);
  return configPath;
}

/**
 * Read config from ~/.panguard/config.json
 * Validates schema before returning.
 */
export function readConfig(): PanguardConfig | null {
  const configPath = join(os.homedir(), '.panguard', 'config.json');
  try {
    const json = readFileSync(configPath, 'utf-8');
    const parsed: unknown = JSON.parse(json);
    if (!validateConfigSchema(parsed)) {
      logger.warn('Config file has invalid schema, ignoring');
      return null;
    }
    return parsed as PanguardConfig;
  } catch (err) {
    if (err instanceof Error && (err as NodeJS.ErrnoException).code !== 'ENOENT') {
      logger.warn(`Failed to read config: ${err.message}`);
    }
    return null;
  }
}

const VALID_PROTECTION_LEVELS = ['aggressive', 'balanced', 'learning'];
const VALID_DEPLOY_TYPES = ['cloud', 'on-prem', 'hybrid'];

/**
 * Validate that an object matches the PanguardConfig schema.
 * Checks top-level structure and critical nested fields.
 */
export function validateConfigSchema(obj: unknown): boolean {
  if (!obj || typeof obj !== 'object') return false;
  const c = obj as Record<string, unknown>;

  // Top-level required fields
  if (typeof c['version'] !== 'string') return false;
  if (!c['meta'] || typeof c['meta'] !== 'object') return false;
  if (!c['organization'] || typeof c['organization'] !== 'object') return false;
  if (!c['environment'] || typeof c['environment'] !== 'object') return false;
  if (!c['security'] || typeof c['security'] !== 'object') return false;

  // Validate critical nested fields
  const org = c['organization'] as Record<string, unknown>;
  if (typeof org['name'] !== 'string') return false;

  const env = c['environment'] as Record<string, unknown>;
  if (typeof env['deployType'] === 'string' && !VALID_DEPLOY_TYPES.includes(env['deployType'])) {
    return false;
  }

  const sec = c['security'] as Record<string, unknown>;
  if (
    typeof sec['protectionLevel'] === 'string' &&
    !VALID_PROTECTION_LEVELS.includes(sec['protectionLevel'])
  ) {
    return false;
  }

  return true;
}

/**
 * Build a PanguardConfig from a quick-setup usage profile.
 * Maps the profile + auto-detected environment to a full config.
 */
export function buildQuickConfig(
  profile: UsageProfile,
  lang: Lang,
  env: EnhancedEnvironment
): PanguardConfig {
  const profileDefaults = PROFILE_DEFAULTS[profile];
  const goals = expandGoals('all');
  const modules = deriveModules(goals);
  const guardPolicy = deriveGuardPolicy(profileDefaults.protectionLevel);
  const trapServices = deriveTrapServices(goals);

  return {
    version: '1.0.0',
    meta: {
      createdAt: new Date().toISOString(),
      language: lang,
    },
    organization: {
      name:
        profile === 'personal'
          ? env.hostname.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 64)
          : profile === 'team'
            ? 'My Team'
            : 'Enterprise',
      size: profileDefaults.orgSize,
      industry: 'tech',
    },
    environment: {
      os: env.os,
      hostname: env.hostname,
      arch: env.arch,
      deployType: profileDefaults.deployType,
      serverCount: profile === 'enterprise' ? 10 : 1,
    },
    security: {
      goals,
      compliance: profileDefaults.compliance,
      protectionLevel: profileDefaults.protectionLevel,
    },
    guard: {
      mode: guardPolicy.mode,
      learningDays: guardPolicy.learningDays,
      actionPolicy: {
        autoRespond: guardPolicy.autoRespond,
        notifyAndWait: guardPolicy.notifyAndWait,
      },
      monitors: {
        logMonitor: true,
        networkMonitor: true,
        processMonitor: true,
        fileMonitor: true,
      },
    },
    ai: {
      preference: profileDefaults.aiPreference,
      provider: deriveAiProvider(profileDefaults.aiPreference),
    },
    notifications: {
      channel: 'none',
      config: {},
    },
    trap: {
      enabled: true,
      services: trapServices,
    },
    modules,
  };
}

/** Profile-to-settings mapping. */
const PROFILE_DEFAULTS: Record<
  UsageProfile,
  {
    orgSize: PanguardConfig['organization']['size'];
    deployType: PanguardConfig['environment']['deployType'];
    protectionLevel: ProtectionLevel;
    aiPreference: AiPreference;
    compliance: string[];
  }
> = {
  personal: {
    orgSize: 'individual',
    deployType: 'cloud',
    protectionLevel: 'balanced',
    aiPreference: 'cloud_ai',
    compliance: [],
  },
  team: {
    orgSize: 'small',
    deployType: 'cloud',
    protectionLevel: 'balanced',
    aiPreference: 'cloud_ai',
    compliance: [],
  },
  enterprise: {
    orgSize: 'large',
    deployType: 'hybrid',
    protectionLevel: 'learning',
    aiPreference: 'cloud_ai',
    compliance: ['iso27001', 'soc2'],
  },
};

// ── Helper functions ────────────────────────────────────────

function expandGoals(goal: string): string[] {
  if (goal === 'all') {
    return ['realtime', 'compliance', 'vulnerability', 'honeypot'];
  }
  return [goal];
}

function deriveModules(goals: string[]): PanguardConfig['modules'] {
  return {
    guard: goals.includes('realtime') || goals.length > 1,
    scan: goals.includes('vulnerability') || goals.length > 1,
    report: goals.includes('compliance') || goals.length > 1,
    chat: true, // Always enabled for notifications
    trap: goals.includes('honeypot'),
    dashboard: true, // Always available
  };
}

function deriveGuardPolicy(level: ProtectionLevel): {
  mode: 'learning' | 'protection';
  learningDays: number;
  autoRespond: number;
  notifyAndWait: number;
} {
  switch (level) {
    case 'aggressive':
      return { mode: 'protection', learningDays: 3, autoRespond: 60, notifyAndWait: 30 };
    case 'learning':
      return { mode: 'learning', learningDays: 14, autoRespond: 100, notifyAndWait: 100 };
    case 'balanced':
    default:
      return { mode: 'learning', learningDays: 7, autoRespond: 85, notifyAndWait: 50 };
  }
}

function deriveTrapServices(goals: string[]): string[] {
  if (!goals.includes('honeypot')) return [];
  return ['ssh', 'http'];
}

function deriveAiProvider(preference: AiPreference): string | undefined {
  switch (preference) {
    case 'cloud_ai':
      return 'claude';
    case 'local_ai':
      return 'ollama';
    case 'rules_only':
      return undefined;
  }
}
