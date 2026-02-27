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
import type { WizardAnswers, PanguardConfig, ProtectionLevel, AiPreference } from './types.js';

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

  // Create directory
  mkdirSync(configDir, { recursive: true });

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
 */
export function readConfig(): PanguardConfig | null {
  const configPath = join(os.homedir(), '.panguard', 'config.json');
  try {
    const json = readFileSync(configPath, 'utf-8');
    return JSON.parse(json) as PanguardConfig;
  } catch {
    return null;
  }
}

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
    case 'balanced':
      return { mode: 'learning', learningDays: 7, autoRespond: 85, notifyAndWait: 50 };
    case 'learning':
      return { mode: 'learning', learningDays: 14, autoRespond: 100, notifyAndWait: 100 };
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
