/**
 * Init Wizard Types
 * 初始設定精靈型別
 *
 * @module @panguard-ai/panguard/init/types
 */

export type Lang = 'en' | 'zh-TW';
export type OrgSize = 'individual' | 'small' | 'medium' | 'large';
export type DeployEnv = 'cloud' | 'on-prem' | 'hybrid';
export type AiPreference = 'cloud_ai' | 'local_ai' | 'rules_only';
export type ProtectionLevel = 'aggressive' | 'balanced' | 'learning';

/** Quick setup profile (maps to all detailed settings automatically). */
export type UsageProfile = 'personal' | 'team' | 'enterprise';

/** Enhanced environment info from auto-detection. */
export interface EnhancedEnvironment {
  os: string;
  hostname: string;
  arch: string;
  platform: string;
  totalMemGB: number;
  openPorts: number[];
  securityTools: string[];
  hasDocker: boolean;
}

/**
 * Answers collected from the setup wizard.
 */
export interface WizardAnswers {
  language: Lang;
  orgName: string;
  orgSize: OrgSize;
  industry: string;
  environment: {
    os: string;
    hostname: string;
    deployType: DeployEnv;
    serverCount: number;
  };
  securityGoals: string;
  compliance: string;
  notification: {
    channel: string;
    config: Record<string, string>;
  };
  aiPreference: AiPreference;
  protectionLevel: ProtectionLevel;
}

/**
 * Unified Panguard configuration file schema.
 * Written to ~/.panguard/config.json
 */
export interface PanguardConfig {
  version: '1.0.0';
  meta: {
    createdAt: string;
    language: Lang;
  };
  organization: {
    name: string;
    size: OrgSize;
    industry: string;
  };
  environment: {
    os: string;
    hostname: string;
    arch: string;
    deployType: DeployEnv;
    serverCount: number;
  };
  security: {
    goals: string[];
    compliance: string[];
    protectionLevel: ProtectionLevel;
  };
  guard: {
    mode: 'learning' | 'protection';
    learningDays: number;
    actionPolicy: {
      autoRespond: number;
      notifyAndWait: number;
    };
    monitors: {
      logMonitor: boolean;
      networkMonitor: boolean;
      processMonitor: boolean;
      fileMonitor: boolean;
    };
  };
  ai: {
    preference: AiPreference;
    provider?: string;
    endpoint?: string;
  };
  notifications: {
    channel: string;
    config: Record<string, string>;
  };
  trap: {
    enabled: boolean;
    services: string[];
  };
  modules: {
    guard: boolean;
    scan: boolean;
    report: boolean;
    chat: boolean;
    trap: boolean;
    dashboard: boolean;
  };
}
