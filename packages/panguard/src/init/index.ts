/**
 * Init Module - Onboarding wizard for Panguard AI
 * 初始設定模組 - Panguard AI 安裝引導精靈
 *
 * @module @panguard-ai/panguard/init
 */

export { runInitWizard } from './wizard-runner.js';
export {
  buildPanguardConfig,
  buildQuickConfig,
  writeConfig,
  readConfig,
  validateConfigSchema,
} from './config-writer.js';
export {
  detectEnvironment,
  detectEnvironmentEnhanced,
  hasExistingConfig,
  getConfigDir,
  getEnvironmentInfo,
  getEnhancedEnvironment,
} from './environment.js';
export { getWizardSteps, getQuickSteps } from './steps.js';
export type {
  WizardAnswers,
  PanguardConfig,
  OrgSize,
  DeployEnv,
  AiPreference,
  ProtectionLevel,
  Lang,
  UsageProfile,
  EnhancedEnvironment,
} from './types.js';
