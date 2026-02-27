/**
 * Environment Auto-Detection
 * 環境自動偵測
 *
 * Detects OS, hostname, and architecture for the setup wizard.
 *
 * @module @panguard-ai/panguard/init/environment
 */

import * as os from 'node:os';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Auto-detect the current system environment.
 * Returns a human-readable summary string.
 */
export async function detectEnvironment(): Promise<string> {
  const platform = os.platform();
  const arch = os.arch();
  const hostname = os.hostname();
  const release = os.release();
  const totalMem = Math.round(os.totalmem() / (1024 * 1024 * 1024));

  let osName: string;
  switch (platform) {
    case 'darwin':
      osName = `macOS ${release}`;
      break;
    case 'linux':
      osName = `Linux ${release}`;
      break;
    case 'win32':
      osName = `Windows ${release}`;
      break;
    default:
      osName = `${platform} ${release}`;
  }

  return `${osName} (${arch}) | ${hostname} | ${totalMem}GB RAM`;
}

/**
 * Check if a Panguard config already exists.
 */
export function hasExistingConfig(): boolean {
  const configPath = join(os.homedir(), '.panguard', 'config.json');
  return existsSync(configPath);
}

/**
 * Get the default config directory path.
 */
export function getConfigDir(): string {
  return join(os.homedir(), '.panguard');
}

/**
 * Get basic environment info as structured data.
 */
export function getEnvironmentInfo(): {
  os: string;
  hostname: string;
  arch: string;
  platform: string;
} {
  return {
    os: `${os.platform()} ${os.release()}`,
    hostname: os.hostname(),
    arch: os.arch(),
    platform: os.platform(),
  };
}
