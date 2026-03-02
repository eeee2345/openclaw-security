/**
 * Environment Auto-Detection
 * 環境自動偵測
 *
 * Detects OS, hostname, and architecture for the setup wizard.
 *
 * @module @panguard-ai/panguard/init/environment
 */

import * as os from 'node:os';
import * as net from 'node:net';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import type { EnhancedEnvironment } from './types.js';

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

// ── Enhanced Detection ─────────────────────────────────────

const COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080];
const SECURITY_TOOLS = ['ufw', 'iptables', 'fail2ban', 'clamav', 'clamd', 'nftables'];

/** Check if a local port is open (listening). */
function checkPort(port: number, timeoutMs = 200): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, '127.0.0.1');
  });
}

/** Check if a command exists on the system. Only allows safe alphanumeric names. */
function commandExists(cmd: string): Promise<boolean> {
  if (!/^[a-zA-Z0-9_-]+$/.test(cmd)) return Promise.resolve(false);
  return new Promise((resolve) => {
    const bin = os.platform() === 'win32' ? 'where' : 'which';
    execFile(bin, [cmd], (err) => resolve(!err));
  });
}

/** Module-level cache for the last enhanced detection result. */
let lastEnhancedResult: EnhancedEnvironment | null = null;

/** Global timeout for the entire detection process. */
const DETECTION_TIMEOUT_MS = 3000;

/**
 * Enhanced environment detection.
 * Returns a human-readable summary string (for WizardEngine auto step).
 * Structured result is cached and retrievable via getEnhancedEnvironment().
 */
export async function detectEnvironmentEnhanced(): Promise<string> {
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

  // Run port checks and tool checks in parallel, with global timeout
  let openPorts: number[] = [];
  let securityTools: string[] = [];
  let hasDocker = false;

  try {
    const detectionPromise = Promise.all([
      Promise.all(COMMON_PORTS.map(async (p) => ({ port: p, open: await checkPort(p) }))),
      Promise.all(SECURITY_TOOLS.map(async (t) => ({ tool: t, exists: await commandExists(t) }))),
      commandExists('docker'),
    ]);

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('detection timeout')), DETECTION_TIMEOUT_MS)
    );

    const [portResults, toolResults, dockerResult] = await Promise.race([
      detectionPromise,
      timeoutPromise,
    ]);

    openPorts = portResults.filter((r) => r.open).map((r) => r.port);
    securityTools = toolResults.filter((r) => r.exists).map((r) => r.tool);
    hasDocker = dockerResult;
  } catch {
    // Timeout or error — proceed with empty detection results
  }

  // Store structured data in module-level cache
  const enhanced: EnhancedEnvironment = {
    os: `${platform} ${release}`,
    hostname,
    arch,
    platform,
    totalMemGB: totalMem,
    openPorts,
    securityTools,
    hasDocker,
  };
  lastEnhancedResult = enhanced;

  // Build human-readable summary
  const parts = [`${osName} (${arch})`, `${hostname}`, `${totalMem}GB RAM`];
  if (openPorts.length > 0) {
    parts.push(`Ports: ${openPorts.join(', ')}`);
  }
  if (securityTools.length > 0) {
    parts.push(`Tools: ${securityTools.join(', ')}`);
  }
  if (hasDocker) {
    parts.push('Docker');
  }

  return parts.join(' | ');
}

/** Get the structured result from the last enhanced detection. */
export function getEnhancedEnvironment(): EnhancedEnvironment {
  if (lastEnhancedResult) {
    return lastEnhancedResult;
  }
  // Fallback to basic info if detection hasn't run yet
  return {
    os: `${os.platform()} ${os.release()}`,
    hostname: os.hostname(),
    arch: os.arch(),
    platform: os.platform(),
    totalMemGB: Math.round(os.totalmem() / (1024 * 1024 * 1024)),
    openPorts: [],
    securityTools: [],
    hasDocker: false,
  };
}
