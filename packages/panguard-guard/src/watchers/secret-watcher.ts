/**
 * SecretWatcher - Monitors .env files for exposed secrets
 * SecretWatcher - 監控 .env 檔案中的機密外洩
 *
 * Watches for:
 * 1. Changes to existing .env files
 * 2. Secret patterns (API keys, tokens, credentials) in file content
 * 3. New .env files created in the project directory
 *
 * Emits SecurityEvent via EventEmitter, same pattern as FalcoMonitor/SuricataMonitor.
 *
 * @module @panguard-ai/panguard-guard/watchers/secret-watcher
 */

import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent, Severity } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:secret-watcher');

/** Secret detection pattern definition */
export interface SecretPattern {
  readonly id: string;
  readonly name: string;
  readonly pattern: RegExp;
  readonly severity: Severity;
}

/** Secret patterns to detect (proven patterns from security scanners) */
export const SECRET_PATTERNS: readonly SecretPattern[] = Object.freeze([
  { id: 'aws-key', name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'critical' },
  {
    id: 'aws-secret',
    name: 'AWS Secret Key',
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}/,
    severity: 'critical',
  },
  {
    id: 'github-token',
    name: 'GitHub Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/,
    severity: 'high',
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/,
    severity: 'high',
  },
  {
    id: 'stripe-live',
    name: 'Stripe Live Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/,
    severity: 'critical',
  },
  {
    id: 'private-key',
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
    severity: 'critical',
  },
  {
    id: 'generic-api-key',
    name: 'Generic API Key Assignment',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['"][A-Za-z0-9_-]{20,}['"]/i,
    severity: 'high',
  },
  {
    id: 'bearer-token',
    name: 'Bearer Token',
    pattern: /['"]Bearer\s+[A-Za-z0-9_.-]{20,}['"]/,
    severity: 'high',
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API Key',
    pattern: /sk-ant-[A-Za-z0-9_-]{20,}/,
    severity: 'critical',
  },
  {
    id: 'openai-key',
    name: 'OpenAI API Key',
    pattern: /sk-[A-Za-z0-9]{20,}/,
    severity: 'high',
  },
  {
    id: 'db-connection',
    name: 'Database Connection String',
    pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]{10,}/,
    severity: 'high',
  },
]);

/** .env file basenames to watch */
const ENV_FILE_PATTERNS: readonly string[] = Object.freeze([
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.staging',
  '.env.test',
  '.env.example',
]);

/** Result from scanning a single line */
export interface SecretFinding {
  readonly pattern: SecretPattern;
  readonly line: number;
  readonly match: string;
}

/**
 * SecretWatcher watches .env files for exposed secrets and emits SecurityEvents.
 *
 * Usage:
 *   const watcher = new SecretWatcher('/path/to/project');
 *   if (await watcher.checkAvailability()) {
 *     watcher.on('event', (event) => processEvent(event));
 *     await watcher.start();
 *   }
 */
export class SecretWatcher extends EventEmitter {
  private running = false;
  private readonly watchers: fs.FSWatcher[] = [];
  private readonly watchDir: string;
  /** Tracks known secrets per file to avoid duplicate alerts: file -> Set<"patternId:line"> */
  private readonly knownSecrets = new Map<string, ReadonlySet<string>>();

  constructor(watchDir?: string) {
    super();
    this.watchDir = watchDir ?? process.cwd();
  }

  /**
   * Check if the watch directory is accessible.
   * Always returns true for a readable directory (no external deps needed).
   */
  async checkAvailability(): Promise<boolean> {
    try {
      await fs.promises.access(this.watchDir, fs.constants.R_OK);
      return true;
    } catch {
      logger.info(`Secret watcher directory not accessible: ${this.watchDir}`);
      return false;
    }
  }

  /**
   * Start watching for secret exposure in .env files.
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    // Initial scan of existing .env files
    await this.scanExistingEnvFiles();

    // Watch individual .env files for modifications
    this.watchEnvFiles();

    // Watch directory for new .env file creation
    this.watchDirectoryForNewEnvFiles();

    logger.info(`SecretWatcher started, monitoring ${this.watchDir}`);
  }

  /**
   * Stop all watchers and clean up.
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    for (const watcher of this.watchers) {
      watcher.close();
    }
    // Clear the array (watchers is readonly ref, mutate contents)
    this.watchers.length = 0;
    this.knownSecrets.clear();

    logger.info('SecretWatcher stopped');
  }

  /**
   * Scan all known .env file patterns on startup.
   */
  private async scanExistingEnvFiles(): Promise<void> {
    for (const envFile of ENV_FILE_PATTERNS) {
      const filePath = path.join(this.watchDir, envFile);
      try {
        await fs.promises.access(filePath, fs.constants.R_OK);
        await this.scanFile(filePath, 'initial_scan');
      } catch {
        // File doesn't exist — skip
      }
    }
  }

  /**
   * Set up fs.watch on each existing .env file for change detection.
   */
  private watchEnvFiles(): void {
    for (const envFile of ENV_FILE_PATTERNS) {
      const filePath = path.join(this.watchDir, envFile);
      try {
        fs.accessSync(filePath, fs.constants.R_OK);
        const watcher = fs.watch(filePath, (eventType) => {
          if (eventType === 'change') {
            void this.scanFile(filePath, 'file_modified');
          }
        });
        watcher.on('error', () => {
          // File may be deleted — ignore
        });
        this.watchers.push(watcher);
      } catch {
        // File doesn't exist yet — directory watcher will handle creation
      }
    }
  }

  /**
   * Watch the project directory for new .env files appearing.
   */
  private watchDirectoryForNewEnvFiles(): void {
    try {
      const watcher = fs.watch(this.watchDir, (eventType, filename) => {
        if (!filename || eventType !== 'rename') return;
        const basename = path.basename(filename);
        const isEnvFile =
          ENV_FILE_PATTERNS.includes(basename) || basename.startsWith('.env');
        if (isEnvFile) {
          const filePath = path.join(this.watchDir, filename);
          // Small delay to let the file be fully written
          setTimeout(() => {
            void this.scanFile(filePath, 'file_created');
          }, 100);
        }
      });
      watcher.on('error', () => {
        // Directory watch error — ignore
      });
      this.watchers.push(watcher);
    } catch {
      logger.warn(`Could not watch directory: ${this.watchDir}`);
    }
  }

  /**
   * Scan a file for secret patterns and emit events for new findings.
   */
  private async scanFile(filePath: string, trigger: string): Promise<void> {
    if (!this.running) return;

    try {
      const content = await fs.promises.readFile(filePath, 'utf-8');
      const lines = content.split('\n');
      const findings = this.detectSecrets(lines);

      // Build current secret fingerprint set
      const currentSecretKeys = new Set(
        findings.map((f) => `${f.pattern.id}:${f.line}`)
      );

      // Determine which findings are new (deduplication)
      const previousKeys = this.knownSecrets.get(filePath) ?? new Set<string>();
      const newFindings = findings.filter(
        (f) => !previousKeys.has(`${f.pattern.id}:${f.line}`)
      );

      // Update known secrets (immutable set replacement)
      this.knownSecrets.set(filePath, Object.freeze(new Set(currentSecretKeys)));

      // Emit events for each new secret finding
      for (const finding of newFindings) {
        this.emitSecretEvent(filePath, finding, trigger);
      }

      // Emit informational event when a new .env file is created
      if (trigger === 'file_created') {
        this.emitEnvFileCreatedEvent(filePath);
      }
    } catch {
      // File read error (deleted, permission denied) — ignore
    }
  }

  /**
   * Detect secrets in file lines. Pure function (no side effects).
   */
  private detectSecrets(lines: readonly string[]): readonly SecretFinding[] {
    const findings: SecretFinding[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      // Skip comments and empty lines
      if (line.trimStart().startsWith('#') || line.trim() === '') continue;

      for (const secretPattern of SECRET_PATTERNS) {
        const match = line.match(secretPattern.pattern);
        if (match) {
          findings.push({
            pattern: secretPattern,
            line: i + 1,
            match: match[0],
          });
        }
      }
    }

    return findings;
  }

  /**
   * Emit a SecurityEvent for a detected secret.
   */
  private emitSecretEvent(
    filePath: string,
    finding: SecretFinding,
    trigger: string
  ): void {
    const redacted = this.redactValue(finding.match);
    const fileName = path.basename(filePath);

    const event: SecurityEvent = {
      id: `secret-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: new Date(),
      source: 'file',
      severity: finding.pattern.severity,
      category: 'credential-access',
      description: `${finding.pattern.name} detected in ${fileName} (line ${finding.line})`,
      raw: { filePath, line: finding.line, patternId: finding.pattern.id, trigger },
      host: os.hostname(),
      metadata: {
        filePath,
        fileName,
        lineNumber: finding.line,
        secretType: finding.pattern.name,
        patternId: finding.pattern.id,
        redactedValue: redacted,
        trigger,
        watcher: 'secret-watcher',
      },
    };

    this.emit('event', event);
  }

  /**
   * Emit an informational SecurityEvent when a new .env file is created.
   */
  private emitEnvFileCreatedEvent(filePath: string): void {
    const fileName = path.basename(filePath);

    const event: SecurityEvent = {
      id: `env-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: new Date(),
      source: 'file',
      severity: 'info',
      category: 'file-monitoring',
      description: `Environment file created: ${fileName}`,
      raw: { filePath, trigger: 'file_created' },
      host: os.hostname(),
      metadata: {
        filePath,
        fileName,
        trigger: 'file_created',
        watcher: 'secret-watcher',
      },
    };

    this.emit('event', event);
  }

  /**
   * Redact a matched secret value, keeping only the first 8 chars visible.
   */
  private redactValue(value: string): string {
    if (value.length <= 8) return '...[REDACTED]';
    return `${value.substring(0, 8)}...[REDACTED]`;
  }
}
