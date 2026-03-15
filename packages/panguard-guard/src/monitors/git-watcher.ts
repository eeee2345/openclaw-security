/**
 * GitWatcher - Monitors git repositories for security-relevant operations
 * GitWatcher - 監控 git 存儲庫的安全相關操作
 *
 * Detects:
 * - Secrets committed in diffs (API keys, private keys, tokens)
 * - Sensitive file modifications (.env, credentials, keys)
 * - Direct commits to main/master branch (policy violation)
 * - Force push operations (reflog analysis)
 *
 * Uses fs.watch on .git/ directory to detect git operations,
 * then runs lightweight git commands to analyze what happened.
 *
 * @module @panguard-ai/panguard-guard/monitors/git-watcher
 */

import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent, Severity } from '@panguard-ai/core';

const execFileAsync = promisify(execFile);
const logger = createLogger('panguard-guard:git-watcher');

/** Sensitive file patterns that trigger alerts when committed */
const SENSITIVE_PATTERNS: readonly RegExp[] = [
  /\.env(?:\..+)?$/,
  /credentials/i,
  /\.pem$/,
  /\.key$/,
  /\.p12$/,
  /\.pfx$/,
  /id_rsa/,
  /id_ed25519/,
  /\.aws\/config/,
  /\.ssh\/config/,
  /secrets?\./i,
  /password/i,
] as const;

/** Secret patterns to scan in diffs */
export interface DiffSecretPattern {
  readonly id: string;
  readonly name: string;
  readonly pattern: RegExp;
  readonly severity: Severity;
}

const DIFF_SECRET_PATTERNS: readonly DiffSecretPattern[] = [
  { id: 'aws-key', name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'high' },
  { id: 'github-token', name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/, severity: 'high' },
  { id: 'private-key', name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, severity: 'critical' },
  { id: 'anthropic-key', name: 'Anthropic Key', pattern: /sk-ant-[A-Za-z0-9_-]{20,}/, severity: 'high' },
  { id: 'openai-key', name: 'OpenAI Key', pattern: /sk-[A-Za-z0-9]{20,}/, severity: 'high' },
  { id: 'stripe-live', name: 'Stripe Live Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/, severity: 'high' },
  { id: 'db-connection', name: 'DB Connection String', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]{10,}/, severity: 'high' },
] as const;

/** Protected branch names that should not receive direct commits */
const PROTECTED_BRANCHES: readonly string[] = ['main', 'master'] as const;

let eventCounter = 0;

/**
 * Check if a filename matches any sensitive file pattern
 */
export function isSensitiveFile(filename: string): boolean {
  return SENSITIVE_PATTERNS.some((p) => p.test(filename));
}

/**
 * Scan a line for secret patterns. Returns the first match or null.
 */
export function scanLineForSecrets(line: string): DiffSecretPattern | null {
  for (const secretPattern of DIFF_SECRET_PATTERNS) {
    if (secretPattern.pattern.test(line)) {
      return secretPattern;
    }
  }
  return null;
}

/**
 * Build a SecurityEvent from git watcher detection data
 */
export function createGitEvent(opts: {
  readonly severity: Severity;
  readonly category: string;
  readonly description: string;
  readonly metadata: Record<string, unknown>;
}): SecurityEvent {
  eventCounter++;
  return {
    id: `git-${Date.now()}-${eventCounter}`,
    timestamp: new Date(),
    source: 'git',
    severity: opts.severity,
    category: opts.category,
    description: opts.description,
    raw: opts.metadata,
    host: os.hostname(),
    metadata: {
      ...opts.metadata,
      watcher: 'git-watcher',
    },
  };
}

/**
 * GitWatcher monitors git repositories for security-relevant operations.
 *
 * Usage:
 *   const watcher = new GitWatcher('/path/to/repo');
 *   if (await watcher.checkAvailability()) {
 *     watcher.on('event', (event) => processEvent(event));
 *     await watcher.start();
 *   }
 */
export class GitWatcher extends EventEmitter {
  private running = false;
  private watcher: fs.FSWatcher | null = null;
  private readonly gitDir: string;
  private readonly repoDir: string;
  private lastHeadRef = '';
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly debounceMs: number;

  constructor(repoDir?: string, debounceMs = 500) {
    super();
    this.repoDir = repoDir ?? process.cwd();
    this.gitDir = path.join(this.repoDir, '.git');
    this.debounceMs = debounceMs;
  }

  /**
   * Check if the target directory is a valid git repository
   */
  async checkAvailability(): Promise<boolean> {
    try {
      await fs.promises.access(this.gitDir, fs.constants.R_OK);
      await execFileAsync('git', ['rev-parse', '--git-dir'], {
        cwd: this.repoDir,
        timeout: 3000,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Start watching the git repository for changes
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    this.lastHeadRef = await this.getCurrentHead();
    this.watchGitEvents();

    logger.info(`GitWatcher started, watching ${this.repoDir}`);
  }

  /**
   * Stop watching and clean up resources
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }

    logger.info('GitWatcher stopped');
  }

  /**
   * Whether the watcher is currently active
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Manually trigger analysis of the latest commit.
   * Useful for testing or programmatic invocation without relying on fs.watch.
   */
  async analyzeLatestCommit(): Promise<void> {
    const newHead = await this.getCurrentHead();
    if (newHead && newHead !== this.lastHeadRef) {
      const previousHead = this.lastHeadRef;
      this.lastHeadRef = newHead;
      await this.checkNewCommit(newHead, previousHead);
    }
  }

  /**
   * Set up fs.watch on the .git directory
   */
  private watchGitEvents(): void {
    try {
      this.watcher = fs.watch(
        this.gitDir,
        { recursive: true },
        (_eventType, filename) => {
          if (!filename || !this.running) return;

          // Debounce: git operations trigger multiple fs events
          if (this.debounceTimer) clearTimeout(this.debounceTimer);
          this.debounceTimer = setTimeout(() => {
            void this.analyzeGitChange(filename);
          }, this.debounceMs);
        }
      );
      this.watcher.on('error', (err) => {
        logger.warn(`Git directory watch error: ${err instanceof Error ? err.message : String(err)}`);
      });
    } catch (err) {
      logger.warn(
        `Failed to watch .git directory: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Analyze a git directory change to determine what operation occurred
   */
  private async analyzeGitChange(filename: string): Promise<void> {
    try {
      if (filename === 'HEAD' || filename.startsWith('refs/')) {
        const newHead = await this.getCurrentHead();
        if (newHead && newHead !== this.lastHeadRef) {
          const previousHead = this.lastHeadRef;
          this.lastHeadRef = newHead;
          await this.checkNewCommit(newHead, previousHead);
        }
      }
    } catch {
      // Analysis failed silently; do not crash the watcher
    }
  }

  /**
   * Analyze a new commit for security concerns
   */
  private async checkNewCommit(newHead: string, previousHead: string): Promise<void> {
    const shortHash = newHead.substring(0, 8);

    // Determine diff range: use previous HEAD if valid, otherwise HEAD~1
    const diffBase = previousHead || 'HEAD~1';

    try {
      // Get changed files
      const { stdout: namesOutput } = await execFileAsync(
        'git',
        ['diff', diffBase, newHead, '--name-only'],
        { cwd: this.repoDir, timeout: 5000 }
      );

      const changedFiles = namesOutput
        .trim()
        .split('\n')
        .filter(Boolean);

      // Check for sensitive file changes
      for (const file of changedFiles) {
        if (isSensitiveFile(file)) {
          this.emit(
            'event',
            createGitEvent({
              severity: 'high',
              category: 'credential-access',
              description: `Sensitive file committed: ${file}`,
              metadata: {
                filePath: file,
                commitHash: shortHash,
                trigger: 'sensitive_file_commit',
              },
            })
          );
        }
      }

      // Check diff content for secrets
      await this.scanDiffForSecrets(diffBase, newHead, shortHash);
    } catch {
      // Diff analysis failed (first commit, detached HEAD, etc.)
    }

    // Check for direct commit to protected branch
    await this.checkProtectedBranch(shortHash);

    // Check for force push via reflog
    await this.checkForcePush(shortHash);
  }

  /**
   * Scan git diff output for secret patterns in added lines
   */
  private async scanDiffForSecrets(
    diffBase: string,
    newHead: string,
    shortHash: string
  ): Promise<void> {
    try {
      const { stdout: diffContent } = await execFileAsync(
        'git',
        ['diff', diffBase, newHead],
        { cwd: this.repoDir, timeout: 10000 }
      );

      // Only check added lines (lines starting with +, excluding +++ header)
      const addedLines = diffContent
        .split('\n')
        .filter((line) => line.startsWith('+') && !line.startsWith('+++'));

      for (const line of addedLines) {
        const match = scanLineForSecrets(line);
        if (match) {
          this.emit(
            'event',
            createGitEvent({
              severity: match.severity,
              category: 'credential-access',
              description: `${match.name} detected in commit ${shortHash}`,
              metadata: {
                secretType: match.name,
                patternId: match.id,
                commitHash: shortHash,
                trigger: 'secret_in_commit',
              },
            })
          );
          // One alert per line to avoid noise
          break;
        }
      }
    } catch {
      // Diff content retrieval failed
    }
  }

  /**
   * Check if the current branch is protected and alert on direct commits
   */
  private async checkProtectedBranch(shortHash: string): Promise<void> {
    try {
      const { stdout } = await execFileAsync(
        'git',
        ['rev-parse', '--abbrev-ref', 'HEAD'],
        { cwd: this.repoDir, timeout: 3000 }
      );

      const branch = stdout.trim();
      if (PROTECTED_BRANCHES.includes(branch)) {
        this.emit(
          'event',
          createGitEvent({
            severity: 'medium',
            category: 'policy-violation',
            description: `Direct commit to ${branch} branch`,
            metadata: {
              branch,
              commitHash: shortHash,
              trigger: 'direct_main_commit',
            },
          })
        );
      }
    } catch {
      // Branch detection failed
    }
  }

  /**
   * Check reflog for force push entries
   */
  private async checkForcePush(shortHash: string): Promise<void> {
    try {
      const { stdout } = await execFileAsync(
        'git',
        ['reflog', 'show', '--format=%gs', '-1'],
        { cwd: this.repoDir, timeout: 3000 }
      );

      const entry = stdout.trim().toLowerCase();
      if (entry.includes('forced-update') || entry.includes('force')) {
        this.emit(
          'event',
          createGitEvent({
            severity: 'high',
            category: 'policy-violation',
            description: `Force push detected (${shortHash})`,
            metadata: {
              commitHash: shortHash,
              reflogEntry: stdout.trim(),
              trigger: 'force_push',
            },
          })
        );
      }
    } catch {
      // Reflog check failed
    }
  }

  /**
   * Get the current HEAD commit hash
   */
  private async getCurrentHead(): Promise<string> {
    try {
      const { stdout } = await execFileAsync(
        'git',
        ['rev-parse', 'HEAD'],
        { cwd: this.repoDir, timeout: 3000 }
      );
      return stdout.trim();
    } catch {
      return '';
    }
  }
}
