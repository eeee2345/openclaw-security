/**
 * Hardcoded secrets scanner
 * 硬編碼密鑰掃描器
 *
 * Scans source files for hardcoded secrets such as API keys, tokens, credentials,
 * and private keys. Works independently of semgrep.
 * 掃描原始碼檔案中的硬編碼密鑰，如 API 金鑰、令牌、憑證和私鑰。
 * 獨立於 semgrep 運作。
 *
 * @module @panguard-ai/panguard-scan/scanners/secrets-checker
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type { Finding } from './types.js';

const logger = createLogger('panguard-scan:secrets-checker');

/**
 * Maximum file size in bytes to scan (500 KB)
 * 最大掃描檔案大小（500 KB）
 */
const MAX_FILE_SIZE_BYTES = 500 * 1024;

/**
 * Directories to skip when walking the source tree
 * 遍歷原始碼樹時要跳過的目錄
 */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  'vendor',
  '.next',
  '__pycache__',
]);

/**
 * Source file extensions to scan for secrets
 * 要掃描密鑰的原始碼檔案副檔名
 */
const SCANNABLE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.go',
  '.java',
  '.php',
  '.rb',
  '.cs',
  '.rs',
  '.cpp',
  '.c',
  '.h',
  '.env',
  '.env.local',
  '.env.production',
  '.env.staging',
  '.env.development',
  '.env.test',
  '.yaml',
  '.yml',
  '.json',
  '.toml',
  '.ini',
  '.cfg',
  '.conf',
  '.properties',
  '.xml',
  '.pem',
  '.key',
  '.crt',
  '.cert',
]);

/**
 * Secret pattern definition
 * 密鑰模式定義
 */
interface SecretPattern {
  id: string;
  pattern: RegExp;
  title: string;
  description: string;
}

/**
 * Secret detection patterns
 * 密鑰偵測模式
 */
const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'SECRETS-AWS-KEY',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    title: 'AWS Access Key ID detected / 偵測到 AWS 存取金鑰 ID',
    description:
      'An AWS Access Key ID (starting with AKIA) was found hardcoded in source code. ' +
      'This credential can be used to access AWS services. / ' +
      '在原始碼中發現硬編碼的 AWS 存取金鑰 ID（以 AKIA 開頭）。此憑證可用於存取 AWS 服務。',
  },
  {
    id: 'SECRETS-GITHUB-TOKEN',
    pattern: /\b(ghp|gho|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
    title: 'GitHub token detected / 偵測到 GitHub 令牌',
    description:
      'A GitHub personal access token or OAuth token was found hardcoded in source code. ' +
      'This token can be used to access GitHub repositories and APIs. / ' +
      '在原始碼中發現硬編碼的 GitHub 個人存取令牌或 OAuth 令牌。此令牌可用於存取 GitHub 儲存庫和 API。',
  },
  {
    id: 'SECRETS-SLACK-TOKEN',
    pattern: /\bxox[pboa]-[0-9A-Za-z-]{10,}\b/g,
    title: 'Slack token detected / 偵測到 Slack 令牌',
    description:
      'A Slack API token was found hardcoded in source code. ' +
      'This token can be used to access Slack workspaces and data. / ' +
      '在原始碼中發現硬編碼的 Slack API 令牌。此令牌可用於存取 Slack 工作區和資料。',
  },
  {
    id: 'SECRETS-STRIPE-LIVE-KEY',
    pattern: /\b(sk_live_|pk_live_)[0-9A-Za-z]{24,}\b/g,
    title: 'Stripe live key detected / 偵測到 Stripe 正式金鑰',
    description:
      'A Stripe live API key was found hardcoded in source code. ' +
      'This key can be used to process real financial transactions. / ' +
      '在原始碼中發現硬編碼的 Stripe 正式 API 金鑰。此金鑰可用於處理真實的金融交易。',
  },
  {
    id: 'SECRETS-BEARER-TOKEN',
    pattern: /["']Bearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}["']/g,
    title: 'Hardcoded Bearer token detected / 偵測到硬編碼 Bearer 令牌',
    description:
      'A hardcoded Bearer token was found in source code. ' +
      'Bearer tokens grant access to protected APIs and should not be stored in code. / ' +
      '在原始碼中發現硬編碼的 Bearer 令牌。Bearer 令牌授予對受保護 API 的存取權限，不應儲存在代碼中。',
  },
  {
    id: 'SECRETS-RSA-PRIVATE-KEY',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    title: 'Private key material detected / 偵測到私鑰材料',
    description:
      'A private key header was found in source code or a committed file. ' +
      'Private keys should never be stored in source code repositories. / ' +
      '在原始碼或已提交的檔案中發現私鑰標頭。私鑰絕不應儲存在原始碼儲存庫中。',
  },
  {
    id: 'SECRETS-DB-CONNECTION-STRING',
    pattern:
      /(?:mongodb(?:\+srv)?|postgresql|postgres|mysql|redis|amqp|rabbitmq):\/\/[^:/@\s]+:[^:/@\s]+@[^\s"'`]+/gi,
    title: 'Database connection string with credentials / 含憑證的資料庫連線字串',
    description:
      'A database connection string with embedded credentials was found in source code. ' +
      'Database credentials should be managed via environment variables or secrets management. / ' +
      '在原始碼中發現含嵌入憑證的資料庫連線字串。資料庫憑證應透過環境變數或密鑰管理進行管理。',
  },
  {
    id: 'SECRETS-GENERIC-API-KEY-ENV',
    pattern:
      /^(?:API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN|OAUTH_TOKEN|APP_SECRET)\s*=\s*[^\s#]{8,}/gm,
    title: 'Generic API key or secret in environment file / 環境檔案中的通用 API 金鑰或密鑰',
    description:
      'A generic API key, secret, or token was found hardcoded in a configuration or environment file. ' +
      'These values should be injected at runtime, not stored in files. / ' +
      '在設定或環境檔案中發現硬編碼的通用 API 金鑰、密鑰或令牌。這些值應在執行時注入，而非儲存在檔案中。',
  },
];

/**
 * Remediation message for all secret findings (shared)
 * 所有密鑰發現的修復建議（共用）
 */
const SECRETS_REMEDIATION =
  'Remove the secret from source code immediately. Rotate the compromised credential. ' +
  'Store secrets in environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). ' +
  'Add the file to .gitignore if it contains environment configuration. / ' +
  '立即從原始碼中移除密鑰。輪換已洩露的憑證。' +
  '將密鑰儲存在環境變數或密鑰管理員中（如 AWS Secrets Manager、HashiCorp Vault）。' +
  '如果檔案包含環境設定，請將其加入 .gitignore。';

/**
 * Determine if a file should be scanned based on its name and extension
 * 根據檔案名稱和副檔名決定是否應掃描
 *
 * @param fileName - File name to check / 要檢查的檔案名稱
 * @returns True if the file should be scanned / 若應掃描則為 true
 */
function shouldScanFile(fileName: string): boolean {
  // Always scan .env files and variants
  // 始終掃描 .env 檔案及其變體
  if (/^\.env(\.|$)/.test(fileName)) return true;

  const ext = path.extname(fileName).toLowerCase();
  return SCANNABLE_EXTENSIONS.has(ext);
}

/**
 * Recursively collect all files that should be scanned for secrets
 * 遞迴收集所有應掃描密鑰的檔案
 *
 * @param dir - Directory to walk / 要遍歷的目錄
 * @returns Array of absolute file paths / 絕對檔案路徑陣列
 */
async function collectFilesForSecretScan(dir: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(current: string): Promise<void> {
    let entries: import('node:fs').Dirent<string>[];
    try {
      entries = await fs.readdir(current, { withFileTypes: true, encoding: 'utf-8' });
    } catch (err) {
      logger.debug(`Cannot read directory: ${current}`, {
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          logger.debug(`Skipping directory: ${fullPath}`);
          continue;
        }
        await walk(fullPath);
      } else if (entry.isFile()) {
        if (!shouldScanFile(entry.name)) continue;

        try {
          const stat = await fs.stat(fullPath);
          if (stat.size > MAX_FILE_SIZE_BYTES) {
            logger.debug(`Skipping large file (${stat.size} bytes): ${fullPath}`);
            continue;
          }
          files.push(fullPath);
        } catch {
          logger.debug(`Cannot stat file: ${fullPath}`);
        }
      }
    }
  }

  await walk(dir);
  return files;
}

/**
 * Scan a single file for hardcoded secrets
 * 掃描單個檔案中的硬編碼密鑰
 *
 * @param filePath - Absolute path to the file / 檔案的絕對路徑
 * @param content - File content / 檔案內容
 * @returns Array of secret findings / 密鑰發現陣列
 */
function scanFileForSecrets(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const secretPattern of SECRET_PATTERNS) {
    // Reset lastIndex for global regexes
    // 重置全域正規表示式的 lastIndex
    secretPattern.pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = secretPattern.pattern.exec(content)) !== null) {
      const lineNum = content.slice(0, match.index).split('\n').length;
      const matchedSnippet = match[0].slice(0, 40);

      const dedupeKey = `${secretPattern.id}:${filePath}:${lineNum}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      findings.push({
        id: `${secretPattern.id}-${lineNum}`,
        title: secretPattern.title,
        description:
          `${secretPattern.description}\n\n` +
          `File: ${filePath}, Line: ${lineNum}\n` +
          `Found: ${matchedSnippet}${match[0].length > 40 ? '...' : ''}`,
        severity: 'critical',
        category: 'secrets',
        remediation: SECRETS_REMEDIATION,
        complianceRef: '4.5',
        details: `${filePath}:${lineNum}`,
      });

      // For non-global patterns, break after first match per file
      // 對於非全域模式，每個檔案匹配到第一個後中斷
      if (!secretPattern.pattern.flags.includes('g')) break;
    }

    // Reset lastIndex after each file
    // 每個檔案後重置 lastIndex
    secretPattern.pattern.lastIndex = 0;
  }

  return findings;
}

/**
 * Scan source code directory for hardcoded secrets
 * 掃描原始碼目錄中的硬編碼密鑰
 *
 * Detects common secret patterns including:
 * - AWS Access Key IDs
 * - GitHub tokens (ghp_, gho_, ghs_, ghr_ prefixes)
 * - Slack tokens (xox[pboa]-)
 * - Stripe live keys (sk_live_, pk_live_)
 * - Bearer tokens in hardcoded strings
 * - Private key headers (RSA, EC, etc.)
 * - Database connection strings with credentials
 * - Generic API keys in environment files
 *
 * 偵測常見的密鑰模式包括：
 * - AWS 存取金鑰 ID
 * - GitHub 令牌（ghp_、gho_、ghs_、ghr_ 前綴）
 * - Slack 令牌（xox[pboa]-）
 * - Stripe 正式金鑰（sk_live_、pk_live_）
 * - 硬編碼字串中的 Bearer 令牌
 * - 私鑰標頭（RSA、EC 等）
 * - 含憑證的資料庫連線字串
 * - 環境檔案中的通用 API 金鑰
 *
 * @param targetDir - Source code directory to scan / 要掃描的原始碼目錄
 * @returns Array of secret findings / 密鑰發現陣列
 */
export async function checkHardcodedSecrets(targetDir: string): Promise<Finding[]> {
  // Validate targetDir exists
  // 驗證 targetDir 存在
  try {
    const stat = await fs.stat(targetDir);
    if (!stat.isDirectory()) {
      logger.warn(`Target path is not a directory: ${targetDir}`);
      return [];
    }
  } catch (err) {
    logger.warn(`Target directory does not exist or is not accessible: ${targetDir}`, {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }

  const resolvedDir = path.resolve(targetDir);
  logger.info('Starting hardcoded secrets scan', { targetDir: resolvedDir });

  const files = await collectFilesForSecretScan(resolvedDir);
  logger.info(`Secrets scanner: found ${files.length} file(s) to scan`);

  const allFindings: Finding[] = [];

  for (const filePath of files) {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const findings = scanFileForSecrets(filePath, content);
      if (findings.length > 0) {
        logger.info(`Found ${findings.length} secret(s) in: ${filePath}`);
        allFindings.push(...findings);
      }
    } catch (err) {
      logger.debug(`Cannot read file: ${filePath}`, {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  logger.info(`Secrets scan complete: ${allFindings.length} finding(s)`);
  return allFindings;
}
