/**
 * Secrets checker module unit tests
 * 密鑰檢查器模組單元測試
 *
 * Tests checkHardcodedSecrets function for various secret patterns,
 * directory walking, node_modules skipping, and error handling.
 *
 * 測試 checkHardcodedSecrets 函式，涵蓋各種密鑰模式、目錄遍歷、
 * 跳過 node_modules 和錯誤處理。
 *
 * @module @panguard-ai/panguard-scan/tests/secrets-checker
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// ---------------------------------------------------------------------------
// Mock @panguard-ai/core's createLogger before importing the module under test
// 在匯入受測模組之前模擬 @panguard-ai/core 的 createLogger
// ---------------------------------------------------------------------------
vi.mock('@panguard-ai/core', async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    createLogger: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  };
});

import { checkHardcodedSecrets } from '../src/scanners/secrets-checker.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create a temporary directory with the given file contents
 * 建立包含指定檔案內容的臨時目錄
 *
 * @param files - Map of relative path to file content / 相對路徑到檔案內容的對應
 * @returns Absolute path to the temp directory / 臨時目錄的絕對路徑
 */
async function createTempDir(files: Record<string, string>): Promise<string> {
  const tmpDir = await fs.mkdtemp(
    path.join(os.tmpdir(), 'panguard-secrets-test-')
  );

  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(tmpDir, relPath);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, content, 'utf-8');
  }

  return tmpDir;
}

/**
 * Remove a temporary directory
 * 移除臨時目錄
 *
 * @param dir - Directory to remove / 要移除的目錄
 */
async function removeTempDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('secrets-checker.ts - checkHardcodedSecrets', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = '';
  });

  afterEach(async () => {
    if (tmpDir) {
      await removeTempDir(tmpDir);
    }
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Directory validation
  // -------------------------------------------------------------------------

  /**
   * Passing a non-existent directory should return an empty array without throwing.
   * 傳入不存在的目錄應回傳空陣列而不拋出例外。
   */
  it('should return empty array for non-existent directory', async () => {
    const findings = await checkHardcodedSecrets('/tmp/panguard-nonexistent-99999');
    expect(findings).toEqual([]);
  });

  /**
   * Passing a file path (not a directory) should return an empty array.
   * 傳入檔案路徑（非目錄）應回傳空陣列。
   */
  it('should return empty array when target is a file not a directory', async () => {
    tmpDir = await createTempDir({ 'test.js': 'const x = 1;' });
    const filePath = path.join(tmpDir, 'test.js');
    const findings = await checkHardcodedSecrets(filePath);
    expect(findings).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // AWS Access Key ID
  // -------------------------------------------------------------------------

  /**
   * An AWS access key starting with AKIA should be detected.
   * 以 AKIA 開頭的 AWS 存取金鑰應被偵測到。
   */
  it('should detect AWS Access Key ID (AKIA...)', async () => {
    tmpDir = await createTempDir({
      'aws-config.ts': `
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const awsFindings = findings.filter((f) => f.id.startsWith('SECRETS-AWS-KEY'));
    expect(awsFindings.length).toBeGreaterThanOrEqual(1);
    expect(awsFindings[0].severity).toBe('critical');
    expect(awsFindings[0].category).toBe('secrets');
    expect(awsFindings[0].complianceRef).toBe('4.5');
  });

  // -------------------------------------------------------------------------
  // GitHub tokens
  // -------------------------------------------------------------------------

  /**
   * GitHub personal access tokens (ghp_ prefix) should be detected.
   * GitHub 個人存取令牌（ghp_ 前綴）應被偵測到。
   */
  it('should detect GitHub personal access token (ghp_ prefix)', async () => {
    tmpDir = await createTempDir({
      'github.js': `
const GITHUB_TOKEN = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a';
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const ghFindings = findings.filter((f) => f.id.startsWith('SECRETS-GITHUB-TOKEN'));
    expect(ghFindings.length).toBeGreaterThanOrEqual(1);
    expect(ghFindings[0].severity).toBe('critical');
  });

  /**
   * GitHub OAuth tokens (gho_ prefix) should be detected.
   * GitHub OAuth 令牌（gho_ 前綴）應被偵測到。
   */
  it('should detect GitHub OAuth token (gho_ prefix)', async () => {
    tmpDir = await createTempDir({
      'oauth.ts': `export const GH_OAUTH = 'gho_16C7e42F292c6912E7710c838347Ae178B4a';`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const ghFindings = findings.filter((f) => f.id.startsWith('SECRETS-GITHUB-TOKEN'));
    expect(ghFindings.length).toBeGreaterThanOrEqual(1);
  });

  /**
   * GitHub server tokens (ghs_ prefix) should be detected.
   * GitHub 伺服器令牌（ghs_ 前綴）應被偵測到。
   */
  it('should detect GitHub server-to-server token (ghs_ prefix)', async () => {
    tmpDir = await createTempDir({
      'server.ts': `const token = 'ghs_9C7e42F292c6912E7710c838347Ae178B4a9X';`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const ghFindings = findings.filter((f) => f.id.startsWith('SECRETS-GITHUB-TOKEN'));
    expect(ghFindings.length).toBeGreaterThanOrEqual(1);
  });

  /**
   * GitHub refresh tokens (ghr_ prefix) should be detected.
   * GitHub 刷新令牌（ghr_ 前綴）應被偵測到。
   */
  it('should detect GitHub refresh token (ghr_ prefix)', async () => {
    tmpDir = await createTempDir({
      'refresh.js': `const refreshToken = 'ghr_16C7e42F292c6912E7710c838347Ae178B4a';`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const ghFindings = findings.filter((f) => f.id.startsWith('SECRETS-GITHUB-TOKEN'));
    expect(ghFindings.length).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Slack tokens
  // -------------------------------------------------------------------------

  /**
   * Slack bot tokens (xoxb- prefix) should be detected.
   * Slack 機器人令牌（xoxb- 前綴）應被偵測到。
   */
  it('should detect Slack bot token (xoxb- prefix)', async () => {
    tmpDir = await createTempDir({
      'slack.ts': `
const SLACK_BOT_TOKEN = '${'xo' + 'xb'}-1234567890-1234567890-abcdefghijklmnop';
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const slackFindings = findings.filter((f) => f.id.startsWith('SECRETS-SLACK-TOKEN'));
    expect(slackFindings.length).toBeGreaterThanOrEqual(1);
    expect(slackFindings[0].severity).toBe('critical');
  });

  /**
   * Slack app tokens (xoxa- prefix) should be detected.
   * Slack 應用程式令牌（xoxa- 前綴）應被偵測到。
   */
  it('should detect Slack app token (xoxa- prefix)', async () => {
    tmpDir = await createTempDir({
      'integration.js': `const token = '${'xo' + 'xa'}-1234567890-1234567890-abcdefghijklmnop';`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const slackFindings = findings.filter((f) => f.id.startsWith('SECRETS-SLACK-TOKEN'));
    expect(slackFindings.length).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Stripe keys
  // -------------------------------------------------------------------------

  /**
   * Stripe live secret keys (sk_live_ prefix) should be detected.
   * Stripe 正式密鑰（sk_live_ 前綴）應被偵測到。
   */
  it('should detect Stripe live secret key (sk_live_ prefix)', async () => {
    tmpDir = await createTempDir({
      'payment.ts': `
const stripe = new Stripe('${'sk' + '_live'}_51FAKEFAKEFAKEFAKEFAKE000');
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const stripeFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-STRIPE-LIVE-KEY')
    );
    expect(stripeFindings.length).toBeGreaterThanOrEqual(1);
    expect(stripeFindings[0].severity).toBe('critical');
  });

  /**
   * Stripe live publishable keys (pk_live_ prefix) should be detected.
   * Stripe 正式公鑰（pk_live_ 前綴）應被偵測到。
   */
  it('should detect Stripe live publishable key (pk_live_ prefix)', async () => {
    tmpDir = await createTempDir({
      'frontend.js': `const key = 'pk_live_51H7tR2LkdIwHuIn0oAx3YK9Lbg0K';`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const stripeFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-STRIPE-LIVE-KEY')
    );
    expect(stripeFindings.length).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Bearer tokens
  // -------------------------------------------------------------------------

  /**
   * A hardcoded Bearer token string should be detected.
   * 硬編碼的 Bearer 令牌字串應被偵測到。
   */
  it('should detect hardcoded Bearer token', async () => {
    tmpDir = await createTempDir({
      'api-client.ts': `
const headers = {
  Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123',
};
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const bearerFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-BEARER-TOKEN')
    );
    expect(bearerFindings.length).toBeGreaterThanOrEqual(1);
    expect(bearerFindings[0].severity).toBe('critical');
  });

  // -------------------------------------------------------------------------
  // RSA/Private key headers
  // -------------------------------------------------------------------------

  /**
   * An RSA private key header in source code should be detected.
   * 原始碼中的 RSA 私鑰標頭應被偵測到。
   */
  it('should detect RSA private key header', async () => {
    tmpDir = await createTempDir({
      'private-key.pem': `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4m+hVEGNMCQEFo0F25LbG7h5...
-----END RSA PRIVATE KEY-----`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const keyFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-RSA-PRIVATE-KEY')
    );
    expect(keyFindings.length).toBeGreaterThanOrEqual(1);
    expect(keyFindings[0].severity).toBe('critical');
  });

  /**
   * A generic PRIVATE KEY header should also be detected.
   * 通用私鑰標頭也應被偵測到。
   */
  it('should detect generic PRIVATE KEY header', async () => {
    tmpDir = await createTempDir({
      'key.ts': `const key = \`-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN...\n-----END PRIVATE KEY-----\`;`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const keyFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-RSA-PRIVATE-KEY')
    );
    expect(keyFindings.length).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Database connection strings
  // -------------------------------------------------------------------------

  /**
   * A PostgreSQL connection string with credentials should be detected.
   * 含憑證的 PostgreSQL 連線字串應被偵測到。
   */
  it('should detect PostgreSQL connection string with credentials', async () => {
    tmpDir = await createTempDir({
      'db.ts': `
const DATABASE_URL = 'postgresql://admin:mypassword@localhost:5432/mydb';
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const dbFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-DB-CONNECTION-STRING')
    );
    expect(dbFindings.length).toBeGreaterThanOrEqual(1);
    expect(dbFindings[0].severity).toBe('critical');
  });

  /**
   * A MongoDB connection string with credentials should be detected.
   * 含憑證的 MongoDB 連線字串應被偵測到。
   */
  it('should detect MongoDB connection string with credentials', async () => {
    tmpDir = await createTempDir({
      'mongo.js': `
mongoose.connect('mongodb://user:secret@cluster0.mongodb.net/mydb');
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const dbFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-DB-CONNECTION-STRING')
    );
    expect(dbFindings.length).toBeGreaterThanOrEqual(1);
  });

  /**
   * A MySQL connection string with credentials should be detected.
   * 含憑證的 MySQL 連線字串應被偵測到。
   */
  it('should detect MySQL connection string with credentials', async () => {
    tmpDir = await createTempDir({
      'mysql.ts': `const url = 'mysql://root:password123@127.0.0.1:3306/app';`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const dbFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-DB-CONNECTION-STRING')
    );
    expect(dbFindings.length).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Generic API key in .env files
  // -------------------------------------------------------------------------

  /**
   * An .env file containing API_KEY should trigger a finding.
   * 包含 API_KEY 的 .env 檔案應觸發發現。
   */
  it('should detect generic API_KEY in .env file', async () => {
    tmpDir = await createTempDir({
      '.env': `
DATABASE_URL=postgres://localhost/db
API_KEY=sk-1234567890abcdef1234567890abcdef
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const apiKeyFindings = findings.filter((f) =>
      f.id.startsWith('SECRETS-GENERIC-API-KEY-ENV')
    );
    expect(apiKeyFindings.length).toBeGreaterThanOrEqual(1);
    expect(apiKeyFindings[0].severity).toBe('critical');
  });

  // -------------------------------------------------------------------------
  // node_modules skipping
  // -------------------------------------------------------------------------

  /**
   * Secrets inside node_modules should NOT be reported.
   * node_modules 中的密鑰不應被報告。
   */
  it('should skip node_modules directory', async () => {
    tmpDir = await createTempDir({
      'node_modules/aws-sdk/lib/config.js': `
const KEY = 'AKIAIOSFODNN7EXAMPLE';
const TOKEN = '${'xo' + 'xb'}-1234567890-1234567890-abcdefghijklmnop';
`,
      'src/app.ts': `export const x = 1;`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);

    for (const finding of findings) {
      expect(finding.details ?? '').not.toContain('node_modules');
    }
  });

  // -------------------------------------------------------------------------
  // .git directory skipping
  // -------------------------------------------------------------------------

  /**
   * Secrets inside .git directory should NOT be reported.
   * .git 目錄中的密鑰不應被報告。
   */
  it('should skip .git directory', async () => {
    tmpDir = await createTempDir({
      '.git/config': `
[credential]
  helper = store
  token = ghp_16C7e42F292c6912E7710c838347Ae178B4a
`,
      'src/main.ts': `export const x = 1;`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    for (const finding of findings) {
      expect(finding.details ?? '').not.toContain('.git');
    }
  });

  // -------------------------------------------------------------------------
  // Clean file produces no findings
  // -------------------------------------------------------------------------

  /**
   * Files with no secrets should produce no findings.
   * 沒有密鑰的檔案應不產生發現。
   */
  it('should return empty array for clean source files', async () => {
    tmpDir = await createTempDir({
      'clean.ts': `
export function add(a: number, b: number): number {
  return a + b;
}

const API_URL = process.env.API_URL ?? 'https://api.example.com';
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    expect(findings).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Finding structure validation
  // -------------------------------------------------------------------------

  /**
   * Each finding should have all required fields populated correctly.
   * 每個發現都應正確填充所有必要欄位。
   */
  it('should produce findings with correct structure', async () => {
    tmpDir = await createTempDir({
      'credentials.ts': `const key = 'AKIAIOSFODNN7EXAMPLE';`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    expect(findings.length).toBeGreaterThan(0);

    const f = findings[0];
    expect(f).toHaveProperty('id');
    expect(f).toHaveProperty('title');
    expect(f).toHaveProperty('description');
    expect(f).toHaveProperty('severity');
    expect(f).toHaveProperty('category');
    expect(f).toHaveProperty('remediation');
    expect(f).toHaveProperty('complianceRef');

    expect(typeof f.id).toBe('string');
    expect(f.id.length).toBeGreaterThan(0);
    expect(f.severity).toBe('critical');
    expect(f.category).toBe('secrets');
    expect(f.complianceRef).toBe('4.5');
    expect(f.remediation.length).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------------
  // Multiple secrets in same file
  // -------------------------------------------------------------------------

  /**
   * Multiple different secrets in the same file should each produce a finding.
   * 同一檔案中的多個不同密鑰應各自產生一個發現。
   */
  it('should detect multiple secrets in the same file', async () => {
    tmpDir = await createTempDir({
      'secrets.ts': `
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const GH_TOKEN = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a';
const STRIPE_KEY = '${'sk' + '_live'}_51FAKEFAKEFAKEFAKEFAKE000';
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    expect(findings.length).toBeGreaterThanOrEqual(3);

    const ids = findings.map((f) => f.id.split('-').slice(0, 3).join('-'));
    expect(ids).toContain('SECRETS-AWS-KEY');
    expect(ids.some((id) => id === 'SECRETS-GITHUB-TOKEN' || id.startsWith('SECRETS-GITHUB'))).toBe(true);
    expect(ids.some((id) => id.startsWith('SECRETS-STRIPE'))).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Deduplication
  // -------------------------------------------------------------------------

  /**
   * The same secret at the same position should only be reported once.
   * 同一位置的相同密鑰應只被報告一次。
   */
  it('should deduplicate findings at same line in same file', async () => {
    tmpDir = await createTempDir({
      'dup.ts': `const key = 'AKIAIOSFODNN7EXAMPLE';`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const awsFindings = findings.filter((f) => f.id.startsWith('SECRETS-AWS-KEY'));

    // Group by details (file:line) - should be unique
    // 按 details（檔案:行號）分組 - 應唯一
    const detailsSeen = new Set<string>();
    for (const f of awsFindings) {
      const key = f.details ?? '';
      expect(detailsSeen.has(key)).toBe(false);
      detailsSeen.add(key);
    }
  });

  // -------------------------------------------------------------------------
  // Scans YAML/config files
  // -------------------------------------------------------------------------

  /**
   * Secrets in YAML configuration files should also be detected.
   * YAML 設定檔中的密鑰也應被偵測到。
   */
  it('should scan YAML configuration files for secrets', async () => {
    tmpDir = await createTempDir({
      'config.yml': `
aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  region: us-east-1
`,
    });

    const findings = await checkHardcodedSecrets(tmpDir);
    const awsFindings = findings.filter((f) => f.id.startsWith('SECRETS-AWS-KEY'));
    expect(awsFindings.length).toBeGreaterThanOrEqual(1);
  });
});
