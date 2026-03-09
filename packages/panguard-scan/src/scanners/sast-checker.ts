/**
 * SAST (Static Application Security Testing) - Semgrep integration
 * 靜態應用程式安全測試 - Semgrep 整合
 *
 * Runs Semgrep-based SAST analysis when semgrep is installed.
 * If Semgrep is not available, returns an empty result with an info message.
 * 當 semgrep 已安裝時執行基於 Semgrep 的 SAST 分析。
 * 若 Semgrep 不可用，回傳空結果並附帶提示訊息。
 *
 * @module @panguard-ai/panguard-scan/scanners/sast-checker
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type { Finding } from './types.js';
import type { Severity } from '@panguard-ai/core';

const logger = createLogger('panguard-scan:sast');
const execFileAsync = promisify(execFile);

/**
 * Semgrep execution timeout in milliseconds (60 seconds)
 * Semgrep 執行逾時（毫秒，60 秒）
 */
const SEMGREP_TIMEOUT_MS = 60_000;

/**
 * Semgrep JSON result item structure
 * Semgrep JSON 結果項目結構
 */
interface SemgrepResult {
  check_id: string;
  path: string;
  start: {
    line: number;
    col: number;
  };
  extra: {
    message: string;
    severity: 'ERROR' | 'WARNING' | 'INFO';
    metadata?: {
      severity?: string;
      cwe?: string | string[];
      owasp?: string | string[];
    };
  };
}

/**
 * Semgrep JSON output structure
 * Semgrep JSON 輸出結構
 */
interface SemgrepOutput {
  results: SemgrepResult[];
}

/**
 * Check if semgrep is available on the PATH
 * 檢查 semgrep 是否在 PATH 上可用
 *
 * @returns True if semgrep is available / 若 semgrep 可用則為 true
 */
async function isSemgrepAvailable(): Promise<boolean> {
  try {
    await execFileAsync('which', ['semgrep'], { timeout: 5_000 });
    return true;
  } catch {
    try {
      await execFileAsync('semgrep', ['--version'], { timeout: 5_000 });
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Map semgrep severity string to Severity type
 * 將 semgrep 嚴重度字串映射到 Severity 型別
 *
 * @param semgrepSeverity - Semgrep severity string / Semgrep 嚴重度字串
 * @param metadataSeverity - Optional metadata severity override / 可選的元資料嚴重度覆蓋
 * @returns Mapped severity level / 映射後的嚴重等級
 */
function mapSemgrepSeverity(
  semgrepSeverity: string,
  metadataSeverity?: string
): Severity {
  if (metadataSeverity) {
    const upper = metadataSeverity.toUpperCase();
    if (upper === 'CRITICAL') return 'critical';
    if (upper === 'HIGH') return 'high';
    if (upper === 'MEDIUM') return 'medium';
    if (upper === 'LOW') return 'low';
  }

  switch (semgrepSeverity.toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    default:
      return 'low';
  }
}

/**
 * Derive a remediation message from a semgrep check_id
 * 從 semgrep check_id 推導修復建議訊息
 *
 * @param checkId - Semgrep rule ID / Semgrep 規則 ID
 * @returns Remediation recommendation / 修復建議
 */
function deriveRemediation(checkId: string): string {
  const lower = checkId.toLowerCase();

  if (lower.includes('secret') || lower.includes('password') || lower.includes('key')) {
    return (
      'Move secrets to environment variables or a dedicated secrets manager. / ' +
      '將密鑰移至環境變數或專用密鑰管理員。'
    );
  }
  if (lower.includes('sql') || lower.includes('injection') || lower.includes('sqli')) {
    return (
      'Use parameterized queries or prepared statements to prevent SQL injection. / ' +
      '使用參數化查詢或預備語句以防止 SQL 注入。'
    );
  }
  if (lower.includes('xss') || lower.includes('html') || lower.includes('innerhtml')) {
    return (
      'Sanitize user-supplied content before rendering it as HTML. / ' +
      '在將使用者提供的內容呈現為 HTML 之前進行清理。'
    );
  }
  if (lower.includes('eval') || lower.includes('exec') || lower.includes('command')) {
    return (
      'Avoid executing user-controlled input as code or system commands. / ' +
      '避免將使用者控制的輸入作為代碼或系統命令執行。'
    );
  }
  if (lower.includes('crypto') || lower.includes('hash') || lower.includes('random')) {
    return (
      'Use cryptographically secure algorithms and random number generators. / ' +
      '使用加密安全的演算法和隨機數生成器。'
    );
  }
  if (lower.includes('tls') || lower.includes('ssl') || lower.includes('cert')) {
    return (
      'Ensure proper TLS/SSL configuration and certificate validation. / ' +
      '確保正確的 TLS/SSL 配置和憑證驗證。'
    );
  }

  return (
    'Review and remediate this security finding according to your security policy. / ' +
    '根據您的安全策略審查並修復此安全發現。'
  );
}

/**
 * Map OWASP reference string to a compliance ref
 * 將 OWASP 參照字串映射到合規參照
 *
 * @param owasp - OWASP category / OWASP 類別
 * @returns Compliance reference string or undefined / 合規參照字串或 undefined
 */
function mapOwaspToComplianceRef(owasp?: string | string[]): string | undefined {
  if (!owasp) return undefined;

  const owaspStr = Array.isArray(owasp) ? owasp.join(' ') : owasp;
  const lower = owaspStr.toLowerCase();

  if (lower.includes('a01') || lower.includes('broken access')) return '4.1';
  if (lower.includes('a02') || lower.includes('cryptographic')) return '4.4';
  if (lower.includes('a03') || lower.includes('injection')) return '4.3';
  if (lower.includes('a07') || lower.includes('identification')) return '4.5';
  if (lower.includes('a09') || lower.includes('logging')) return '4.7';

  return undefined;
}

/**
 * Convert a semgrep result to a Finding
 * 將 semgrep 結果轉換為 Finding
 *
 * @param result - Semgrep result item / Semgrep 結果項目
 * @returns Converted Finding / 轉換後的 Finding
 */
function semgrepResultToFinding(result: SemgrepResult): Finding {
  const checkId = result.check_id;
  const lineNum = result.start.line;
  const col = result.start.col;
  const filePath = result.path;

  // Build a safe ID from the check_id last segment + line number
  // 從 check_id 最後片段和行號建立安全 ID
  const idSuffix =
    (checkId.split('.').pop() ?? checkId)
      .toUpperCase()
      .replace(/[^A-Z0-9-_]/g, '-')
      .slice(0, 30);
  const id = `SAST-${idSuffix}-${lineNum}`;

  const message = result.extra.message;
  const title = message.length > 80 ? message.slice(0, 80) : message;
  const description =
    `${message}\n\nFile: ${filePath}, Line: ${lineNum}, Col: ${col}`;

  const severity = mapSemgrepSeverity(
    result.extra.severity,
    result.extra.metadata?.severity
  );

  const remediation = deriveRemediation(checkId);

  const cwe = result.extra.metadata?.cwe;
  const owasp = result.extra.metadata?.owasp;
  const complianceRef = mapOwaspToComplianceRef(owasp) ?? (cwe ? '4.3' : undefined);

  return {
    id,
    title,
    description,
    severity,
    category: 'code',
    remediation,
    complianceRef,
    details: `${filePath}:${lineNum}:${col}`,
  };
}

/**
 * Run semgrep and parse the JSON output into findings
 * 執行 semgrep 並將 JSON 輸出解析為發現
 *
 * @param targetDir - Directory to scan / 要掃描的目錄
 * @returns Array of findings from semgrep / 來自 semgrep 的發現陣列
 */
async function runSemgrep(targetDir: string): Promise<Finding[]> {
  logger.info('Running semgrep SAST scan', { targetDir });

  try {
    const { stdout } = await execFileAsync(
      'semgrep',
      [
        '--json',
        '--config=p/security-audit',
        '--config=p/secrets',
        '--no-git-ignore',
        '--timeout=60',
        targetDir,
      ],
      { timeout: SEMGREP_TIMEOUT_MS }
    );

    let parsed: SemgrepOutput;
    try {
      parsed = JSON.parse(stdout) as SemgrepOutput;
    } catch (parseErr) {
      logger.warn('Failed to parse semgrep JSON output', {
        error: parseErr instanceof Error ? parseErr.message : String(parseErr),
      });
      return [];
    }

    const results = parsed.results ?? [];
    logger.info(`Semgrep found ${results.length} raw result(s)`);

    // Convert results to findings, deduplicating by check_id + path + line
    // 將結果轉換為發現，按 check_id + 路徑 + 行號去重
    const seen = new Set<string>();
    const findings: Finding[] = [];

    for (const result of results) {
      const dedupeKey = `${result.check_id}:${result.path}:${result.start.line}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      findings.push(semgrepResultToFinding(result));
    }

    logger.info(`Semgrep produced ${findings.length} deduplicated finding(s)`);
    return findings;
  } catch (err) {
    // Exit code 1 from semgrep means findings were found (not an error)
    // semgrep 退出碼 1 表示有發現（非錯誤）
    if (
      err &&
      typeof err === 'object' &&
      'code' in err &&
      err.code === 1 &&
      'stdout' in err &&
      typeof (err as { stdout: unknown }).stdout === 'string'
    ) {
      const stdout = (err as { stdout: string }).stdout;
      try {
        const parsed = JSON.parse(stdout) as SemgrepOutput;
        const results = parsed.results ?? [];
        logger.info(`Semgrep (exit 1) found ${results.length} result(s)`);

        const seen = new Set<string>();
        const findings: Finding[] = [];

        for (const result of results) {
          const dedupeKey = `${result.check_id}:${result.path}:${result.start.line}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);
          findings.push(semgrepResultToFinding(result));
        }

        return findings;
      } catch {
        logger.warn('Failed to parse semgrep exit-1 output');
        return [];
      }
    }

    logger.warn('Semgrep execution failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
}

/**
 * Scan source code for security vulnerabilities using SAST
 * 使用 SAST 掃描原始碼的安全漏洞
 *
 * Runs Semgrep if available. If Semgrep is not installed, returns an empty
 * result array. Install Semgrep for full SAST coverage.
 * 若 Semgrep 可用則執行。若 Semgrep 未安裝，回傳空結果陣列。
 * 安裝 Semgrep 以取得完整 SAST 覆蓋。
 *
 * @param targetDir - Source code directory to scan / 要掃描的原始碼目錄
 * @returns Array of security findings / 安全發現陣列
 */
export async function checkSourceCode(targetDir: string): Promise<Finding[]> {
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

  const semgrepAvailable = await isSemgrepAvailable();

  if (semgrepAvailable) {
    logger.info('Semgrep is available, running SAST scan', { targetDir: resolvedDir });
    return runSemgrep(resolvedDir);
  }

  logger.info(
    'Semgrep is not installed. Install Semgrep for SAST scanning: https://semgrep.dev'
  );
  return [];
}
