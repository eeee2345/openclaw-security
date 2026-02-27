/**
 * Password policy checker
 * 密碼策略檢查器
 *
 * Checks the system's password policy configuration to identify weak or
 * missing policies. Supports macOS, Linux, and Windows.
 * 檢查系統的密碼策略配置以識別弱或缺失的策略。支援 macOS、Linux 和 Windows。
 *
 * @module @panguard-ai/panguard-scan/scanners/password-policy
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { platform as osPlatform } from 'os';
import { createLogger } from '@panguard-ai/core';
import type { Finding } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('panguard-scan:password-policy');

/**
 * Safely execute a command and return stdout, or empty string on failure
 * 安全地執行命令並回傳 stdout，失敗時回傳空字串
 *
 * @param cmd - Command to execute / 要執行的命令
 * @param args - Command arguments / 命令參數
 * @returns stdout output trimmed / 修剪後的 stdout 輸出
 */
async function safeExecFile(cmd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, { timeout: 15_000 });
    return stdout.trim();
  } catch (err) {
    logger.debug(`Command failed: ${cmd} ${args.join(' ')}`, {
      error: err instanceof Error ? err.message : String(err),
    });
    return '';
  }
}

/**
 * Check password policy on macOS
 * 檢查 macOS 上的密碼策略
 *
 * Uses pwpolicy getaccountpolicies to retrieve and parse the current policy.
 * 使用 pwpolicy getaccountpolicies 來擷取並解析目前的策略。
 *
 * @returns Array of findings related to macOS password policy / 與 macOS 密碼策略相關的發現陣列
 */
async function checkMacOSPolicy(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const output = await safeExecFile('pwpolicy', ['getaccountpolicies']);

  if (!output) {
    // No password policy configured at all
    // 完全未配置密碼策略
    findings.push({
      id: 'SCAN-PWD-001',
      title: 'No password policy configured / 未配置密碼策略',
      description:
        'No account password policy was found on this macOS system. ' +
        'Without a password policy, users can set weak or empty passwords. / ' +
        '在此 macOS 系統上未找到帳號密碼策略。' +
        '沒有密碼策略，使用者可以設定弱或空密碼。',
      severity: 'high',
      category: 'password',
      remediation:
        'Configure a password policy using pwpolicy or an MDM profile ' +
        'that enforces minimum length, complexity, and expiration. / ' +
        '使用 pwpolicy 或 MDM 設定檔配置密碼策略，' +
        '強制最小長度、複雜度和到期時間。',
      complianceRef: '4.5',
    });
    return findings;
  }

  // Check for weak policy indicators
  // 檢查弱策略指標
  const hasMinLength =
    output.includes('minLength') || output.includes('policyAttributeMinimumLength');
  const hasComplexity =
    output.includes('requiresAlpha') ||
    output.includes('requiresNumeric') ||
    output.includes('policyAttributeMinimumNumericCharacters');
  const hasExpiration =
    output.includes('maxPINAgeInDays') || output.includes('policyAttributeExpiresEveryNDays');

  if (!hasMinLength && !hasComplexity) {
    findings.push({
      id: 'SCAN-PWD-001',
      title: 'Weak password policy detected / 偵測到弱密碼策略',
      description:
        'The macOS password policy does not enforce minimum length or complexity requirements. / ' +
        'macOS 密碼策略未強制最小長度或複雜度要求。',
      severity: 'medium',
      category: 'password',
      remediation:
        'Update the password policy to require a minimum length of at least 8 characters ' +
        'and include alphanumeric complexity requirements. / ' +
        '更新密碼策略以要求至少 8 個字元的最小長度，' +
        '並包含英數複雜度要求。',
      complianceRef: '4.5',
    });
  }

  if (!hasExpiration) {
    findings.push({
      id: 'SCAN-PWD-001',
      title: 'No password expiration policy / 無密碼到期策略',
      description:
        'The macOS password policy does not enforce password expiration. ' +
        'Passwords that never expire increase the risk of credential compromise. / ' +
        'macOS 密碼策略未強制密碼到期。' +
        '永不過期的密碼增加了憑證被破解的風險。',
      severity: 'medium',
      category: 'password',
      remediation:
        'Configure password expiration to require password changes at least every 90 days. / ' +
        '配置密碼到期以要求至少每 90 天更改密碼。',
      complianceRef: '4.5',
    });
  }

  return findings;
}

/**
 * Check password policy on Linux
 * 檢查 Linux 上的密碼策略
 *
 * Reads /etc/pam.d/common-password and /etc/security/pwquality.conf to
 * determine if a password quality policy is configured.
 * 讀取 /etc/pam.d/common-password 和 /etc/security/pwquality.conf 以
 * 判斷是否已配置密碼品質策略。
 *
 * @returns Array of findings related to Linux password policy / 與 Linux 密碼策略相關的發現陣列
 */
async function checkLinuxPolicy(): Promise<Finding[]> {
  const findings: Finding[] = [];
  let policyFound = false;

  // Try /etc/pam.d/common-password
  // 嘗試 /etc/pam.d/common-password
  try {
    const pamContent = await readFile('/etc/pam.d/common-password', 'utf-8');
    policyFound = true;

    const hasMinLen = pamContent.includes('minlen') || pamContent.includes('min=');
    const hasComplexity =
      pamContent.includes('ucredit') ||
      pamContent.includes('lcredit') ||
      pamContent.includes('dcredit') ||
      pamContent.includes('ocredit') ||
      pamContent.includes('pam_pwquality') ||
      pamContent.includes('pam_cracklib');

    if (!hasMinLen && !hasComplexity) {
      findings.push({
        id: 'SCAN-PWD-001',
        title: 'Weak PAM password policy / 弱 PAM 密碼策略',
        description:
          'The PAM password configuration (/etc/pam.d/common-password) does not enforce ' +
          'minimum length or complexity requirements. / ' +
          'PAM 密碼配置 (/etc/pam.d/common-password) 未強制最小長度或複雜度要求。',
        severity: 'medium',
        category: 'password',
        remediation:
          'Install and configure pam_pwquality or pam_cracklib with minlen >= 8, ' +
          'and enforce uppercase, lowercase, digit, and special character requirements. / ' +
          '安裝並配置 pam_pwquality 或 pam_cracklib，設定 minlen >= 8，' +
          '並強制大寫、小寫、數字和特殊字元要求。',
        complianceRef: '4.5',
      });
    }
  } catch {
    logger.debug('Could not read /etc/pam.d/common-password');
  }

  // Try /etc/security/pwquality.conf
  // 嘗試 /etc/security/pwquality.conf
  try {
    const pwqContent = await readFile('/etc/security/pwquality.conf', 'utf-8');
    policyFound = true;

    // Parse minlen value
    // 解析 minlen 值
    const minlenMatch = pwqContent.match(/^\s*minlen\s*=\s*(\d+)/m);
    const minlen = minlenMatch ? parseInt(minlenMatch[1] ?? '0', 10) : 0;

    if (minlen > 0 && minlen < 8) {
      findings.push({
        id: 'SCAN-PWD-001',
        title: 'Insufficient minimum password length / 最小密碼長度不足',
        description:
          `Password minimum length is set to ${minlen} in pwquality.conf. ` +
          'A minimum of 8 characters is recommended. / ' +
          `pwquality.conf 中密碼最小長度設定為 ${minlen}。建議至少 8 個字元。`,
        severity: 'medium',
        category: 'password',
        remediation:
          'Set minlen = 8 or higher in /etc/security/pwquality.conf. / ' +
          '在 /etc/security/pwquality.conf 中設定 minlen = 8 或更高。',
        complianceRef: '4.5',
      });
    }
  } catch {
    logger.debug('Could not read /etc/security/pwquality.conf');
  }

  if (!policyFound) {
    findings.push({
      id: 'SCAN-PWD-001',
      title: 'No password policy configured / 未配置密碼策略',
      description:
        'No password quality policy files were found on this Linux system. ' +
        'Neither /etc/pam.d/common-password nor /etc/security/pwquality.conf exist. / ' +
        '在此 Linux 系統上未找到密碼品質策略檔案。' +
        '/etc/pam.d/common-password 和 /etc/security/pwquality.conf 均不存在。',
      severity: 'high',
      category: 'password',
      remediation:
        'Install libpam-pwquality and configure /etc/security/pwquality.conf ' +
        'with appropriate password complexity and length requirements. / ' +
        '安裝 libpam-pwquality 並配置 /etc/security/pwquality.conf，' +
        '設定適當的密碼複雜度和長度要求。',
      complianceRef: '4.5',
    });
  }

  return findings;
}

/**
 * Check password policy on Windows
 * 檢查 Windows 上的密碼策略
 *
 * Uses 'net accounts' to retrieve the current password policy settings.
 * 使用 'net accounts' 來擷取目前的密碼策略設定。
 *
 * @returns Array of findings related to Windows password policy / 與 Windows 密碼策略相關的發現陣列
 */
async function checkWindowsPolicy(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const output = await safeExecFile('net', ['accounts']);

  if (!output) {
    findings.push({
      id: 'SCAN-PWD-001',
      title: 'Unable to retrieve password policy / 無法擷取密碼策略',
      description:
        'Could not run "net accounts" to retrieve the Windows password policy. / ' +
        '無法執行 "net accounts" 來擷取 Windows 密碼策略。',
      severity: 'medium',
      category: 'password',
      remediation:
        'Run this scan with administrator privileges to read the password policy. / ' +
        '以管理員權限執行此掃描以讀取密碼策略。',
      complianceRef: '4.5',
    });
    return findings;
  }

  // Parse minimum password length
  // 解析最小密碼長度
  const minLengthMatch = output.match(/Minimum password length\s*:\s*(\d+)/i);
  const minLength = minLengthMatch ? parseInt(minLengthMatch[1] ?? '0', 10) : 0;

  if (minLength < 8) {
    findings.push({
      id: 'SCAN-PWD-001',
      title: 'Insufficient minimum password length / 最小密碼長度不足',
      description:
        `Windows minimum password length is set to ${minLength}. ` +
        'A minimum of 8 characters is recommended. / ' +
        `Windows 最小密碼長度設定為 ${minLength}。建議至少 8 個字元。`,
      severity: minLength === 0 ? 'high' : 'medium',
      category: 'password',
      remediation:
        'Use Group Policy (secpol.msc) to set the minimum password length to at least 8 characters. / ' +
        '使用群組原則 (secpol.msc) 將最小密碼長度設定為至少 8 個字元。',
      complianceRef: '4.5',
    });
  }

  // Parse maximum password age
  // 解析最大密碼使用天數
  const maxAgeMatch = output.match(/Maximum password age\s*\(days\)\s*:\s*(\w+)/i);
  const maxAgeStr = maxAgeMatch?.[1] ?? '';

  if (maxAgeStr.toLowerCase() === 'unlimited' || maxAgeStr === '0') {
    findings.push({
      id: 'SCAN-PWD-001',
      title: 'No password expiration policy / 無密碼到期策略',
      description:
        'Windows password policy has no maximum password age. ' +
        'Passwords that never expire increase the risk of credential compromise. / ' +
        'Windows 密碼策略未設定最大密碼使用天數。' +
        '永不過期的密碼增加了憑證被破解的風險。',
      severity: 'medium',
      category: 'password',
      remediation:
        'Set a maximum password age of 90 days or less via Group Policy. / ' +
        '透過群組原則設定最大密碼使用天數為 90 天或更短。',
      complianceRef: '4.5',
    });
  }

  // Parse lockout threshold
  // 解析鎖定閾值
  const lockoutMatch = output.match(/Lockout threshold\s*:\s*(\w+)/i);
  const lockoutStr = lockoutMatch?.[1] ?? '';

  if (lockoutStr.toLowerCase() === 'never' || lockoutStr === '0') {
    findings.push({
      id: 'SCAN-PWD-001',
      title: 'No account lockout policy / 無帳號鎖定策略',
      description:
        'No account lockout threshold is configured. ' +
        'This allows unlimited password guessing attempts. / ' +
        '未配置帳號鎖定閾值。這允許無限次密碼猜測嘗試。',
      severity: 'high',
      category: 'password',
      remediation:
        'Configure an account lockout threshold of 5 or fewer failed attempts ' +
        'via Group Policy. / ' +
        '透過群組原則配置帳號鎖定閾值為 5 次或更少的失敗嘗試。',
      complianceRef: '4.5',
    });
  }

  return findings;
}

/**
 * Check password policy strength on the current platform
 * 檢查目前平台上的密碼策略強度
 *
 * Cross-platform password policy checker that dispatches to the appropriate
 * platform-specific implementation.
 * 跨平台密碼策略檢查器，分派到適當的平台特定實作。
 *
 * @returns Array of password policy findings / 密碼策略發現陣列
 */
export async function checkPasswordPolicy(): Promise<Finding[]> {
  const currentPlatform = osPlatform();

  logger.info(`Checking password policy on ${currentPlatform}`);

  try {
    let findings: Finding[] = [];

    switch (currentPlatform) {
      case 'darwin':
        findings = await checkMacOSPolicy();
        break;
      case 'linux':
        findings = await checkLinuxPolicy();
        break;
      case 'win32':
        findings = await checkWindowsPolicy();
        break;
      default:
        logger.warn(`Unsupported platform for password policy check: ${currentPlatform}`);
        return [];
    }

    logger.info(`Password policy check complete: ${findings.length} finding(s)`);
    return findings;
  } catch (err) {
    logger.error('Password policy check failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
}
