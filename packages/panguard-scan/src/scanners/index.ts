/**
 * Scanner modules for PanguardScan - main orchestrator
 * PanguardScan 掃描模組 - 主要編排器
 *
 * Coordinates all scanner modules to perform a comprehensive security scan.
 * Aggregates findings from discovery, password policy, open ports, SSL certificates,
 * scheduled tasks, and shared folder checks into a unified ScanResult.
 * 協調所有掃描模組執行全面的安全掃描。
 * 將偵察、密碼策略、開放埠、SSL 憑證、排程任務和共用資料夾檢查的發現
 * 彙總為統一的 ScanResult。
 *
 * @module @panguard-ai/panguard-scan/scanners
 */

import { createLogger, getRiskLevel } from '@panguard-ai/core';
import type { RiskFactor } from '@panguard-ai/core';
import { discover } from './discovery-scanner.js';
import { checkPasswordPolicy } from './password-policy.js';
import { checkUnnecessaryPorts } from './open-ports.js';
import { checkSslCertificates } from './ssl-checker.js';
import { checkScheduledTasks } from './scheduled-tasks.js';
import { checkSharedFolders } from './shared-folders.js';
import { checkCVEs } from './cve-checker.js';
import type { ScanConfig, ScanResult, Finding } from './types.js';
import { sortBySeverity } from './types.js';

const logger = createLogger('panguard-scan:orchestrator');

/** Scanner modules version / 掃描模組版本 */
export const SCANNERS_VERSION = '0.1.0';

/**
 * Category-to-title mapping for risk factor conversion
 * 風險因素轉換的類別到標題對應表
 *
 * Maps core RiskFactor categories to human-readable titles for Findings.
 * 將核心 RiskFactor 類別映射到 Finding 的人類可讀標題。
 */
const RISK_FACTOR_TITLES: Record<string, string> = {
  noFirewall: 'Firewall disabled / 防火牆已停用',
  tooManyAdmins: 'Excessive administrator accounts / 過多的管理員帳號',
  dangerousPorts: 'Dangerous ports open / 危險埠已開放',
  noUpdates: 'System updates missing / 系統更新缺失',
  noSecurityTools: 'No active security tools / 無啟用中的安全工具',
  defaultPasswords: 'Old or default passwords detected / 偵測到舊或預設密碼',
  excessiveServices: 'Excessive running services / 過多的執行中服務',
};

/**
 * Category-to-manual-fix mapping for risk factor conversion
 * 風險因素轉換的類別到手動修復指令對應表
 */
const RISK_FACTOR_MANUAL_FIX: Record<string, string[]> = {
  noFirewall: ['sudo ufw enable', 'sudo ufw default deny incoming'],
  dangerousPorts: ['sudo ufw deny <port>', 'sudo iptables -A INPUT -p tcp --dport <port> -j DROP'],
  noUpdates: ['sudo apt update && sudo apt upgrade -y'],
  noSecurityTools: [
    'sudo apt install fail2ban -y',
    'sudo systemctl enable fail2ban && sudo systemctl start fail2ban',
  ],
  defaultPasswords: [
    "sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
    'sudo systemctl restart sshd',
  ],
  excessiveServices: [
    'sudo systemctl list-units --type=service --state=running',
    'sudo systemctl disable <service-name>',
  ],
};

/**
 * Category-to-remediation mapping for risk factor conversion
 * 風險因素轉換的類別到修復建議對應表
 *
 * Maps core RiskFactor categories to remediation recommendations for Findings.
 * 將核心 RiskFactor 類別映射到 Finding 的修復建議。
 */
const RISK_FACTOR_REMEDIATIONS: Record<string, string> = {
  noFirewall:
    'Enable and configure the system firewall to block unnecessary inbound traffic. / ' +
    '啟用並配置系統防火牆以封鎖不必要的入站流量。',
  tooManyAdmins:
    'Review administrator accounts and reduce to a maximum of 2. Remove unnecessary admin privileges. / ' +
    '審查管理員帳號並減少至最多 2 個。移除不必要的管理員權限。',
  dangerousPorts:
    'Close unnecessary dangerous ports or restrict access via firewall rules. / ' +
    '關閉不必要的危險埠或透過防火牆規則限制存取。',
  noUpdates:
    'Enable automatic updates and install all pending security patches. / ' +
    '啟用自動更新並安裝所有待安裝的安全修補程式。',
  noSecurityTools:
    'Install and activate endpoint security software (antivirus, EDR, or equivalent). / ' +
    '安裝並啟動端點安全軟體（防毒、EDR 或同等產品）。',
  defaultPasswords:
    'Enforce password rotation policy. Require all users with old passwords to change them. / ' +
    '強制執行密碼輪換策略。要求所有使用舊密碼的使用者更改密碼。',
  excessiveServices:
    'Review running services and disable or remove those not required for operations. / ' +
    '審查執行中的服務，停用或移除營運不需要的服務。',
};

/**
 * Convert a core RiskFactor to a scanner Finding
 * 將核心 RiskFactor 轉換為掃描器 Finding
 *
 * Maps the discovery engine's risk factors into the standardized Finding format
 * used by PanguardScan's scan results.
 * 將偵察引擎的風險因素映射為 PanguardScan 掃描結果使用的標準化 Finding 格式。
 *
 * @param factor - Core risk factor from discovery / 來自偵察的核心風險因素
 * @returns Converted Finding / 轉換後的 Finding
 */
function riskFactorToFinding(factor: RiskFactor): Finding {
  const title =
    RISK_FACTOR_TITLES[factor.category] ??
    `Risk factor: ${factor.category} / 風險因素：${factor.category}`;

  const remediation =
    RISK_FACTOR_REMEDIATIONS[factor.category] ??
    'Review and address this risk factor according to your security policy. / ' +
      '根據您的安全策略審查並處理此風險因素。';

  const manualFix = RISK_FACTOR_MANUAL_FIX[factor.category];

  return {
    id: `DISC-${factor.category}`,
    title,
    description: factor.description,
    severity: factor.severity,
    category: factor.category,
    remediation,
    details: factor.details,
    manualFix,
  };
}

/**
 * Calculate an enhanced risk score incorporating additional scan findings
 * 計算包含額外掃描發現的增強風險評分
 *
 * Starts with the base risk score from discovery and adds extra points
 * based on the number and severity of additional findings from the scanners.
 * 從偵察的基礎風險評分開始，根據掃描器額外發現的數量和嚴重性加分。
 *
 * @param baseScore - Base risk score from discovery (0-100) / 來自偵察的基礎風險評分（0-100）
 * @param additionalFindings - Findings from additional scanners / 來自額外掃描器的發現
 * @returns Enhanced risk score (0-100) / 增強風險評分（0-100）
 */
function calculateEnhancedRiskScore(baseScore: number, additionalFindings: Finding[]): number {
  const severityPoints: Record<string, number> = {
    critical: 8,
    high: 5,
    medium: 3,
    low: 1,
    info: 0,
  };

  let extraPoints = 0;
  for (const finding of additionalFindings) {
    extraPoints += severityPoints[finding.severity] ?? 0;
  }

  // Cap the enhanced score at 100
  // 增強評分上限為 100
  return Math.min(100, Math.max(0, baseScore + extraPoints));
}

/**
 * Fallback manual fix commands by finding category/keyword
 * 依據發現類別/關鍵字的備用手動修復指令
 */
const CATEGORY_MANUAL_FIX: Record<string, string[]> = {
  password: ['sudo passwd -e $(whoami)', 'sudo apt install libpam-pwquality -y'],
  ssl: [
    "sudo sed -i 's/TLSv1.1/TLSv1.3/' /etc/nginx/nginx.conf",
    'sudo nginx -t && sudo systemctl reload nginx',
  ],
};

/**
 * Enrich a finding with manual fix commands if not already present
 * 若尚未存在，為發現補充手動修復指令
 */
function enrichManualFix(finding: Finding): Finding {
  if (finding.manualFix && finding.manualFix.length > 0) return finding;
  const fix = CATEGORY_MANUAL_FIX[finding.category];
  if (fix) return { ...finding, manualFix: fix };
  return finding;
}

/**
 * Run a complete security scan
 * 執行完整的安全掃描
 *
 * Orchestrates the full scan workflow:
 * 1. Run environment discovery
 * 2. Convert discovery risk factors to findings
 * 3. Run password policy check
 * 4. Check for unnecessary open ports
 * 5. (Full mode only) Check SSL certificates, scheduled tasks, shared folders
 * 6. Merge and sort all findings by severity
 * 7. Calculate enhanced risk score
 * 8. Return complete ScanResult
 *
 * 編排完整的掃描工作流程：
 * 1. 執行環境偵察
 * 2. 將偵察風險因素轉換為發現
 * 3. 執行密碼策略檢查
 * 4. 檢查不必要的開放埠
 * 5.（完整模式限定）檢查 SSL 憑證、排程任務、共用資料夾
 * 6. 合併並按嚴重度排序所有發現
 * 7. 計算增強風險評分
 * 8. 回傳完整 ScanResult
 *
 * @param config - Scan configuration / 掃描配置
 * @returns Complete scan result / 完整掃描結果
 */
export async function runScan(config: ScanConfig): Promise<ScanResult> {
  const startTime = Date.now();

  logger.info('Starting security scan', { depth: config.depth, lang: config.lang });

  // Step 1: Run environment discovery
  // 步驟 1：執行環境偵察
  logger.info('Phase 1: Environment discovery');
  const discovery = await discover({ depth: config.depth, lang: config.lang });

  // Step 2: Convert core risk factors to findings
  // 步驟 2：將核心風險因素轉換為發現
  logger.info('Phase 2: Converting risk factors to findings');
  const discoveryFindings: Finding[] = discovery.vulnerabilities.map(riskFactorToFinding);
  logger.info(`Converted ${discoveryFindings.length} risk factors to findings`);

  // Step 3: Check password policy
  // 步驟 3：檢查密碼策略
  logger.info('Phase 3: Checking password policy');
  const passwordFindings = await checkPasswordPolicy();
  logger.info(`Password policy check: ${passwordFindings.length} finding(s)`);

  // Step 4: Check unnecessary ports
  // 步驟 4：檢查不必要的埠
  logger.info('Phase 4: Checking unnecessary open ports');
  const portFindings = checkUnnecessaryPorts(discovery.openPorts);
  logger.info(`Open ports check: ${portFindings.length} finding(s)`);

  // Collect additional findings (beyond discovery base)
  // 收集額外發現（超出偵察基礎）
  const additionalFindings: Finding[] = [...passwordFindings, ...portFindings];

  // Step 5: Full mode - additional checks
  // 步驟 5：完整模式 - 額外檢查
  if (config.depth === 'full') {
    logger.info('Phase 5: Running full-depth additional checks');

    // SSL certificate check
    // SSL 憑證檢查
    logger.info('Checking SSL certificates');
    const sslFindings = await checkSslCertificates(discovery.openPorts);
    logger.info(`SSL certificate check: ${sslFindings.length} finding(s)`);
    additionalFindings.push(...sslFindings);

    // Scheduled tasks check
    // 排程任務檢查
    logger.info('Checking scheduled tasks');
    const taskFindings = await checkScheduledTasks();
    logger.info(`Scheduled tasks check: ${taskFindings.length} finding(s)`);
    additionalFindings.push(...taskFindings);

    // Shared folders check
    // 共用資料夾檢查
    logger.info('Checking shared folders');
    const shareFindings = await checkSharedFolders();
    logger.info(`Shared folders check: ${shareFindings.length} finding(s)`);
    additionalFindings.push(...shareFindings);

    // CVE/NVD check (uses detected services from discovery)
    // CVE/NVD 檢查（使用偵察發現的服務）
    logger.info('Phase 6: Checking known CVEs via NVD API');
    const cveFindings = await checkCVEs(discovery.openPorts);
    logger.info(`CVE check: ${cveFindings.length} finding(s)`);
    additionalFindings.push(...cveFindings);
  } else {
    logger.info('Skipping full-depth checks in quick mode');
  }

  // Step 6: Merge, enrich with manual fix commands, and sort all findings
  // 步驟 6：合併、補充手動修復指令，並排序所有發現
  const allFindings: Finding[] = [...discoveryFindings, ...additionalFindings]
    .map(enrichManualFix)
    .sort(sortBySeverity);

  logger.info(`Total findings: ${allFindings.length}`);

  // Step 7: Calculate enhanced risk score
  // 步驟 7：計算增強風險評分
  const enhancedRiskScore = calculateEnhancedRiskScore(discovery.riskScore, additionalFindings);
  const riskLevel = getRiskLevel(enhancedRiskScore);

  logger.info(`Enhanced risk score: ${enhancedRiskScore}/100 (level: ${riskLevel})`);

  // Step 8: Assemble and return ScanResult
  // 步驟 8：組裝並回傳 ScanResult
  const scanDuration = Date.now() - startTime;

  const result: ScanResult = {
    discovery,
    findings: allFindings,
    riskScore: enhancedRiskScore,
    riskLevel,
    scanDuration,
    scannedAt: new Date().toISOString(),
    config,
  };

  logger.info('Security scan complete', {
    duration: `${scanDuration}ms`,
    findings: allFindings.length,
    riskScore: enhancedRiskScore,
    riskLevel,
  });

  return result;
}

// Re-export all scanner functions and types for external use
// 重新匯出所有掃描器功能和類型供外部使用
export { discover } from './discovery-scanner.js';
export { checkPasswordPolicy } from './password-policy.js';
export { checkUnnecessaryPorts } from './open-ports.js';
export { checkSslCertificates } from './ssl-checker.js';
export { checkScheduledTasks } from './scheduled-tasks.js';
export { checkSharedFolders } from './shared-folders.js';
export { checkCVEs } from './cve-checker.js';
export type { ScanConfig, ScanResult, Finding } from './types.js';
export { sortBySeverity, SEVERITY_ORDER } from './types.js';
