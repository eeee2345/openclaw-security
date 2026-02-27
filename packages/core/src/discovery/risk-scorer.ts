/**
 * Risk scoring algorithm
 * 風險評分演算法
 *
 * Calculates an overall risk score (0-100) based on discovered environment
 * factors including firewall status, admin accounts, open ports, update status,
 * security tools presence, and service count.
 * 根據已發現的環境因素計算總體風險評分（0-100），包括防火牆狀態、管理員帳號、
 * 開放埠、更新狀態、安全工具存在狀況和服務數量。
 *
 * @module @panguard-ai/core/discovery/risk-scorer
 */

import { createLogger } from '../utils/logger.js';
import type { DiscoveryResult, RiskFactor } from './types.js';
import type { Severity } from '../types.js';

const logger = createLogger('discovery:risk-scorer');

/**
 * Dangerous ports that indicate potential security risks when open
 * 開放時表示潛在安全風險的危險埠
 */
const DANGEROUS_PORTS = new Set([
  22, // SSH - can be brute-forced / SSH - 可能被暴力破解
  23, // Telnet - unencrypted / Telnet - 未加密
  445, // SMB - common attack vector / SMB - 常見攻擊向量
  3389, // RDP - remote desktop / RDP - 遠端桌面
  135, // MSRPC - Windows RPC / MSRPC - Windows RPC
  139, // NetBIOS - legacy protocol / NetBIOS - 舊版協定
  1433, // MSSQL - database / MSSQL - 資料庫
  3306, // MySQL - database / MySQL - 資料庫
  5432, // PostgreSQL - database / PostgreSQL - 資料庫
  6379, // Redis - often unprotected / Redis - 通常無保護
  27017, // MongoDB - often unprotected / MongoDB - 通常無保護
  5900, // VNC - remote access / VNC - 遠端存取
]);

/**
 * Check for missing firewall and return a risk factor if applicable
 * 檢查防火牆是否缺失，如適用則回傳風險因素
 *
 * @param result - Partial discovery result / 部分偵察結果
 * @returns Risk factor if firewall is disabled, or null / 如果防火牆停用則回傳風險因素，否則為 null
 */
function checkFirewallRisk(result: Partial<DiscoveryResult>): RiskFactor | null {
  if (!result.security?.firewall) return null;

  if (!result.security.firewall.enabled) {
    return {
      category: 'noFirewall',
      description:
        'Firewall is disabled - system is exposed to network attacks / 防火牆已停用 - 系統暴露於網路攻擊',
      score: 25,
      severity: 'high',
      details: `Firewall product: ${result.security.firewall.product || 'unknown'}`,
    };
  }

  return null;
}

/**
 * Check for excessive administrator accounts
 * 檢查過多的管理員帳號
 *
 * @param result - Partial discovery result / 部分偵察結果
 * @returns Risk factor if too many admins, or null / 如果管理員過多則回傳風險因素，否則為 null
 */
function checkAdminRisk(result: Partial<DiscoveryResult>): RiskFactor | null {
  if (!result.security?.users) return null;

  const adminCount = result.security.users.filter((u) => u.isAdmin).length;

  if (adminCount > 2) {
    return {
      category: 'tooManyAdmins',
      description:
        'Too many administrator accounts increase attack surface / 過多的管理員帳號增加攻擊面',
      score: 15,
      severity: 'medium',
      details: `Found ${adminCount} admin accounts (recommended: 2 or fewer). Admin users: ${result.security.users
        .filter((u) => u.isAdmin)
        .map((u) => u.username)
        .join(', ')}`,
    };
  }

  return null;
}

/**
 * Check for dangerous open ports
 * 檢查危險的開放埠
 *
 * @param result - Partial discovery result / 部分偵察結果
 * @returns Risk factor if dangerous ports are open, or null / 如果危險埠開放則回傳風險因素，否則為 null
 */
function checkDangerousPortsRisk(result: Partial<DiscoveryResult>): RiskFactor | null {
  const ports = result.openPorts || result.network?.openPorts;
  if (!ports || ports.length === 0) return null;

  const dangerousOpen = ports.filter((p) => DANGEROUS_PORTS.has(p.port));

  if (dangerousOpen.length > 0) {
    return {
      category: 'dangerousPorts',
      description: 'Dangerous ports are open and may be exploitable / 危險埠已開放，可能被利用',
      score: 20,
      severity: 'high',
      details: `Open dangerous ports: ${dangerousOpen
        .map((p) => `${p.port}/${p.protocol} (${p.service || 'unknown'})`)
        .join(', ')}`,
    };
  }

  return null;
}

/**
 * Check for missing or outdated system updates
 * 檢查缺失或過時的系統更新
 *
 * @param result - Partial discovery result / 部分偵察結果
 * @returns Risk factor if updates are needed, or null / 如果需要更新則回傳風險因素，否則為 null
 */
function checkUpdateRisk(result: Partial<DiscoveryResult>): RiskFactor | null {
  if (!result.security?.updates) return null;

  const updates = result.security.updates;
  const issues: string[] = [];

  if (updates.pendingUpdates > 0) {
    issues.push(`${updates.pendingUpdates} pending updates`);
  }

  if (updates.lastCheck) {
    const lastCheckDate = new Date(updates.lastCheck);
    const daysSinceCheck = Math.floor(
      (Date.now() - lastCheckDate.getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysSinceCheck > 30) {
      issues.push(`last update check was ${daysSinceCheck} days ago`);
    }
  }

  if (!updates.autoUpdateEnabled) {
    issues.push('automatic updates are disabled');
  }

  if (issues.length > 0) {
    return {
      category: 'noUpdates',
      description: 'System updates are missing or not configured properly / 系統更新缺失或配置不當',
      score: 15,
      severity: 'medium',
      details: issues.join('; '),
    };
  }

  return null;
}

/**
 * Check for absence of security tools
 * 檢查安全工具是否缺失
 *
 * @param result - Partial discovery result / 部分偵察結果
 * @returns Risk factor if no security tools detected, or null / 如果未偵測到安全工具則回傳風險因素，否則為 null
 */
function checkSecurityToolsRisk(result: Partial<DiscoveryResult>): RiskFactor | null {
  if (!result.security?.existingTools) return null;

  const runningTools = result.security.existingTools.filter((t) => t.running);

  if (runningTools.length === 0) {
    return {
      category: 'noSecurityTools',
      description:
        'No active security tools detected - system lacks protection / 未偵測到啟用中的安全工具 - 系統缺乏保護',
      score: 25,
      severity: 'high',
      details:
        result.security.existingTools.length > 0
          ? `Found ${result.security.existingTools.length} tool(s) installed but none are running`
          : 'No security tools (antivirus, EDR, IDS) were found on this system',
    };
  }

  return null;
}

/**
 * Check for default or weak password indicators
 * 檢查預設或弱密碼指標
 *
 * @param result - Partial discovery result / 部分偵察結果
 * @returns Risk factor if default passwords suspected, or null / 如果懷疑使用預設密碼則回傳風險因素，否則為 null
 */
function checkDefaultPasswordRisk(result: Partial<DiscoveryResult>): RiskFactor | null {
  if (!result.security?.users) return null;

  const usersWithOldPasswords = result.security.users.filter(
    (u) => u.passwordAge !== undefined && u.passwordAge > 365
  );

  if (usersWithOldPasswords.length > 0) {
    return {
      category: 'defaultPasswords',
      description:
        'User accounts have very old passwords that may be weak or default / 使用者帳號的密碼非常舊，可能很弱或為預設值',
      score: 10,
      severity: 'medium',
      details: `${usersWithOldPasswords.length} user(s) have passwords older than 365 days: ${usersWithOldPasswords.map((u) => u.username).join(', ')}`,
    };
  }

  return null;
}

/**
 * Check for excessive running services
 * 檢查過多的執行中服務
 *
 * @param result - Partial discovery result / 部分偵察結果
 * @returns Risk factor if too many services, or null / 如果服務過多則回傳風險因素，否則為 null
 */
function checkExcessiveServicesRisk(result: Partial<DiscoveryResult>): RiskFactor | null {
  if (!result.services) return null;

  const runningServices = result.services.filter((s) => s.status === 'running');

  if (runningServices.length > 50) {
    return {
      category: 'excessiveServices',
      description:
        'Excessive number of running services increases attack surface / 過多的執行中服務增加攻擊面',
      score: 5,
      severity: 'low',
      details: `${runningServices.length} services are running (recommended: review and disable unnecessary services)`,
    };
  }

  return null;
}

/**
 * Calculate the overall risk score and identify risk factors
 * 計算總體風險評分並識別風險因素
 *
 * Evaluates multiple security dimensions:
 * - Firewall status (max 25 points)
 * - Admin account count (max 15 points)
 * - Dangerous open ports (max 20 points)
 * - Update status (max 15 points)
 * - Security tool presence (max 25 points)
 * - Password hygiene (max 10 points)
 * - Service count (max 5 points)
 *
 * 評估多個安全面向：
 * - 防火牆狀態（最高 25 分）
 * - 管理員帳號數量（最高 15 分）
 * - 危險開放埠（最高 20 分）
 * - 更新狀態（最高 15 分）
 * - 安全工具存在狀況（最高 25 分）
 * - 密碼衛生（最高 10 分）
 * - 服務數量（最高 5 分）
 *
 * @param result - Partial discovery result to evaluate / 要評估的部分偵察結果
 * @returns Risk score (0-100) and identified risk factors / 風險評分（0-100）和已識別的風險因素
 */
export function calculateRiskScore(result: Partial<DiscoveryResult>): {
  riskScore: number;
  factors: RiskFactor[];
} {
  const factors: RiskFactor[] = [];

  logger.info('Calculating risk score');

  // Run all risk checks
  // 執行所有風險檢查
  const checks = [
    checkFirewallRisk(result),
    checkAdminRisk(result),
    checkDangerousPortsRisk(result),
    checkUpdateRisk(result),
    checkSecurityToolsRisk(result),
    checkDefaultPasswordRisk(result),
    checkExcessiveServicesRisk(result),
  ];

  for (const check of checks) {
    if (check !== null) {
      factors.push(check);
    }
  }

  // Sum up all factor scores, capped at 100
  // 加總所有因素分數，上限為 100
  const rawScore = factors.reduce((sum, f) => sum + f.score, 0);
  const riskScore = Math.min(100, Math.max(0, rawScore));

  logger.info(`Risk score calculated: ${riskScore}/100 with ${factors.length} risk factors`, {
    factors: factors.map((f) => ({ category: f.category, score: f.score, severity: f.severity })),
  });

  return { riskScore, factors };
}

/**
 * Map a numeric risk score to a severity level
 * 將數值風險評分映射到嚴重性等級
 *
 * Score ranges:
 * - 0-20:  info     (minimal risk / 最小風險)
 * - 21-40: low      (some concerns / 有一些問題)
 * - 41-60: medium   (moderate risk / 中等風險)
 * - 61-80: high     (significant risk / 重大風險)
 * - 81-100: critical (severe risk / 嚴重風險)
 *
 * 評分範圍：
 * - 0-20：info（最小風險）
 * - 21-40：low（有一些問題）
 * - 41-60：medium（中等風險）
 * - 61-80：high（重大風險）
 * - 81-100：critical（嚴重風險）
 *
 * @param score - Numeric risk score (0-100) / 數值風險評分（0-100）
 * @returns Corresponding severity level / 對應的嚴重性等級
 */
export function getRiskLevel(score: number): Severity {
  const clampedScore = Math.min(100, Math.max(0, score));

  if (clampedScore <= 20) return 'info';
  if (clampedScore <= 40) return 'low';
  if (clampedScore <= 60) return 'medium';
  if (clampedScore <= 80) return 'high';
  return 'critical';
}
