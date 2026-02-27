/**
 * Security Score Engine - Weighted security posture scoring
 * 安全分數引擎 - 加權安全態勢評分
 *
 * Calculates a 0-100 security score based on multiple factors:
 * - Firewall status (15%)
 * - Open port risk (15%)
 * - Password policy (10%)
 * - System updates (15%)
 * - Security tools running (10%)
 * - Recent threat count (15%)
 * - Compliance progress (10%)
 * - Response speed (10%)
 *
 * @module @panguard-ai/core/scoring/security-score
 */

import { createLogger } from '../utils/logger.js';

const logger = createLogger('security-score');

/** Individual score factor / 個別評分因子 */
export interface ScoreFactor {
  name: string;
  weight: number;
  score: number; // 0-100
  description: string;
}

/** Security score snapshot / 安全分數快照 */
export interface SecurityScoreSnapshot {
  totalScore: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  factors: ScoreFactor[];
  calculatedAt: string;
  trend: 'improving' | 'stable' | 'declining';
  previousScore?: number;
}

/** Input data for score calculation / 計算分數的輸入資料 */
export interface ScoreInput {
  firewallEnabled: boolean;
  openPorts: Array<{ port: number; service?: string }>;
  dangerousPorts: number[]; // ports considered dangerous (22, 23, 445, 3389, etc.)
  passwordPolicyStrength: number; // 0-100
  pendingUpdates: number;
  securityToolsRunning: string[];
  recentThreats24h: number;
  recentThreats7d: number;
  complianceProgress: number; // 0-100
  avgResponseTimeMs: number; // avg time to respond to threats
}

/** Score thresholds for actions / 分數行動閾值 */
const DANGEROUS_PORTS = new Set([
  21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017,
]);

/**
 * Calculate security score from system state
 * 從系統狀態計算安全分數
 */
export function calculateSecurityScore(
  input: ScoreInput,
  previousScore?: number
): SecurityScoreSnapshot {
  const factors: ScoreFactor[] = [];

  // 1. Firewall (15%)
  const firewallScore = input.firewallEnabled ? 100 : 0;
  factors.push({
    name: 'firewall',
    weight: 0.15,
    score: firewallScore,
    description: input.firewallEnabled
      ? 'Firewall is active'
      : 'Firewall is disabled - critical risk',
  });

  // 2. Open Port Risk (15%)
  const dangerousOpenPorts = input.openPorts.filter(
    (p) => DANGEROUS_PORTS.has(p.port) || input.dangerousPorts.includes(p.port)
  );
  const portScore =
    dangerousOpenPorts.length === 0
      ? 100
      : dangerousOpenPorts.length <= 1
        ? 70
        : dangerousOpenPorts.length <= 3
          ? 40
          : 10;
  factors.push({
    name: 'open_ports',
    weight: 0.15,
    score: portScore,
    description:
      dangerousOpenPorts.length === 0
        ? 'No dangerous ports exposed'
        : `${dangerousOpenPorts.length} dangerous port(s) open`,
  });

  // 3. Password Policy (10%)
  factors.push({
    name: 'password_policy',
    weight: 0.1,
    score: input.passwordPolicyStrength,
    description:
      input.passwordPolicyStrength >= 80
        ? 'Strong password policy'
        : input.passwordPolicyStrength >= 50
          ? 'Moderate password policy'
          : 'Weak password policy',
  });

  // 4. System Updates (15%)
  const updateScore =
    input.pendingUpdates === 0
      ? 100
      : input.pendingUpdates <= 5
        ? 70
        : input.pendingUpdates <= 20
          ? 40
          : 10;
  factors.push({
    name: 'system_updates',
    weight: 0.15,
    score: updateScore,
    description:
      input.pendingUpdates === 0
        ? 'System is fully updated'
        : `${input.pendingUpdates} pending update(s)`,
  });

  // 5. Security Tools (10%)
  const toolScore =
    input.securityToolsRunning.length >= 3
      ? 100
      : input.securityToolsRunning.length === 2
        ? 80
        : input.securityToolsRunning.length === 1
          ? 50
          : 0;
  factors.push({
    name: 'security_tools',
    weight: 0.1,
    score: toolScore,
    description:
      input.securityToolsRunning.length === 0
        ? 'No security tools detected'
        : `${input.securityToolsRunning.length} security tool(s) active`,
  });

  // 6. Recent Threats (15%)
  const threatScore =
    input.recentThreats24h === 0 && input.recentThreats7d === 0
      ? 100
      : input.recentThreats24h === 0
        ? 80
        : input.recentThreats24h <= 3
          ? 50
          : input.recentThreats24h <= 10
            ? 25
            : 5;
  factors.push({
    name: 'recent_threats',
    weight: 0.15,
    score: threatScore,
    description:
      input.recentThreats24h === 0
        ? 'No threats in the last 24 hours'
        : `${input.recentThreats24h} threat(s) in the last 24 hours`,
  });

  // 7. Compliance Progress (10%)
  factors.push({
    name: 'compliance',
    weight: 0.1,
    score: input.complianceProgress,
    description:
      input.complianceProgress >= 80
        ? 'Good compliance progress'
        : input.complianceProgress >= 50
          ? 'Moderate compliance progress'
          : 'Compliance needs attention',
  });

  // 8. Response Speed (10%)
  const responseScore =
    input.avgResponseTimeMs <= 60000
      ? 100 // < 1 min
      : input.avgResponseTimeMs <= 300000
        ? 80 // < 5 min
        : input.avgResponseTimeMs <= 900000
          ? 50 // < 15 min
          : input.avgResponseTimeMs <= 3600000
            ? 25 // < 1 hour
            : 10;
  factors.push({
    name: 'response_speed',
    weight: 0.1,
    score: responseScore,
    description: `Average response time: ${Math.round(input.avgResponseTimeMs / 1000)}s`,
  });

  // Calculate weighted total
  const totalScore = Math.round(factors.reduce((sum, f) => sum + f.score * f.weight, 0));

  // Determine trend
  let trend: 'improving' | 'stable' | 'declining' = 'stable';
  if (previousScore !== undefined) {
    if (totalScore > previousScore + 2) trend = 'improving';
    else if (totalScore < previousScore - 2) trend = 'declining';
  }

  const snapshot: SecurityScoreSnapshot = {
    totalScore,
    grade: scoreToGrade(totalScore),
    factors,
    calculatedAt: new Date().toISOString(),
    trend,
    previousScore,
  };

  logger.info(
    `Security score calculated: ${totalScore}/100 (Grade: ${snapshot.grade}, Trend: ${trend})`
  );
  return snapshot;
}

/** Convert score to letter grade / 分數轉換為等級 */
export function scoreToGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/** Get color for score (for CLI/UI) / 取得分數的顏色 */
export function scoreToColor(score: number): 'green' | 'yellow' | 'orange' | 'red' {
  if (score >= 80) return 'green';
  if (score >= 60) return 'yellow';
  if (score >= 40) return 'orange';
  return 'red';
}

/** Generate human-readable summary / 產生人類可讀的摘要 */
export function generateScoreSummary(
  snapshot: SecurityScoreSnapshot,
  lang: 'en' | 'zh-TW' = 'en'
): string {
  const { totalScore, grade, trend, factors } = snapshot;

  const trendText =
    lang === 'zh-TW'
      ? trend === 'improving'
        ? 'improving'
        : trend === 'declining'
          ? 'declining'
          : 'stable'
      : trend;

  const trendArrow = trend === 'improving' ? '+' : trend === 'declining' ? '-' : '=';

  const worstFactors = [...factors]
    .sort((a, b) => a.score - b.score)
    .slice(0, 3)
    .filter((f) => f.score < 70);

  let summary =
    lang === 'zh-TW'
      ? `Security Score: ${totalScore}/100 (${grade}) [${trendArrow} ${trendText}]`
      : `Security Score: ${totalScore}/100 (${grade}) [${trendArrow} ${trendText}]`;

  if (worstFactors.length > 0) {
    const items = worstFactors.map((f) => `  - ${f.name}: ${f.score}/100 - ${f.description}`);
    summary += `\n\nTop issues:\n${items.join('\n')}`;
  }

  return summary;
}
