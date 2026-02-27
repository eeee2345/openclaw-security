/**
 * Trap Intelligence Module
 * 蜜罐情報模組
 *
 * Converts trap sessions to anonymized intelligence data
 * for upload to Panguard Threat Cloud.
 * 將蜜罐連線轉換為匿名化情報資料，用於上傳到 Panguard Threat Cloud。
 *
 * @module @panguard-ai/panguard-trap/intel
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapSession, TrapIntelligence, AttackerProfile } from '../types.js';

const logger = createLogger('panguard-trap:intel');

// ---------------------------------------------------------------------------
// IP Anonymization
// IP 匿名化
// ---------------------------------------------------------------------------

/** Check if IP is private / 檢查是否為私有 IP */
function isPrivateIP(ip: string): boolean {
  const cleanIP = ip.replace('::ffff:', '');
  if (cleanIP.startsWith('10.')) return true;
  if (cleanIP.startsWith('172.')) {
    const secondOctet = parseInt(cleanIP.split('.')[1] ?? '0', 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  if (cleanIP.startsWith('192.168.')) return true;
  if (cleanIP === '127.0.0.1' || cleanIP === 'localhost') return true;
  if (cleanIP === '::1') return true;
  return false;
}

// ---------------------------------------------------------------------------
// Intelligence Builder
// 情報建構器
// ---------------------------------------------------------------------------

/**
 * Convert a trap session to anonymized intelligence
 * 將蜜罐連線轉換為匿名化情報
 */
export function buildTrapIntel(
  session: TrapSession,
  profile?: AttackerProfile
): TrapIntelligence | null {
  // Don't report private IPs
  if (isPrivateIP(session.sourceIP)) {
    logger.debug('Skipping private IP for intel / 跳過私有 IP');
    return null;
  }

  // Need at least some activity to report
  if (session.events.length < 2) {
    return null;
  }

  // Build top credentials (generic patterns only)
  const usernameCounts = new Map<string, number>();
  for (const cred of session.credentials) {
    if (cred.username) {
      usernameCounts.set(cred.username, (usernameCounts.get(cred.username) ?? 0) + 1);
    }
  }
  const topCredentials = Array.from(usernameCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([username, count]) => ({ username, count }));

  // Determine attack type
  const attackType = determineAttackType(session);

  const intel: TrapIntelligence = {
    timestamp: session.startTime,
    serviceType: session.serviceType,
    sourceIP: session.sourceIP,
    attackType,
    mitreTechniques: [...session.mitreTechniques],
    skillLevel: profile?.skillLevel ?? 'script_kiddie',
    intent: profile?.intent ?? 'unknown',
    tools: profile?.toolsDetected ?? [],
    topCredentials,
    region: profile?.geoHints?.country,
  };

  logger.info(`Trap intel built for ${session.sourceIP} (${attackType}) / 蜜罐情報已建立`);

  return intel;
}

/**
 * Build batch intel from multiple sessions
 * 從多個連線建構批次情報
 */
export function buildBatchIntel(
  sessions: TrapSession[],
  profiles: Map<string, AttackerProfile>
): TrapIntelligence[] {
  const results: TrapIntelligence[] = [];

  for (const session of sessions) {
    const profile = session.attackerProfileId ? profiles.get(session.attackerProfileId) : undefined;
    const intel = buildTrapIntel(session, profile);
    if (intel) {
      results.push(intel);
    }
  }

  return results;
}

/**
 * Determine the primary attack type from a session
 * 從連線判定主要攻擊類型
 */
function determineAttackType(session: TrapSession): string {
  // Check for specific attack types based on events and techniques
  if (session.mitreTechniques.includes('T1110')) {
    return 'brute_force';
  }
  if (session.mitreTechniques.includes('T1190')) {
    return 'exploit_attempt';
  }
  if (session.mitreTechniques.includes('T1496')) {
    return 'cryptomining';
  }
  if (session.mitreTechniques.includes('T1505.003')) {
    return 'webshell_upload';
  }
  if (session.mitreTechniques.includes('T1485')) {
    return 'data_destruction';
  }
  if (session.mitreTechniques.includes('T1105')) {
    return 'malware_download';
  }
  if (session.mitreTechniques.includes('T1595')) {
    return 'reconnaissance';
  }

  // Fallback by service type
  if (session.serviceType === 'ssh' || session.serviceType === 'telnet') {
    return session.credentials.length > 0 ? 'brute_force' : 'reconnaissance';
  }
  if (session.serviceType === 'http') {
    return 'web_attack';
  }

  return 'unknown';
}

// ---------------------------------------------------------------------------
// Intel Statistics
// 情報統計
// ---------------------------------------------------------------------------

/** Intel summary / 情報摘要 */
export interface IntelSummary {
  totalIntelReports: number;
  uniqueSourceIPs: number;
  attackTypeDistribution: Record<string, number>;
  topSourceIPs: { ip: string; count: number }[];
  serviceDistribution: Record<string, number>;
}

/**
 * Generate intel summary from collected reports
 * 從收集的報告生成情報摘要
 */
export function generateIntelSummary(reports: TrapIntelligence[]): IntelSummary {
  const ipCounts = new Map<string, number>();
  const attackTypes: Record<string, number> = {};
  const services: Record<string, number> = {};

  for (const report of reports) {
    ipCounts.set(report.sourceIP, (ipCounts.get(report.sourceIP) ?? 0) + 1);
    attackTypes[report.attackType] = (attackTypes[report.attackType] ?? 0) + 1;
    services[report.serviceType] = (services[report.serviceType] ?? 0) + 1;
  }

  const topSourceIPs = Array.from(ipCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));

  return {
    totalIntelReports: reports.length,
    uniqueSourceIPs: ipCounts.size,
    attackTypeDistribution: attackTypes,
    topSourceIPs,
    serviceDistribution: services,
  };
}
