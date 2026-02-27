/**
 * Detect Agent - Event detection through rules and threat intelligence
 * 偵測代理 - 透過規則和威脅情報進行事件偵測
 *
 * First stage of the multi-agent pipeline. Receives raw SecurityEvents,
 * runs them through the Sigma rule engine and threat intelligence feeds,
 * and emits DetectionResults for events that match.
 * 多代理管線的第一階段。接收原始安全事件，透過 Sigma 規則引擎和
 * 威脅情報來源進行比對，為符合條件的事件產生偵測結果。
 *
 * @module @panguard-ai/panguard-guard/agent/detect-agent
 */

import { createLogger, checkThreatIntel } from '@panguard-ai/core';
import type { SecurityEvent, RuleMatch, RuleEngine } from '@panguard-ai/core';
import type { DetectionResult } from '../types.js';

const logger = createLogger('panguard-guard:detect-agent');

/**
 * Detect Agent processes security events through rule matching and threat intelligence
 * 偵測代理透過規則比對和威脅情報處理安全事件
 */
export class DetectAgent {
  private readonly ruleEngine: RuleEngine;
  private detectionCount = 0;

  /**
   * @param ruleEngine - The Sigma rule engine instance / Sigma 規則引擎實例
   */
  constructor(ruleEngine: RuleEngine) {
    this.ruleEngine = ruleEngine;
  }

  /**
   * Process a security event and detect threats
   * 處理安全事件並偵測威脅
   *
   * Steps:
   * 1. Match the event against loaded Sigma rules
   * 2. Check threat intelligence for network events (IP lookup)
   * 3. If any matches found, return a DetectionResult; otherwise null
   *
   * 步驟：
   * 1. 將事件與已載入的 Sigma 規則進行比對
   * 2. 對網路事件檢查威脅情報（IP 查詢）
   * 3. 如有任何比對結果，回傳 DetectionResult；否則回傳 null
   *
   * @param event - The security event to process / 要處理的安全事件
   * @returns DetectionResult if threats detected, null if clean / 偵測到威脅回傳 DetectionResult，無威脅回傳 null
   */
  detect(event: SecurityEvent): DetectionResult | null {
    logger.info(`Processing event: ${event.id} [${event.source}] / 處理事件: ${event.id}`);

    // Step 1: Match against Sigma rules / 步驟 1: 比對 Sigma 規則
    const ruleMatches: RuleMatch[] = this.ruleEngine.match(event);

    // Step 2: Check threat intelligence for network events / 步驟 2: 對網路事件檢查威脅情報
    let threatIntelMatch: { ip: string; threat: string } | undefined;
    if (event.source === 'network') {
      const ip =
        (event.metadata?.['remoteAddress'] as string) ?? (event.metadata?.['sourceIP'] as string);
      if (ip) {
        const threatEntry = checkThreatIntel(ip);
        if (threatEntry) {
          threatIntelMatch = { ip, threat: `${threatEntry.type} (${threatEntry.source})` };
        }
      }
    }

    // If no matches found, return null (normal event) / 無比對結果則回傳 null
    if (ruleMatches.length === 0 && !threatIntelMatch) {
      logger.info(`No threats detected for event ${event.id} / 事件 ${event.id} 未偵測到威脅`);
      return null;
    }

    this.detectionCount++;

    const result: DetectionResult = {
      event,
      ruleMatches: ruleMatches.map((m: RuleMatch) => ({
        ruleId: m.rule.id,
        ruleName: m.rule.title,
        severity: (m.rule.level ?? 'medium') as SecurityEvent['severity'],
      })),
      threatIntelMatch,
      timestamp: new Date().toISOString(),
    };

    logger.info(
      `Threat detected for event ${event.id}: ${ruleMatches.length} rule matches, ` +
        `threat intel: ${threatIntelMatch ? 'yes' : 'no'} / ` +
        `事件 ${event.id} 偵測到威脅: ${ruleMatches.length} 條規則比對`
    );

    return result;
  }

  /**
   * Get total number of detections / 取得偵測總數
   */
  getDetectionCount(): number {
    return this.detectionCount;
  }
}
