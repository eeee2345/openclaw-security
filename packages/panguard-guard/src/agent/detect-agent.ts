/**
 * Detect Agent - Event detection through rules, threat intelligence, and correlation
 * 偵測代理 - 透過規則、威脅情報和事件關聯進行事件偵測
 *
 * First stage of the multi-agent pipeline. Receives raw SecurityEvents,
 * runs them through the Sigma rule engine and threat intelligence feeds,
 * correlates events within a sliding time window to detect attack chains,
 * and emits DetectionResults for events that match.
 *
 * @module @panguard-ai/panguard-guard/agent/detect-agent
 */

import { createLogger, checkThreatIntel } from '@panguard-ai/core';
import type { SecurityEvent, RuleMatch, RuleEngine } from '@panguard-ai/core';
import type { DetectionResult } from '../types.js';

const logger = createLogger('panguard-guard:detect-agent');

/** Correlation window in ms (5 minutes) */
const CORRELATION_WINDOW_MS = 5 * 60 * 1000;

/** Max correlated events to keep in memory */
const MAX_CORRELATION_BUFFER = 1000;

/** Deduplication window in ms (60 seconds) */
const DEDUP_WINDOW_MS = 60 * 1000;

/** Max dedup entries to track */
const MAX_DEDUP_ENTRIES = 500;

/** Minimum events from same source to flag as attack chain */
const ATTACK_CHAIN_THRESHOLD = 3;

/** Correlated event stored in sliding window */
interface CorrelatedEvent {
  event: SecurityEvent;
  ruleIds: string[];
  sourceIP?: string;
  timestamp: number;
}

/** Dedup entry key → last-seen timestamp */
interface DedupEntry {
  key: string;
  timestamp: number;
}

/**
 * Detect Agent processes security events through rule matching,
 * threat intelligence, event correlation, and deduplication.
 */
export class DetectAgent {
  private readonly ruleEngine: RuleEngine;
  private detectionCount = 0;

  /** Sliding window for event correlation */
  private readonly correlationBuffer: CorrelatedEvent[] = [];

  /** Deduplication tracker: key → last detection timestamp */
  private readonly dedupMap = new Map<string, number>();

  constructor(ruleEngine: RuleEngine) {
    this.ruleEngine = ruleEngine;
  }

  /**
   * Process a security event and detect threats
   *
   * Steps:
   * 1. Match the event against loaded Sigma rules
   * 2. Check threat intelligence for network events (IP lookup, IPv4 + IPv6)
   * 3. Deduplicate: skip if same source+rule fired within dedup window
   * 4. Correlate: check sliding window for attack chain patterns
   * 5. If any matches found, return a DetectionResult; otherwise null
   */
  detect(event: SecurityEvent): DetectionResult | null {
    logger.info(`Processing event: ${event.id} [${event.source}]`);

    // Step 1: Match against Sigma rules
    const ruleMatches: RuleMatch[] = this.ruleEngine.match(event);

    // Step 2: Check threat intelligence (supports multiple IP fields)
    let threatIntelMatch: { ip: string; threat: string } | undefined;
    if (event.source === 'network' || event.source === 'suricata') {
      const ip = this.extractIP(event);
      if (ip) {
        const threatEntry = checkThreatIntel(ip);
        if (threatEntry) {
          threatIntelMatch = { ip, threat: `${threatEntry.type} (${threatEntry.source})` };
        }
      }
    }

    // If no matches found, return null (normal event)
    if (ruleMatches.length === 0 && !threatIntelMatch) {
      return null;
    }

    // Step 3: Deduplication — skip if identical detection within window
    const dedupKey = this.buildDedupKey(event, ruleMatches);
    if (this.isDuplicate(dedupKey)) {
      logger.info(`Dedup: skipping duplicate detection for event ${event.id}`);
      return null;
    }
    this.recordDedup(dedupKey);

    // Step 4: Correlation — check for attack chain
    const sourceIP = this.extractIP(event);
    const ruleIds = ruleMatches.map((m) => m.rule.id);
    const attackChain = this.correlate(event, ruleIds, sourceIP);

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
      // Attach correlation metadata if attack chain detected
      ...(attackChain ? { attackChain } : {}),
    };

    logger.info(
      `Threat detected for event ${event.id}: ${ruleMatches.length} rule matches, ` +
        `threat intel: ${threatIntelMatch ? 'yes' : 'no'}, ` +
        `attack chain: ${attackChain ? `${attackChain.eventCount} events` : 'no'}`
    );

    return result;
  }

  /**
   * Extract IP address from event metadata (IPv4 + IPv6 support)
   */
  private extractIP(event: SecurityEvent): string | undefined {
    const meta = event.metadata;
    if (!meta) return undefined;

    // Check multiple possible IP fields
    const candidates = [
      meta['remoteAddress'],
      meta['sourceIP'],
      meta['src_ip'],
      meta['destinationIP'],
      meta['dst_ip'],
      meta['clientIP'],
      meta['peerAddress'],
    ];

    for (const candidate of candidates) {
      if (typeof candidate === 'string' && candidate.length > 0) {
        return candidate;
      }
    }

    return undefined;
  }

  // ---------------------------------------------------------------------------
  // Deduplication
  // ---------------------------------------------------------------------------

  /** Build a dedup key from event source + matched rule IDs */
  private buildDedupKey(event: SecurityEvent, matches: RuleMatch[]): string {
    const ip = this.extractIP(event) ?? 'no-ip';
    const rules = matches
      .map((m) => m.rule.id)
      .sort()
      .join(',');
    return `${event.source}:${ip}:${rules}`;
  }

  /** Check if this key was seen within the dedup window */
  private isDuplicate(key: string): boolean {
    const lastSeen = this.dedupMap.get(key);
    if (!lastSeen) return false;
    return Date.now() - lastSeen < DEDUP_WINDOW_MS;
  }

  /** Record a dedup entry and evict old entries if over limit */
  private recordDedup(key: string): void {
    this.dedupMap.set(key, Date.now());

    // Evict expired entries periodically
    if (this.dedupMap.size > MAX_DEDUP_ENTRIES) {
      const now = Date.now();
      for (const [k, ts] of this.dedupMap) {
        if (now - ts > DEDUP_WINDOW_MS) {
          this.dedupMap.delete(k);
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Event Correlation (Attack Chain Detection)
  // ---------------------------------------------------------------------------

  /**
   * Correlate events within a sliding time window.
   * Returns attack chain metadata if multiple events from same source detected.
   */
  private correlate(
    event: SecurityEvent,
    ruleIds: string[],
    sourceIP?: string
  ): { sourceIP: string; eventCount: number; ruleIds: string[]; windowMs: number } | undefined {
    const now = Date.now();

    // Add current event to correlation buffer
    this.correlationBuffer.push({
      event,
      ruleIds,
      sourceIP,
      timestamp: now,
    });

    // Evict events outside the correlation window
    while (
      this.correlationBuffer.length > 0 &&
      now - this.correlationBuffer[0]!.timestamp > CORRELATION_WINDOW_MS
    ) {
      this.correlationBuffer.shift();
    }

    // Trim buffer if too large
    while (this.correlationBuffer.length > MAX_CORRELATION_BUFFER) {
      this.correlationBuffer.shift();
    }

    // Only correlate if we have a source IP
    if (!sourceIP) return undefined;

    // Find all events from this source IP within the window
    const relatedEvents = this.correlationBuffer.filter(
      (e) => e.sourceIP === sourceIP && now - e.timestamp <= CORRELATION_WINDOW_MS
    );

    if (relatedEvents.length >= ATTACK_CHAIN_THRESHOLD) {
      // Collect all unique rule IDs across the chain
      const allRuleIds = new Set<string>();
      for (const re of relatedEvents) {
        for (const rid of re.ruleIds) {
          allRuleIds.add(rid);
        }
      }

      logger.warn(
        `Attack chain detected from ${sourceIP}: ${relatedEvents.length} events, ` +
          `${allRuleIds.size} unique rules in ${CORRELATION_WINDOW_MS / 1000}s window`
      );

      return {
        sourceIP,
        eventCount: relatedEvents.length,
        ruleIds: [...allRuleIds],
        windowMs: CORRELATION_WINDOW_MS,
      };
    }

    return undefined;
  }

  /** Get total number of detections */
  getDetectionCount(): number {
    return this.detectionCount;
  }

  /** Get current correlation buffer size (for monitoring) */
  getCorrelationBufferSize(): number {
    return this.correlationBuffer.length;
  }

  /** Get current dedup map size (for monitoring) */
  getDedupMapSize(): number {
    return this.dedupMap.size;
  }
}
