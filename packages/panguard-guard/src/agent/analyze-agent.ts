/**
 * Analyze Agent - Threat analysis with Dynamic Reasoning, Feedback Loop, and Attack Chain Awareness
 * 分析代理 - 使用動態推理、回饋迴路和攻擊鏈感知進行威脅分析
 *
 * Second stage of the multi-agent pipeline. Receives DetectionResults,
 * performs deep analysis using rule evidence, baseline comparison,
 * attack chain correlation, feedback history, and optional AI reasoning,
 * then produces a ThreatVerdict.
 *
 * @module @panguard-ai/panguard-guard/agent/analyze-agent
 */

import { createLogger } from '@panguard-ai/core';
import type {
  DetectionResult,
  ThreatVerdict,
  Evidence,
  ResponseAction,
  EnvironmentBaseline,
  DeviationResult,
  AnalyzeLLM,
  LLMAnalysisResult,
  LLMClassificationResult,
} from '../types.js';
import { checkDeviation } from '../memory/baseline.js';

const logger = createLogger('panguard-guard:analyze-agent');

/** Severity to base confidence mapping */
const SEVERITY_CONFIDENCE: Record<string, number> = {
  critical: 90,
  high: 75,
  medium: 55,
  low: 35,
  info: 15,
};

/** Feedback record for false positive/negative tracking */
interface FeedbackRecord {
  ruleId: string;
  falsePositives: number;
  truePositives: number;
  lastUpdated: string;
}

/** Time-of-day risk multiplier for unusual hours */
const UNUSUAL_HOUR_MULTIPLIER = 1.15;

/** Attack chain confidence boost per correlated event */
const ATTACK_CHAIN_BOOST_PER_EVENT = 5;

/** Max attack chain boost */
const ATTACK_CHAIN_BOOST_MAX = 25;

/**
 * Analyze Agent performs deep analysis on detected threats
 * with feedback-driven confidence adjustment and attack chain awareness.
 */
export class AnalyzeAgent {
  private readonly llm: AnalyzeLLM | null;
  private analysisCount = 0;

  /** Feedback history: ruleId → FeedbackRecord */
  private readonly feedbackHistory = new Map<string, FeedbackRecord>();

  constructor(llm: AnalyzeLLM | null) {
    this.llm = llm;
  }

  /**
   * Analyze a detection result and produce a verdict
   *
   * Evidence collection pipeline:
   * 1. Sigma rule match evidence (weighted 0.4) with feedback adjustment
   * 2. Threat intelligence evidence
   * 3. Baseline deviation check (weighted 0.3) with time-of-day awareness
   * 4. Attack chain correlation boost
   * 5. AI analysis if available (weighted 0.3)
   * 6. Calculate final weighted confidence
   * 7. Determine conclusion and recommended action
   */
  async analyze(detection: DetectionResult, baseline: EnvironmentBaseline): Promise<ThreatVerdict> {
    logger.info(`Analyzing detection for event ${detection.event.id}`);
    this.analysisCount++;

    const evidenceList: Evidence[] = [];

    // Step 1: Collect rule match evidence with feedback adjustment
    for (const match of detection.ruleMatches) {
      const baseConfidence = SEVERITY_CONFIDENCE[match.severity] ?? 50;
      const adjustedConfidence = this.applyFeedbackAdjustment(match.ruleId, baseConfidence);

      evidenceList.push({
        source: 'rule_match',
        description: `Sigma rule matched: ${match.ruleName} (${match.ruleId})`,
        confidence: adjustedConfidence,
        data: { ruleId: match.ruleId, severity: match.severity },
      });
    }

    // Step 2: Collect threat intel evidence
    if (detection.threatIntelMatch) {
      evidenceList.push({
        source: 'threat_intel',
        description:
          `Known malicious IP: ${detection.threatIntelMatch.ip} - ` +
          detection.threatIntelMatch.threat,
        confidence: 85,
        data: detection.threatIntelMatch,
      });
    }

    // Step 3: Baseline deviation check with time-of-day awareness
    const deviation: DeviationResult = checkDeviation(baseline, detection.event);
    if (deviation.isDeviation) {
      let deviationConfidence = deviation.confidence;

      // Boost confidence if event occurs at unusual hour (00:00-05:59)
      const eventHour = new Date(detection.event.timestamp).getHours();
      if (eventHour >= 0 && eventHour < 6) {
        deviationConfidence = Math.min(
          100,
          Math.round(deviationConfidence * UNUSUAL_HOUR_MULTIPLIER)
        );
      }

      evidenceList.push({
        source: 'baseline_deviation',
        description: deviation.description,
        confidence: deviationConfidence,
        data: {
          deviationType: deviation.deviationType,
          ...(eventHour >= 0 && eventHour < 6 ? { unusualHour: true, hour: eventHour } : {}),
        },
      });
    }

    // Step 4: Attack chain correlation boost
    if (detection.attackChain) {
      const chainBoost = Math.min(
        ATTACK_CHAIN_BOOST_MAX,
        detection.attackChain.eventCount * ATTACK_CHAIN_BOOST_PER_EVENT
      );

      evidenceList.push({
        source: 'rule_match', // counts toward rule weight
        description:
          `Attack chain detected: ${detection.attackChain.eventCount} correlated events ` +
          `from ${detection.attackChain.sourceIP} within ${detection.attackChain.windowMs / 1000}s`,
        confidence: Math.min(95, 70 + chainBoost),
        data: {
          attackChain: true,
          eventCount: detection.attackChain.eventCount,
          sourceIP: detection.attackChain.sourceIP,
          uniqueRules: detection.attackChain.ruleIds.length,
        },
      });
    }

    // Step 5: AI analysis (if available)
    let aiAnalysis: LLMAnalysisResult | null = null;
    let aiClassification: LLMClassificationResult | null = null;

    if (this.llm) {
      try {
        const available = await this.llm.isAvailable();
        if (available) {
          const prompt = buildAnalysisPrompt(detection, deviation);
          aiAnalysis = await this.llm.analyze(prompt);
          aiClassification = await this.llm.classify(detection.event);

          evidenceList.push({
            source: 'ai_analysis',
            description: aiAnalysis.summary,
            confidence: Math.round(aiAnalysis.confidence * 100),
            data: {
              severity: aiAnalysis.severity,
              recommendations: aiAnalysis.recommendations,
            },
          });
        } else {
          logger.info('AI unavailable, using rule-based analysis only');
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`AI analysis failed: ${msg}`);
      }
    }

    // Step 6: Calculate final confidence (weighted average)
    const hasAI = this.llm !== null && aiAnalysis !== null;
    let finalConfidence = calculateFinalConfidence(evidenceList, hasAI);

    // Contradiction detection: if rule says high but baseline says normal, slight reduce
    const hasHighRule = evidenceList.some(
      (e) =>
        e.source === 'rule_match' &&
        e.confidence >= 70 &&
        !(e.data as Record<string, unknown>)?.['attackChain']
    );
    const noDeviation = !deviation.isDeviation;
    if (hasHighRule && noDeviation && baseline.learningComplete) {
      finalConfidence = Math.max(0, finalConfidence - 10);
      logger.info(
        `Contradiction: high rule match but no baseline deviation. Confidence reduced by 10.`
      );
    }

    // Step 7: Determine conclusion and recommended action
    const conclusion = determineConclusion(finalConfidence);
    const recommendedAction = determineAction(finalConfidence, detection);

    const verdict: ThreatVerdict = {
      conclusion,
      confidence: finalConfidence,
      reasoning: buildReasoning(evidenceList, deviation, aiAnalysis),
      evidence: evidenceList,
      recommendedAction,
      mitreTechnique: aiClassification?.technique,
    };

    logger.info(
      `Verdict for event ${detection.event.id}: ${conclusion} (confidence: ${finalConfidence}%)`
    );

    return verdict;
  }

  // ---------------------------------------------------------------------------
  // Feedback Loop
  // ---------------------------------------------------------------------------

  /**
   * Record user feedback: mark a verdict as false positive or true positive.
   * This adjusts future confidence for the same rule.
   */
  recordFeedback(ruleId: string, isFalsePositive: boolean): void {
    const existing = this.feedbackHistory.get(ruleId) ?? {
      ruleId,
      falsePositives: 0,
      truePositives: 0,
      lastUpdated: new Date().toISOString(),
    };

    if (isFalsePositive) {
      existing.falsePositives += 1;
    } else {
      existing.truePositives += 1;
    }
    existing.lastUpdated = new Date().toISOString();

    this.feedbackHistory.set(ruleId, existing);
    logger.info(
      `Feedback recorded for rule ${ruleId}: ` +
        `FP=${existing.falsePositives}, TP=${existing.truePositives}`
    );
  }

  /**
   * Apply feedback adjustment to rule confidence.
   * Rules with high false positive rate get reduced confidence.
   * Rules with high true positive rate get boosted confidence.
   */
  private applyFeedbackAdjustment(ruleId: string, baseConfidence: number): number {
    const feedback = this.feedbackHistory.get(ruleId);
    if (!feedback) return baseConfidence;

    const total = feedback.falsePositives + feedback.truePositives;
    if (total < 3) return baseConfidence; // Not enough data

    const fpRate = feedback.falsePositives / total;

    // High FP rate → reduce confidence (max -30%)
    // Low FP rate → boost confidence (max +10%)
    if (fpRate > 0.5) {
      const reduction = Math.min(30, Math.round(fpRate * 40));
      return Math.max(10, baseConfidence - reduction);
    }

    if (fpRate < 0.1 && total >= 5) {
      const boost = Math.min(10, Math.round((1 - fpRate) * 10));
      return Math.min(100, baseConfidence + boost);
    }

    return baseConfidence;
  }

  /**
   * Get feedback statistics
   */
  getFeedbackStats(): Map<string, FeedbackRecord> {
    return new Map(this.feedbackHistory);
  }

  /** Get total analysis count */
  getAnalysisCount(): number {
    return this.analysisCount;
  }
}

// ---------------------------------------------------------------------------
// Internal scoring functions
// ---------------------------------------------------------------------------

function calculateFinalConfidence(evidence: Evidence[], hasAI: boolean): number {
  const bySource = groupBySource(evidence);

  const ruleConfidence = maxConfidence(bySource['rule_match']);
  const baselineConfidence = maxConfidence(bySource['baseline_deviation']);
  const threatIntelConfidence = maxConfidence(bySource['threat_intel']);
  const aiConfidence = maxConfidence(bySource['ai_analysis']);
  const ebpfConfidence = Math.max(
    maxConfidence(bySource['falco']),
    maxConfidence(bySource['suricata'])
  );

  const ruleScore = Math.max(ruleConfidence, threatIntelConfidence);
  const hasEbpf = ebpfConfidence > 0;

  if (hasEbpf && hasAI) {
    return Math.round(
      ebpfConfidence * 0.2 + ruleScore * 0.3 + baselineConfidence * 0.2 + aiConfidence * 0.3
    );
  }

  if (hasEbpf) {
    return Math.round(ebpfConfidence * 0.25 + ruleScore * 0.4 + baselineConfidence * 0.35);
  }

  if (hasAI) {
    return Math.round(ruleScore * 0.4 + baselineConfidence * 0.3 + aiConfidence * 0.3);
  }

  return Math.round(ruleScore * 0.6 + baselineConfidence * 0.4);
}

function groupBySource(evidence: Evidence[]): Record<string, Evidence[]> {
  const result: Record<string, Evidence[]> = {};
  for (const e of evidence) {
    const key = e.source;
    if (!result[key]) {
      result[key] = [];
    }
    result[key]!.push(e);
  }
  return result;
}

function maxConfidence(items?: Evidence[]): number {
  if (!items || items.length === 0) return 0;
  return Math.max(...items.map((e) => e.confidence));
}

function determineConclusion(confidence: number): 'benign' | 'suspicious' | 'malicious' {
  if (confidence >= 75) return 'malicious';
  if (confidence >= 40) return 'suspicious';
  return 'benign';
}

function determineAction(confidence: number, detection: DetectionResult): ResponseAction {
  const hasCritical = detection.ruleMatches.some((m) => m.severity === 'critical');
  const hasAttackChain = !!detection.attackChain;

  // Attack chains lower the auto-respond threshold
  const autoThreshold = hasAttackChain ? 75 : 85;

  if (confidence >= autoThreshold || (hasCritical && confidence >= 70)) {
    if (detection.event.source === 'network' || detection.event.source === 'suricata')
      return 'block_ip';
    if (detection.event.source === 'process' || detection.event.source === 'falco')
      return 'kill_process';
    return 'notify';
  }

  if (confidence >= 50) return 'notify';
  return 'log_only';
}

function buildAnalysisPrompt(detection: DetectionResult, deviation: DeviationResult): string {
  const parts: string[] = [
    'Security Event Analysis',
    `Event: ${detection.event.description}`,
    `Source: ${detection.event.source}`,
    `Severity: ${detection.event.severity}`,
    `Category: ${detection.event.category}`,
  ];

  if (detection.ruleMatches.length > 0) {
    parts.push(`Rule Matches: ${detection.ruleMatches.map((m) => m.ruleName).join(', ')}`);
  }

  if (detection.threatIntelMatch) {
    parts.push(
      `Threat Intel: ${detection.threatIntelMatch.ip} - ${detection.threatIntelMatch.threat}`
    );
  }

  if (deviation.isDeviation) {
    parts.push(`Baseline Deviation: ${deviation.description}`);
  }

  if (detection.attackChain) {
    parts.push(
      `Attack Chain: ${detection.attackChain.eventCount} correlated events from ${detection.attackChain.sourceIP}`
    );
  }

  parts.push('Analyze the threat level and provide recommendations.');

  return parts.join('\n');
}

function buildReasoning(
  evidence: Evidence[],
  _deviation: DeviationResult,
  aiAnalysis: LLMAnalysisResult | null
): string {
  const parts: string[] = [];

  for (const e of evidence) {
    parts.push(`[${e.source}] ${e.description} (confidence: ${e.confidence}%)`);
  }

  if (aiAnalysis) {
    parts.push(`AI Summary: ${aiAnalysis.summary}`);
    if (aiAnalysis.recommendations.length > 0) {
      parts.push(`Recommendations: ${aiAnalysis.recommendations.join('; ')}`);
    }
  }

  return parts.join('\n');
}
