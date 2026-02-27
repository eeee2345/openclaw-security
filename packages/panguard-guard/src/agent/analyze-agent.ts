/**
 * Analyze Agent - Threat analysis with Dynamic Reasoning and Context Memory
 * 分析代理 - 使用動態推理和 Context Memory 進行威脅分析
 *
 * Second stage of the multi-agent pipeline. Receives DetectionResults,
 * performs deep analysis using rule evidence, baseline comparison,
 * and optional AI reasoning, then produces a ThreatVerdict.
 * 多代理管線的第二階段。接收偵測結果，使用規則證據、基線比較和
 * 可選的 AI 推理進行深度分析，然後產生威脅判決。
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

/** Severity to base confidence mapping / 嚴重度到基礎信心度映射 */
const SEVERITY_CONFIDENCE: Record<string, number> = {
  critical: 90,
  high: 75,
  medium: 55,
  low: 35,
  info: 15,
};

/**
 * Analyze Agent performs deep analysis on detected threats
 * 分析代理對偵測到的威脅執行深度分析
 */
export class AnalyzeAgent {
  private readonly llm: AnalyzeLLM | null;
  private analysisCount = 0;

  /**
   * @param llm - Optional LLM provider for AI analysis / 可選的 LLM 供應商用於 AI 分析
   */
  constructor(llm: AnalyzeLLM | null) {
    this.llm = llm;
  }

  /**
   * Analyze a detection result and produce a verdict
   * 分析偵測結果並產生判決
   *
   * Evidence collection pipeline:
   * 1. Sigma rule match evidence (weighted 0.4)
   * 2. Threat intelligence evidence
   * 3. Baseline deviation check (weighted 0.3)
   * 4. AI analysis if available (weighted 0.3)
   * 5. Calculate final weighted confidence
   * 6. Determine conclusion and recommended action
   *
   * 證據收集管線：
   * 1. Sigma 規則比對證據（權重 0.4）
   * 2. 威脅情報證據
   * 3. 基線偏離檢查（權重 0.3）
   * 4. AI 分析（如可用）（權重 0.3）
   * 5. 計算最終加權信心度
   * 6. 決定結論和建議動作
   *
   * @param detection - The detection result to analyze / 要分析的偵測結果
   * @param baseline - Current environment baseline / 當前環境基線
   * @returns ThreatVerdict with conclusion and evidence / 包含結論和證據的威脅判決
   */
  async analyze(detection: DetectionResult, baseline: EnvironmentBaseline): Promise<ThreatVerdict> {
    logger.info(
      `Analyzing detection for event ${detection.event.id} / ` +
        `分析事件 ${detection.event.id} 的偵測結果`
    );
    this.analysisCount++;

    const evidenceList: Evidence[] = [];

    // Step 1: Collect rule match evidence / 步驟 1: 收集規則比對證據
    for (const match of detection.ruleMatches) {
      evidenceList.push({
        source: 'rule_match',
        description:
          `Sigma rule matched: ${match.ruleName} (${match.ruleId}) / ` +
          `Sigma 規則比對: ${match.ruleName}`,
        confidence: SEVERITY_CONFIDENCE[match.severity] ?? 50,
        data: { ruleId: match.ruleId, severity: match.severity },
      });
    }

    // Step 2: Collect threat intel evidence / 步驟 2: 收集威脅情報證據
    if (detection.threatIntelMatch) {
      evidenceList.push({
        source: 'threat_intel',
        description:
          `Known malicious IP: ${detection.threatIntelMatch.ip} - ` +
          `${detection.threatIntelMatch.threat} / 已知惡意 IP`,
        confidence: 85,
        data: detection.threatIntelMatch,
      });
    }

    // Step 3: Baseline deviation check / 步驟 3: 基線偏離檢查
    const deviation: DeviationResult = checkDeviation(baseline, detection.event);
    if (deviation.isDeviation) {
      evidenceList.push({
        source: 'baseline_deviation',
        description: deviation.description,
        confidence: deviation.confidence,
        data: { deviationType: deviation.deviationType },
      });
    }

    // Step 4: AI analysis (if available) / 步驟 4: AI 分析（如可用）
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
          logger.info(
            'AI unavailable, using rule-based analysis only / ' + 'AI 不可用，僅使用規則式分析'
          );
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`AI analysis failed: ${msg} / AI 分析失敗: ${msg}`);
      }
    }

    // Step 5: Calculate final confidence (weighted average)
    // 步驟 5: 計算最終信心度（加權平均）
    const hasAI = this.llm !== null && aiAnalysis !== null;
    const finalConfidence = calculateFinalConfidence(evidenceList, hasAI);

    // Step 6: Determine conclusion and recommended action
    // 步驟 6: 決定結論和建議動作
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
      `Verdict for event ${detection.event.id}: ${conclusion} ` +
        `(confidence: ${finalConfidence}%) / ` +
        `事件 ${detection.event.id} 判決: ${conclusion} ` +
        `(信心度: ${finalConfidence}%)`
    );

    return verdict;
  }

  /**
   * Get total analysis count / 取得分析總數
   */
  getAnalysisCount(): number {
    return this.analysisCount;
  }
}

// ---------------------------------------------------------------------------
// Internal scoring functions / 內部評分函數
// ---------------------------------------------------------------------------

/**
 * Calculate final confidence from all evidence
 * 從所有證據計算最終信心度
 *
 * Weights:
 * - rule_match / threat_intel: 0.4
 * - baseline_deviation: 0.3
 * - ai_analysis: 0.3 (redistributed to rules+baseline if no AI)
 *
 * 權重：
 * - 規則比對 / 威脅情報: 0.4
 * - 基線偏離: 0.3
 * - AI 分析: 0.3（無 AI 時重新分配至規則+基線）
 */
function calculateFinalConfidence(evidence: Evidence[], hasAI: boolean): number {
  const bySource = groupBySource(evidence);

  const ruleConfidence = maxConfidence(bySource['rule_match']);
  const baselineConfidence = maxConfidence(bySource['baseline_deviation']);
  const threatIntelConfidence = maxConfidence(bySource['threat_intel']);
  const aiConfidence = maxConfidence(bySource['ai_analysis']);

  // Use max of rule match and threat intel for the "rule" weight
  // 使用規則比對和威脅情報的最大值作為「規則」權重
  const ruleScore = Math.max(ruleConfidence, threatIntelConfidence);

  if (hasAI) {
    // With AI: 40% rule, 30% baseline, 30% AI
    return Math.round(ruleScore * 0.4 + baselineConfidence * 0.3 + aiConfidence * 0.3);
  }

  // Without AI: 60% rule, 40% baseline
  return Math.round(ruleScore * 0.6 + baselineConfidence * 0.4);
}

/** Group evidence by source type / 按來源類型分組證據 */
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

/** Get maximum confidence from a list of evidence / 從證據列表中取得最大信心度 */
function maxConfidence(items?: Evidence[]): number {
  if (!items || items.length === 0) return 0;
  return Math.max(...items.map((e) => e.confidence));
}

/**
 * Determine verdict conclusion based on confidence
 * 根據信心度決定判決結論
 */
function determineConclusion(confidence: number): 'benign' | 'suspicious' | 'malicious' {
  if (confidence >= 75) return 'malicious';
  if (confidence >= 40) return 'suspicious';
  return 'benign';
}

/**
 * Determine recommended response action based on confidence and detection context
 * 根據信心度和偵測上下文決定建議的回應動作
 */
function determineAction(confidence: number, detection: DetectionResult): ResponseAction {
  // Critical severity rules always recommend stronger actions
  // 嚴重（critical）級別的規則總是建議更強的動作
  const hasCritical = detection.ruleMatches.some((m) => m.severity === 'critical');

  if (confidence >= 85 || (hasCritical && confidence >= 70)) {
    // High confidence: take source-appropriate action
    // 高信心度：採取與來源適當的動作
    if (detection.event.source === 'network') return 'block_ip';
    if (detection.event.source === 'process') return 'kill_process';
    return 'notify';
  }

  if (confidence >= 50) return 'notify';
  return 'log_only';
}

/**
 * Build analysis prompt for LLM / 建立 LLM 分析提示
 */
function buildAnalysisPrompt(detection: DetectionResult, deviation: DeviationResult): string {
  const parts: string[] = [
    'Security Event Analysis / 安全事件分析',
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

  parts.push('Analyze the threat level and provide recommendations.');

  return parts.join('\n');
}

/**
 * Build human-readable reasoning from collected evidence
 * 從收集的證據建立人類可讀的推理
 */
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
