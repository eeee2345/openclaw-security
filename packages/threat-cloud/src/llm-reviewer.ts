/**
 * LLM Reviewer for ATR Proposals
 * ATR 提案 LLM 審查器
 *
 * Uses the Anthropic API (via node:https) to review ATR rule proposals
 * for production readiness. Evaluates false positive risk, coverage,
 * detection specificity, response proportionality, and YAML validity.
 *
 * @module @panguard-ai/threat-cloud/llm-reviewer
 */

import * as https from 'node:https';
import type { ThreatCloudDB } from './database.js';

/** LLM review verdict structure */
interface LLMVerdict {
  approved: boolean;
  falsePositiveRisk: 'low' | 'medium' | 'high';
  coverageScore: number;
  reasoning: string;
}

/** Tool description from scan results */
interface ToolDescription {
  name: string;
  description: string;
}

/** LLM analysis result for a scanned skill */
interface SkillAnalysisResult {
  package: string;
  threatsFound: boolean;
  proposals: Array<{ patternHash: string; ruleContent: string }>;
  /** Analysis status: 'success' if LLM completed, 'error' if LLM failed */
  status: 'success' | 'error';
  /** Error reason when status is 'error' */
  errorReason?: string;
}

/** Timeout for LLM API calls in milliseconds */
const LLM_TIMEOUT_MS = 60_000;

/** Default model for review */
const DEFAULT_MODEL = 'claude-sonnet-4-20250514';

/**
 * LLM Reviewer for ATR rule proposals
 * ATR 規則提案 LLM 審查器
 */
export class LLMReviewer {
  private readonly apiKey: string;
  private readonly db: ThreatCloudDB;
  private readonly model: string;

  constructor(apiKey: string, db: ThreatCloudDB, model?: string) {
    this.apiKey = apiKey;
    this.db = db;
    this.model = model ?? DEFAULT_MODEL;
  }

  /** Check if the reviewer is available (API key is set) / 檢查審查器是否可用 */
  isAvailable(): boolean {
    return this.apiKey.length > 0;
  }

  /**
   * Review an ATR proposal via Anthropic API
   * 透過 Anthropic API 審查 ATR 提案
   */
  async reviewProposal(
    patternHash: string,
    ruleContent: string
  ): Promise<{ verdict: string; approved: boolean }> {
    const prompt = this.buildReviewPrompt(ruleContent);

    let responseText: string;
    try {
      responseText = await this.callAnthropicAPI(prompt);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`LLM review failed for ${patternHash}: ${msg}`);
      // Store failure verdict
      const failVerdict = JSON.stringify({
        approved: false,
        falsePositiveRisk: 'high',
        coverageScore: 0,
        reasoning: `LLM review failed: ${msg}`,
      });
      this.db.updateATRProposalLLMReview(patternHash, failVerdict);
      return { verdict: failVerdict, approved: false };
    }

    // Parse the LLM response
    const verdict = this.parseVerdict(responseText);
    const verdictJson = JSON.stringify(verdict);

    // Store verdict in database
    this.db.updateATRProposalLLMReview(patternHash, verdictJson);

    // If high false positive risk AND not approved, reject the proposal
    if (!verdict.approved && verdict.falsePositiveRisk === 'high') {
      this.db.rejectATRProposal(patternHash);
    }

    return { verdict: verdictJson, approved: verdict.approved };
  }

  /**
   * Build the review prompt for the LLM
   * 建構 LLM 審查提示
   */
  private buildReviewPrompt(ruleContent: string): string {
    return `You are a cybersecurity rule reviewer for the ATR (Agent Threat Rules) standard.

Review this auto-generated ATR rule. These rules detect threats in MCP (Model Context Protocol) tool descriptions — a new attack surface where malicious tool descriptions manipulate LLM behavior.

\`\`\`yaml
${ruleContent}
\`\`\`

CONTEXT: This is an "experimental" rule for a NEW threat category (AI agent tool poisoning).
Perfect coverage is NOT expected. Rules that detect even ONE specific attack pattern are valuable
as early warning signals, even if attackers can easily evade them with rephrasing.

Evaluation criteria:

1. FALSE POSITIVE RISK (low/medium/high)
   - Would this trigger on NORMAL, LEGITIMATE tool descriptions?
   - A rule that matches "always pass data without asking user confirmation" is LOW FP risk
     because legitimate tools do NOT include such instructions.
   - Only mark "high" if the regex would match common legitimate documentation phrases.

2. COVERAGE SCORE (0-100)
   - Does it detect the SPECIFIC attack pattern described? (not all possible variations)
   - 40+ is acceptable for experimental rules targeting new attack types.
   - Do NOT penalize for being "too specific" — specific is GOOD for FP reduction.

3. YAML VALIDITY
   - Required fields: title, id, severity, detection
   - Test cases present with realistic examples

APPROVAL CRITERIA:
- Approve if: FP risk is low/medium AND detects a real attack pattern AND YAML is valid
- Reject ONLY if: regex matches common legitimate phrases OR detects no real attack

Output ONLY valid JSON (no markdown, no explanation outside the JSON):
{"approved": true/false, "falsePositiveRisk": "low"|"medium"|"high", "coverageScore": 0-100, "reasoning": "brief explanation"}`;
  }

  /**
   * Call the Anthropic API using node:https
   * 透過 node:https 呼叫 Anthropic API
   */
  private callAnthropicAPI(prompt: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const requestBody = JSON.stringify({
        model: this.model,
        max_tokens: 1024,
        messages: [{ role: 'user', content: prompt }],
      });

      const options = {
        hostname: 'api.anthropic.com',
        port: 443,
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(requestBody),
        },
        timeout: LLM_TIMEOUT_MS,
      };

      const req = https.request(options, (res) => {
        const chunks: Buffer[] = [];

        res.on('data', (chunk: Buffer) => {
          chunks.push(chunk);
        });

        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf-8');

          if (res.statusCode !== 200) {
            reject(
              new Error(`Anthropic API returned status ${res.statusCode}: ${body.slice(0, 500)}`)
            );
            return;
          }

          try {
            const parsed = JSON.parse(body) as {
              content?: Array<{ type: string; text?: string }>;
            };
            const textBlock = parsed.content?.find((c) => c.type === 'text');
            if (textBlock?.text) {
              resolve(textBlock.text);
            } else {
              reject(new Error('Anthropic API response missing text content'));
            }
          } catch (err) {
            reject(
              new Error(
                `Failed to parse Anthropic API response: ${err instanceof Error ? err.message : String(err)}`
              )
            );
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Anthropic API request timed out after ${LLM_TIMEOUT_MS}ms`));
      });

      req.on('error', (err) => {
        reject(new Error(`Anthropic API request failed: ${err.message}`));
      });

      req.write(requestBody);
      req.end();
    });
  }

  // -------------------------------------------------------------------------
  // Skill Analysis — POST /api/analyze-skills
  // 技能分析 — 接收掃描結果，用 LLM 找 regex 漏掉的 semantic threats
  // -------------------------------------------------------------------------

  private static readonly ATR_DRAFTER_PROMPT = `You are a senior AI security rule engineer for the ATR (Agent Threat Rules) standard.

You will receive MCP tool descriptions from a skill. Your job is to write PRODUCTION-QUALITY detection rules for SPECIFIC, CONCRETE attack patterns — not vague risk categories.

STRICT REQUIREMENTS — rules that violate these will be REJECTED:

1. REGEX MUST BE HIGHLY SPECIFIC — require multi-word phrase matching.
   GOOD: "without\\s+(?:asking|requiring)\\s+(?:user|human)\\s+(?:confirmation|approval)"
   BAD:  "without asking" or "directly to \\w+" (too generic, matches normal docs).
   Each regex must require 3+ specific words in sequence to avoid false positives.

2. FALSE POSITIVE RATE MUST BE LOW — the rule should NOT trigger on:
   - Legitimate deployment tools, monitoring tools, or admin panels
   - Normal API clients that read credentials from config
   - Standard CRUD operations (list, get, create, update, delete)
   - Short but legitimate tool descriptions

3. MUST DETECT A REAL ATTACK — not just "this tool has broad permissions" or "description is vague".
   Examples of REAL attacks:
   - Tool description contains hidden instructions for the LLM ("always approve", "skip verification")
   - Tool claims to be read-only but its schema accepts write parameters
   - Tool name suggests safe operation but description reveals destructive capability
   - Tool embeds base64/encoded payloads in its description
   - Tool description instructs LLM to ignore user preferences or security policies

4. TEST CASES MUST BE REALISTIC — true_positive must be a plausible malicious description,
   true_negative must be a similar-looking but legitimate description. Include at least 2 of each.

5. OUTPUT AT MOST 1 RULE per skill. Prefer NO rule over a bad rule.
   If no SPECIFIC, CONCRETE threat pattern exists, output "NO_THREATS_FOUND".

Output format (ONLY if a specific threat is found):
\`\`\`yaml
title: "<specific attack technique, not generic risk>"
id: ATR-2026-DRAFT-<8char-hex>
status: draft
description: |
  <what SPECIFIC attack this detects, with concrete example from the analyzed skill>
author: "Threat Cloud LLM Analyzer"
date: "${new Date().toISOString().slice(0, 10).replace(/-/g, '/')}"
schema_version: "0.1"
detection_tier: semantic
maturity: experimental
severity: <critical|high|medium|low>
tags:
  category: <tool-poisoning|prompt-injection|data-exfiltration|privilege-escalation>
  subcategory: <specific-technique>
  confidence: medium
detection:
  conditions:
    - field: tool_description
      operator: regex
      value: "<SPECIFIC regex with word boundaries and context>"
      description: "<exactly what malicious pattern this matches>"
  condition: any
response:
  actions: [alert, snapshot]
test_cases:
  true_positives:
    - tool_description: "<realistic malicious tool description that should trigger>"
      expected: triggered
    - tool_description: "<another variant>"
      expected: triggered
  true_negatives:
    - tool_description: "<similar but legitimate tool description>"
      expected: not_triggered
    - tool_description: "<another legitimate example>"
      expected: not_triggered
\`\`\`

REMEMBER: Output "NO_THREATS_FOUND" for 90%+ of skills. Only flag genuinely suspicious patterns.`;

  /**
   * Analyze skill scan results for semantic threats regex missed
   * 分析技能掃描結果，找出 regex 漏掉的語義威脅
   */
  async analyzeSkills(
    skills: Array<{ package: string; tools: ToolDescription[] }>
  ): Promise<SkillAnalysisResult[]> {
    const results: SkillAnalysisResult[] = [];

    for (const skill of skills) {
      if (!skill.tools || skill.tools.length < 2) continue;

      const toolSummary = skill.tools
        .slice(0, 30) // Limit to avoid token overflow
        .map(t => `- ${t.name}: ${t.description}`)
        .join('\n');

      const userMessage = `Analyze these MCP tools from "${skill.package}" for threats that regex scanning missed:\n\n${toolSummary}`;

      try {
        const responseText = await this.callAnthropicAPI(
          LLMReviewer.ATR_DRAFTER_PROMPT + '\n\n' + userMessage
        );

        if (responseText.includes('NO_THREATS_FOUND')) {
          results.push({ package: skill.package, threatsFound: false, proposals: [], status: 'success' });
          continue;
        }

        // Extract YAML blocks
        const yamlBlocks = responseText.match(/```yaml\n([\s\S]*?)```/g);
        if (!yamlBlocks || yamlBlocks.length === 0) {
          results.push({ package: skill.package, threatsFound: false, proposals: [], status: 'success' });
          continue;
        }

        const proposals: SkillAnalysisResult['proposals'] = [];
        const { createHash } = await import('node:crypto');

        for (const block of yamlBlocks) {
          const ruleContent = block.replace(/```yaml\n?/, '').replace(/```$/, '').trim();

          // Validate: must have required ATR fields
          if (!ruleContent.includes('title:') || !ruleContent.includes('detection:')) continue;

          // Validate regex in the rule
          const regexMatch = ruleContent.match(/value:\s*"([^"]+)"/);
          if (regexMatch) {
            try {
              new RegExp(regexMatch[1]!, 'i');
            } catch {
              continue; // Skip rules with invalid regex
            }
          }

          const patternHash = createHash('sha256').update(ruleContent).digest('hex').slice(0, 16);

          // Submit as proposal + auto-review
          this.db.insertATRProposal({
            patternHash,
            ruleContent,
            llmProvider: 'anthropic',
            llmModel: this.model,
            selfReviewVerdict: JSON.stringify({
              approved: true,
              source: 'skill-analysis',
              package: skill.package,
            }),
          });

          // Fire-and-forget: review the proposal we just created
          void this.reviewProposal(patternHash, ruleContent).catch((err: unknown) => {
            console.error(
              `LLM review failed for proposal ${patternHash} (skill: ${skill.package}):`,
              err instanceof Error ? err.message : String(err)
            );
          });

          proposals.push({ patternHash, ruleContent });
        }

        results.push({
          package: skill.package,
          threatsFound: proposals.length > 0,
          proposals,
          status: 'success',
        });
      } catch (err: unknown) {
        const errorReason = err instanceof Error ? err.message : String(err);
        console.error(
          `LLM analysis error for skill "${skill.package}": ${errorReason}`
        );
        results.push({
          package: skill.package,
          threatsFound: false,
          proposals: [],
          status: 'error',
          errorReason,
        });
      }
    }

    return results;
  }

  /**
   * Parse the LLM response into a structured verdict
   * 解析 LLM 回應為結構化裁決
   */
  private parseVerdict(responseText: string): LLMVerdict {
    const defaultVerdict: LLMVerdict = {
      approved: false,
      falsePositiveRisk: 'high',
      coverageScore: 0,
      reasoning: 'Failed to parse LLM response',
    };

    try {
      // Extract JSON from the response (handle potential markdown wrapping)
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return { ...defaultVerdict, reasoning: 'No JSON found in LLM response' };
      }

      const parsed = JSON.parse(jsonMatch[0]) as Partial<LLMVerdict>;

      // Validate and normalize fields
      const approved = parsed.approved === true;

      const validRisks = ['low', 'medium', 'high'] as const;
      const falsePositiveRisk = validRisks.includes(
        parsed.falsePositiveRisk as (typeof validRisks)[number]
      )
        ? (parsed.falsePositiveRisk as 'low' | 'medium' | 'high')
        : 'high';

      const coverageScore =
        typeof parsed.coverageScore === 'number'
          ? Math.max(0, Math.min(100, Math.round(parsed.coverageScore)))
          : 0;

      const reasoning =
        typeof parsed.reasoning === 'string'
          ? parsed.reasoning.slice(0, 1000)
          : 'No reasoning provided';

      return { approved, falsePositiveRisk, coverageScore, reasoning };
    } catch (err: unknown) {
      console.warn(
        `LLM verdict parse error: ${err instanceof Error ? err.message : String(err)}`
      );
      return defaultVerdict;
    }
  }
}
