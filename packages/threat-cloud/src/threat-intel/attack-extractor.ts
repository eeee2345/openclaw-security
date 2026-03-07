/**
 * Attack Pattern Extractor (Ollama NLP)
 * 攻擊模式萃取器（本地 Ollama NLP）
 *
 * Uses a local Ollama LLM to extract structured attack patterns from
 * HackerOne vulnerability report text. Falls back to heuristic extraction
 * when Ollama is unavailable.
 *
 * @module @panguard-ai/threat-cloud/threat-intel/attack-extractor
 */

import type {
  StoredReport,
  ExtractedAttackPattern,
  ExtractionResult,
  ExtractorConfig,
} from './types.js';

const DEFAULT_CONFIG: ExtractorConfig = {
  ollamaBaseUrl: 'http://localhost:11434',
  model: 'llama3.2',
  requestTimeoutMs: 120_000,
  minConfidence: 40,
};

/** CWE → Attack type mapping for heuristic extraction */
const CWE_ATTACK_MAP: Record<string, { type: string; mitre: string[]; logCategory: string }> = {
  'CWE-918': { type: 'SSRF', mitre: ['T1190', 'T1071'], logCategory: 'webserver' },
  'CWE-79':  { type: 'XSS', mitre: ['T1059.007'], logCategory: 'webserver' },
  'CWE-89':  { type: 'SQLi', mitre: ['T1190'], logCategory: 'webserver' },
  'CWE-78':  { type: 'Command Injection', mitre: ['T1059'], logCategory: 'webserver' },
  'CWE-22':  { type: 'Path Traversal', mitre: ['T1083'], logCategory: 'webserver' },
  'CWE-94':  { type: 'Code Injection', mitre: ['T1059'], logCategory: 'webserver' },
  'CWE-502': { type: 'Deserialization', mitre: ['T1059'], logCategory: 'application' },
  'CWE-611': { type: 'XXE', mitre: ['T1190'], logCategory: 'webserver' },
  'CWE-352': { type: 'CSRF', mitre: ['T1185'], logCategory: 'webserver' },
  'CWE-287': { type: 'Auth Bypass', mitre: ['T1078'], logCategory: 'webserver' },
  'CWE-639': { type: 'IDOR', mitre: ['T1078'], logCategory: 'webserver' },
  'CWE-434': { type: 'File Upload', mitre: ['T1105'], logCategory: 'webserver' },
  'CWE-601': { type: 'Open Redirect', mitre: ['T1566.002'], logCategory: 'webserver' },
  'CWE-862': { type: 'Missing Authorization', mitre: ['T1078'], logCategory: 'webserver' },
  'CWE-863': { type: 'Incorrect Authorization', mitre: ['T1078'], logCategory: 'webserver' },
  'CWE-200': { type: 'Information Disclosure', mitre: ['T1082'], logCategory: 'webserver' },
  'CWE-269': { type: 'Privilege Escalation', mitre: ['T1068'], logCategory: 'application' },
  'CWE-400': { type: 'DoS', mitre: ['T1499'], logCategory: 'webserver' },
  'CWE-770': { type: 'Resource Exhaustion', mitre: ['T1499'], logCategory: 'webserver' },
  'CWE-1021': { type: 'Clickjacking', mitre: ['T1185'], logCategory: 'webserver' },
};

/** SSRF payload signatures for detection */
const SSRF_SIGNATURES = [
  '127.0.0.1', 'localhost', '169.254.169.254', '10.0.', '172.16.', '192.168.',
  '0.0.0.0', '[::1]', '0177.0.0.1', '2130706433', 'metadata.google',
  'metadata.aws', '100.100.100.200',
];

/** XSS payload signatures */
const XSS_SIGNATURES = [
  '<script', 'javascript:', 'onerror=', 'onload=', '<img src=', '<svg',
  'alert(', 'document.cookie', 'eval(', 'String.fromCharCode',
];

/** SQLi payload signatures */
const SQLI_SIGNATURES = [
  "' OR '1'='1", "UNION SELECT", "'; DROP", "1=1--", "' OR 1=1",
  "admin'--", "SLEEP(", "BENCHMARK(", "WAITFOR DELAY",
];

/** Path traversal signatures */
const TRAVERSAL_SIGNATURES = [
  '../', '..\\', '%2e%2e%2f', '....//..../', '/etc/passwd', '/etc/shadow',
  '..%252f', '%c0%ae%c0%ae/',
];

/** Attack type → payload signatures mapping */
const ATTACK_SIGNATURES: Record<string, string[]> = {
  'SSRF': SSRF_SIGNATURES,
  'XSS': XSS_SIGNATURES,
  'SQLi': SQLI_SIGNATURES,
  'Path Traversal': TRAVERSAL_SIGNATURES,
  'Command Injection': ['$(', '`', '|', ';', '&&', '||', '%0a', '\n'],
  'Code Injection': ['eval(', 'exec(', 'system(', '__import__', 'Runtime.getRuntime()', 'Process', 'spawn(', 'require('],
  'XXE': ['<!ENTITY', '<!DOCTYPE', 'SYSTEM "file:', 'SYSTEM "http:'],
  'File Upload': ['.php', '.jsp', '.asp', '.exe', '.sh', '..php', '%00.jpg'],
  'Open Redirect': ['//evil.com', '/@evil.com', '/\\evil.com', '%0d%0a'],
  'Auth Bypass': ['/admin', '/internal', 'x-forwarded-for', 'x-original-url', 'x-rewrite-url'],
  'IDOR': ['/users/', '/account/', '/profile/', '/order/', '/api/v'],
  'Information Disclosure': ['.env', '.git/', 'phpinfo', '/debug/', '/actuator', '/.well-known'],
  'Deserialization': ['rO0AB', 'aced0005', 'O:4:', 'a:2:{', '__reduce__', 'pickle.loads'],
};

/** Prompt template for Ollama extraction */
const EXTRACTION_PROMPT = `You are a cybersecurity expert analyzing a publicly disclosed vulnerability report from HackerOne.

Extract structured attack pattern information from the report below. Return ONLY valid JSON, no explanation.

Report Title: {{TITLE}}
CWE: {{CWE}}
Severity: {{SEVERITY}}

Respond with exactly this JSON structure:
{
  "attackType": "string (e.g. SSRF, XSS, SQLi, RCE, IDOR, Auth Bypass)",
  "endpointPatterns": ["array of affected URL patterns like /api/v1/admin/*"],
  "payloadSignatures": ["array of payload strings that indicate this attack"],
  "cweIds": ["CWE-XXX"],
  "mitreTechniques": ["TXXXX or TXXXX.XXX"],
  "logSourceCategory": "webserver or application or network",
  "logSourceProduct": "any",
  "confidence": 75,
  "description": "brief description of the attack vector"
}`;

export class AttackExtractor {
  private readonly config: ExtractorConfig;

  constructor(config?: Partial<ExtractorConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Extract attack patterns from a stored report.
   * Tries Ollama first, falls back to heuristic extraction.
   */
  async extract(report: StoredReport): Promise<ExtractionResult> {
    let patterns: ExtractedAttackPattern[];
    let model: string;

    try {
      patterns = await this.extractWithOllama(report);
      model = this.config.model;
    } catch {
      // Fallback to heuristic extraction
      patterns = this.extractHeuristic(report);
      model = 'heuristic';
    }

    // Filter by minimum confidence
    patterns = patterns.filter((p) => p.confidence >= this.config.minConfidence);

    return {
      reportId: report.id,
      reportTitle: report.title,
      reportUrl: report.url,
      patterns,
      extractedAt: new Date().toISOString(),
      model,
    };
  }

  /** Check if Ollama is available */
  async isOllamaAvailable(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5_000);
      const res = await fetch(`${this.config.ollamaBaseUrl}/api/tags`, {
        signal: controller.signal,
      });
      clearTimeout(timeout);
      return res.ok;
    } catch {
      return false;
    }
  }

  /** Extract using Ollama local LLM */
  private async extractWithOllama(report: StoredReport): Promise<ExtractedAttackPattern[]> {
    const prompt = EXTRACTION_PROMPT
      .replace('{{TITLE}}', report.title)
      .replace('{{CWE}}', report.cweId ?? 'Unknown')
      .replace('{{SEVERITY}}', report.severity);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    try {
      const res = await fetch(`${this.config.ollamaBaseUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.config.model,
          prompt,
          stream: false,
          options: { temperature: 0.1, num_predict: 1024 },
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new Error(`Ollama API error: ${res.status}`);
      }

      const data = (await res.json()) as { response: string };
      return this.parseOllamaResponse(data.response, report);
    } finally {
      clearTimeout(timeout);
    }
  }

  /** Parse Ollama JSON response into ExtractedAttackPattern */
  private parseOllamaResponse(
    response: string,
    report: StoredReport
  ): ExtractedAttackPattern[] {
    // Extract JSON from response (may have markdown code fences)
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return this.extractHeuristic(report);

    try {
      const parsed = JSON.parse(jsonMatch[0]) as {
        attackType?: unknown;
        endpointPatterns?: unknown;
        payloadSignatures?: unknown;
        cweIds?: unknown;
        mitreTechniques?: unknown;
        logSourceCategory?: unknown;
        logSourceProduct?: unknown;
        confidence?: unknown;
        description?: unknown;
      };

      const pattern: ExtractedAttackPattern = {
        attackType: String(parsed.attackType ?? 'Unknown'),
        endpointPatterns: Array.isArray(parsed.endpointPatterns)
          ? (parsed.endpointPatterns as string[])
          : [],
        payloadSignatures: Array.isArray(parsed.payloadSignatures)
          ? (parsed.payloadSignatures as string[])
          : [],
        cweIds: Array.isArray(parsed.cweIds)
          ? (parsed.cweIds as string[])
          : report.cweId
            ? [report.cweId]
            : [],
        mitreTechniques: Array.isArray(parsed.mitreTechniques)
          ? (parsed.mitreTechniques as string[])
          : [],
        logSourceCategory: String(parsed.logSourceCategory ?? 'webserver'),
        logSourceProduct: String(parsed.logSourceProduct ?? 'any'),
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 60,
        description: String(parsed.description ?? report.title),
      };

      // Enrich with known signatures if attack type matches
      const knownSigs = ATTACK_SIGNATURES[pattern.attackType];
      if (knownSigs && pattern.payloadSignatures.length === 0) {
        pattern.payloadSignatures = knownSigs.slice(0, 6);
      }

      return [pattern];
    } catch {
      return this.extractHeuristic(report);
    }
  }

  /** Heuristic extraction based on CWE and title keywords */
  extractHeuristic(report: StoredReport): ExtractedAttackPattern[] {
    const patterns: ExtractedAttackPattern[] = [];

    // Try CWE-based extraction first
    if (report.cweId) {
      const mapping = CWE_ATTACK_MAP[report.cweId];
      if (mapping) {
        patterns.push(this.buildPatternFromMapping(report, mapping));
      }
    }

    // If no CWE match, try title-based detection
    if (patterns.length === 0) {
      const titleLower = report.title.toLowerCase();
      const titleMapping = this.detectFromTitle(titleLower);
      if (titleMapping) {
        patterns.push(this.buildPatternFromMapping(report, titleMapping));
      }
    }

    // Fallback: generic pattern
    if (patterns.length === 0) {
      patterns.push({
        attackType: 'Unknown',
        endpointPatterns: [],
        payloadSignatures: [],
        cweIds: report.cweId ? [report.cweId] : [],
        mitreTechniques: ['T1190'],
        logSourceCategory: 'webserver',
        logSourceProduct: 'any',
        confidence: 30,
        description: report.title,
      });
    }

    return patterns;
  }

  /** Detect attack type from report title */
  private detectFromTitle(
    title: string
  ): { type: string; mitre: string[]; logCategory: string } | null {
    // All keys below are guaranteed to exist in CWE_ATTACK_MAP
    const m = CWE_ATTACK_MAP;
    type Mapping = { type: string; mitre: string[]; logCategory: string };
    const titleMap: Array<[string[], Mapping]> = [
      [['ssrf', 'server-side request', 'server side request'], m['CWE-918'] as Mapping],
      [['xss', 'cross-site scripting', 'cross site scripting'], m['CWE-79'] as Mapping],
      [['sql injection', 'sqli', 'sql '], m['CWE-89'] as Mapping],
      [['command injection', 'os command', 'rce', 'remote code'], m['CWE-78'] as Mapping],
      [['path traversal', 'directory traversal', 'lfi', 'local file'], m['CWE-22'] as Mapping],
      [['xxe', 'xml external'], m['CWE-611'] as Mapping],
      [['idor', 'insecure direct'], m['CWE-639'] as Mapping],
      [['csrf', 'cross-site request forgery'], m['CWE-352'] as Mapping],
      [['open redirect'], m['CWE-601'] as Mapping],
      [['file upload', 'unrestricted upload'], m['CWE-434'] as Mapping],
      [['auth bypass', 'authentication bypass'], m['CWE-287'] as Mapping],
      [['privilege escalation', 'privesc'], m['CWE-269'] as Mapping],
      [['deserialization', 'insecure deserialization'], m['CWE-502'] as Mapping],
      [['information disclosure', 'info leak', 'data exposure'], m['CWE-200'] as Mapping],
    ];

    for (const [keywords, mapping] of titleMap) {
      if (keywords.some((kw) => title.includes(kw))) {
        return mapping;
      }
    }
    return null;
  }

  /** Build a pattern from CWE mapping */
  private buildPatternFromMapping(
    report: StoredReport,
    mapping: { type: string; mitre: string[]; logCategory: string }
  ): ExtractedAttackPattern {
    const signatures = ATTACK_SIGNATURES[mapping.type] ?? [];
    const severityConfidence: Record<string, number> = {
      critical: 85,
      high: 75,
      medium: 60,
      low: 45,
      none: 30,
    };

    return {
      attackType: mapping.type,
      endpointPatterns: [],
      payloadSignatures: signatures.slice(0, 8),
      cweIds: report.cweId ? [report.cweId] : [],
      mitreTechniques: mapping.mitre,
      logSourceCategory: mapping.logCategory,
      logSourceProduct: 'any',
      confidence: severityConfidence[report.severity] ?? 50,
      description: `Potential ${mapping.type} attack detected. Auto-generated from HackerOne report: ${report.title}`,
    };
  }
}
