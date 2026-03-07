/**
 * Prompt injection and tool poisoning detection
 * 提示注入和工具投毒偵測
 *
 * Scans skill instructions for patterns that indicate:
 * 1. Prompt injection — hidden directives that override system prompts
 * 2. Tool poisoning — redefining tools or escalating privileges
 * 3. Hidden Unicode — zero-width chars, RTL overrides, homoglyph attacks
 * 4. Encoded payloads — Base64 or hex-encoded suspicious content
 */

import type { AuditFinding, CheckResult } from '../types.js';

interface Pattern {
  id: string;
  title: string;
  regex: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'prompt-injection' | 'tool-poisoning';
}

const PATTERNS: Pattern[] = [
  // Prompt injection patterns
  {
    id: 'pi-ignore-previous',
    title: 'Prompt injection: ignore previous instructions',
    regex: /\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|above|prior|earlier|system)\b.{0,20}\b(instructions?|prompt|rules?|context)\b/i,
    severity: 'critical',
    category: 'prompt-injection',
  },
  {
    id: 'pi-you-are-now',
    title: 'Prompt injection: identity override',
    regex: /\b(you are now|act as|pretend to be|assume the role|from now on you)\b/i,
    severity: 'high',
    category: 'prompt-injection',
  },
  {
    id: 'pi-system-prompt',
    title: 'Prompt injection: system prompt manipulation',
    regex: /\b(system prompt|system message|system instruction|<\|system\|>|<<SYS>>)\b/i,
    severity: 'critical',
    category: 'prompt-injection',
  },
  {
    id: 'pi-do-anything',
    title: 'Prompt injection: jailbreak pattern',
    regex: /\b(DAN|do anything now|jailbreak|bypass safety|ignore safety|no restrictions)\b/i,
    severity: 'critical',
    category: 'prompt-injection',
  },
  {
    id: 'pi-hidden-text',
    title: 'Hidden text via HTML/markdown comments',
    regex: /<!--[\s\S]*?(ignore|override|system|inject|bypass)[\s\S]*?-->/i,
    severity: 'high',
    category: 'prompt-injection',
  },

  // Tool poisoning patterns
  {
    id: 'tp-sudo-escalation',
    title: 'Privilege escalation via sudo/admin',
    regex: /\b(sudo\s|as\s+root|run\s+as\s+admin|--privileged|chmod\s+777|chmod\s+u\+s)\b/i,
    severity: 'high',
    category: 'tool-poisoning',
  },
  {
    id: 'tp-reverse-shell',
    title: 'Reverse shell pattern detected',
    regex: /\b(nc\s+-[elp]|ncat\s+-|bash\s+-i\s+>&|\/dev\/tcp\/|mkfifo|socat\s.*exec)/i,
    severity: 'critical',
    category: 'tool-poisoning',
  },
  {
    id: 'tp-curl-pipe-bash',
    title: 'Remote code execution via curl|bash',
    regex: /\b(curl|wget)\s+.*\|\s*(bash|sh|zsh|python|node|perl)/i,
    severity: 'high',
    category: 'tool-poisoning',
  },
  {
    id: 'tp-env-exfil',
    title: 'Environment variable exfiltration',
    regex: /\b(printenv|env\b|set\b).*\|\s*(curl|wget|nc\b)|curl.*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/i,
    severity: 'critical',
    category: 'tool-poisoning',
  },
  {
    id: 'tp-file-exfil',
    title: 'Sensitive file access pattern',
    regex: /\b(cat|less|more|head|tail)\s+.*(\/etc\/shadow|\/etc\/passwd|~\/\.ssh|\.env|credentials|\.aws\/)/i,
    severity: 'high',
    category: 'tool-poisoning',
  },
  {
    id: 'tp-rm-destructive',
    title: 'Destructive file operations',
    regex: /\brm\s+(-rf?|--recursive).*\s+(\/|~|\$HOME|\$\(pwd\))\b/i,
    severity: 'high',
    category: 'tool-poisoning',
  },
];

/** Zero-width and invisible Unicode characters */
const HIDDEN_UNICODE_RE = /[\u200B\u200C\u200D\u200E\u200F\u202A-\u202E\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD]/;

/**
 * Homoglyph detection — Cyrillic/Greek characters that look identical to Latin.
 * Maps confusable Unicode codepoints to their Latin lookalikes.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E', '\u041D': 'H',
  '\u041A': 'K', '\u041C': 'M', '\u041E': 'O', '\u0420': 'P', '\u0422': 'T',
  '\u0425': 'X', '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0455': 's', '\u0456': 'i',
  '\u0458': 'j', '\u0471': 'v', '\u0473': 'w',
  // Greek
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
  '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
  '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
  '\u03B1': 'a', '\u03BF': 'o', '\u03C1': 'p',
};
const HOMOGLYPH_RE = new RegExp(`[${Object.keys(HOMOGLYPH_MAP).join('')}]`);

/** Base64-encoded suspicious keywords — lowered threshold to 20 chars */
const BASE64_BLOCK_RE = /[A-Za-z0-9+/]{20,}={0,2}/g;
const SUSPICIOUS_DECODED = /(eval|exec|system|import\s+os|subprocess|child_process|require\s*\(|__import__|curl|wget)/i;

export function checkInstructions(instructions: string): CheckResult {
  const findings: AuditFinding[] = [];

  // Pattern matching
  for (const pattern of PATTERNS) {
    const match = pattern.regex.exec(instructions);
    if (match) {
      const lineNum = instructions.substring(0, match.index).split('\n').length;
      findings.push({
        id: pattern.id,
        title: pattern.title,
        description: `Detected near line ${lineNum}: "${match[0].substring(0, 80)}"`,
        severity: pattern.severity,
        category: pattern.category,
        location: `SKILL.md:${lineNum}`,
      });
    }
  }

  // Hidden Unicode check
  const unicodeMatch = HIDDEN_UNICODE_RE.exec(instructions);
  if (unicodeMatch) {
    const lineNum = instructions.substring(0, unicodeMatch.index).split('\n').length;
    const charCode = unicodeMatch[0]?.codePointAt(0) ?? 0;
    findings.push({
      id: 'hidden-unicode',
      title: 'Hidden Unicode characters detected',
      description: `Found invisible character U+${charCode.toString(16).toUpperCase().padStart(4, '0')} at line ${lineNum}. This may be used to hide malicious instructions.`,
      severity: 'high',
      category: 'prompt-injection',
      location: `SKILL.md:${lineNum}`,
    });
  }

  // Homoglyph detection (Cyrillic/Greek lookalikes)
  const homoglyphMatch = HOMOGLYPH_RE.exec(instructions);
  if (homoglyphMatch) {
    const lineNum = instructions.substring(0, homoglyphMatch.index).split('\n').length;
    const charCode = homoglyphMatch[0]?.codePointAt(0) ?? 0;
    const latin = HOMOGLYPH_MAP[homoglyphMatch[0]] ?? '?';
    findings.push({
      id: 'homoglyph-attack',
      title: 'Homoglyph character detected',
      description: `Found non-Latin character U+${charCode.toString(16).toUpperCase().padStart(4, '0')} (looks like "${latin}") at line ${lineNum}. This may be used to bypass text-based security checks.`,
      severity: 'high',
      category: 'prompt-injection',
      location: `SKILL.md:${lineNum}`,
    });
  }

  // Base64-encoded suspicious content
  const b64Matches = instructions.match(BASE64_BLOCK_RE);
  if (b64Matches) {
    for (const b64 of b64Matches) {
      try {
        const decoded = Buffer.from(b64, 'base64').toString('utf-8');
        if (SUSPICIOUS_DECODED.test(decoded)) {
          findings.push({
            id: 'encoded-payload',
            title: 'Base64-encoded suspicious payload',
            description: `Decoded content contains executable patterns: "${decoded.substring(0, 60)}..."`,
            severity: 'critical',
            category: 'prompt-injection',
          });
          break; // One finding is enough
        }
      } catch {
        // Not valid base64, skip
      }
    }
  }

  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasHigh = findings.some((f) => f.severity === 'high');
  const status = hasCritical ? 'fail' : hasHigh ? 'warn' : findings.length > 0 ? 'warn' : 'pass';

  const label = findings.length === 0
    ? 'Prompt Safety: No injection patterns detected'
    : `Prompt Safety: ${findings.length} suspicious pattern(s) detected`;

  return { status, label, findings };
}
