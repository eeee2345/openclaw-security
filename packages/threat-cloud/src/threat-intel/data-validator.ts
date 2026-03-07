/**
 * Threat Intel Data Validator
 * 威脅情報資料驗證器
 *
 * Strict validation for all ingested threat intelligence data.
 * Every record must pass validation before entering the system.
 *
 * Security checks:
 * - Input sanitization (no script injection in strings)
 * - Format validation (CVE IDs, CWE IDs, IPs, hashes, URLs)
 * - Freshness checks (reject stale data beyond threshold)
 * - Completeness scoring
 * - Deduplication via content fingerprint
 *
 * @module @panguard-ai/threat-cloud/threat-intel/data-validator
 */

import { createHash } from 'node:crypto';
import type {
  ThreatIntelRecord,
  ThreatIndicator,
  ValidationStatus,
  ValidationCheck,
} from './types.js';

/** Maximum age in days for records to be considered fresh */
const MAX_AGE_DAYS = 365;

/** Maximum string length for any single field (prevent memory abuse) */
const MAX_STRING_LENGTH = 10_000;

/** Maximum number of indicators per record */
const MAX_INDICATORS = 500;

/** Maximum number of references per record */
const MAX_REFERENCES = 100;

/** Regex patterns for strict format validation */
const PATTERNS = {
  cveId: /^CVE-\d{4}-\d{4,}$/,
  cweId: /^CWE-\d+$/,
  mitreTechnique: /^T\d{4}(\.\d{3})?$/,
  ipv4: /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/,
  ipv6: /^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,6}:$/,
  domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
  md5: /^[a-fA-F0-9]{32}$/,
  sha1: /^[a-fA-F0-9]{40}$/,
  sha256: /^[a-fA-F0-9]{64}$/,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  isoDate: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,
  /** Detect potential injection in string fields */
  injection: /<script|javascript:|on\w+\s*=|eval\(|document\.|window\./i,
} as const;

/** Seen fingerprints for deduplication */
const seenFingerprints = new Set<string>();

export class DataValidator {
  /**
   * Validate a threat intel record. Returns sanitized record with
   * validation status attached. Invalid records are marked but not
   * discarded — caller decides based on validation.score.
   */
  validate(record: ThreatIntelRecord): ThreatIntelRecord {
    const checks: ValidationCheck[] = [];

    // 1. Required fields
    checks.push(this.checkRequired('id', record.id));
    checks.push(this.checkRequired('title', record.title));
    checks.push(this.checkRequired('source', record.source));
    checks.push(this.checkRequired('type', record.type));
    checks.push(this.checkRequired('publishedAt', record.publishedAt));

    // 2. String length limits (prevent memory abuse)
    checks.push(this.checkStringLength('title', record.title, 500));
    if (record.description) {
      checks.push(this.checkStringLength('description', record.description, MAX_STRING_LENGTH));
    }

    // 3. Injection detection on string fields
    checks.push(this.checkNoInjection('title', record.title));
    if (record.description) {
      checks.push(this.checkNoInjection('description', record.description));
    }

    // 4. CVE ID format
    for (const cve of record.cveIds) {
      checks.push(this.checkFormat('cveId', cve, PATTERNS.cveId));
    }

    // 5. CWE ID format
    for (const cwe of record.cweIds) {
      checks.push(this.checkFormat('cweId', cwe, PATTERNS.cweId));
    }

    // 6. MITRE technique format
    for (const tech of record.mitreTechniques) {
      checks.push(this.checkFormat('mitreTechnique', tech, PATTERNS.mitreTechnique));
    }

    // 7. Date validity
    checks.push(this.checkDate('publishedAt', record.publishedAt));
    if (record.modifiedAt) {
      checks.push(this.checkDate('modifiedAt', record.modifiedAt));
    }

    // 8. Freshness check
    checks.push(this.checkFreshness(record.publishedAt));

    // 9. CVSS range
    if (record.cvssScore !== null) {
      checks.push(this.checkCvssRange(record.cvssScore));
    }

    // 10. Severity value
    checks.push(this.checkSeverity(record.severity));

    // 11. Indicator validation
    checks.push(this.checkIndicatorCount(record.indicators));
    for (const indicator of record.indicators.slice(0, MAX_INDICATORS)) {
      checks.push(this.checkIndicator(indicator));
    }

    // 12. Reference count limit
    checks.push(this.checkReferenceCount(record.references));

    // 13. URL validation for references
    for (const ref of record.references.slice(0, MAX_REFERENCES)) {
      checks.push(this.checkUrl('reference', ref));
    }

    // 14. Deduplication
    const fingerprint = this.fingerprint(record);
    const isDuplicate = seenFingerprints.has(fingerprint);
    checks.push({
      name: 'deduplication',
      passed: !isDuplicate,
      message: isDuplicate ? `Duplicate record: ${fingerprint.slice(0, 16)}` : 'Unique record',
    });
    if (!isDuplicate) {
      seenFingerprints.add(fingerprint);
    }

    // Calculate score
    const passed = checks.filter((c) => c.passed).length;
    const total = checks.length;
    const score = total > 0 ? Math.round((passed / total) * 100) : 0;

    const validation: ValidationStatus = {
      valid: score >= 70 && !checks.some((c) => !c.passed && c.name === 'required'),
      score,
      checks,
      validatedAt: new Date().toISOString(),
    };

    // Sanitize and return
    return {
      ...this.sanitize(record),
      validation,
    };
  }

  /** Reset deduplication cache (for testing or new sync cycles) */
  resetDeduplication(): void {
    seenFingerprints.clear();
  }

  /** Get deduplication cache size */
  get deduplicationSize(): number {
    return seenFingerprints.size;
  }

  // -- Private validation checks --

  private checkRequired(field: string, value: unknown): ValidationCheck {
    const passed = value !== null && value !== undefined && value !== '';
    return { name: 'required', passed, message: passed ? `${field} present` : `${field} is required` };
  }

  private checkStringLength(field: string, value: string, maxLen: number): ValidationCheck {
    const passed = value.length <= maxLen;
    return {
      name: 'string_length',
      passed,
      message: passed ? `${field} length OK` : `${field} exceeds ${maxLen} chars (${value.length})`,
    };
  }

  private checkNoInjection(field: string, value: string): ValidationCheck {
    const hasInjection = PATTERNS.injection.test(value);
    return {
      name: 'no_injection',
      passed: !hasInjection,
      message: hasInjection ? `${field} contains potential injection payload` : `${field} clean`,
    };
  }

  private checkFormat(field: string, value: string, pattern: RegExp): ValidationCheck {
    const passed = pattern.test(value);
    return {
      name: 'format',
      passed,
      message: passed ? `${field}:${value} valid` : `${field}:${value} invalid format`,
    };
  }

  private checkDate(field: string, value: string): ValidationCheck {
    const date = new Date(value);
    const passed = !isNaN(date.getTime()) && PATTERNS.isoDate.test(value);
    return {
      name: 'date_valid',
      passed,
      message: passed ? `${field} valid date` : `${field} invalid date: ${value}`,
    };
  }

  private checkFreshness(publishedAt: string): ValidationCheck {
    const date = new Date(publishedAt);
    const ageMs = Date.now() - date.getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    const passed = ageDays <= MAX_AGE_DAYS && ageDays >= -1; // allow 1 day future tolerance
    return {
      name: 'freshness',
      passed,
      message: passed
        ? `Record age: ${Math.round(ageDays)} days`
        : `Record too old or future-dated: ${Math.round(ageDays)} days`,
    };
  }

  private checkCvssRange(score: number): ValidationCheck {
    const passed = score >= 0 && score <= 10;
    return {
      name: 'cvss_range',
      passed,
      message: passed ? `CVSS ${score} in range` : `CVSS ${score} out of range [0-10]`,
    };
  }

  private checkSeverity(severity: string): ValidationCheck {
    const valid = ['none', 'low', 'medium', 'high', 'critical'];
    const passed = valid.includes(severity);
    return {
      name: 'severity_valid',
      passed,
      message: passed ? `Severity ${severity} valid` : `Invalid severity: ${severity}`,
    };
  }

  private checkIndicatorCount(indicators: ThreatIndicator[]): ValidationCheck {
    const passed = indicators.length <= MAX_INDICATORS;
    return {
      name: 'indicator_count',
      passed,
      message: passed
        ? `${indicators.length} indicators`
        : `Too many indicators: ${indicators.length} (max ${MAX_INDICATORS})`,
    };
  }

  private checkIndicator(indicator: ThreatIndicator): ValidationCheck {
    const patternMap: Record<string, RegExp | undefined> = {
      ipv4: PATTERNS.ipv4,
      ipv6: PATTERNS.ipv6,
      domain: PATTERNS.domain,
      md5: PATTERNS.md5,
      sha1: PATTERNS.sha1,
      sha256: PATTERNS.sha256,
      email: PATTERNS.email,
    };

    const pattern = patternMap[indicator.type];
    if (!pattern) {
      // URL and filename don't have strict regex; just check non-empty
      const passed = indicator.value.length > 0 && indicator.value.length <= 2048;
      return {
        name: 'indicator_format',
        passed,
        message: passed ? `${indicator.type} indicator OK` : `${indicator.type} indicator invalid`,
      };
    }

    const passed = pattern.test(indicator.value);
    return {
      name: 'indicator_format',
      passed,
      message: passed
        ? `${indicator.type}:${indicator.value.slice(0, 32)} valid`
        : `${indicator.type}:${indicator.value.slice(0, 32)} invalid format`,
    };
  }

  private checkReferenceCount(refs: string[]): ValidationCheck {
    const passed = refs.length <= MAX_REFERENCES;
    return {
      name: 'reference_count',
      passed,
      message: passed ? `${refs.length} references` : `Too many references: ${refs.length}`,
    };
  }

  private checkUrl(field: string, url: string): ValidationCheck {
    try {
      const parsed = new URL(url);
      const passed = ['http:', 'https:'].includes(parsed.protocol);
      return {
        name: 'url_valid',
        passed,
        message: passed ? `${field} URL valid` : `${field} URL non-http(s) protocol: ${parsed.protocol}`,
      };
    } catch {
      return { name: 'url_valid', passed: false, message: `${field} URL invalid: ${url.slice(0, 64)}` };
    }
  }

  // -- Sanitization --

  /** Sanitize record strings to prevent stored XSS/injection */
  private sanitize(record: ThreatIntelRecord): ThreatIntelRecord {
    return {
      ...record,
      title: this.sanitizeString(record.title),
      description: record.description ? this.sanitizeString(record.description) : null,
      // Truncate arrays to safe limits
      indicators: record.indicators.slice(0, MAX_INDICATORS),
      references: record.references.slice(0, MAX_REFERENCES),
    };
  }

  /** Strip dangerous characters from strings */
  private sanitizeString(value: string): string {
    return value
      .replace(/<script[^>]*>.*?<\/script>/gi, '[removed]')
      .replace(/javascript:/gi, '[removed]')
      .replace(/on\w+\s*=/gi, '[removed]')
      .slice(0, MAX_STRING_LENGTH);
  }

  // -- Fingerprinting --

  /** Generate a content fingerprint for deduplication */
  private fingerprint(record: ThreatIntelRecord): string {
    const content = `${record.source}:${record.id}:${record.title}`;
    return createHash('sha256').update(content).digest('hex');
  }
}
