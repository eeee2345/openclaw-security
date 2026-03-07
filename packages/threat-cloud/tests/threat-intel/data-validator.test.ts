/**
 * Data Validator Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DataValidator } from '../../src/threat-intel/data-validator.js';
import type { ThreatIntelRecord, ThreatIndicator } from '../../src/threat-intel/types.js';

function makeRecord(overrides: Partial<ThreatIntelRecord> = {}): ThreatIntelRecord {
  return {
    id: 'nvd:CVE-2024-1234',
    source: 'nvd',
    type: 'vulnerability',
    title: 'Test Vulnerability',
    description: 'A test vulnerability for validation',
    severity: 'high',
    cvssScore: 7.5,
    cveIds: ['CVE-2024-1234'],
    cweIds: ['CWE-79'],
    mitreTechniques: ['T1059'],
    indicators: [],
    affectedProducts: [],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-1234'],
    publishedAt: new Date().toISOString(),
    modifiedAt: null,
    fetchedAt: new Date().toISOString(),
    sourceReliability: 'authoritative',
    validation: { valid: true, score: 100, checks: [], validatedAt: new Date().toISOString() },
    ...overrides,
  };
}

describe('DataValidator', () => {
  let validator: DataValidator;

  beforeEach(() => {
    validator = new DataValidator();
    validator.resetDeduplication();
  });

  it('validates a correct record', () => {
    const result = validator.validate(makeRecord());
    expect(result.validation.valid).toBe(true);
    expect(result.validation.score).toBeGreaterThanOrEqual(90);
  });

  it('rejects missing required fields', () => {
    const result = validator.validate(makeRecord({ id: '', title: '' }));
    expect(result.validation.valid).toBe(false);
    const required = result.validation.checks.filter(c => c.name === 'required' && !c.passed);
    expect(required.length).toBeGreaterThanOrEqual(2);
  });

  it('validates CVE ID format', () => {
    const good = validator.validate(makeRecord({ cveIds: ['CVE-2024-12345'] }));
    const goodChecks = good.validation.checks.filter(c => c.name === 'format' && c.passed);
    expect(goodChecks.length).toBeGreaterThan(0);

    const bad = validator.validate(makeRecord({ id: 'bad2', cveIds: ['NOTCVE-123'] }));
    const badChecks = bad.validation.checks.filter(c => c.name === 'format' && !c.passed);
    expect(badChecks.length).toBeGreaterThan(0);
  });

  it('validates CWE ID format', () => {
    const good = validator.validate(makeRecord({ id: 'cwe-test', cweIds: ['CWE-79'] }));
    expect(good.validation.checks.some(c => c.name === 'format' && c.passed && c.message.includes('CWE-79'))).toBe(true);

    const bad = validator.validate(makeRecord({ id: 'cwe-bad', cweIds: ['CWE-ABC'] }));
    expect(bad.validation.checks.some(c => c.name === 'format' && !c.passed)).toBe(true);
  });

  it('validates MITRE technique ID format', () => {
    const good = validator.validate(makeRecord({ id: 'mitre-test', mitreTechniques: ['T1059', 'T1059.001'] }));
    const formatChecks = good.validation.checks.filter(c => c.name === 'format' && c.passed);
    expect(formatChecks.length).toBeGreaterThanOrEqual(2);
  });

  it('detects injection in title', () => {
    const result = validator.validate(makeRecord({
      id: 'inject-test',
      title: 'Test <script>alert("xss")</script>',
    }));
    const injCheck = result.validation.checks.find(c => c.name === 'no_injection' && !c.passed);
    expect(injCheck).toBeDefined();
    // Sanitized title should not contain script tag
    expect(result.title).not.toContain('<script>');
  });

  it('rejects overly long strings', () => {
    const result = validator.validate(makeRecord({
      id: 'long-test',
      title: 'x'.repeat(600),
    }));
    const lenCheck = result.validation.checks.find(c => c.name === 'string_length' && !c.passed);
    expect(lenCheck).toBeDefined();
  });

  it('validates date format', () => {
    const result = validator.validate(makeRecord({
      id: 'date-test',
      publishedAt: 'not-a-date',
    }));
    const dateCheck = result.validation.checks.find(c => c.name === 'date_valid' && !c.passed);
    expect(dateCheck).toBeDefined();
  });

  it('rejects stale records (older than 365 days)', () => {
    const oldDate = new Date();
    oldDate.setFullYear(oldDate.getFullYear() - 2);
    const result = validator.validate(makeRecord({
      id: 'stale-test',
      publishedAt: oldDate.toISOString(),
    }));
    const freshCheck = result.validation.checks.find(c => c.name === 'freshness' && !c.passed);
    expect(freshCheck).toBeDefined();
  });

  it('validates CVSS score range', () => {
    const good = validator.validate(makeRecord({ id: 'cvss-good', cvssScore: 9.8 }));
    expect(good.validation.checks.some(c => c.name === 'cvss_range' && c.passed)).toBe(true);

    const bad = validator.validate(makeRecord({ id: 'cvss-bad', cvssScore: 15.0 }));
    expect(bad.validation.checks.some(c => c.name === 'cvss_range' && !c.passed)).toBe(true);
  });

  it('validates indicator formats', () => {
    const indicators: ThreatIndicator[] = [
      { type: 'ipv4', value: '192.168.1.1', context: null, firstSeen: null, lastSeen: null },
      { type: 'sha256', value: 'a'.repeat(64), context: null, firstSeen: null, lastSeen: null },
      { type: 'domain', value: 'example.com', context: null, firstSeen: null, lastSeen: null },
    ];
    const result = validator.validate(makeRecord({ id: 'ioc-test', indicators }));
    const iocChecks = result.validation.checks.filter(c => c.name === 'indicator_format' && c.passed);
    expect(iocChecks).toHaveLength(3);
  });

  it('rejects invalid IP addresses', () => {
    const indicators: ThreatIndicator[] = [
      { type: 'ipv4', value: '999.999.999.999', context: null, firstSeen: null, lastSeen: null },
    ];
    const result = validator.validate(makeRecord({ id: 'bad-ip', indicators }));
    const bad = result.validation.checks.find(c => c.name === 'indicator_format' && !c.passed);
    expect(bad).toBeDefined();
  });

  it('rejects invalid hashes', () => {
    const indicators: ThreatIndicator[] = [
      { type: 'sha256', value: 'not-a-hash', context: null, firstSeen: null, lastSeen: null },
    ];
    const result = validator.validate(makeRecord({ id: 'bad-hash', indicators }));
    const bad = result.validation.checks.find(c => c.name === 'indicator_format' && !c.passed);
    expect(bad).toBeDefined();
  });

  it('detects duplicate records', () => {
    const record = makeRecord();
    validator.validate(record); // First time
    const dup = validator.validate(record); // Same record
    const dupCheck = dup.validation.checks.find(c => c.name === 'deduplication' && !c.passed);
    expect(dupCheck).toBeDefined();
  });

  it('validates URL references', () => {
    const result = validator.validate(makeRecord({
      id: 'url-test',
      references: ['https://example.com', 'ftp://bad.com', 'not-a-url'],
    }));
    const urlChecks = result.validation.checks.filter(c => c.name === 'url_valid');
    const passed = urlChecks.filter(c => c.passed);
    const failed = urlChecks.filter(c => !c.passed);
    expect(passed).toHaveLength(1);
    expect(failed).toHaveLength(2);
  });

  it('limits indicators to MAX_INDICATORS', () => {
    const indicators: ThreatIndicator[] = Array.from({ length: 600 }, (_, i) => ({
      type: 'ipv4' as const,
      value: `10.0.${Math.floor(i / 256)}.${i % 256}`,
      context: null,
      firstSeen: null,
      lastSeen: null,
    }));
    const result = validator.validate(makeRecord({ id: 'many-ioc', indicators }));
    expect(result.indicators.length).toBeLessThanOrEqual(500);
  });

  it('resets deduplication cache', () => {
    const record = makeRecord();
    validator.validate(record);
    expect(validator.deduplicationSize).toBe(1);
    validator.resetDeduplication();
    expect(validator.deduplicationSize).toBe(0);
  });

  it('accepts records with null optional fields', () => {
    const result = validator.validate(makeRecord({
      id: 'null-test',
      description: null,
      cvssScore: null,
      modifiedAt: null,
    }));
    expect(result.validation.valid).toBe(true);
  });

  it('validates severity values', () => {
    const good = validator.validate(makeRecord({ id: 'sev-good', severity: 'critical' }));
    expect(good.validation.checks.some(c => c.name === 'severity_valid' && c.passed)).toBe(true);
  });
});
