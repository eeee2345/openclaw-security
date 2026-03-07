import { describe, it, expect } from 'vitest';
import { calculateRiskScore } from '../src/risk-scorer.js';
import type { AuditFinding } from '../src/types.js';

function makeFinding(overrides: Partial<AuditFinding> & Pick<AuditFinding, 'id' | 'severity'>): AuditFinding {
  return {
    title: 'Test finding',
    description: 'Test description',
    category: 'prompt-injection',
    ...overrides,
  };
}

describe('calculateRiskScore', () => {
  describe('severity weights', () => {
    it('should assign weight 25 to CRITICAL findings', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'critical' }),
      ]);
      expect(score).toBe(25);
    });

    it('should assign weight 15 to HIGH findings', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'high' }),
      ]);
      expect(score).toBe(15);
    });

    it('should assign weight 5 to MEDIUM findings', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'medium' }),
      ]);
      expect(score).toBe(5);
    });

    it('should assign weight 1 to LOW findings', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'low' }),
      ]);
      expect(score).toBe(1);
    });

    it('should assign weight 0 to INFO findings', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'info' }),
      ]);
      expect(score).toBe(0);
    });
  });

  describe('empty findings', () => {
    it('should return score 0 and level LOW for empty findings', () => {
      const result = calculateRiskScore([]);
      expect(result.score).toBe(0);
      expect(result.level).toBe('LOW');
    });
  });

  describe('deduplication', () => {
    it('should keep only highest severity when same ID appears with different severities', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'dup-1', severity: 'low' }),
        makeFinding({ id: 'dup-1', severity: 'critical' }),
      ]);
      // Should count only the critical (25), not low (1) + critical (25)
      expect(score).toBe(25);
    });

    it('should keep highest severity regardless of order', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'dup-1', severity: 'critical' }),
        makeFinding({ id: 'dup-1', severity: 'low' }),
      ]);
      expect(score).toBe(25);
    });

    it('should deduplicate multiple IDs independently', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'a', severity: 'low' }),
        makeFinding({ id: 'a', severity: 'high' }),
        makeFinding({ id: 'b', severity: 'medium' }),
        makeFinding({ id: 'b', severity: 'critical' }),
      ]);
      // a: high(15) + b: critical(25) = 40
      expect(score).toBe(40);
    });

    it('should not deduplicate findings with different IDs', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'high' }),
        makeFinding({ id: 'f2', severity: 'high' }),
      ]);
      // 15 + 15 = 30
      expect(score).toBe(30);
    });
  });

  describe('score capping', () => {
    it('should cap score at 100', () => {
      const findings = Array.from({ length: 10 }, (_, i) =>
        makeFinding({ id: `f${i}`, severity: 'critical' }),
      );
      // 10 * 25 = 250, but capped at 100
      const { score } = calculateRiskScore(findings);
      expect(score).toBe(100);
    });
  });

  describe('risk level thresholds', () => {
    it('should return LOW for score 0-14', () => {
      // score = 1 (one low finding)
      const result1 = calculateRiskScore([makeFinding({ id: 'f1', severity: 'low' })]);
      expect(result1.level).toBe('LOW');

      // score = 5 (one medium finding)
      const result5 = calculateRiskScore([makeFinding({ id: 'f1', severity: 'medium' })]);
      expect(result5.level).toBe('LOW');
    });

    it('should return MEDIUM for score 15-39', () => {
      // score = 15 (one high finding)
      const result15 = calculateRiskScore([makeFinding({ id: 'f1', severity: 'high' })]);
      expect(result15.level).toBe('MEDIUM');

      // score = 25 (one critical finding)
      const result25 = calculateRiskScore([makeFinding({ id: 'f1', severity: 'critical' })]);
      expect(result25.level).toBe('MEDIUM');
    });

    it('should return HIGH for score 40-69', () => {
      // score = 40 (high + critical = 15 + 25)
      const result40 = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'high' }),
        makeFinding({ id: 'f2', severity: 'critical' }),
      ]);
      expect(result40.level).toBe('HIGH');

      // score = 65 (two critical + one high = 50 + 15)
      const result65 = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'critical' }),
        makeFinding({ id: 'f2', severity: 'critical' }),
        makeFinding({ id: 'f3', severity: 'high' }),
      ]);
      expect(result65.level).toBe('HIGH');
    });

    it('should return CRITICAL for score 70+', () => {
      // score = 75 (three critical = 75)
      const result75 = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'critical' }),
        makeFinding({ id: 'f2', severity: 'critical' }),
        makeFinding({ id: 'f3', severity: 'critical' }),
      ]);
      expect(result75.level).toBe('CRITICAL');

      // score = 100 (capped)
      const findings = Array.from({ length: 5 }, (_, i) =>
        makeFinding({ id: `f${i}`, severity: 'critical' }),
      );
      const result100 = calculateRiskScore(findings);
      expect(result100.level).toBe('CRITICAL');
    });
  });

  describe('accumulation', () => {
    it('should sum scores from multiple different findings', () => {
      const { score } = calculateRiskScore([
        makeFinding({ id: 'f1', severity: 'critical' }),
        makeFinding({ id: 'f2', severity: 'high' }),
        makeFinding({ id: 'f3', severity: 'medium' }),
        makeFinding({ id: 'f4', severity: 'low' }),
      ]);
      // 25 + 15 + 5 + 1 = 46
      expect(score).toBe(46);
    });
  });
});
