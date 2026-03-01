import { describe, it, expect } from 'vitest';
import { caseStudies } from '../../src/data/case-studies';

describe('case studies data', () => {
  it('exports a non-empty array', () => {
    expect(Array.isArray(caseStudies)).toBe(true);
    expect(caseStudies.length).toBeGreaterThan(0);
  });

  it('every case study has required fields', () => {
    for (const cs of caseStudies) {
      expect(cs.slug).toBeTruthy();
      expect(cs.company).toBeTruthy();
      expect(cs.industry).toBeTruthy();
      expect(cs.companySize).toBeTruthy();
      expect(cs.productsUsed.length).toBeGreaterThan(0);
      expect(cs.headline).toBeTruthy();
      expect(cs.excerpt).toBeTruthy();
      expect(cs.challenge).toBeTruthy();
      expect(cs.solution).toBeTruthy();
      expect(cs.results.length).toBeGreaterThan(0);
      expect(cs.quote).toBeTruthy();
      expect(cs.quoteName).toBeTruthy();
      expect(cs.quoteRole).toBeTruthy();
    }
  });

  it('all case studies are marked as scenarios', () => {
    for (const cs of caseStudies) {
      expect(cs.isScenario).toBe(true);
    }
  });

  it('slugs are unique', () => {
    const slugs = caseStudies.map((cs) => cs.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it('results have metric and value', () => {
    for (const cs of caseStudies) {
      for (const result of cs.results) {
        expect(result.metric).toBeTruthy();
        expect(result.value).toBeTruthy();
      }
    }
  });
});
