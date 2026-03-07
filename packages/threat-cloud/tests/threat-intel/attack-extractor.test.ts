/**
 * Attack Pattern Extractor Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AttackExtractor } from '../../src/threat-intel/attack-extractor.js';
import type { StoredReport } from '../../src/threat-intel/types.js';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function makeReport(overrides: Partial<StoredReport> = {}): StoredReport {
  return {
    id: '12345',
    title: 'SSRF via webhook URL parameter',
    severity: 'high',
    cweId: 'CWE-918',
    cweName: 'Server-Side Request Forgery',
    cveIds: [],
    summary: null,
    disclosedAt: '2026-02-01T10:00:00Z',
    programHandle: 'example',
    programName: 'Example Corp',
    reporterUsername: 'testuser',
    url: 'https://hackerone.com/reports/12345',
    fetchedAt: '2026-03-07T00:00:00Z',
    ...overrides,
  };
}

describe('AttackExtractor', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe('heuristic extraction', () => {
    it('extracts SSRF pattern from CWE-918', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({ cweId: 'CWE-918' });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns).toHaveLength(1);
      expect(patterns[0].attackType).toBe('SSRF');
      expect(patterns[0].mitreTechniques).toContain('T1190');
      expect(patterns[0].payloadSignatures.length).toBeGreaterThan(0);
      expect(patterns[0].payloadSignatures).toContain('127.0.0.1');
      expect(patterns[0].logSourceCategory).toBe('webserver');
    });

    it('extracts XSS pattern from CWE-79', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({ cweId: 'CWE-79', title: 'XSS in search' });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns[0].attackType).toBe('XSS');
      expect(patterns[0].payloadSignatures).toContain('<script');
    });

    it('extracts SQLi pattern from CWE-89', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({ cweId: 'CWE-89', title: 'SQL injection' });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns[0].attackType).toBe('SQLi');
      expect(patterns[0].payloadSignatures).toContain('UNION SELECT');
    });

    it('extracts Command Injection from CWE-78', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({ cweId: 'CWE-78', title: 'OS command injection' });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns[0].attackType).toBe('Command Injection');
    });

    it('extracts Path Traversal from CWE-22', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({ cweId: 'CWE-22' });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns[0].attackType).toBe('Path Traversal');
      expect(patterns[0].payloadSignatures).toContain('../');
    });

    it('falls back to title-based detection when CWE unknown', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({
        cweId: null,
        title: 'SSRF vulnerability in image proxy',
      });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns[0].attackType).toBe('SSRF');
    });

    it('detects XSS from title keywords', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({
        cweId: null,
        title: 'Stored Cross-Site Scripting in profile page',
      });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns[0].attackType).toBe('XSS');
    });

    it('detects IDOR from title keywords', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({
        cweId: null,
        title: 'IDOR allows access to other user data',
      });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns[0].attackType).toBe('IDOR');
    });

    it('returns Unknown for unrecognized reports', () => {
      const extractor = new AttackExtractor();
      const report = makeReport({
        cweId: null,
        title: 'Some obscure vulnerability type',
      });
      const patterns = extractor.extractHeuristic(report);

      expect(patterns[0].attackType).toBe('Unknown');
      expect(patterns[0].confidence).toBe(30);
    });

    it('sets confidence based on severity', () => {
      const extractor = new AttackExtractor();

      const critical = extractor.extractHeuristic(makeReport({ cweId: 'CWE-918', severity: 'critical' }));
      const high = extractor.extractHeuristic(makeReport({ cweId: 'CWE-918', severity: 'high' }));
      const medium = extractor.extractHeuristic(makeReport({ cweId: 'CWE-918', severity: 'medium' }));
      const low = extractor.extractHeuristic(makeReport({ cweId: 'CWE-918', severity: 'low' }));

      expect(critical[0].confidence).toBe(85);
      expect(high[0].confidence).toBe(75);
      expect(medium[0].confidence).toBe(60);
      expect(low[0].confidence).toBe(45);
    });

    it('includes CWE IDs when available', () => {
      const extractor = new AttackExtractor();
      const patterns = extractor.extractHeuristic(makeReport({ cweId: 'CWE-918' }));

      expect(patterns[0].cweIds).toContain('CWE-918');
    });
  });

  describe('Ollama integration', () => {
    it('checks Ollama availability', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });

      const extractor = new AttackExtractor();
      const available = await extractor.isOllamaAvailable();

      expect(available).toBe(true);
    });

    it('returns false when Ollama is down', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const extractor = new AttackExtractor();
      const available = await extractor.isOllamaAvailable();

      expect(available).toBe(false);
    });

    it('falls back to heuristic when Ollama fails', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const extractor = new AttackExtractor();
      const result = await extractor.extract(makeReport());

      expect(result.model).toBe('heuristic');
      expect(result.patterns.length).toBeGreaterThan(0);
    });

    it('uses Ollama response when available', async () => {
      const ollamaResponse = {
        response: JSON.stringify({
          attackType: 'SSRF',
          endpointPatterns: ['/api/webhooks/*'],
          payloadSignatures: ['127.0.0.1', 'localhost'],
          cweIds: ['CWE-918'],
          mitreTechniques: ['T1190'],
          logSourceCategory: 'webserver',
          logSourceProduct: 'any',
          confidence: 85,
          description: 'SSRF via webhook URL',
        }),
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ollamaResponse,
      });

      const extractor = new AttackExtractor();
      const result = await extractor.extract(makeReport());

      expect(result.model).toBe('llama3.2');
      expect(result.patterns).toHaveLength(1);
      expect(result.patterns[0].attackType).toBe('SSRF');
      expect(result.patterns[0].confidence).toBe(85);
    });

    it('handles malformed Ollama response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ response: 'not valid json here' }),
      });

      const extractor = new AttackExtractor();
      const result = await extractor.extract(makeReport());

      // Should fall back to heuristic
      expect(result.patterns.length).toBeGreaterThan(0);
    });

    it('filters patterns by minimum confidence', async () => {
      const extractor = new AttackExtractor({ minConfidence: 90 });
      const result = await extractor.extract(
        makeReport({ cweId: 'CWE-918', severity: 'medium' })
      );

      // Medium severity → 60% confidence → filtered out at minConfidence=90
      // Falls back to heuristic which also gets filtered
      expect(result.patterns).toHaveLength(0);
    });
  });

  describe('extraction pipeline', () => {
    it('returns correct metadata in ExtractionResult', async () => {
      mockFetch.mockRejectedValueOnce(new Error('no ollama'));

      const extractor = new AttackExtractor();
      const report = makeReport();
      const result = await extractor.extract(report);

      expect(result.reportId).toBe('12345');
      expect(result.reportTitle).toBe('SSRF via webhook URL parameter');
      expect(result.reportUrl).toBe('https://hackerone.com/reports/12345');
      expect(result.extractedAt).toBeTruthy();
    });
  });
});
