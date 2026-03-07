import { describe, it, expect, vi } from 'vitest';
import { checkWithAI, type SkillAnalysisLLM } from '../src/checks/ai-check.js';

function makeLLM(overrides: Partial<SkillAnalysisLLM> = {}): SkillAnalysisLLM {
  return {
    analyze: overrides.analyze ?? vi.fn().mockResolvedValue({
      summary: '{"findings": [], "overallAssessment": "safe", "confidence": 0.9}',
      severity: 'info' as const,
      confidence: 0.9,
      recommendations: [],
    }),
    isAvailable: overrides.isAvailable ?? vi.fn().mockResolvedValue(true),
  };
}

describe('checkWithAI', () => {
  describe('no LLM provided', () => {
    it('should return empty findings when no LLM is given', async () => {
      const result = await checkWithAI('some instructions', 'some description');
      expect(result.findings).toHaveLength(0);
      expect(result.status).toBe('info');
      expect(result.label).toContain('Skipped');
    });

    it('should return empty findings when LLM is undefined', async () => {
      const result = await checkWithAI('instructions', 'desc', undefined);
      expect(result.findings).toHaveLength(0);
    });
  });

  describe('LLM not available', () => {
    it('should return empty findings when LLM.isAvailable returns false', async () => {
      const llm = makeLLM({
        isAvailable: vi.fn().mockResolvedValue(false),
      });
      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings).toHaveLength(0);
      expect(result.status).toBe('info');
      expect(result.label).toContain('not available');
    });

    it('should handle isAvailable throwing an error', async () => {
      const llm = makeLLM({
        isAvailable: vi.fn().mockRejectedValue(new Error('connection failed')),
      });
      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings).toHaveLength(0);
      expect(result.status).toBe('info');
    });
  });

  describe('LLM returns valid findings', () => {
    it('should map LLM findings to AuditFindings correctly', async () => {
      const llmFindings = {
        findings: [
          {
            id: 'ai-social-engineering',
            title: 'Deceptive language detected',
            description: 'Skill uses false urgency to trick users',
            severity: 'high',
          },
        ],
        overallAssessment: 'suspicious',
        confidence: 0.85,
      };

      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary: JSON.stringify(llmFindings),
          severity: 'high' as const,
          confidence: 0.85,
          recommendations: ['Review skill carefully'],
        }),
      });

      const result = await checkWithAI('instructions', 'description', llm);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].id).toBe('ai-social-engineering');
      expect(result.findings[0].title).toBe('Deceptive language detected');
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].category).toBe('ai-analysis');
      expect(result.findings[0].location).toBe('AI analysis');
    });

    it('should return warn status for high severity findings', async () => {
      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary: JSON.stringify({
            findings: [
              { id: 'ai-test', title: 'Test', description: 'Test', severity: 'high' },
            ],
          }),
          severity: 'high' as const,
          confidence: 0.8,
          recommendations: [],
        }),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.status).toBe('warn');
    });

    it('should return fail status for critical severity findings', async () => {
      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary: JSON.stringify({
            findings: [
              { id: 'ai-test', title: 'Critical issue', description: 'Very bad', severity: 'critical' },
            ],
          }),
          severity: 'critical' as const,
          confidence: 0.95,
          recommendations: [],
        }),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.status).toBe('fail');
    });

    it('should return pass status when LLM finds no issues', async () => {
      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary: JSON.stringify({ findings: [], overallAssessment: 'safe', confidence: 0.9 }),
          severity: 'info' as const,
          confidence: 0.9,
          recommendations: [],
        }),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.status).toBe('pass');
      expect(result.findings).toHaveLength(0);
    });
  });

  describe('findings capped at 10', () => {
    it('should limit findings to maximum 10', async () => {
      const manyFindings = Array.from({ length: 15 }, (_, i) => ({
        id: `ai-finding-${i}`,
        title: `Finding ${i}`,
        description: `Description ${i}`,
        severity: 'medium',
      }));

      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary: JSON.stringify({ findings: manyFindings }),
          severity: 'medium' as const,
          confidence: 0.7,
          recommendations: [],
        }),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings.length).toBeLessThanOrEqual(10);
    });
  });

  describe('LLM error handling', () => {
    it('should return empty findings when LLM.analyze throws', async () => {
      const llm = makeLLM({
        analyze: vi.fn().mockRejectedValue(new Error('API rate limit exceeded')),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings).toHaveLength(0);
      expect(result.status).toBe('info');
      expect(result.label).toContain('Error');
      expect(result.label).toContain('API rate limit exceeded');
    });

    it('should handle non-Error thrown values gracefully', async () => {
      const llm = makeLLM({
        analyze: vi.fn().mockRejectedValue('string error'),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings).toHaveLength(0);
      expect(result.status).toBe('info');
      expect(result.label).toContain('unknown');
    });

    it('should handle malformed JSON from LLM gracefully', async () => {
      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary: 'This is not valid JSON at all',
          severity: 'info' as const,
          confidence: 0.5,
          recommendations: [],
        }),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings).toHaveLength(0);
      expect(result.status).toBe('pass');
    });

    it('should handle JSON with no findings array', async () => {
      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary: JSON.stringify({ overallAssessment: 'safe' }),
          severity: 'info' as const,
          confidence: 0.9,
          recommendations: [],
        }),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings).toHaveLength(0);
    });
  });

  describe('markdown code fence handling', () => {
    it('should parse findings from JSON wrapped in code fences', async () => {
      const summary = '```json\n{"findings": [{"id": "ai-test", "title": "Test", "description": "Desc", "severity": "medium"}]}\n```';
      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary,
          severity: 'medium' as const,
          confidence: 0.8,
          recommendations: [],
        }),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].id).toBe('ai-test');
    });
  });

  describe('finding validation', () => {
    it('should filter out findings with missing required fields', async () => {
      const llm = makeLLM({
        analyze: vi.fn().mockResolvedValue({
          summary: JSON.stringify({
            findings: [
              { id: 'valid', title: 'Valid', description: 'Desc', severity: 'high' },
              { id: 'missing-title', description: 'Desc', severity: 'high' },
              { id: 'bad-severity', title: 'Bad', description: 'Desc', severity: 'unknown' },
              { title: 'No ID', description: 'Desc', severity: 'low' },
            ],
          }),
          severity: 'high' as const,
          confidence: 0.7,
          recommendations: [],
        }),
      });

      const result = await checkWithAI('instructions', 'desc', llm);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].id).toBe('valid');
    });
  });
});
