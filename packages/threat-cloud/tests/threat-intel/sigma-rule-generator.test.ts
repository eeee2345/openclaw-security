/**
 * Sigma Rule Generator Tests
 */

import { describe, it, expect } from 'vitest';
import { SigmaRuleGenerator } from '../../src/threat-intel/sigma-rule-generator.js';
import type { ExtractionResult, ExtractedAttackPattern } from '../../src/threat-intel/types.js';

function makeExtraction(
  patternOverrides: Partial<ExtractedAttackPattern> = {}
): ExtractionResult {
  return {
    reportId: '12345',
    reportTitle: 'Test Report',
    reportUrl: 'https://hackerone.com/reports/12345',
    patterns: [
      {
        attackType: 'SSRF',
        endpointPatterns: [],
        payloadSignatures: ['127.0.0.1', 'localhost', '169.254.169.254'],
        cweIds: ['CWE-918'],
        mitreTechniques: ['T1190', 'T1071'],
        logSourceCategory: 'webserver',
        logSourceProduct: 'any',
        confidence: 85,
        description: 'SSRF via internal network access',
        ...patternOverrides,
      },
    ],
    extractedAt: '2026-03-07T00:00:00Z',
    model: 'heuristic',
  };
}

describe('SigmaRuleGenerator', () => {
  const generator = new SigmaRuleGenerator();

  it('generates a valid Sigma rule from SSRF pattern', () => {
    const rules = generator.generate(makeExtraction());

    expect(rules).toHaveLength(1);
    const rule = rules[0];

    expect(rule.id).toBeTruthy();
    expect(rule.attackType).toBe('SSRF');
    expect(rule.confidence).toBe(85);
    expect(rule.status).toBe('experimental');
    expect(rule.sourceReportId).toBe('12345');
    expect(rule.sourceReportUrl).toBe('https://hackerone.com/reports/12345');

    // Verify YAML content
    const yaml = rule.yamlContent;
    expect(yaml).toContain('title: Potential SSRF via Internal Network Access');
    expect(yaml).toContain(`id: ${rule.id}`);
    expect(yaml).toContain('status: experimental');
    expect(yaml).toContain('Auto-generated from HackerOne report analysis');
    expect(yaml).toContain('https://hackerone.com/reports/12345');
    expect(yaml).toContain('author: Panguard Threat Intel');
    expect(yaml).toContain('category: webserver');
    expect(yaml).toContain("- '127.0.0.1'");
    expect(yaml).toContain("- 'localhost'");
    expect(yaml).toContain('condition: selection');
    expect(yaml).toContain('level: high');
  });

  it('includes MITRE ATT&CK tags', () => {
    const rules = generator.generate(makeExtraction());
    const yaml = rules[0].yamlContent;

    expect(yaml).toContain('attack.initial_access');
    expect(yaml).toContain('attack.t1190');
    expect(yaml).toContain('attack.command_and_control');
    expect(yaml).toContain('attack.t1071');
    expect(yaml).toContain('cwe.918');
  });

  it('generates XSS rule with dual selection (query + body)', () => {
    const rules = generator.generate(
      makeExtraction({
        attackType: 'XSS',
        payloadSignatures: ['<script', 'javascript:', 'onerror='],
        cweIds: ['CWE-79'],
        mitreTechniques: ['T1059.007'],
      })
    );

    const yaml = rules[0].yamlContent;
    expect(yaml).toContain('selection_query:');
    expect(yaml).toContain('selection_body:');
    expect(yaml).toContain('condition: selection_query or selection_body');
    expect(yaml).toContain("- '<script'");
  });

  it('generates SQLi rule', () => {
    const rules = generator.generate(
      makeExtraction({
        attackType: 'SQLi',
        payloadSignatures: ["' OR '1'='1", 'UNION SELECT'],
        cweIds: ['CWE-89'],
        mitreTechniques: ['T1190'],
      })
    );

    const yaml = rules[0].yamlContent;
    expect(yaml).toContain('Potential SQL Injection Attempt');
    expect(yaml).toContain('cs-uri-query|contains:');
    expect(yaml).toContain('UNION SELECT');
  });

  it('generates Path Traversal rule using cs-uri', () => {
    const rules = generator.generate(
      makeExtraction({
        attackType: 'Path Traversal',
        payloadSignatures: ['../', '..\\', '/etc/passwd'],
        cweIds: ['CWE-22'],
        mitreTechniques: ['T1083'],
      })
    );

    const yaml = rules[0].yamlContent;
    expect(yaml).toContain('cs-uri|contains:');
    expect(yaml).toContain("- '../'");
  });

  it('generates XXE rule using cs-body', () => {
    const rules = generator.generate(
      makeExtraction({
        attackType: 'XXE',
        payloadSignatures: ['<!ENTITY', '<!DOCTYPE'],
        cweIds: ['CWE-611'],
        mitreTechniques: ['T1190'],
      })
    );

    const yaml = rules[0].yamlContent;
    expect(yaml).toContain('cs-body|contains:');
  });

  it('generates File Upload rule with method + extension check', () => {
    const rules = generator.generate(
      makeExtraction({
        attackType: 'File Upload',
        payloadSignatures: ['.php', '.jsp', '.exe'],
        cweIds: ['CWE-434'],
        mitreTechniques: ['T1105'],
      })
    );

    const yaml = rules[0].yamlContent;
    expect(yaml).toContain('selection_method:');
    expect(yaml).toContain("cs-method: 'POST'");
    expect(yaml).toContain('cs-uri|endswith:');
    expect(yaml).toContain('condition: selection_method and selection_ext');
  });

  it('generates SSRF rule with endpoint filter when patterns present', () => {
    const rules = generator.generate(
      makeExtraction({
        endpointPatterns: ['/api/webhooks/', '/api/proxy/'],
      })
    );

    const yaml = rules[0].yamlContent;
    expect(yaml).toContain('filter_endpoint:');
    expect(yaml).toContain('cs-uri-stem|contains:');
    expect(yaml).toContain('condition: selection and filter_endpoint');
  });

  it('marks rules with confidence < 70 as draft', () => {
    const rules = generator.generate(makeExtraction({ confidence: 55 }));

    expect(rules[0].status).toBe('draft');
  });

  it('marks rules with confidence >= 70 as experimental', () => {
    const rules = generator.generate(makeExtraction({ confidence: 75 }));

    expect(rules[0].status).toBe('experimental');
  });

  it('skips patterns with no signatures or endpoints', () => {
    const rules = generator.generate(
      makeExtraction({
        payloadSignatures: [],
        endpointPatterns: [],
      })
    );

    expect(rules).toHaveLength(0);
  });

  it('includes false positives section', () => {
    const rules = generator.generate(makeExtraction());
    const yaml = rules[0].yamlContent;

    expect(yaml).toContain('falsepositives:');
    expect(yaml).toContain('Legitimate internal API calls');
  });

  it('handles multiple patterns in one extraction', () => {
    const extraction: ExtractionResult = {
      reportId: '12345',
      reportTitle: 'Test',
      reportUrl: 'https://hackerone.com/reports/12345',
      patterns: [
        {
          attackType: 'SSRF',
          endpointPatterns: [],
          payloadSignatures: ['127.0.0.1'],
          cweIds: ['CWE-918'],
          mitreTechniques: ['T1190'],
          logSourceCategory: 'webserver',
          logSourceProduct: 'any',
          confidence: 80,
          description: 'Pattern 1',
        },
        {
          attackType: 'XSS',
          endpointPatterns: [],
          payloadSignatures: ['<script'],
          cweIds: ['CWE-79'],
          mitreTechniques: ['T1059.007'],
          logSourceCategory: 'webserver',
          logSourceProduct: 'any',
          confidence: 70,
          description: 'Pattern 2',
        },
      ],
      extractedAt: '2026-03-07T00:00:00Z',
      model: 'heuristic',
    };

    const rules = generator.generate(extraction);
    expect(rules).toHaveLength(2);
    expect(rules[0].attackType).toBe('SSRF');
    expect(rules[1].attackType).toBe('XSS');
  });

  it('sets level based on confidence', () => {
    const high = generator.generate(makeExtraction({ confidence: 85 }));
    const medium = generator.generate(makeExtraction({ confidence: 65 }));
    const low = generator.generate(makeExtraction({ confidence: 45 }));

    expect(high[0].yamlContent).toContain('level: high');
    expect(medium[0].yamlContent).toContain('level: medium');
    expect(low[0].yamlContent).toContain('level: low');
  });

  it('escapes special YAML characters in values', () => {
    const rules = generator.generate(
      makeExtraction({
        payloadSignatures: ["' OR '1'='1"],
      })
    );

    const yaml = rules[0].yamlContent;
    // Single quotes inside single-quoted YAML should be escaped with ''
    expect(yaml).toContain("'' OR ''1''=''1");
  });
});
