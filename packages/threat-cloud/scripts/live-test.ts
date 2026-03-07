/**
 * Live test: Fetch HackerOne reports and generate Sigma rules
 * Run: npx tsx packages/threat-cloud/scripts/live-test.ts
 */

import { HackerOneAdapter } from '../src/threat-intel/hackerone-adapter.js';
import { AttackExtractor } from '../src/threat-intel/attack-extractor.js';
import { SigmaRuleGenerator } from '../src/threat-intel/sigma-rule-generator.js';
import { RuleValidator } from '../src/threat-intel/rule-validator.js';

async function run() {
  console.log('=== Panguard Threat Intel Pipeline - Live Test ===\n');

  // Step 1: Fetch reports
  const adapter = new HackerOneAdapter({ maxReports: 25, minSeverity: 'low' });
  console.log('Fetching HackerOne Hacktivity reports...');
  const reports = await adapter.fetchReports();
  console.log(`Found ${reports.length} disclosed reports with severity >= low\n`);

  if (reports.length === 0) {
    console.log('No reports found. Try lowering severity filter.');
    return;
  }

  // Step 2: Extract patterns and generate rules
  const extractor = new AttackExtractor({ minConfidence: 20 });
  const generator = new SigmaRuleGenerator();
  const validator = new RuleValidator();
  let totalRules = 0;

  for (const report of reports) {
    const extraction = {
      reportId: report.id,
      reportTitle: report.title,
      reportUrl: report.url,
      patterns: extractor.extractHeuristic(report),
      extractedAt: new Date().toISOString(),
      model: 'heuristic',
    };

    const rules = generator.generate(extraction);

    for (const rule of rules) {
      const validation = validator.validate(rule);
      if (!validation.valid || validation.isDuplicate) continue;
      totalRules++;

      console.log(`--- Report: ${report.title}`);
      console.log(`    Program: ${report.programName ?? 'N/A'}`);
      console.log(`    CWE: ${report.cweId ?? report.cweName ?? 'N/A'} | Severity: ${report.severity}`);
      console.log(`    CVEs: ${report.cveIds.length > 0 ? report.cveIds.join(', ') : 'N/A'}`);
      console.log(`    Attack Type: ${rule.attackType}`);
      console.log(`    Confidence: ${rule.confidence}% | Status: ${rule.status}`);
      console.log('    Generated Sigma Rule:');
      console.log('    ────────────────────');
      for (const line of rule.yamlContent.split('\n')) {
        console.log(`    ${line}`);
      }
      console.log('');
    }
  }

  console.log(`=== Summary: ${reports.length} reports -> ${totalRules} Sigma rules generated ===`);
}

run().catch(console.error);
