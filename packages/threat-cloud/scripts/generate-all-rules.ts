/**
 * Generate Sigma + YARA rules from all crawled threat intel records
 * Run: npx tsx packages/threat-cloud/scripts/generate-all-rules.ts
 */

import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { AttackExtractor } from '../src/threat-intel/attack-extractor.js';
import { SigmaRuleGenerator } from '../src/threat-intel/sigma-rule-generator.js';
import { YaraRuleGenerator } from '../src/threat-intel/yara-rule-generator.js';
import { RuleValidator } from '../src/threat-intel/rule-validator.js';
import type { StoredReport, GeneratedRule, GeneratedYaraRule } from '../src/threat-intel/types.js';

const DATA_FILE = './packages/threat-cloud/data/threat-intel/records.json';
const RULES_DIR = './config/sigma-rules/auto-generated';

/** Map ThreatIntelRecord (summary) to StoredReport for rule generation */
interface RecordSummary {
  id: string;
  source: string;
  type: string;
  title: string;
  severity: string;
  cvssScore: number | null;
  cveIds: string[];
  cweIds: string[];
  mitreTechniques: string[];
  indicatorCount: number;
  publishedAt: string;
  validationScore: number;
}

function toStoredReport(rec: RecordSummary): StoredReport | null {
  // Only vulnerability/exploit types are useful for Sigma/YARA
  if (rec.type !== 'vulnerability' && rec.type !== 'exploit') return null;
  if (!rec.title || rec.title.length < 5) return null;

  return {
    id: rec.id,
    title: rec.title,
    severity: (rec.severity || 'medium') as StoredReport['severity'],
    cweId: rec.cweIds[0] ?? null,
    cweName: null,
    cveIds: rec.cveIds,
    summary: null,
    disclosedAt: rec.publishedAt,
    programHandle: rec.source,
    programName: rec.source.toUpperCase(),
    reporterUsername: null,
    url: rec.cveIds[0]
      ? `https://nvd.nist.gov/vuln/detail/${rec.cveIds[0]}`
      : `https://panguard.ai/intel/${rec.id}`,
    fetchedAt: new Date().toISOString(),
  };
}

async function run() {
  console.log('=== Generate Sigma + YARA Rules from All Crawled Data ===\n');

  const raw = readFileSync(DATA_FILE, 'utf-8');
  const records: RecordSummary[] = JSON.parse(raw);
  console.log(`Loaded ${records.length} records from ${DATA_FILE}\n`);

  const extractor = new AttackExtractor({ minConfidence: 20 });
  const sigmaGen = new SigmaRuleGenerator();
  const yaraGen = new YaraRuleGenerator();
  const validator = new RuleValidator();
  const allSigma: GeneratedRule[] = [];
  const allYara: GeneratedYaraRule[] = [];

  mkdirSync(RULES_DIR, { recursive: true });

  let converted = 0;
  let skipped = 0;

  for (const rec of records) {
    const report = toStoredReport(rec);
    if (!report) { skipped++; continue; }
    converted++;

    const patterns = extractor.extractHeuristic(report);
    const extraction = {
      reportId: report.id,
      reportTitle: report.title,
      reportUrl: report.url,
      patterns,
      extractedAt: new Date().toISOString(),
      model: 'heuristic',
    };

    // Sigma
    const sigmaRules = sigmaGen.generate(extraction);
    for (const rule of sigmaRules) {
      const v = validator.validate(rule);
      if (!v.valid || v.isDuplicate) continue;

      const filename = `${rule.attackType.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${rule.id.slice(0, 8)}.yml`;
      writeFileSync(join(RULES_DIR, filename), rule.yamlContent);
      allSigma.push(rule);
    }

    // YARA
    const yaraRules = yaraGen.generate(extraction);
    for (const rule of yaraRules) {
      const filename = `${rule.attackType.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${rule.id}.yar`;
      writeFileSync(join(RULES_DIR, filename), rule.ruleContent);
      allYara.push(rule);
    }
  }

  // Save metadata
  const meta = {
    generatedAt: new Date().toISOString(),
    inputRecords: records.length,
    convertedToReports: converted,
    skipped,
    sigmaRules: allSigma.length,
    yaraRules: allYara.length,
    sigmaByAttackType: countBy(allSigma, r => r.attackType),
    yaraByAttackType: countBy(allYara, r => r.attackType),
    sigmaByStatus: countBy(allSigma, r => r.status),
    yaraByStatus: countBy(allYara, r => r.status),
  };
  writeFileSync(join(RULES_DIR, '.rules-meta.json'), JSON.stringify(meta, null, 2));

  // Print summary
  console.log(`Converted: ${converted} records → reports (${skipped} skipped: IOC/technique/malware)`);
  console.log('');
  console.log('--- Sigma Rules ---');
  for (const [type, count] of Object.entries(meta.sigmaByAttackType)) {
    console.log(`  ${type.padEnd(25)} ${count}`);
  }
  console.log(`  ${'TOTAL'.padEnd(25)} ${allSigma.length}`);
  console.log(`  Experimental: ${meta.sigmaByStatus['experimental'] ?? 0}  Draft: ${meta.sigmaByStatus['draft'] ?? 0}`);

  console.log('');
  console.log('--- YARA Rules ---');
  for (const [type, count] of Object.entries(meta.yaraByAttackType)) {
    console.log(`  ${type.padEnd(25)} ${count}`);
  }
  console.log(`  ${'TOTAL'.padEnd(25)} ${allYara.length}`);
  console.log(`  Experimental: ${meta.yaraByStatus['experimental'] ?? 0}  Draft: ${meta.yaraByStatus['draft'] ?? 0}`);

  console.log(`\nAll rules saved to: ${RULES_DIR}/`);
}

function countBy<T>(arr: T[], fn: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of arr) {
    const key = fn(item);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

run().catch(console.error);
