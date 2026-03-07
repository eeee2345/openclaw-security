/**
 * Scheduled Threat Intel Sync
 * 定期威脅情報同步 + 自動規則生成
 *
 * Crawl all sources → validate → generate Sigma/YARA rules → save
 * Designed to run on cron (e.g. every 6 hours)
 *
 * Run: npx tsx packages/threat-cloud/scripts/scheduled-sync.ts
 * Cron: 0 0,6,12,18 * * * cd /path/to/panguard-ai && npx tsx packages/threat-cloud/scripts/scheduled-sync.ts
 */

import { existsSync, readFileSync, mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { ThreatIntelPipeline } from '../src/threat-intel/pipeline.js';
import { HackerOneAdapter } from '../src/threat-intel/hackerone-adapter.js';
import { AttackExtractor } from '../src/threat-intel/attack-extractor.js';
import { SigmaRuleGenerator } from '../src/threat-intel/sigma-rule-generator.js';
import { YaraRuleGenerator } from '../src/threat-intel/yara-rule-generator.js';
import { RuleValidator } from '../src/threat-intel/rule-validator.js';
import type {
  ThreatIntelRecord,
  StoredReport,
  GeneratedRule,
  GeneratedYaraRule,
} from '../src/threat-intel/types.js';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const DATA_DIR = './packages/threat-cloud/data/threat-intel';
const RULES_DIR = './config/sigma-rules/auto-generated';
const SYNC_STATE_FILE = join(DATA_DIR, 'sync-state.json');
const RECORDS_FILE = join(DATA_DIR, 'records.json');
const RULES_META_FILE = join(RULES_DIR, '.rules-meta.json');
const AUDIT_LOG_FILE = join(DATA_DIR, 'audit-log.jsonl');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SyncState {
  lastSyncAt: string;
  totalRecordsAllTime: number;
  totalSigmaRules: number;
  totalYaraRules: number;
  syncHistory: Array<{
    syncAt: string;
    newRecords: number;
    newSigma: number;
    newYara: number;
    durationMs: number;
    errors: string[];
  }>;
}

interface AuditEntry {
  timestamp: string;
  action: 'rule_created' | 'rule_promoted' | 'data_ingested' | 'sync_complete';
  ruleType?: 'sigma' | 'yara';
  ruleId?: string;
  attackType?: string;
  confidence?: number;
  status?: string;
  source?: string;
  details?: string;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function run() {
  const startTime = Date.now();
  log('=== Panguard Scheduled Threat Intel Sync ===');
  log(`Time: ${new Date().toISOString()}`);

  mkdirSync(DATA_DIR, { recursive: true });
  mkdirSync(RULES_DIR, { recursive: true });

  // Load previous sync state
  const state = loadSyncState();
  const since = state.lastSyncAt || undefined;
  log(`Last sync: ${since ?? 'never (full sync)'}`);

  // =========================================================================
  // Phase 1: Crawl all sources (incremental if possible)
  // =========================================================================

  log('\n--- Phase 1: Crawling 10 sources ---');

  const pipeline = new ThreatIntelPipeline({
    maxRecordsPerSource: 500,
    minValidationScore: 70,
    parallel: false,
  });

  const pipelineResult = await pipeline.run(since);

  for (const s of pipelineResult.stats) {
    const status = s.errors.length > 0 ? `ERR: ${s.errors[0]?.slice(0, 60)}` : 'OK';
    log(`  ${s.source.padEnd(18)} +${s.validated} records  ${status}`);
  }

  // Also crawl HackerOne
  log('  Crawling HackerOne...');
  let hackeroneRecords: StoredReport[] = [];
  try {
    const h1 = new HackerOneAdapter({ maxReports: 100, minSeverity: 'none', rateLimitPerMinute: 60 });
    hackeroneRecords = await h1.fetchReports(since);
    log(`  hackerone          +${hackeroneRecords.length} reports  OK`);
  } catch (err) {
    log(`  hackerone          ERR: ${err instanceof Error ? err.message : String(err)}`);
  }

  const totalNewRecords = pipelineResult.records.length + hackeroneRecords.length;
  log(`\nTotal new records: ${totalNewRecords}`);

  // Audit log
  auditLog({
    timestamp: new Date().toISOString(),
    action: 'data_ingested',
    details: `${totalNewRecords} records from ${pipelineResult.stats.filter(s => s.validated > 0).length + (hackeroneRecords.length > 0 ? 1 : 0)} sources`,
  });

  // =========================================================================
  // Phase 2: Convert to reports + generate rules
  // =========================================================================

  log('\n--- Phase 2: Generating Sigma + YARA rules ---');

  const extractor = new AttackExtractor({ minConfidence: 20 });
  const sigmaGen = new SigmaRuleGenerator();
  const yaraGen = new YaraRuleGenerator();
  const validator = new RuleValidator();
  const newSigma: GeneratedRule[] = [];
  const newYara: GeneratedYaraRule[] = [];

  // Process unified records (convert to StoredReport)
  for (const rec of pipelineResult.records) {
    const report = unifiedToStoredReport(rec);
    if (!report) continue;
    generateRules(report, extractor, sigmaGen, yaraGen, validator, newSigma, newYara);
  }

  // Process HackerOne reports directly
  for (const report of hackeroneRecords) {
    generateRules(report, extractor, sigmaGen, yaraGen, validator, newSigma, newYara);
  }

  log(`  New Sigma rules: ${newSigma.length}`);
  log(`  New YARA rules:  ${newYara.length}`);

  // =========================================================================
  // Phase 3: Auto-promote rules based on confidence
  // =========================================================================

  log('\n--- Phase 3: Rule Review & Promotion ---');

  let promoted = 0;
  for (const rule of newSigma) {
    // Auto-promote: experimental (>=70 confidence) from authoritative sources
    if (rule.confidence >= 70) {
      rule.status = 'experimental';
      rule.reviewed = true;
      rule.reviewDecision = 'approved';
      promoted++;
      auditLog({
        timestamp: new Date().toISOString(),
        action: 'rule_promoted',
        ruleType: 'sigma',
        ruleId: rule.id,
        attackType: rule.attackType,
        confidence: rule.confidence,
        status: 'experimental',
        details: `Auto-promoted: confidence ${rule.confidence}% >= 70%`,
      });
    }
    // Write rule file
    const filename = `${rule.attackType.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${rule.id.slice(0, 8)}.yml`;
    writeFileSync(join(RULES_DIR, filename), rule.yamlContent);
    auditLog({
      timestamp: new Date().toISOString(),
      action: 'rule_created',
      ruleType: 'sigma',
      ruleId: rule.id,
      attackType: rule.attackType,
      confidence: rule.confidence,
      status: rule.status,
    });
  }

  for (const rule of newYara) {
    if (rule.confidence >= 70) {
      rule.status = 'experimental';
      rule.reviewed = true;
      rule.reviewDecision = 'approved';
      promoted++;
      auditLog({
        timestamp: new Date().toISOString(),
        action: 'rule_promoted',
        ruleType: 'yara',
        ruleId: rule.id,
        attackType: rule.attackType,
        confidence: rule.confidence,
        status: 'experimental',
        details: `Auto-promoted: confidence ${rule.confidence}% >= 70%`,
      });
    }
    const filename = `${rule.attackType.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${rule.id}.yar`;
    writeFileSync(join(RULES_DIR, filename), rule.ruleContent);
    auditLog({
      timestamp: new Date().toISOString(),
      action: 'rule_created',
      ruleType: 'yara',
      ruleId: rule.id,
      attackType: rule.attackType,
      confidence: rule.confidence,
      status: rule.status,
    });
  }

  log(`  Auto-promoted: ${promoted} rules (confidence >= 70%)`);
  log(`  Pending review: ${newSigma.length + newYara.length - promoted} rules (draft, confidence < 70%)`);

  // =========================================================================
  // Phase 4: Save state
  // =========================================================================

  const durationMs = Date.now() - startTime;

  // Update sync state
  state.lastSyncAt = new Date().toISOString();
  state.totalRecordsAllTime += totalNewRecords;
  state.totalSigmaRules += newSigma.length;
  state.totalYaraRules += newYara.length;
  state.syncHistory.push({
    syncAt: state.lastSyncAt,
    newRecords: totalNewRecords,
    newSigma: newSigma.length,
    newYara: newYara.length,
    durationMs,
    errors: pipelineResult.stats.flatMap(s => s.errors),
  });
  // Keep only last 30 sync entries
  if (state.syncHistory.length > 30) {
    state.syncHistory = state.syncHistory.slice(-30);
  }
  writeFileSync(SYNC_STATE_FILE, JSON.stringify(state, null, 2));

  // Save records (append new)
  const existingRecords = loadExistingRecords();
  const allRecords = [...existingRecords, ...pipelineResult.records.map(r => ({
    id: r.id,
    source: r.source,
    type: r.type,
    title: r.title,
    severity: r.severity,
    cvssScore: r.cvssScore,
    cveIds: r.cveIds,
    cweIds: r.cweIds,
    publishedAt: r.publishedAt,
    validationScore: r.validation.score,
  }))];
  writeFileSync(RECORDS_FILE, JSON.stringify(allRecords, null, 2));

  auditLog({
    timestamp: new Date().toISOString(),
    action: 'sync_complete',
    details: `${totalNewRecords} records, ${newSigma.length} sigma, ${newYara.length} yara, ${promoted} promoted, ${durationMs}ms`,
  });

  // Summary
  log('\n=== Sync Complete ===');
  log(`New records:        ${totalNewRecords}`);
  log(`New Sigma rules:    ${newSigma.length}`);
  log(`New YARA rules:     ${newYara.length}`);
  log(`Auto-promoted:      ${promoted}`);
  log(`All-time records:   ${state.totalRecordsAllTime}`);
  log(`All-time Sigma:     ${state.totalSigmaRules}`);
  log(`All-time YARA:      ${state.totalYaraRules}`);
  log(`Duration:           ${Math.round(durationMs / 1000)}s`);
  log(`Next sync:          set up cron for every 6 hours`);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateRules(
  report: StoredReport,
  extractor: AttackExtractor,
  sigmaGen: SigmaRuleGenerator,
  yaraGen: YaraRuleGenerator,
  validator: RuleValidator,
  sigmaOut: GeneratedRule[],
  yaraOut: GeneratedYaraRule[],
) {
  const patterns = extractor.extractHeuristic(report);
  const extraction = {
    reportId: report.id,
    reportTitle: report.title,
    reportUrl: report.url,
    patterns,
    extractedAt: new Date().toISOString(),
    model: 'heuristic',
  };

  for (const rule of sigmaGen.generate(extraction)) {
    const v = validator.validate(rule);
    if (v.valid && !v.isDuplicate) sigmaOut.push(rule);
  }

  for (const rule of yaraGen.generate(extraction)) {
    yaraOut.push(rule);
  }
}

function unifiedToStoredReport(rec: ThreatIntelRecord): StoredReport | null {
  if (rec.type !== 'vulnerability' && rec.type !== 'exploit') return null;
  if (!rec.title || rec.title.length < 5) return null;

  return {
    id: rec.id,
    title: rec.title,
    severity: (rec.severity || 'medium') as StoredReport['severity'],
    cweId: rec.cweIds[0] ?? null,
    cweName: null,
    cveIds: rec.cveIds,
    summary: rec.description,
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

function loadSyncState(): SyncState {
  if (existsSync(SYNC_STATE_FILE)) {
    return JSON.parse(readFileSync(SYNC_STATE_FILE, 'utf-8'));
  }
  return {
    lastSyncAt: '',
    totalRecordsAllTime: 0,
    totalSigmaRules: 0,
    totalYaraRules: 0,
    syncHistory: [],
  };
}

function loadExistingRecords(): unknown[] {
  if (existsSync(RECORDS_FILE)) {
    try {
      return JSON.parse(readFileSync(RECORDS_FILE, 'utf-8'));
    } catch { return []; }
  }
  return [];
}

function auditLog(entry: AuditEntry) {
  appendFileSync(AUDIT_LOG_FILE, JSON.stringify(entry) + '\n');
}

function log(msg: string) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
}

run().catch((err) => {
  log(`FATAL: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
