/**
 * panguard hacktivity - HackerOne threat intel pipeline
 * panguard hacktivity - HackerOne 威脅情報管線
 *
 * Fetches publicly disclosed HackerOne reports, extracts attack patterns,
 * and auto-generates Sigma detection rules.
 */

import { Command } from 'commander';
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  HackerOneAdapter,
  AttackExtractor,
  SigmaRuleGenerator,
  RuleValidator,
} from '@panguard-ai/threat-cloud';
import type { StoredReport, GeneratedRule } from '@panguard-ai/threat-cloud';
import { c, spinner, statusPanel, divider, table, symbols } from '@panguard-ai/core';
import { withAuth } from '../auth-guard.js';

/** Default directory for auto-generated rules */
const RULES_DIR = './config/sigma-rules/auto-generated';
/** Metadata file tracking sync state */
const META_FILE = './config/sigma-rules/auto-generated/.meta.json';
/** Reports cache */
const REPORTS_DIR = './config/sigma-rules/auto-generated/.reports';

interface SyncMeta {
  lastSyncAt: string | null;
  reports: StoredReport[];
  rules: GeneratedRule[];
}

function loadMeta(): SyncMeta {
  if (existsSync(META_FILE)) {
    return JSON.parse(readFileSync(META_FILE, 'utf-8')) as SyncMeta;
  }
  return { lastSyncAt: null, reports: [], rules: [] };
}

function saveMeta(meta: SyncMeta): void {
  mkdirSync(RULES_DIR, { recursive: true });
  mkdirSync(REPORTS_DIR, { recursive: true });
  writeFileSync(META_FILE, JSON.stringify(meta, null, 2));
}

export function hacktivityCommand(): Command {
  const cmd = new Command('hacktivity').description(
    'HackerOne threat intel pipeline / HackerOne 威脅情報管線'
  );

  // ─── sync ───
  cmd
    .command('sync')
    .description('Fetch latest disclosed reports from HackerOne / 拉取最新公開報告')
    .option('--max <number>', 'Max reports to fetch / 最大拉取數量', '50')
    .option('--severity <level>', 'Min severity (low|medium|high|critical)', 'medium')
    .action(
      withAuth('solo', async (opts: { max: string; severity: string }) => {
        const meta = loadMeta();
        const adapter = new HackerOneAdapter({
          maxReports: parseInt(opts.max, 10),
          minSeverity: opts.severity as 'low' | 'medium' | 'high' | 'critical',
        });

        const sp = spinner('Fetching HackerOne Hacktivity reports...');

        try {
          const reports = await adapter.fetchReports(meta.lastSyncAt ?? undefined);
          sp.succeed(`Fetched ${reports.length} new reports`);

          if (reports.length === 0) {
            console.log(`  ${symbols.info} ${c.dim('No new reports since last sync.')}`);
            return;
          }

          // Merge with existing reports (dedup by id)
          const existingIds = new Set(meta.reports.map((r) => r.id));
          const newReports = reports.filter((r) => !existingIds.has(r.id));

          meta.reports = [...meta.reports, ...newReports];
          meta.lastSyncAt = new Date().toISOString();
          saveMeta(meta);

          // Summary table
          const columns = [
            { header: 'ID', key: 'id', width: 12 },
            { header: 'Severity', key: 'severity', width: 10 },
            { header: 'CWE', key: 'cwe', width: 12 },
            { header: 'Title', key: 'title', width: 50 },
          ];
          const rows = newReports.slice(0, 20).map((r) => ({
            id: r.id,
            severity: r.severity === 'critical'
              ? c.red(r.severity)
              : r.severity === 'high'
                ? c.yellow(r.severity)
                : r.severity,
            cwe: r.cweId ?? c.dim('N/A'),
            title: r.title.length > 48 ? r.title.slice(0, 48) + '...' : r.title,
          }));

          console.log('');
          console.log(divider(`New Reports (${newReports.length})`));
          console.log(table(columns, rows));
          if (newReports.length > 20) {
            console.log(`  ${c.dim(`... and ${newReports.length - 20} more`)}`);
          }
          console.log('');
          console.log(
            `  ${symbols.info} Run ${c.sage('panguard hacktivity generate-rules')} to create detection rules.`
          );
        } catch (err) {
          sp.fail(`Sync failed: ${err instanceof Error ? err.message : String(err)}`);
          process.exitCode = 1;
        }
      })
    );

  // ─── generate-rules ───
  cmd
    .command('generate-rules')
    .description('Generate Sigma rules from fetched reports / 從報告生成偵測規則')
    .option('--ollama-url <url>', 'Ollama API URL', 'http://localhost:11434')
    .option('--model <name>', 'Ollama model name', 'llama3.2')
    .option('--heuristic-only', 'Skip Ollama, use heuristic extraction only', false)
    .action(
      withAuth('solo', async (opts: { ollamaUrl: string; model: string; heuristicOnly: boolean }) => {
        const meta = loadMeta();

        if (meta.reports.length === 0) {
          console.log(
            `  ${symbols.warn} ${c.dim('No reports found. Run')} ${c.sage('panguard hacktivity sync')} ${c.dim('first.')}`
          );
          return;
        }

        const extractor = new AttackExtractor({
          ollamaBaseUrl: opts.ollamaUrl,
          model: opts.model,
        });
        const generator = new SigmaRuleGenerator();
        const validator = new RuleValidator();

        // Register existing rules for dedup
        validator.registerExistingRules(meta.rules);

        // Check Ollama availability
        let useOllama = !opts.heuristicOnly;
        if (useOllama) {
          const sp = spinner('Checking Ollama availability...');
          useOllama = await extractor.isOllamaAvailable();
          if (useOllama) {
            sp.succeed(`Ollama connected (model: ${opts.model})`);
          } else {
            sp.warn('Ollama unavailable, using heuristic extraction');
          }
        }

        // Find reports without rules
        const ruledReportIds = new Set(meta.rules.map((r) => r.sourceReportId));
        const pendingReports = meta.reports.filter((r) => !ruledReportIds.has(r.id));

        if (pendingReports.length === 0) {
          console.log(`  ${symbols.info} ${c.dim('All reports already have generated rules.')}`);
          return;
        }

        const sp2 = spinner(`Generating rules for ${pendingReports.length} reports...`);
        const newRules: GeneratedRule[] = [];
        let skippedDupes = 0;
        let skippedInvalid = 0;

        for (const report of pendingReports) {
          try {
            const extraction = useOllama
              ? await extractor.extract(report)
              : {
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

              if (validation.isDuplicate) {
                skippedDupes++;
                continue;
              }

              if (!validation.valid) {
                skippedInvalid++;
                continue;
              }

              // Write rule file
              mkdirSync(RULES_DIR, { recursive: true });
              const filename = `${rule.attackType.toLowerCase().replace(/\s+/g, '-')}-${rule.id.slice(0, 8)}.yml`;
              writeFileSync(join(RULES_DIR, filename), rule.yamlContent);
              newRules.push(rule);
            }
          } catch {
            // Skip failed extractions silently
          }
        }

        meta.rules = [...meta.rules, ...newRules];
        saveMeta(meta);

        sp2.succeed(`Generated ${newRules.length} new rules`);

        if (skippedDupes > 0) {
          console.log(`  ${symbols.info} ${c.dim(`Skipped ${skippedDupes} duplicates`)}`);
        }
        if (skippedInvalid > 0) {
          console.log(`  ${symbols.warn} ${c.dim(`Skipped ${skippedInvalid} invalid rules`)}`);
        }

        // Summary
        const draftCount = newRules.filter((r) => r.status === 'draft').length;
        const experimentalCount = newRules.filter((r) => r.status === 'experimental').length;

        console.log('');
        console.log(
          statusPanel('Rule Generation Summary', [
            { label: 'New Rules', value: String(newRules.length) },
            {
              label: 'Experimental (auto-enabled)',
              value: String(experimentalCount),
              status: 'safe',
            },
            {
              label: 'Draft (needs review)',
              value: String(draftCount),
              status: draftCount > 0 ? 'caution' : 'safe',
            },
            { label: 'Output', value: RULES_DIR },
          ])
        );

        if (draftCount > 0) {
          console.log('');
          console.log(
            `  ${symbols.info} Run ${c.sage('panguard hacktivity review')} to review draft rules.`
          );
        }
      })
    );

  // ─── review ───
  cmd
    .command('review')
    .description('Review auto-generated rules / 審核自動生成的規則')
    .option('--status <status>', 'Filter by status (draft|experimental|all)', 'draft')
    .action(
      withAuth('solo', async (opts: { status: string }) => {
        const meta = loadMeta();
        const pendingRules = meta.rules.filter((r) => {
          if (opts.status === 'all') return r.reviewDecision === 'pending';
          return r.status === opts.status && r.reviewDecision === 'pending';
        });

        if (pendingRules.length === 0) {
          console.log(`  ${symbols.info} ${c.dim('No rules pending review.')}`);
          return;
        }

        console.log(divider(`Pending Review (${pendingRules.length})`));
        console.log('');

        const columns = [
          { header: '#', key: 'idx', width: 4, align: 'right' as const },
          { header: 'ID', key: 'id', width: 10 },
          { header: 'Attack', key: 'attack', width: 20 },
          { header: 'Confidence', key: 'confidence', width: 12, align: 'right' as const },
          { header: 'Status', key: 'status', width: 14 },
          { header: 'Source', key: 'source', width: 30 },
        ];

        const rows = pendingRules.map((r, i) => ({
          idx: String(i + 1),
          id: r.id.slice(0, 8),
          attack: r.attackType,
          confidence: r.confidence >= 70
            ? c.sage(`${r.confidence}%`)
            : c.yellow(`${r.confidence}%`),
          status: r.status === 'draft' ? c.yellow(r.status) : c.sage(r.status),
          source: r.sourceReportUrl,
        }));

        console.log(table(columns, rows));
        console.log('');
        console.log(
          `  ${symbols.info} ${c.dim('To approve/reject, edit the .meta.json file or use the dashboard.')}`
        );
      })
    );

  // ─── stats ───
  cmd
    .command('stats')
    .description('Show pipeline statistics / 顯示管線統計')
    .action(async () => {
      const meta = loadMeta();

      const totalRules = meta.rules.length;
      const approved = meta.rules.filter((r) => r.reviewDecision === 'approved').length;
      const rejected = meta.rules.filter((r) => r.reviewDecision === 'rejected').length;
      const draft = meta.rules.filter((r) => r.status === 'draft').length;
      const experimental = meta.rules.filter((r) => r.status === 'experimental').length;

      // Count rule files on disk
      let filesOnDisk = 0;
      if (existsSync(RULES_DIR)) {
        filesOnDisk = readdirSync(RULES_DIR).filter((f) => f.endsWith('.yml')).length;
      }

      // Attack type breakdown
      const attackCounts = new Map<string, number>();
      for (const rule of meta.rules) {
        attackCounts.set(rule.attackType, (attackCounts.get(rule.attackType) ?? 0) + 1);
      }

      console.log(
        statusPanel('Hacktivity Pipeline Stats', [
          { label: 'Last Sync', value: meta.lastSyncAt ?? c.dim('Never') },
          { label: 'Reports Fetched', value: String(meta.reports.length) },
          { label: 'Total Rules', value: String(totalRules) },
          { label: 'Experimental', value: String(experimental), status: 'safe' },
          { label: 'Draft', value: String(draft), status: draft > 0 ? 'caution' : 'safe' },
          { label: 'Approved', value: String(approved), status: 'safe' },
          { label: 'Rejected', value: String(rejected) },
          { label: 'Files on Disk', value: String(filesOnDisk) },
        ])
      );

      if (attackCounts.size > 0) {
        console.log(divider('Rules by Attack Type'));
        console.log('');
        const columns = [
          { header: 'Attack Type', key: 'type', width: 25 },
          { header: 'Count', key: 'count', width: 10, align: 'right' as const },
        ];
        const rows = [...attackCounts.entries()]
          .sort((a, b) => b[1] - a[1])
          .map(([type, count]) => ({
            type,
            count: String(count),
          }));
        console.log(table(columns, rows));
        console.log('');
      }
    });

  return cmd;
}
