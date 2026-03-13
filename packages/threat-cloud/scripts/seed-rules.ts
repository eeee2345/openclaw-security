#!/usr/bin/env npx tsx
/**
 * Seed rules into Threat Cloud database via HTTP API
 *
 * Reads Sigma, YARA, and ATR rule files from disk and uploads them
 * to a running Threat Cloud server via POST /api/rules (batch).
 *
 * Usage:
 *   npx tsx scripts/seed-rules.ts [--endpoint URL] [--batch-size N] [--dry-run]
 *
 * Defaults:
 *   --endpoint  https://tc.panguard.ai  (or TC_ENDPOINT env)
 *   --batch-size 200
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, basename, extname, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

interface SeedConfig {
  endpoint: string;
  batchSize: number;
  dryRun: boolean;
  sigmaDir: string;
  yaraDir: string;
  atrDir: string;
  adminApiKey?: string;
}

function parseArgs(): SeedConfig {
  const args = process.argv.slice(2);
  const config: SeedConfig = {
    endpoint: process.env['TC_ENDPOINT'] ?? 'https://tc.panguard.ai',
    batchSize: 200,
    dryRun: false,
    sigmaDir: resolve(__dirname, '../../../config/sigma-rules'),
    yaraDir: resolve(__dirname, '../../../config/yara-rules'),
    atrDir: resolve(process.env['ATR_DIR'] ?? '/Users/user/Downloads/agent-threat-rules/rules'),
    adminApiKey: process.env['TC_ADMIN_API_KEY'],
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--endpoint':
        config.endpoint = args[++i]!;
        break;
      case '--batch-size':
        config.batchSize = Number(args[++i]);
        break;
      case '--dry-run':
        config.dryRun = true;
        break;
      case '--sigma-dir':
        config.sigmaDir = resolve(args[++i]!);
        break;
      case '--yara-dir':
        config.yaraDir = resolve(args[++i]!);
        break;
      case '--atr-dir':
        config.atrDir = resolve(args[++i]!);
        break;
      case '--admin-api-key':
        config.adminApiKey = args[++i];
        break;
    }
  }

  return config;
}

// ---------------------------------------------------------------------------
// File scanning
// ---------------------------------------------------------------------------

function findFiles(dir: string, extensions: string[]): string[] {
  const results: string[] = [];

  function walk(d: string): void {
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(d, entry);
      try {
        const st = statSync(full);
        if (st.isDirectory()) {
          walk(full);
        } else if (extensions.some((ext) => entry.endsWith(ext))) {
          results.push(full);
        }
      } catch {
        // skip inaccessible files
      }
    }
  }

  walk(dir);
  return results;
}

// ---------------------------------------------------------------------------
// Rule preparation
// ---------------------------------------------------------------------------

interface RulePayload {
  ruleId: string;
  ruleContent: string;
  publishedAt: string;
  source: string;
}

function fileToRuleId(filePath: string, source: string): string {
  const name = basename(filePath, extname(filePath));
  return `${source}:${name}`;
}

function contentHash(content: string): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 12);
}

/**
 * Split a YARA file that may contain multiple rules into individual rules.
 * Each "rule <name>" block becomes a separate entry.
 */
function splitYaraRules(filePath: string, content: string): RulePayload[] {
  const rules: RulePayload[] = [];
  const rulePattern = /^(rule\s+\w[\w_]*\s*(?::\s*[^\n]*)?\{)/gm;
  const matches = [...content.matchAll(rulePattern)];

  if (matches.length <= 1) {
    // Single rule or unparseable — upload as-is
    return [{
      ruleId: `yara:${contentHash(content)}-${basename(filePath, extname(filePath))}`,
      ruleContent: content,
      publishedAt: new Date().toISOString(),
      source: 'yara',
    }];
  }

  // Multiple rules in one file
  for (let i = 0; i < matches.length; i++) {
    const start = matches[i]!.index!;
    const end = i + 1 < matches.length ? matches[i + 1]!.index! : content.length;
    const ruleText = content.slice(start, end).trim();
    const nameMatch = ruleText.match(/^rule\s+(\w[\w_]*)/);
    const name = nameMatch?.[1] ?? `rule${i}`;

    rules.push({
      ruleId: `yara:${contentHash(ruleText)}-${name}`,
      ruleContent: ruleText,
      publishedAt: new Date().toISOString(),
      source: 'yara',
    });
  }

  return rules;
}

function prepareSigmaRules(dir: string): RulePayload[] {
  const files = findFiles(dir, ['.yml', '.yaml']);
  const now = new Date().toISOString();
  return files.map((f) => ({
    ruleId: fileToRuleId(f, 'sigma'),
    ruleContent: readFileSync(f, 'utf-8'),
    publishedAt: now,
    source: 'sigma',
  }));
}

function prepareYaraRules(dir: string): RulePayload[] {
  const files = findFiles(dir, ['.yar', '.yara']);
  const rules: RulePayload[] = [];
  for (const f of files) {
    const content = readFileSync(f, 'utf-8');
    rules.push(...splitYaraRules(f, content));
  }
  return rules;
}

function prepareATRRules(dir: string): RulePayload[] {
  const files = findFiles(dir, ['.yml', '.yaml']);
  const now = new Date().toISOString();
  return files.map((f) => ({
    ruleId: fileToRuleId(f, 'atr'),
    ruleContent: readFileSync(f, 'utf-8'),
    publishedAt: now,
    source: 'atr',
  }));
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

async function uploadBatch(endpoint: string, rules: RulePayload[], adminApiKey?: string): Promise<number> {
  const url = `${endpoint}/api/rules`;
  const body = JSON.stringify({ rules });

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (adminApiKey) {
    headers['Authorization'] = `Bearer ${adminApiKey}`;
  }

  const res = await fetch(url, {
    method: 'POST',
    headers,
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }

  const data = (await res.json()) as { ok: boolean; data?: { count: number } };
  return data.data?.count ?? rules.length;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const config = parseArgs();

  console.log('=== Threat Cloud Rule Seeder ===');
  console.log(`Endpoint:    ${config.endpoint}`);
  console.log(`Batch size:  ${config.batchSize}`);
  console.log(`Dry run:     ${config.dryRun}`);
  console.log(`Sigma dir:   ${config.sigmaDir}`);
  console.log(`YARA dir:    ${config.yaraDir}`);
  console.log(`ATR dir:     ${config.atrDir}`);
  console.log('');

  // Prepare all rules
  console.log('Scanning rule files...');

  const sigmaRules = prepareSigmaRules(config.sigmaDir);
  console.log(`  Sigma: ${sigmaRules.length} rules`);

  const yaraRules = prepareYaraRules(config.yaraDir);
  console.log(`  YARA:  ${yaraRules.length} rules (from ${findFiles(config.yaraDir, ['.yar', '.yara']).length} files)`);

  const atrRules = prepareATRRules(config.atrDir);
  console.log(`  ATR:   ${atrRules.length} rules`);

  const allRules = [...sigmaRules, ...yaraRules, ...atrRules];
  console.log(`  Total: ${allRules.length} rules`);
  console.log('');

  if (config.dryRun) {
    console.log('[DRY RUN] Would upload these rules. Exiting.');
    return;
  }

  // Upload in batches
  let uploaded = 0;
  const total = allRules.length;
  const batches = Math.ceil(total / config.batchSize);

  console.log(`Uploading ${total} rules in ${batches} batches...`);

  for (let i = 0; i < total; i += config.batchSize) {
    const batch = allRules.slice(i, i + config.batchSize);
    const batchNum = Math.floor(i / config.batchSize) + 1;

    try {
      const count = await uploadBatch(config.endpoint, batch, config.adminApiKey);
      uploaded += count;
      const pct = ((uploaded / total) * 100).toFixed(1);
      process.stdout.write(`  Batch ${batchNum}/${batches}: ${count} rules uploaded (${pct}% total)\n`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  Batch ${batchNum}/${batches}: FAILED - ${msg}`);
      // Continue with next batch
    }
  }

  console.log('');
  console.log(`Done! ${uploaded}/${total} rules uploaded to ${config.endpoint}`);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
