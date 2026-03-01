#!/usr/bin/env npx tsx
/**
 * Threat Cloud Seed Script
 * 威脅雲種子資料匯入腳本
 *
 * Fetches public threat intelligence feeds and imports them into
 * the Threat Cloud database to provide baseline data.
 *
 * Usage:
 *   npx tsx scripts/seed.ts [--db ./threat-cloud.db] [--feeds all]
 *   npx tsx scripts/seed.ts --feeds ipsum,feodo,blocklist
 *
 * Available feeds (all free, no auth required):
 *   ipsum       - IPsum aggregated malicious IPs (score >= 3)
 *   feodo       - Feodo Tracker botnet C2 IPs
 *   blocklist   - Blocklist.de attack IPs (SSH/FTP/Web)
 *   spamhaus    - Spamhaus DROP + EDROP hijacked netblocks
 *   cins        - CINS Army bad actor IPs
 *   urlhaus     - URLhaus malicious URLs
 *   all         - All of the above (default)
 */

import { ThreatCloudDB } from '../src/database.js';
import { IoCStore } from '../src/ioc-store.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FeedConfig {
  name: string;
  url: string;
  type: 'ip' | 'domain' | 'url' | 'hash_sha256' | 'hash_md5';
  threatType: string;
  confidence: number;
  /** Admiralty Scale: A=completely reliable .. F=cannot be judged */
  sourceReliability: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
  /** License type for compliance tracking */
  license: 'public_domain' | 'cc0' | 'fair_use' | 'commercial_restricted' | 'unknown';
  /** Can be included in public/commercial feeds? */
  redistributable: boolean;
  parser: (
    text: string
  ) => Array<{ value: string; tags?: string[]; metadata?: Record<string, string> }>;
}

/** Plain text IP list parser (skip comments starting with # or ;) */
function plainIPParser(tagName: string, commentChar = '#'): FeedConfig['parser'] {
  return (text) => {
    const results: Array<{ value: string; tags: string[] }> = [];
    for (const line of text.split('\n')) {
      if (line.startsWith(commentChar) || !line.trim()) continue;
      const ip = line.trim().split(/\s+/)[0] ?? '';
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        results.push({ value: ip, tags: [tagName] });
      }
    }
    return results;
  };
}

// ---------------------------------------------------------------------------
// Feed definitions (all free, no auth)
// ---------------------------------------------------------------------------

const FEEDS: Record<string, FeedConfig> = {
  ipsum: {
    name: 'IPsum (Aggregated Malicious IPs)',
    url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
    type: 'ip',
    threatType: 'malicious',
    confidence: 70,
    sourceReliability: 'C',
    license: 'public_domain',
    redistributable: true,
    parser: (text) => {
      const results: Array<{ value: string; tags: string[] }> = [];
      for (const line of text.split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue;
        const parts = line.trim().split(/\s+/);
        const ip = parts[0] ?? '';
        const score = Number(parts[1] ?? '1');
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) && score >= 3) {
          results.push({ value: ip, tags: [`ipsum-score:${score}`] });
        }
      }
      return results;
    },
  },

  feodo: {
    name: 'Feodo Tracker (Botnet C2 IPs)',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    type: 'ip',
    threatType: 'c2',
    confidence: 95,
    sourceReliability: 'A',
    license: 'cc0',
    redistributable: true,
    parser: (text) => {
      // Feodo format: lines starting with # are comments, "DstIP" is header
      const results: Array<{ value: string; tags: string[] }> = [];
      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed === 'DstIP') continue;
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
          results.push({ value: trimmed, tags: ['feodo-tracker', 'botnet-c2'] });
        }
      }
      return results;
    },
  },

  blocklist: {
    name: 'Blocklist.de (Attack IPs)',
    url: 'https://lists.blocklist.de/lists/all.txt',
    type: 'ip',
    threatType: 'scanner',
    confidence: 60,
    sourceReliability: 'D',
    license: 'unknown',
    redistributable: false,
    parser: plainIPParser('blocklist-de'),
  },

  spamhaus: {
    name: 'Spamhaus DROP + EDROP',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    type: 'ip',
    threatType: 'malicious',
    confidence: 95,
    sourceReliability: 'A',
    license: 'commercial_restricted',
    redistributable: false,
    parser: (text) => {
      const results: Array<{ value: string; tags: string[]; metadata: Record<string, string> }> =
        [];
      for (const line of text.split('\n')) {
        if (line.startsWith(';') || !line.trim()) continue;
        const parts = line.split(';');
        const cidr = parts[0]?.trim() ?? '';
        const sbl = parts[1]?.trim() ?? '';
        const ip = cidr.split('/')[0] ?? '';
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
          results.push({
            value: ip,
            tags: ['spamhaus-drop', sbl].filter(Boolean),
            metadata: { cidr, sblRef: sbl },
          });
        }
      }
      return results;
    },
  },

  cins: {
    name: 'CINS Army (Bad Actor IPs)',
    url: 'https://cinsscore.com/list/ci-badguys.txt',
    type: 'ip',
    threatType: 'scanner',
    confidence: 65,
    sourceReliability: 'C',
    license: 'unknown',
    redistributable: false,
    parser: plainIPParser('cins-army'),
  },

  urlhaus: {
    name: 'URLhaus (Malicious URLs)',
    url: 'https://urlhaus.abuse.ch/downloads/text_recent/',
    type: 'url',
    threatType: 'malware_distribution',
    confidence: 80,
    sourceReliability: 'B',
    license: 'fair_use',
    redistributable: false,
    parser: (text) => {
      const results: Array<{ value: string; tags: string[] }> = [];
      for (const line of text.split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue;
        const url = line.trim();
        if (url.startsWith('http://') || url.startsWith('https://')) {
          results.push({ value: url, tags: ['urlhaus'] });
        }
      }
      return results;
    },
  },
};

// Also fetch Spamhaus EDROP as a second request under the 'spamhaus' umbrella
const SPAMHAUS_EDROP_URL = 'https://www.spamhaus.org/drop/edrop.txt';

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

async function fetchText(url: string, timeoutMs = 60_000): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Import logic
// ---------------------------------------------------------------------------

function importEntries(
  store: IoCStore,
  feed: FeedConfig,
  entries: Array<{ value: string; tags?: string[]; metadata?: Record<string, string> }>
): { imported: number; duplicates: number; errors: number } {
  let imported = 0;
  let duplicates = 0;
  let errors = 0;

  for (const entry of entries) {
    try {
      const result = store.upsertIoC({
        type: feed.type,
        value: entry.value,
        threatType: feed.threatType,
        source: `feed:${feed.name.split('(')[0]?.trim().toLowerCase().replace(/\s+/g, '-')}`,
        confidence: feed.confidence,
        tags: entry.tags,
        metadata: {
          ...entry.metadata,
          sourceReliability: feed.sourceReliability,
          license: feed.license,
          redistributable: String(feed.redistributable),
        },
      });

      if (result.sightings === 1) imported++;
      else duplicates++;
    } catch {
      errors++;
    }
  }

  return { imported, duplicates, errors };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(): { dbPath: string; feedNames: string[] } {
  const args = process.argv.slice(2);
  let dbPath = './threat-cloud.db';
  let feedNames = ['all'];

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--db':
        dbPath = args[++i] ?? dbPath;
        break;
      case '--feeds':
        feedNames = (args[++i] ?? 'all').split(',');
        break;
      case '--help':
        console.log(`
Threat Cloud Seed Script

Usage: npx tsx scripts/seed.ts [options]

Options:
  --db <path>        Database path (default: ./threat-cloud.db)
  --feeds <names>    Comma-separated feed names or "all" (default: all)
  --help             Show this help

Available feeds: ${Object.keys(FEEDS).join(', ')}
`);
        process.exit(0);
    }
  }

  return { dbPath, feedNames };
}

async function main(): Promise<void> {
  const { dbPath, feedNames } = parseArgs();

  console.log('=== Threat Cloud Seed Script ===\n');
  console.log(`Database: ${dbPath}`);

  const dbWrapper = new ThreatCloudDB(dbPath);
  const store = new IoCStore(dbWrapper.getDB());

  const selectedFeeds = feedNames.includes('all')
    ? Object.values(FEEDS)
    : feedNames.map((n) => FEEDS[n.trim()]).filter((f): f is FeedConfig => f !== undefined);

  if (selectedFeeds.length === 0) {
    console.error('No valid feeds selected. Available:', Object.keys(FEEDS).join(', '));
    process.exit(1);
  }

  console.log(`Feeds: ${selectedFeeds.map((f) => f.name).join(', ')}\n`);

  let totalImported = 0;
  let totalDuplicates = 0;
  let totalErrors = 0;

  for (const feed of selectedFeeds) {
    process.stdout.write(`[*] ${feed.name}... `);

    try {
      const text = await fetchText(feed.url);
      const entries = feed.parser(text);
      process.stdout.write(`${entries.length} entries, `);

      const result = importEntries(store, feed, entries);
      totalImported += result.imported;
      totalDuplicates += result.duplicates;
      totalErrors += result.errors;

      console.log(`${result.imported} new, ${result.duplicates} merged, ${result.errors} errors`);

      // Special: also fetch EDROP for spamhaus feed
      if (feed.name.includes('Spamhaus')) {
        process.stdout.write(`    + Spamhaus EDROP... `);
        try {
          const edropText = await fetchText(SPAMHAUS_EDROP_URL);
          const edropEntries = feed.parser(edropText);
          // Re-tag as edrop
          for (const e of edropEntries) {
            if (e.tags) e.tags = e.tags.map((t) => (t === 'spamhaus-drop' ? 'spamhaus-edrop' : t));
          }
          process.stdout.write(`${edropEntries.length} entries, `);
          const edropResult = importEntries(store, feed, edropEntries);
          totalImported += edropResult.imported;
          totalDuplicates += edropResult.duplicates;
          console.log(`${edropResult.imported} new, ${edropResult.duplicates} merged`);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.log(`FAILED: ${msg}`);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`FAILED: ${msg}`);
      totalErrors++;
    }
  }

  // -------------------------------------------------------------------------
  // Post-seed: run reputation + correlation
  // -------------------------------------------------------------------------
  console.log('\n[*] Running reputation scoring...');
  const { ReputationEngine } = await import('../src/reputation-engine.js');
  const rep = new ReputationEngine(dbWrapper.getDB());
  const repResult = rep.recalculateAll();
  console.log(`    ${repResult.updated} IoCs scored in ${repResult.duration}ms`);

  console.log('\n=== Summary ===');
  console.log(`Total imported:   ${totalImported}`);
  console.log(`Total merged:     ${totalDuplicates}`);
  console.log(`Total errors:     ${totalErrors}`);

  const counts = store.getIoCCountsByType();
  const totalActive = store.getTotalActiveCount();
  console.log(`\nDatabase: ${totalActive} active IoCs`);
  for (const [type, count] of Object.entries(counts)) {
    console.log(`  ${type}: ${count}`);
  }

  dbWrapper.close();
  console.log('\nDone.');
}

void main();
