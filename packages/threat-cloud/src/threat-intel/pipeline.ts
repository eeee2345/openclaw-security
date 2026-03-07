/**
 * Unified Threat Intelligence Pipeline
 * 統一威脅情報管線
 *
 * Orchestrates all 11 data sources, validates ingested data,
 * and generates Sigma + YARA rules from the results.
 *
 * @module @panguard-ai/threat-cloud/threat-intel/pipeline
 */

import type { ThreatIntelAdapter, ThreatIntelRecord, ThreatSource } from './types.js';
import { DataValidator } from './data-validator.js';
import { NvdAdapter } from './adapters/nvd-adapter.js';
import { CisaKevAdapter } from './adapters/cisa-kev-adapter.js';
import { MitreAttackAdapter } from './adapters/mitre-attack-adapter.js';
import { UrlhausAdapter } from './adapters/urlhaus-adapter.js';
import { MalwareBazaarAdapter } from './adapters/malwarebazaar-adapter.js';
import { ThreatFoxAdapter } from './adapters/threatfox-adapter.js';
import { OsvAdapter } from './adapters/osv-adapter.js';
import { GitHubAdvisoryAdapter } from './adapters/github-advisory-adapter.js';
import { OtxAdapter } from './adapters/otx-adapter.js';
import { ExploitDbAdapter } from './adapters/exploitdb-adapter.js';

export interface PipelineConfig {
  /** Which sources to enable (default: all) */
  sources?: ThreatSource[];
  /** NVD API key (optional, increases rate limit) */
  nvdApiKey?: string;
  /** GitHub token (optional, increases rate limit) */
  githubToken?: string;
  /** Max records per source */
  maxRecordsPerSource?: number;
  /** Minimum validation score to accept (0-100) */
  minValidationScore?: number;
  /** Whether to run sources in parallel */
  parallel?: boolean;
}

export interface PipelineResult {
  /** All validated records */
  records: ThreatIntelRecord[];
  /** Per-source statistics */
  stats: SourceStats[];
  /** Total time in ms */
  durationMs: number;
}

export interface SourceStats {
  source: ThreatSource;
  fetched: number;
  validated: number;
  rejected: number;
  errors: string[];
  durationMs: number;
}

const ALL_SOURCES: ThreatSource[] = [
  'nvd', 'cisa-kev', 'mitre-attack',
  'urlhaus', 'malwarebazaar', 'threatfox',
  'osv', 'github-advisory', 'alienvault-otx', 'exploitdb',
];

export class ThreatIntelPipeline {
  private readonly config: Required<PipelineConfig>;
  private readonly validator = new DataValidator();

  constructor(config: PipelineConfig = {}) {
    this.config = {
      sources: config.sources ?? ALL_SOURCES,
      nvdApiKey: config.nvdApiKey ?? '',
      githubToken: config.githubToken ?? '',
      maxRecordsPerSource: config.maxRecordsPerSource ?? 500,
      minValidationScore: config.minValidationScore ?? 70,
      parallel: config.parallel ?? false,
    };
  }

  /** Run the full pipeline across all configured sources */
  async run(since?: string): Promise<PipelineResult> {
    const startTime = Date.now();
    this.validator.resetDeduplication();

    const adapters = this.buildAdapters();
    const allStats: SourceStats[] = [];
    const allRecords: ThreatIntelRecord[] = [];

    if (this.config.parallel) {
      const results = await Promise.allSettled(
        adapters.map((adapter) => this.fetchSource(adapter, since))
      );

      for (const result of results) {
        if (result.status === 'fulfilled') {
          allStats.push(result.value.stats);
          allRecords.push(...result.value.records);
        }
      }
    } else {
      for (const adapter of adapters) {
        const result = await this.fetchSource(adapter, since);
        allStats.push(result.stats);
        allRecords.push(...result.records);
      }
    }

    return {
      records: allRecords,
      stats: allStats,
      durationMs: Date.now() - startTime,
    };
  }

  /** Fetch and validate records from a single source */
  private async fetchSource(
    adapter: ThreatIntelAdapter,
    since?: string
  ): Promise<{ records: ThreatIntelRecord[]; stats: SourceStats }> {
    const startTime = Date.now();
    const stats: SourceStats = {
      source: adapter.source,
      fetched: 0,
      validated: 0,
      rejected: 0,
      errors: [],
      durationMs: 0,
    };

    const validRecords: ThreatIntelRecord[] = [];

    try {
      const raw = await adapter.fetch(since);
      stats.fetched = raw.length;

      for (const record of raw) {
        const validated = this.validator.validate(record);

        if (validated.validation.score >= this.config.minValidationScore) {
          validRecords.push(validated);
          stats.validated++;
        } else {
          stats.rejected++;
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      stats.errors.push(message);
    }

    stats.durationMs = Date.now() - startTime;
    return { records: validRecords, stats };
  }

  /** Build adapter instances for configured sources */
  private buildAdapters(): ThreatIntelAdapter[] {
    const max = this.config.maxRecordsPerSource;
    const adapterMap: Record<ThreatSource, () => ThreatIntelAdapter> = {
      'hackerone': () => { throw new Error('Use HackerOneAdapter directly'); },
      'nvd': () => new NvdAdapter({
        requestTimeoutMs: 30_000,
        rateLimitPerMinute: this.config.nvdApiKey ? 100 : 10,
        maxRecords: max,
        apiKey: this.config.nvdApiKey || undefined,
      }),
      'cisa-kev': () => new CisaKevAdapter({
        requestTimeoutMs: 60_000, rateLimitPerMinute: 10, maxRecords: max,
      }),
      'mitre-attack': () => new MitreAttackAdapter({
        requestTimeoutMs: 120_000, rateLimitPerMinute: 10, maxRecords: max,
      }),
      'urlhaus': () => new UrlhausAdapter({
        requestTimeoutMs: 30_000, rateLimitPerMinute: 10, maxRecords: max,
      }),
      'malwarebazaar': () => new MalwareBazaarAdapter({
        requestTimeoutMs: 30_000, rateLimitPerMinute: 10, maxRecords: max,
      }),
      'threatfox': () => new ThreatFoxAdapter({
        requestTimeoutMs: 30_000, rateLimitPerMinute: 10, maxRecords: max,
      }),
      'osv': () => new OsvAdapter({
        requestTimeoutMs: 30_000, rateLimitPerMinute: 60, maxRecords: max,
      }),
      'github-advisory': () => new GitHubAdvisoryAdapter({
        token: this.config.githubToken || undefined,
        config: {
          requestTimeoutMs: 30_000,
          rateLimitPerMinute: this.config.githubToken ? 60 : 10,
          maxRecords: max,
        },
      }),
      'alienvault-otx': () => new OtxAdapter({
        requestTimeoutMs: 30_000, rateLimitPerMinute: 60, maxRecords: max,
      }),
      'exploitdb': () => new ExploitDbAdapter({
        requestTimeoutMs: 60_000, rateLimitPerMinute: 10, maxRecords: max,
      }),
    };

    return this.config.sources
      .filter((s) => s !== 'hackerone')
      .map((source) => {
        const factory = adapterMap[source];
        return factory();
      });
  }
}
