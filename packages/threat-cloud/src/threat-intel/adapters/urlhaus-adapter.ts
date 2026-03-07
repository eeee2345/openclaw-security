/**
 * URLhaus Adapter - Abuse.ch Malware URL Feed
 * URLhaus 適配器 - Abuse.ch 惡意軟體 URL 資料源
 *
 * Fetches recent malware distribution URLs from URLhaus.
 *
 * API: https://urlhaus-api.abuse.ch/v1/
 * License: CC0 public domain
 *
 * @module @panguard-ai/threat-cloud/threat-intel/adapters/urlhaus-adapter
 */

import type {
  ThreatIntelRecord,
  ThreatIntelAdapter,
  ThreatSource,
  AdapterConfig,
  UrlhausRecentResponse,
  UrlhausEntry,
  ThreatIndicator,
} from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const API_URL = 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/';
const USER_AGENT = 'Panguard-ThreatIntel/1.0';

const DEFAULT_CONFIG: AdapterConfig = {
  requestTimeoutMs: 30_000,
  rateLimitPerMinute: 10,
  maxRecords: 1000,
};

/** Strict URL validation — must be http(s) and parseable */
function isValidUrl(raw: unknown): raw is string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return false;
  try {
    const parsed = new URL(raw);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/** Strict domain validation */
const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function isValidDomain(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 253 && DOMAIN_RE.test(value);
}

/** Sanitize a string field — strip injection payloads, truncate */
function sanitize(value: unknown, maxLen = 1000): string {
  if (typeof value !== 'string') return '';
  return value
    .replace(/<script[^>]*>.*?<\/script>/gi, '[removed]')
    .replace(/javascript:/gi, '[removed]')
    .replace(/on\w+\s*=/gi, '[removed]')
    .slice(0, maxLen);
}

/** Validate ISO date string */
function isValidIsoDate(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const d = new Date(value);
  return !isNaN(d.getTime());
}

/** Extract hostname from a URL safely */
function extractHost(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class UrlhausAdapter implements ThreatIntelAdapter {
  readonly source: ThreatSource = 'urlhaus';

  private readonly config: AdapterConfig;
  private lastRequestAt = 0;

  constructor(config?: Partial<AdapterConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Fetch recent malware URLs from URLhaus and convert to ThreatIntelRecords.
   * @param since - Optional ISO date string; records before this date are skipped.
   */
  async fetch(since?: string): Promise<ThreatIntelRecord[]> {
    await this.rateLimit();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    let body: UrlhausRecentResponse;
    try {
      const res = await fetch(API_URL, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': USER_AGENT,
        },
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new Error(`URLhaus API error: ${res.status} ${res.statusText}`);
      }

      body = (await res.json()) as UrlhausRecentResponse;
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error(`URLhaus API request timed out after ${this.config.requestTimeoutMs}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }

    // Validate top-level response shape
    if (body?.query_status !== 'ok' || !Array.isArray(body?.urls)) {
      return [];
    }

    const sinceDate = since ? new Date(since) : null;
    const records: ThreatIntelRecord[] = [];

    for (const entry of body.urls) {
      if (records.length >= this.config.maxRecords) break;

      const record = this.convertEntry(entry, sinceDate);
      if (record) {
        records.push(record);
      }
    }

    return records;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private convertEntry(entry: UrlhausEntry, sinceDate: Date | null): ThreatIntelRecord | null {
    // Validate required fields with optional chaining / type guards
    const entryId = typeof entry?.id === 'string' ? entry.id : String(entry?.id ?? '');
    if (!entryId) return null;

    const rawUrl = entry?.url;
    if (!isValidUrl(rawUrl)) return null;

    const dateAdded = entry?.date_added;
    if (!isValidIsoDate(dateAdded)) return null;

    // Incremental sync: skip old records
    if (sinceDate && new Date(dateAdded) <= sinceDate) return null;

    // Build indicators
    const indicators: ThreatIndicator[] = [];

    // URL indicator
    indicators.push({
      type: 'url',
      value: rawUrl,
      context: 'malware_distribution',
      firstSeen: dateAdded,
      lastSeen: null,
    });

    // Domain indicator from host field or parsed from URL
    const host = typeof entry?.host === 'string' ? entry.host : extractHost(rawUrl);
    if (host && isValidDomain(host)) {
      indicators.push({
        type: 'domain',
        value: host,
        context: 'malware_host',
        firstSeen: dateAdded,
        lastSeen: null,
      });
    }

    const threat = sanitize(entry?.threat, 200) || 'unknown';
    const tags = Array.isArray(entry?.tags)
      ? entry.tags.filter((t): t is string => typeof t === 'string').map((t) => sanitize(t, 100))
      : [];
    const urlStatus = entry?.url_status === 'online' ? 'online' : 'offline';

    const title = `URLhaus: ${threat} - ${urlStatus} malware URL`;
    const description = [
      `Malware URL reported to URLhaus.`,
      `Threat: ${threat}`,
      `Status: ${urlStatus}`,
      tags.length > 0 ? `Tags: ${tags.join(', ')}` : null,
      typeof entry?.reporter === 'string' ? `Reporter: ${sanitize(entry.reporter, 100)}` : null,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      id: `urlhaus:${entryId}`,
      source: 'urlhaus',
      type: 'ioc',
      title,
      description,
      severity: 'high',
      cvssScore: null,
      cveIds: [],
      cweIds: [],
      mitreTechniques: [],
      indicators,
      affectedProducts: [],
      references: [rawUrl],
      publishedAt: dateAdded,
      modifiedAt: null,
      fetchedAt: new Date().toISOString(),
      sourceReliability: 'high',
      validation: {
        valid: true,
        score: 100,
        checks: [],
        validatedAt: new Date().toISOString(),
      },
    };
  }

  /** Enforce rate limiting between requests */
  private async rateLimit(): Promise<void> {
    const minInterval = 60_000 / this.config.rateLimitPerMinute;
    const elapsed = Date.now() - this.lastRequestAt;
    if (elapsed < minInterval) {
      await new Promise((resolve) => setTimeout(resolve, minInterval - elapsed));
    }
    this.lastRequestAt = Date.now();
  }
}
