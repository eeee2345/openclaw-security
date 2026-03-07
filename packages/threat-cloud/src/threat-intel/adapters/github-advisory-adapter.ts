/**
 * GitHub Advisory Database Adapter
 * GitHub 安全通報資料庫適配器
 *
 * Fetches security advisories from the GitHub Advisory Database REST API.
 * Supports both unauthenticated (60 req/hr) and authenticated (5000 req/hr)
 * access. Pagination is handled via the Link header.
 *
 * API docs: https://docs.github.com/en/rest/security-advisories/global-advisories
 * License: CC-BY 4.0
 *
 * @module @panguard-ai/threat-cloud/threat-intel/adapters/github-advisory-adapter
 */

import type {
  ThreatIntelAdapter,
  ThreatIntelRecord,
  ThreatSource,
  AdapterConfig,
  GhsaAdvisory,
  AffectedProduct,
  ValidationStatus,
} from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GHSA_API_URL = 'https://api.github.com/advisories';

const DEFAULT_CONFIG: AdapterConfig = {
  requestTimeoutMs: 30_000,
  rateLimitPerMinute: 30,
  maxRecords: 500,
};

/** Strict GHSA ID pattern */
const GHSA_ID_PATTERN = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;

/** Strict CVE pattern */
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;

/** CWE pattern */
const CWE_PATTERN = /^CWE-\d+$/;

/** Basic sanitisation */
function sanitizeString(raw: unknown, maxLength: number): string {
  if (typeof raw !== 'string') return '';
  return raw
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

function isValidIsoDate(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  const d = new Date(v);
  return !Number.isNaN(d.getTime());
}

function freshValidation(): ValidationStatus {
  return { valid: true, score: 100, checks: [], validatedAt: new Date().toISOString() };
}

/**
 * Parse the Link header to extract the URL for rel="next".
 * Format: <https://api.github.com/advisories?...>; rel="next", <...>; rel="last"
 */
function parseLinkHeaderNext(header: string | null): string | null {
  if (!header) return null;
  const parts = header.split(',');
  for (const part of parts) {
    const match = part.match(/<([^>]+)>;\s*rel="next"/);
    if (match?.[1]) {
      const url = match[1].trim();
      // Validate it points to GitHub API
      if (url.startsWith('https://api.github.com/')) {
        return url;
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export interface GitHubAdvisoryAdapterOptions {
  /** GitHub personal access token for higher rate limits (optional) */
  token?: string;
  /** Adapter config overrides */
  config?: Partial<AdapterConfig>;
}

export class GitHubAdvisoryAdapter implements ThreatIntelAdapter {
  readonly source: ThreatSource = 'github-advisory';
  private readonly config: AdapterConfig;
  private readonly token: string | null;
  private lastRequestAt = 0;

  constructor(options?: GitHubAdvisoryAdapterOptions) {
    this.config = { ...DEFAULT_CONFIG, ...options?.config };
    this.token = options?.token ? String(options.token) : null;
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  async fetch(since?: string): Promise<ThreatIntelRecord[]> {
    const records: ThreatIntelRecord[] = [];
    const maxPages = 50; // safety cap
    let page = 0;

    // Build initial URL
    const params = new URLSearchParams({ per_page: '100' });
    if (since && isValidIsoDate(since)) {
      params.set('updated', since);
    }
    let nextUrl: string | null = `${GHSA_API_URL}?${params.toString()}`;

    while (nextUrl && records.length < this.config.maxRecords && page < maxPages) {
      await this.rateLimit();

      const result = await this.fetchPage(nextUrl);
      if (!result) break;

      const { advisories, linkNext } = result;
      if (!Array.isArray(advisories) || advisories.length === 0) break;

      for (const advisory of advisories) {
        if (records.length >= this.config.maxRecords) break;

        const record = this.toRecord(advisory);
        if (record) records.push(record);
      }

      nextUrl = linkNext;
      page++;
    }

    return records;
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private async fetchPage(
    url: string,
  ): Promise<{ advisories: unknown[]; linkNext: string | null } | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    try {
      const headers: Record<string, string> = {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Panguard-ThreatIntel/1.0',
        'X-GitHub-Api-Version': '2022-11-28',
      };
      if (this.token) {
        headers['Authorization'] = `Bearer ${this.token}`;
      }

      const res = await fetch(url, {
        headers,
        signal: controller.signal,
      });

      if (!res.ok) {
        if (res.status === 429 || res.status === 403) {
          // Rate limited — stop pagination gracefully
          return null;
        }
        throw new Error(`GitHub Advisory API error: ${String(res.status)} ${String(res.statusText)}`);
      }

      const data: unknown = await res.json();
      if (!Array.isArray(data)) return null;

      const linkHeader = res.headers.get('link');
      const linkNext = parseLinkHeaderNext(linkHeader);

      return { advisories: data, linkNext };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error(
          `GitHub Advisory API request timed out after ${String(this.config.requestTimeoutMs)}ms`,
        );
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  private toRecord(raw: unknown): ThreatIntelRecord | null {
    if (typeof raw !== 'object' || raw === null) return null;
    const advisory = raw as GhsaAdvisory;

    // Validate GHSA ID
    const ghsaId = sanitizeString(advisory?.ghsa_id, 30);
    if (!GHSA_ID_PATTERN.test(ghsaId)) return null;

    const title = sanitizeString(advisory?.summary, 500) || ghsaId;
    const description = sanitizeString(advisory?.description, 10_000) || null;

    // CVE ID
    const cveIds: string[] = [];
    const rawCveId = sanitizeString(advisory?.cve_id, 30);
    if (CVE_PATTERN.test(rawCveId)) {
      cveIds.push(rawCveId);
    }

    // CWE IDs
    const cweIds: string[] = [];
    if (Array.isArray(advisory?.cwes)) {
      for (const cwe of advisory.cwes) {
        const cweId = sanitizeString(cwe?.cwe_id, 20);
        if (CWE_PATTERN.test(cweId)) {
          cweIds.push(cweId);
        }
      }
    }

    // CVSS
    let cvssScore: number | null = null;
    if (advisory?.cvss && typeof advisory.cvss.score === 'number') {
      const score = advisory.cvss.score;
      if (score >= 0 && score <= 10) {
        cvssScore = Math.round(score * 10) / 10;
      }
    }

    // Severity from API field or derived from CVSS
    const severity = this.resolveSeverity(advisory?.severity, cvssScore);

    // Affected packages
    const affectedProducts: AffectedProduct[] = [];
    if (Array.isArray(advisory?.vulnerabilities)) {
      for (const vuln of advisory.vulnerabilities) {
        const pkgName = sanitizeString(vuln?.package?.name, 200);
        const ecosystem = sanitizeString(vuln?.package?.ecosystem, 50);
        if (!pkgName) continue;

        const versionRange = sanitizeString(vuln?.vulnerable_version_range, 200) || null;
        const fixedVersion = sanitizeString(vuln?.first_patched_version, 50) || null;

        affectedProducts.push({
          name: pkgName,
          vendor: ecosystem || null,
          versionRange,
          fixedVersion,
        });
      }
    }

    // References
    const references: string[] = [];
    if (Array.isArray(advisory?.references)) {
      for (const ref of advisory.references) {
        const url = sanitizeString(ref, 2048);
        if (url && (url.startsWith('https://') || url.startsWith('http://'))) {
          references.push(url);
        }
      }
    }

    const publishedAt = isValidIsoDate(advisory?.published_at)
      ? String(advisory.published_at)
      : new Date().toISOString();
    const modifiedAt = isValidIsoDate(advisory?.updated_at)
      ? String(advisory.updated_at)
      : null;

    return {
      id: `github-advisory:${ghsaId}`,
      source: 'github-advisory',
      type: 'vulnerability',
      title,
      description,
      severity,
      cvssScore,
      cveIds,
      cweIds,
      mitreTechniques: [],
      indicators: [],
      affectedProducts,
      references,
      publishedAt,
      modifiedAt,
      fetchedAt: new Date().toISOString(),
      sourceReliability: 'high',
      validation: freshValidation(),
    };
  }

  private resolveSeverity(
    rawSeverity: unknown,
    cvssScore: number | null,
  ): ThreatIntelRecord['severity'] {
    // Try API-provided severity first
    if (typeof rawSeverity === 'string') {
      const normalized = rawSeverity.toLowerCase().trim();
      const valid = ['none', 'low', 'medium', 'high', 'critical'] as const;
      const match = valid.find((v) => v === normalized);
      if (match) return match;
    }

    // Fall back to CVSS
    if (cvssScore !== null) {
      if (cvssScore >= 9.0) return 'critical';
      if (cvssScore >= 7.0) return 'high';
      if (cvssScore >= 4.0) return 'medium';
      if (cvssScore > 0) return 'low';
      return 'none';
    }

    return 'medium';
  }

  private async rateLimit(): Promise<void> {
    const minInterval = 60_000 / this.config.rateLimitPerMinute;
    const elapsed = Date.now() - this.lastRequestAt;
    if (elapsed < minInterval) {
      await new Promise((resolve) => setTimeout(resolve, minInterval - elapsed));
    }
    this.lastRequestAt = Date.now();
  }
}
