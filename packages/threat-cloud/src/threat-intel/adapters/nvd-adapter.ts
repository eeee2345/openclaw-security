/**
 * NVD (National Vulnerability Database) Adapter
 * NIST NVD CVE API 2.0 adapter
 *
 * API: https://services.nvd.nist.gov/rest/json/cves/2.0
 * Rate limits: 50 req/30s with API key, 5 req/30s without
 *
 * @module @panguard-ai/threat-cloud/threat-intel/adapters/nvd-adapter
 */

import type {
  AdapterConfig,
  AffectedProduct,
  NvdCveResponse,
  NvdVulnerability,
  ThreatIntelAdapter,
  ThreatIntelRecord,
  ThreatSource,
  ValidationStatus,
} from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const MAX_RESULTS_PER_PAGE = 2000;
const USER_AGENT = 'Panguard-ThreatIntel/1.0';

/** Strict CVE format: CVE-YYYY-NNNNN+ */
const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/;

/** Strict CWE format: CWE-NNN+ */
const CWE_REGEX = /^CWE-\d+$/;

/** Maximum description length to prevent oversized records */
const MAX_DESCRIPTION_LENGTH = 4000;

/** Maximum number of references per record */
const MAX_REFERENCES = 50;

/** Maximum number of affected products per record */
const MAX_PRODUCTS = 100;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

interface NvdAdapterConfig extends AdapterConfig {
  /** NVD API key (optional, increases rate limit) */
  apiKey?: string;
}

const DEFAULT_CONFIG: NvdAdapterConfig = {
  requestTimeoutMs: 30_000,
  rateLimitPerMinute: 10, // ~5 req/30s without key = 10/min
  maxRecords: 5000,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Sanitize a string: trim, truncate, strip control characters */
function sanitizeString(value: unknown, maxLength: number): string | null {
  if (typeof value !== 'string') return null;
  const cleaned = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
  if (cleaned.length === 0) return null;
  return cleaned.length > maxLength ? cleaned.slice(0, maxLength) : cleaned;
}

/** Validate and sanitize a CVE ID */
function sanitizeCveId(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim().toUpperCase();
  return CVE_REGEX.test(trimmed) ? trimmed : null;
}

/** Validate and sanitize a CWE ID */
function sanitizeCweId(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim().toUpperCase();
  return CWE_REGEX.test(trimmed) ? trimmed : null;
}

/** Validate a URL string */
function sanitizeUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return trimmed;
    }
    return null;
  } catch {
    return null;
  }
}

/** Validate ISO date string */
function isValidIsoDate(raw: unknown): raw is string {
  if (typeof raw !== 'string') return false;
  const d = new Date(raw);
  return !isNaN(d.getTime());
}

/** Normalize CVSS severity string to our union type */
function normalizeSeverity(raw: string | undefined): ThreatIntelRecord['severity'] {
  if (!raw) return 'medium';
  const lower = raw.toLowerCase().trim();
  switch (lower) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'none':
      return 'none';
    default:
      return 'medium';
  }
}

/** Derive severity from CVSS score when no severity string is available */
function severityFromScore(score: number): ThreatIntelRecord['severity'] {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'none';
}

/** Create initial validation placeholder (DataValidator re-validates later) */
function initialValidation(): ValidationStatus {
  return {
    valid: true,
    score: 100,
    checks: [],
    validatedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class NvdAdapter implements ThreatIntelAdapter {
  readonly source: ThreatSource = 'nvd';

  private readonly config: NvdAdapterConfig;
  private lastRequestAt = 0;

  constructor(config?: Partial<NvdAdapterConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Adjust rate limit when API key is present (50 req/30s = 100/min)
    if (this.config.apiKey && this.config.rateLimitPerMinute <= 10) {
      this.config = { ...this.config, rateLimitPerMinute: 100 };
    }
  }

  /**
   * Fetch CVE records from NVD, optionally since a given ISO timestamp.
   * Paginates through results using startIndex.
   */
  async fetch(since?: string): Promise<ThreatIntelRecord[]> {
    const records: ThreatIntelRecord[] = [];
    let startIndex = 0;
    let totalResults = Infinity;

    while (startIndex < totalResults && records.length < this.config.maxRecords) {
      await this.rateLimit();

      const url = this.buildUrl(startIndex, since);
      const response = await this.fetchPage(url);

      if (!response) break;

      totalResults = typeof response.totalResults === 'number' ? response.totalResults : 0;

      if (!Array.isArray(response.vulnerabilities) || response.vulnerabilities.length === 0) {
        break;
      }

      for (const vuln of response.vulnerabilities) {
        if (records.length >= this.config.maxRecords) break;

        const record = this.convertVulnerability(vuln);
        if (record) {
          records.push(record);
        }
      }

      const pageSize =
        typeof response.resultsPerPage === 'number'
          ? response.resultsPerPage
          : response.vulnerabilities.length;

      startIndex += pageSize;

      // Safety: if page returned 0 items but totalResults says more, bail
      if (response.vulnerabilities.length === 0) break;
    }

    return records;
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  /** Build NVD API URL with pagination and optional date filtering */
  private buildUrl(startIndex: number, since?: string): string {
    const params = new URLSearchParams();
    params.set('startIndex', String(startIndex));
    params.set('resultsPerPage', String(MAX_RESULTS_PER_PAGE));

    if (since && isValidIsoDate(since)) {
      const sinceDate = new Date(since);
      params.set('lastModStartDate', sinceDate.toISOString());
      params.set('lastModEndDate', new Date().toISOString());
    }

    return `${NVD_API_BASE}?${params.toString()}`;
  }

  /** Fetch a single page from NVD API */
  private async fetchPage(url: string): Promise<NvdCveResponse | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    try {
      const headers: Record<string, string> = {
        Accept: 'application/json',
        'User-Agent': USER_AGENT,
      };

      if (this.config.apiKey) {
        headers['apiKey'] = this.config.apiKey;
      }

      const res = await fetch(url, {
        headers,
        signal: controller.signal,
      });

      if (!res.ok) {
        // Rate limited — stop pagination gracefully
        if (res.status === 403 || res.status === 429) {
          return null;
        }
        throw new Error(`NVD API error: ${res.status} ${res.statusText}`);
      }

      const data: unknown = await res.json();

      // Basic structural validation of response
      if (!data || typeof data !== 'object') return null;
      const response = data as Record<string, unknown>;
      if (!Array.isArray(response['vulnerabilities'])) return null;

      return data as NvdCveResponse;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error(`NVD API request timed out after ${this.config.requestTimeoutMs}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
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

  /** Convert a single NVD vulnerability to a ThreatIntelRecord */
  private convertVulnerability(vuln: NvdVulnerability): ThreatIntelRecord | null {
    const cve = vuln?.cve;
    if (!cve || typeof cve !== 'object') return null;

    // Validate CVE ID
    const cveId = sanitizeCveId(cve.id);
    if (!cveId) return null;

    // Extract English description
    const description = this.extractDescription(cve.descriptions);

    // Extract CVSS score and severity
    const { score, severity } = this.extractCvss(cve.metrics);

    // Extract CWE IDs
    const cweIds = this.extractCweIds(cve.weaknesses);

    // Extract references
    const references = this.extractReferences(cve.references);

    // Extract affected products from CPE
    const affectedProducts = this.extractProducts(cve.configurations);

    // Validate dates
    const publishedAt = isValidIsoDate(cve.published) ? cve.published : new Date().toISOString();
    const modifiedAt = isValidIsoDate(cve.lastModified) ? cve.lastModified : null;

    return {
      id: `nvd:${cveId}`,
      source: 'nvd',
      type: 'vulnerability',
      title: cveId,
      description,
      severity,
      cvssScore: score,
      cveIds: [cveId],
      cweIds,
      mitreTechniques: [],
      indicators: [],
      affectedProducts,
      references,
      publishedAt,
      modifiedAt,
      fetchedAt: new Date().toISOString(),
      sourceReliability: 'authoritative',
      validation: initialValidation(),
    };
  }

  /** Extract the English description from NVD descriptions array */
  private extractDescription(
    descriptions: NvdVulnerability['cve']['descriptions'] | undefined,
  ): string | null {
    if (!Array.isArray(descriptions)) return null;

    const english = descriptions.find((d) => d?.lang === 'en');
    const desc = english ?? descriptions[0];
    if (!desc) return null;

    return sanitizeString(desc.value, MAX_DESCRIPTION_LENGTH);
  }

  /** Extract CVSS v3.1 score (fallback to v2) and severity */
  private extractCvss(metrics: NvdVulnerability['cve']['metrics']): {
    score: number | null;
    severity: ThreatIntelRecord['severity'];
  } {
    if (!metrics || typeof metrics !== 'object') {
      return { score: null, severity: 'medium' };
    }

    // Try CVSS v3.1 first
    const v31 = Array.isArray(metrics.cvssMetricV31) ? metrics.cvssMetricV31[0] : undefined;
    if (v31?.cvssData) {
      const baseScore =
        typeof v31.cvssData.baseScore === 'number' ? v31.cvssData.baseScore : null;
      const baseSeverity = normalizeSeverity(v31.cvssData.baseSeverity);
      return {
        score: baseScore,
        severity: baseScore !== null ? severityFromScore(baseScore) : baseSeverity,
      };
    }

    // Fallback to CVSS v2
    const v2 = Array.isArray(metrics.cvssMetricV2) ? metrics.cvssMetricV2[0] : undefined;
    if (v2?.cvssData) {
      const baseScore =
        typeof v2.cvssData.baseScore === 'number' ? v2.cvssData.baseScore : null;
      return {
        score: baseScore,
        severity: baseScore !== null ? severityFromScore(baseScore) : 'medium',
      };
    }

    return { score: null, severity: 'medium' };
  }

  /** Extract validated CWE IDs from weaknesses array */
  private extractCweIds(
    weaknesses: NvdVulnerability['cve']['weaknesses'],
  ): string[] {
    if (!Array.isArray(weaknesses)) return [];

    const cweIds: string[] = [];

    for (const weakness of weaknesses) {
      if (!weakness || !Array.isArray(weakness.description)) continue;

      for (const desc of weakness.description) {
        if (!desc || typeof desc.value !== 'string') continue;

        const cweId = sanitizeCweId(desc.value);
        if (cweId && !cweIds.includes(cweId)) {
          cweIds.push(cweId);
        }
      }
    }

    return cweIds;
  }

  /** Extract validated reference URLs */
  private extractReferences(
    refs: NvdVulnerability['cve']['references'],
  ): string[] {
    if (!Array.isArray(refs)) return [];

    const urls: string[] = [];

    for (const ref of refs) {
      if (urls.length >= MAX_REFERENCES) break;
      if (!ref || typeof ref !== 'object') continue;

      const url = sanitizeUrl(ref.url);
      if (url && !urls.includes(url)) {
        urls.push(url);
      }
    }

    return urls;
  }

  /** Extract affected products from CPE configurations */
  private extractProducts(
    configurations: NvdVulnerability['cve']['configurations'],
  ): AffectedProduct[] {
    if (!Array.isArray(configurations)) return [];

    const products: AffectedProduct[] = [];

    for (const config of configurations) {
      if (!config || !Array.isArray(config.nodes)) continue;

      for (const node of config.nodes) {
        if (!node || !Array.isArray(node.cpeMatch)) continue;

        for (const match of node.cpeMatch) {
          if (products.length >= MAX_PRODUCTS) break;
          if (!match || !match.vulnerable) continue;

          const parsed = this.parseCpe(match.criteria);
          if (!parsed) continue;

          const versionEnd = sanitizeString(match.versionEndExcluding, 100);
          const versionStart = sanitizeString(match.versionStartIncluding, 100);
          const versionRange =
            versionStart && versionEnd
              ? `>=${versionStart}, <${versionEnd}`
              : versionEnd
                ? `<${versionEnd}`
                : versionStart
                  ? `>=${versionStart}`
                  : null;

          products.push({
            name: parsed.product,
            vendor: parsed.vendor,
            versionRange,
            fixedVersion: versionEnd ?? null,
          });
        }
      }
    }

    return products;
  }

  /** Parse CPE 2.3 URI into vendor/product */
  private parseCpe(
    criteria: unknown,
  ): { vendor: string; product: string } | null {
    if (typeof criteria !== 'string') return null;

    // CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
    const parts = criteria.split(':');
    const vendor = parts[3];
    const product = parts[4];

    if (!vendor || !product || vendor === '*' || product === '*') return null;

    const sanitizedVendor = sanitizeString(vendor, 200);
    const sanitizedProduct = sanitizeString(product, 200);

    if (!sanitizedVendor || !sanitizedProduct) return null;

    return { vendor: sanitizedVendor, product: sanitizedProduct };
  }
}
