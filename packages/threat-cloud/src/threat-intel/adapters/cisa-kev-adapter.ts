/**
 * CISA Known Exploited Vulnerabilities (KEV) Adapter
 * CISA KEV catalog adapter
 *
 * API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 * Single JSON download — no pagination needed.
 * All entries are confirmed actively exploited vulnerabilities.
 *
 * @module @panguard-ai/threat-cloud/threat-intel/adapters/cisa-kev-adapter
 */

import type {
  AdapterConfig,
  CisaKevCatalog,
  CisaKevEntry,
  ThreatIntelAdapter,
  ThreatIntelRecord,
  ThreatSource,
  ValidationStatus,
} from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const USER_AGENT = 'Panguard-ThreatIntel/1.0';

/** Strict CVE format: CVE-YYYY-NNNNN+ */
const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/;

/** Maximum description length to prevent oversized records */
const MAX_DESCRIPTION_LENGTH = 4000;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const DEFAULT_CONFIG: AdapterConfig = {
  requestTimeoutMs: 60_000, // Larger timeout — single big JSON download
  rateLimitPerMinute: 6, // Conservative: ~1 req per 10s
  maxRecords: 10_000,
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

/** Validate ISO/date string (accepts YYYY-MM-DD or full ISO) */
function isValidDate(raw: unknown): raw is string {
  if (typeof raw !== 'string') return false;
  const d = new Date(raw);
  return !isNaN(d.getTime());
}

/** Convert a date-only string (YYYY-MM-DD) to ISO timestamp */
function toIsoTimestamp(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toISOString();
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

export class CisaKevAdapter implements ThreatIntelAdapter {
  readonly source: ThreatSource = 'cisa-kev';

  private readonly config: AdapterConfig;
  private lastRequestAt = 0;

  constructor(config?: Partial<AdapterConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Fetch the CISA KEV catalog.
   * Optionally filter entries added after `since` timestamp.
   */
  async fetch(since?: string): Promise<ThreatIntelRecord[]> {
    await this.rateLimit();

    const catalog = await this.fetchCatalog();
    if (!catalog) return [];

    if (!Array.isArray(catalog.vulnerabilities)) return [];

    const sinceDate = since && isValidDate(since) ? new Date(since) : null;
    const records: ThreatIntelRecord[] = [];

    for (const entry of catalog.vulnerabilities) {
      if (records.length >= this.config.maxRecords) break;

      // Skip entries before `since` date
      if (sinceDate && isValidDate(entry?.dateAdded)) {
        const addedDate = new Date(entry.dateAdded);
        if (addedDate <= sinceDate) continue;
      }

      const record = this.convertEntry(entry);
      if (record) {
        records.push(record);
      }
    }

    return records;
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  /** Fetch the full KEV catalog JSON */
  private async fetchCatalog(): Promise<CisaKevCatalog | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    try {
      const res = await fetch(CISA_KEV_URL, {
        headers: {
          Accept: 'application/json',
          'User-Agent': USER_AGENT,
        },
        signal: controller.signal,
      });

      if (!res.ok) {
        if (res.status === 429) return null;
        throw new Error(`CISA KEV API error: ${res.status} ${res.statusText}`);
      }

      const data: unknown = await res.json();

      // Basic structural validation
      if (!data || typeof data !== 'object') return null;
      const catalog = data as Record<string, unknown>;
      if (!Array.isArray(catalog['vulnerabilities'])) return null;

      return data as CisaKevCatalog;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error(`CISA KEV request timed out after ${this.config.requestTimeoutMs}ms`);
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

  /** Convert a CISA KEV entry to a ThreatIntelRecord */
  private convertEntry(entry: CisaKevEntry): ThreatIntelRecord | null {
    if (!entry || typeof entry !== 'object') return null;

    // Validate CVE ID — mandatory for KEV entries
    const cveId = sanitizeCveId(entry.cveID);
    if (!cveId) return null;

    // Sanitize text fields
    const vulnerabilityName = sanitizeString(entry.vulnerabilityName, 500);
    const shortDescription = sanitizeString(entry.shortDescription, MAX_DESCRIPTION_LENGTH);
    const requiredAction = sanitizeString(entry.requiredAction, MAX_DESCRIPTION_LENGTH);
    const vendorProject = sanitizeString(entry.vendorProject, 200);
    const product = sanitizeString(entry.product, 200);
    const notes = sanitizeString(entry.notes, MAX_DESCRIPTION_LENGTH);

    // Build description from available fields
    const descriptionParts: string[] = [];
    if (shortDescription) descriptionParts.push(shortDescription);
    if (requiredAction) descriptionParts.push(`Required Action: ${requiredAction}`);
    if (notes && notes !== 'n/a' && notes !== 'N/A') {
      descriptionParts.push(`Notes: ${notes}`);
    }
    const description = descriptionParts.length > 0 ? descriptionParts.join(' | ') : null;

    // Title: use vulnerability name or fall back to CVE ID
    const title = vulnerabilityName ?? cveId;

    // Determine severity: KEV entries are actively exploited, so critical or high
    const isRansomware = entry.knownRansomwareCampaignUse === 'Known';
    const severity: ThreatIntelRecord['severity'] = isRansomware ? 'critical' : 'high';

    // Date handling
    const publishedAt = isValidDate(entry.dateAdded)
      ? toIsoTimestamp(entry.dateAdded)
      : new Date().toISOString();

    // Build affected product
    const affectedProducts =
      vendorProject && product
        ? [
            {
              name: product,
              vendor: vendorProject,
              versionRange: null,
              fixedVersion: null,
            },
          ]
        : [];

    return {
      id: `cisa-kev:${cveId}`,
      source: 'cisa-kev',
      type: 'vulnerability',
      title,
      description,
      severity,
      cvssScore: null, // CISA KEV does not provide CVSS scores
      cveIds: [cveId],
      cweIds: [], // CISA KEV does not include CWE data
      mitreTechniques: [],
      indicators: [],
      affectedProducts,
      references: [],
      publishedAt,
      modifiedAt: null,
      fetchedAt: new Date().toISOString(),
      sourceReliability: 'authoritative',
      validation: initialValidation(),
    };
  }
}
