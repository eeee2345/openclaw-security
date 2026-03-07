/**
 * MITRE ATT&CK Adapter
 * MITRE ATT&CK 攻擊技術資料庫適配器
 *
 * Fetches enterprise ATT&CK techniques from the official STIX 2.1 JSON bundle
 * hosted on GitHub. Each attack-pattern object is converted to a ThreatIntelRecord.
 *
 * Data source: https://github.com/mitre-attack/attack-stix-data
 * License: Public domain (CC0)
 *
 * @module @panguard-ai/threat-cloud/threat-intel/adapters/mitre-attack-adapter
 */

import type {
  ThreatIntelAdapter,
  ThreatIntelRecord,
  ThreatSource,
  AdapterConfig,
  ValidationStatus,
} from '../types.js';

// ---------------------------------------------------------------------------
// Internal STIX types (only the fields we need)
// ---------------------------------------------------------------------------

interface StixExternalReference {
  readonly source_name?: string;
  readonly external_id?: string;
  readonly url?: string;
}

interface StixKillChainPhase {
  readonly kill_chain_name?: string;
  readonly phase_name?: string;
}

interface StixAttackPattern {
  readonly type?: string;
  readonly id?: string;
  readonly name?: string;
  readonly description?: string;
  readonly external_references?: readonly StixExternalReference[];
  readonly kill_chain_phases?: readonly StixKillChainPhase[];
  readonly created?: string;
  readonly modified?: string;
  readonly x_mitre_deprecated?: boolean;
  readonly revoked?: boolean;
}

interface StixBundle {
  readonly type?: string;
  readonly objects?: readonly StixAttackPattern[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STIX_BUNDLE_URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';

const HIGH_SEVERITY_TACTICS = new Set([
  'initial-access',
  'execution',
  'privilege-escalation',
]);

const DEFAULT_CONFIG: AdapterConfig = {
  requestTimeoutMs: 120_000, // large file, generous timeout
  rateLimitPerMinute: 6,
  maxRecords: 10_000,
};

/** Strict pattern for MITRE technique IDs: T followed by digits, optional .digits */
const TECHNIQUE_ID_PATTERN = /^T\d{4}(?:\.\d{3})?$/;

/** Basic sanitisation: strip control chars, collapse whitespace, limit length */
function sanitizeString(raw: unknown, maxLength: number): string {
  if (typeof raw !== 'string') return '';
  return raw
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0;
}

function isValidIsoDate(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  const d = new Date(v);
  return !Number.isNaN(d.getTime());
}

function freshValidation(): ValidationStatus {
  return { valid: true, score: 100, checks: [], validatedAt: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class MitreAttackAdapter implements ThreatIntelAdapter {
  readonly source: ThreatSource = 'mitre-attack';
  private readonly config: AdapterConfig;
  private lastRequestAt = 0;

  constructor(config?: Partial<AdapterConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  async fetch(since?: string): Promise<ThreatIntelRecord[]> {
    await this.rateLimit();

    const bundle = await this.fetchBundle();
    const objects = bundle?.objects;
    if (!Array.isArray(objects)) return [];

    const sinceDate = since ? new Date(since) : null;
    const records: ThreatIntelRecord[] = [];

    for (const obj of objects) {
      if (records.length >= this.config.maxRecords) break;
      if (obj?.type !== 'attack-pattern') continue;
      if (obj.x_mitre_deprecated === true || obj.revoked === true) continue;

      // Incremental filtering
      if (sinceDate && obj.modified) {
        const modDate = new Date(obj.modified);
        if (!Number.isNaN(modDate.getTime()) && modDate <= sinceDate) continue;
      }

      const record = this.toRecord(obj);
      if (record) records.push(record);
    }

    return records;
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private async fetchBundle(): Promise<StixBundle | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    try {
      const res = await fetch(STIX_BUNDLE_URL, {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'Panguard-ThreatIntel/1.0',
        },
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new Error(`MITRE ATT&CK fetch error: ${String(res.status)} ${String(res.statusText)}`);
      }

      const data: unknown = await res.json();
      if (typeof data !== 'object' || data === null) return null;
      return data as StixBundle;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error(
          `MITRE ATT&CK request timed out after ${String(this.config.requestTimeoutMs)}ms`,
        );
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  private toRecord(obj: StixAttackPattern): ThreatIntelRecord | null {
    // Extract technique ID from external_references
    const mitreRef = obj.external_references?.find(
      (r) => r?.source_name === 'mitre-attack',
    );
    const rawTechniqueId = sanitizeString(mitreRef?.external_id, 20);
    if (!TECHNIQUE_ID_PATTERN.test(rawTechniqueId)) return null;

    const name = sanitizeString(obj.name, 500);
    if (!name) return null;

    const description = sanitizeString(obj.description, 10_000) || null;

    // Collect tactic phase names
    const tactics: string[] = [];
    if (Array.isArray(obj.kill_chain_phases)) {
      for (const phase of obj.kill_chain_phases) {
        const phaseName = sanitizeString(phase?.phase_name, 100);
        if (phaseName && phase?.kill_chain_name === 'mitre-attack') {
          tactics.push(phaseName);
        }
      }
    }

    // Severity: high if any tactic is in HIGH_SEVERITY_TACTICS
    const severity = tactics.some((t) => HIGH_SEVERITY_TACTICS.has(t)) ? 'high' : 'medium';

    // Reference URLs from external_references
    const references: string[] = [];
    if (Array.isArray(obj.external_references)) {
      for (const ref of obj.external_references) {
        const url = sanitizeString(ref?.url, 2048);
        if (url && (url.startsWith('https://') || url.startsWith('http://'))) {
          references.push(url);
        }
      }
    }

    const publishedAt = isValidIsoDate(obj.created) ? String(obj.created) : new Date().toISOString();
    const modifiedAt = isValidIsoDate(obj.modified) ? String(obj.modified) : null;

    return {
      id: `mitre-attack:${rawTechniqueId}`,
      source: 'mitre-attack',
      type: 'technique',
      title: name,
      description,
      severity,
      cvssScore: null,
      cveIds: [],
      cweIds: [],
      mitreTechniques: [rawTechniqueId],
      indicators: [],
      affectedProducts: [],
      references,
      publishedAt,
      modifiedAt,
      fetchedAt: new Date().toISOString(),
      sourceReliability: 'authoritative',
      validation: freshValidation(),
    };
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
