/**
 * Skill Whitelist Manager
 * Skill 白名單管理器
 *
 * Manages a set of trusted skills that bypass heavy LLM analysis.
 * Skills can be whitelisted statically (config) or dynamically
 * (auto-promoted from SkillFingerprintStore after reaching stability).
 *
 * Whitelisted skills still run through ATR pattern rules — they only
 * skip the expensive LLM deep-analysis layer.
 *
 * @module @panguard-ai/panguard-guard/engines/skill-whitelist
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:skill-whitelist');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** How a skill was whitelisted */
export type WhitelistSource = 'static' | 'fingerprint' | 'community' | 'manual';

/** A whitelisted skill entry */
export interface WhitelistedSkill {
  /** Skill name (e.g., "read-file", "web-search") */
  name: string;
  /** Normalized name for matching (lowercase, trimmed) */
  normalizedName: string;
  /** How this skill was whitelisted */
  source: WhitelistSource;
  /** When this skill was added */
  addedAt: string;
  /** Optional: SHA-256 of the skill's stable fingerprint at whitelist time */
  fingerprintHash?: string;
  /** Optional: human reason for whitelisting */
  reason?: string;
}

/** Whitelist configuration */
export interface SkillWhitelistConfig {
  /** Path to persist whitelist on disk */
  persistPath?: string;
  /** Static skill names to always whitelist */
  staticSkills?: string[];
  /** Whether to auto-promote stable fingerprints (default: true) */
  autoPromoteStable?: boolean;
  /** Minimum stable streak before auto-promotion (default: 10) */
  minStableStreak?: number;
  /** Maximum whitelist size (default: 1000) */
  maxSize?: number;
}

const DEFAULT_CONFIG: Required<SkillWhitelistConfig> = {
  persistPath: '',
  staticSkills: [],
  autoPromoteStable: true,
  minStableStreak: 10,
  maxSize: 1000,
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

export class SkillWhitelistManager {
  private readonly config: Required<SkillWhitelistConfig>;
  private readonly whitelist = new Map<string, WhitelistedSkill>();
  private readonly revokedSkills = new Set<string>();

  constructor(config?: SkillWhitelistConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Load persisted whitelist
    if (this.config.persistPath) {
      this.loadFromDisk();
    }

    // Add static skills
    for (const name of this.config.staticSkills) {
      this.add(name, 'static', 'Pre-configured trusted skill');
    }
  }

  // -------------------------------------------------------------------------
  // Core API
  // -------------------------------------------------------------------------

  /**
   * Check if a skill is whitelisted.
   * 檢查 skill 是否在白名單中
   */
  isWhitelisted(skillName: string): boolean {
    const normalized = this.normalize(skillName);
    return this.whitelist.has(normalized) && !this.revokedSkills.has(normalized);
  }

  /**
   * Add a skill to the whitelist.
   * 將 skill 加入白名單
   */
  add(
    skillName: string,
    source: WhitelistSource,
    reason?: string,
    fingerprintHash?: string
  ): boolean {
    const normalized = this.normalize(skillName);

    // Don't exceed max size
    if (this.whitelist.size >= this.config.maxSize && !this.whitelist.has(normalized)) {
      logger.warn(`Whitelist full (${this.config.maxSize}), cannot add: ${skillName}`);
      return false;
    }

    // Remove from revoked if re-adding
    this.revokedSkills.delete(normalized);

    const entry: WhitelistedSkill = {
      name: skillName,
      normalizedName: normalized,
      source,
      addedAt: new Date().toISOString(),
      fingerprintHash,
      reason,
    };

    this.whitelist.set(normalized, entry);
    logger.info(`Skill whitelisted: ${skillName} (source: ${source})`);

    this.persistToDisk();
    return true;
  }

  /**
   * Remove a skill from the whitelist.
   * 將 skill 從白名單移除
   */
  revoke(skillName: string, reason?: string): boolean {
    const normalized = this.normalize(skillName);
    if (!this.whitelist.has(normalized)) return false;

    this.revokedSkills.add(normalized);
    logger.warn(`Skill revoked from whitelist: ${skillName} (reason: ${reason ?? 'manual'})`);

    this.persistToDisk();
    return true;
  }

  /**
   * Permanently remove a skill from the whitelist.
   * 永久移除 skill
   */
  remove(skillName: string): boolean {
    const normalized = this.normalize(skillName);
    const removed = this.whitelist.delete(normalized);
    this.revokedSkills.delete(normalized);
    if (removed) this.persistToDisk();
    return removed;
  }

  /**
   * Auto-promote a skill based on fingerprint stability.
   * Called by ATR engine when a skill's fingerprint reaches stable state.
   * 根據指紋穩定性自動升級 skill
   */
  autoPromote(skillName: string, fingerprintHash: string): boolean {
    if (!this.config.autoPromoteStable) return false;

    const normalized = this.normalize(skillName);

    // Don't auto-promote if manually revoked
    if (this.revokedSkills.has(normalized)) return false;

    // Don't auto-promote if already whitelisted from a stronger source
    const existing = this.whitelist.get(normalized);
    if (existing && (existing.source === 'static' || existing.source === 'manual')) {
      return false;
    }

    return this.add(
      skillName,
      'fingerprint',
      `Auto-promoted: stable fingerprint (hash: ${fingerprintHash.slice(0, 8)})`,
      fingerprintHash
    );
  }

  /**
   * Revoke whitelist if fingerprint drifts.
   * Called when SkillFingerprintStore detects anomalies.
   * 指紋偏移時撤銷白名單
   */
  onFingerprintDrift(skillName: string): void {
    const normalized = this.normalize(skillName);
    const entry = this.whitelist.get(normalized);

    // Only auto-revoke fingerprint-sourced entries
    if (entry?.source === 'fingerprint') {
      this.revoke(skillName, 'Fingerprint drift detected');
    }
  }

  // -------------------------------------------------------------------------
  // Bulk Operations
  // -------------------------------------------------------------------------

  /**
   * Import a whitelist from community consensus or Threat Cloud.
   * 從社群共識或 Threat Cloud 匯入白名單
   */
  importCommunityWhitelist(skills: Array<{ name: string; hash?: string }>): number {
    let imported = 0;
    for (const skill of skills) {
      if (this.add(skill.name, 'community', 'Community consensus', skill.hash)) {
        imported++;
      }
    }
    return imported;
  }

  /**
   * Get all whitelisted skills.
   * 取得所有白名單 skills
   */
  getAll(): WhitelistedSkill[] {
    return [...this.whitelist.values()].filter(
      (s) => !this.revokedSkills.has(s.normalizedName)
    );
  }

  /**
   * Get whitelist stats.
   * 取得白名單統計
   */
  getStats(): {
    total: number;
    active: number;
    revoked: number;
    bySource: Record<WhitelistSource, number>;
  } {
    const all = [...this.whitelist.values()];
    const active = all.filter((s) => !this.revokedSkills.has(s.normalizedName));
    const bySource: Record<WhitelistSource, number> = {
      static: 0,
      fingerprint: 0,
      community: 0,
      manual: 0,
    };
    for (const s of active) {
      bySource[s.source]++;
    }
    return {
      total: all.length,
      active: active.length,
      revoked: this.revokedSkills.size,
      bySource,
    };
  }

  // -------------------------------------------------------------------------
  // Export for MiroFish / Threat Cloud
  // -------------------------------------------------------------------------

  /**
   * Export whitelist as JSON for sharing with other nodes.
   * 匯出白名單 JSON（供其他節點分享）
   */
  exportJSON(): string {
    const active = this.getAll();
    return JSON.stringify(
      {
        version: '1.0',
        exportedAt: new Date().toISOString(),
        skills: active.map((s) => ({
          name: s.name,
          source: s.source,
          fingerprintHash: s.fingerprintHash,
          addedAt: s.addedAt,
        })),
      },
      null,
      2
    );
  }

  /**
   * Import whitelist from JSON.
   * 從 JSON 匯入白名單
   */
  importJSON(json: string): number {
    let data: {
      skills?: Array<{ name: string; source?: string; fingerprintHash?: string }>;
    };
    try {
      data = JSON.parse(json) as typeof data;
    } catch {
      logger.warn('importJSON: failed to parse JSON input');
      return 0;
    }
    if (!data.skills || !Array.isArray(data.skills)) return 0;

    let imported = 0;
    for (const s of data.skills) {
      if (s.name && typeof s.name === 'string') {
        const source = (s.source as WhitelistSource) || 'community';
        if (this.add(s.name, source, 'Imported', s.fingerprintHash)) {
          imported++;
        }
      }
    }
    return imported;
  }

  // -------------------------------------------------------------------------
  // Persistence
  // -------------------------------------------------------------------------

  private persistToDisk(): void {
    if (!this.config.persistPath) return;

    try {
      const dir = dirname(this.config.persistPath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }

      const data = {
        whitelist: [...this.whitelist.values()],
        revoked: [...this.revokedSkills],
      };
      writeFileSync(this.config.persistPath, JSON.stringify(data, null, 2), 'utf-8');
    } catch (err) {
      logger.warn(`Failed to persist whitelist: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private loadFromDisk(): void {
    if (!this.config.persistPath || !existsSync(this.config.persistPath)) return;

    try {
      const raw = readFileSync(this.config.persistPath, 'utf-8');
      const data = JSON.parse(raw) as {
        whitelist?: WhitelistedSkill[];
        revoked?: string[];
      };

      if (data.whitelist) {
        for (const entry of data.whitelist) {
          this.whitelist.set(entry.normalizedName, entry);
        }
      }

      if (data.revoked) {
        for (const name of data.revoked) {
          this.revokedSkills.add(name);
        }
      }

      logger.info(`Whitelist loaded: ${this.whitelist.size} skills (${this.revokedSkills.size} revoked)`);
    } catch (err) {
      logger.warn(`Failed to load whitelist: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private normalize(name: string): string {
    return name.toLowerCase().trim().replace(/\s+/g, '-');
  }

  /**
   * Compute a hash for a skill's capabilities (for fingerprint tracking).
   */
  static computeHash(capabilities: Record<string, string[]>): string {
    const sorted = Object.keys(capabilities)
      .sort()
      .map((k) => `${k}:${capabilities[k]!.sort().join(',')}`)
      .join('|');
    return createHash('sha256').update(sorted).digest('hex');
  }
}
