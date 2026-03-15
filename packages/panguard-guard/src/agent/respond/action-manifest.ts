/**
 * Action manifest for persistence and rollback tracking.
 * @module @panguard-ai/panguard-guard/agent/respond/action-manifest
 */

import { appendFileSync, readFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type { ResponseAction, ThreatVerdict } from '../../types.js';
import type { ActionManifestEntry } from './types.js';

const logger = createLogger('panguard-guard:action-manifest');

export class ActionManifest {
  private readonly entries: ActionManifestEntry[] = [];
  private readonly manifestPath: string;

  constructor(dataDir: string) {
    this.manifestPath = `${dataDir}/action-manifest.jsonl`;

    // Ensure manifest directory exists
    try {
      mkdirSync(dirname(this.manifestPath), { recursive: true });
    } catch {
      // Directory may already exist
    }

    this.load();
  }

  /** Record a new action and persist it */
  record(
    action: ResponseAction,
    target: string,
    verdict: ThreatVerdict,
    expiresAt?: string
  ): ActionManifestEntry {
    const entry: ActionManifestEntry = {
      id: `act-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      action,
      target,
      timestamp: new Date().toISOString(),
      expiresAt,
      rolledBack: false,
      verdict: { conclusion: verdict.conclusion, confidence: verdict.confidence },
    };

    this.entries.push(entry);
    this.persist(entry);
    return entry;
  }

  /** Find an entry by ID that has not been rolled back */
  findRollbackable(entryId: string): ActionManifestEntry | undefined {
    return this.entries.find((e) => e.id === entryId && !e.rolledBack);
  }

  /** Find an entry by ID */
  findById(entryId: string): ActionManifestEntry | undefined {
    return this.entries.find((e) => e.id === entryId);
  }

  /** Get all active (non-rolled-back) entries */
  getActive(): ActionManifestEntry[] {
    return this.entries.filter((e) => !e.rolledBack);
  }

  /** Mark an entry as rolled back and persist the change */
  markRolledBack(entryId: string): void {
    const entry = this.entries.find((e) => e.id === entryId);
    if (entry) {
      entry.rolledBack = true;
      this.persist(entry);
    }
  }

  /** Persist a single entry to the JSONL file */
  persist(entry: ActionManifestEntry): void {
    try {
      appendFileSync(this.manifestPath, JSON.stringify(entry) + '\n', 'utf-8');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to persist action manifest: ${msg}`);
    }
  }

  /** Load existing manifest entries from disk */
  private load(): void {
    try {
      const content = readFileSync(this.manifestPath, 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);
      for (const line of lines) {
        try {
          const entry = JSON.parse(line) as ActionManifestEntry;
          this.entries.push(entry);
        } catch {
          // Skip malformed lines
        }
      }
      logger.info(`Loaded ${this.entries.length} action manifest entries`);
    } catch {
      // Manifest file may not exist yet
    }
  }
}
