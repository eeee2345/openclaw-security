/**
 * Background Scheduler
 * 背景排程器
 *
 * Manages periodic tasks: reputation recalculation, correlation scanning,
 * rule generation, and data lifecycle cleanup.
 *
 * @module @panguard-ai/threat-cloud/scheduler
 */

import { existsSync, mkdirSync, readdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import type Database from 'better-sqlite3';
import { ReputationEngine } from './reputation-engine.js';
import { CorrelationEngine } from './correlation-engine.js';
import { RuleGenerator } from './rule-generator.js';
import { IoCStore } from './ioc-store.js';
import type { SchedulerConfig } from './types.js';

/** Default scheduler configuration */
const DEFAULT_CONFIG: SchedulerConfig = {
  reputationIntervalMs: 60 * 60 * 1000, // 1 hour
  correlationIntervalMs: 5 * 60 * 1000, // 5 minutes
  ruleGenerationIntervalMs: 6 * 60 * 60 * 1000, // 6 hours
  threatRetentionDays: 90,
  iocRetentionDays: 365,
  aggregationIntervalMs: 24 * 60 * 60 * 1000, // 24 hours
};

export class Scheduler {
  private readonly config: SchedulerConfig;
  private readonly reputation: ReputationEngine;
  private readonly correlation: CorrelationEngine;
  private readonly ruleGen: RuleGenerator;
  private readonly iocStore: IoCStore;
  private timers: Array<ReturnType<typeof setInterval>> = [];
  private running = false;

  constructor(
    private readonly db: Database.Database,
    config?: Partial<SchedulerConfig>
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.reputation = new ReputationEngine(db);
    this.correlation = new CorrelationEngine(db);
    this.ruleGen = new RuleGenerator(db);
    this.iocStore = new IoCStore(db);
  }

  /** Start all scheduled tasks / 啟動所有排程任務 */
  start(): void {
    if (this.running) return;
    this.running = true;

    // Run correlation immediately, then on interval
    this.runCorrelation();
    this.timers.push(setInterval(() => this.runCorrelation(), this.config.correlationIntervalMs));

    // Reputation recalculation
    this.timers.push(setInterval(() => this.runReputation(), this.config.reputationIntervalMs));

    // Rule generation
    this.timers.push(
      setInterval(() => this.runRuleGeneration(), this.config.ruleGenerationIntervalMs)
    );

    // Data lifecycle cleanup
    this.timers.push(setInterval(() => this.runLifecycle(), this.config.aggregationIntervalMs));
  }

  /** Stop all scheduled tasks / 停止所有排程任務 */
  stop(): void {
    this.running = false;
    for (const timer of this.timers) {
      clearInterval(timer);
    }
    this.timers = [];
  }

  /** Check if scheduler is running */
  isRunning(): boolean {
    return this.running;
  }

  /** Run correlation scan manually */
  runCorrelation(): { newCampaigns: number; eventsCorrelated: number } {
    const result = this.correlation.scanForCampaigns();
    return { newCampaigns: result.newCampaigns, eventsCorrelated: result.eventsCorrelated };
  }

  /** Run reputation recalculation manually */
  runReputation(): { updated: number } {
    const result = this.reputation.recalculateAll();
    return { updated: result.updated };
  }

  /** Run rule generation manually */
  runRuleGeneration(): { rulesGenerated: number; rulesUpdated: number } {
    const result = this.ruleGen.generateRules();
    return { rulesGenerated: result.rulesGenerated, rulesUpdated: result.rulesUpdated };
  }

  /** Run data lifecycle cleanup */
  runLifecycle(): { expired: number; purged: number; vacuumed: boolean; auditPurged: number } {
    const expireCutoff = new Date(
      Date.now() - this.config.iocRetentionDays * 24 * 60 * 60 * 1000
    ).toISOString();

    const purgeCutoff = new Date(
      Date.now() - (this.config.iocRetentionDays + 30) * 24 * 60 * 60 * 1000
    ).toISOString();

    const expired = this.iocStore.expireStaleIoCs(expireCutoff);
    const purged = this.iocStore.purgeExpiredIoCs(purgeCutoff);

    // Purge old enriched threats
    const threatCutoff = new Date(
      Date.now() - this.config.threatRetentionDays * 24 * 60 * 60 * 1000
    ).toISOString();

    this.db
      .prepare('DELETE FROM enriched_threats WHERE received_at < ? AND campaign_id IS NULL')
      .run(threatCutoff);

    // Purge old audit log entries (180 days retention)
    const auditCutoff = new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString();
    const auditResult = this.db
      .prepare('DELETE FROM audit_log WHERE created_at < ?')
      .run(auditCutoff);
    const auditPurged = auditResult.changes;

    // WAL checkpoint
    let vacuumed = false;
    try {
      this.db.pragma('wal_checkpoint(PASSIVE)');
      vacuumed = true;
    } catch {
      /* ignore checkpoint errors */
    }

    return { expired, purged, vacuumed, auditPurged };
  }

  /** Run database backup / 執行資料庫備份 */
  runBackup(backupDir: string, maxBackups = 30): string | null {
    try {
      if (!existsSync(backupDir)) {
        mkdirSync(backupDir, { recursive: true });
      }
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const dest = join(backupDir, `threat-cloud-${timestamp}.db`);
      this.db.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);

      // Rotate: remove oldest backups beyond maxBackups
      const backups = readdirSync(backupDir)
        .filter((f) => f.startsWith('threat-cloud-') && f.endsWith('.db'))
        .sort();
      while (backups.length > maxBackups) {
        const oldest = backups.shift();
        if (oldest) {
          try {
            unlinkSync(join(backupDir, oldest));
          } catch {
            /* best effort */
          }
        }
      }
      return dest;
    } catch {
      return null;
    }
  }
}
