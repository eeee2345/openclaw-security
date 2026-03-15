/**
 * Escalation tracker: monitors repeat offenders for progressive response.
 * @module @panguard-ai/panguard-guard/agent/respond/escalation-tracker
 */

import type { EscalationRecord } from './types.js';

export class EscalationTracker {
  private readonly records = new Map<string, EscalationRecord>();

  /** Track a violation for the given target */
  track(target: string): void {
    const now = new Date().toISOString();
    const existing = this.records.get(target);
    if (existing) {
      existing.violationCount += 1;
      existing.lastSeen = now;
    } else {
      this.records.set(target, {
        target,
        violationCount: 1,
        firstSeen: now,
        lastSeen: now,
      });
    }
  }

  /** Get the escalation record for a target (if any) */
  get(target: string): EscalationRecord | undefined {
    return this.records.get(target);
  }

  /** Check if target is a repeat offender (>= threshold violations) */
  isRepeatOffender(target: string, threshold: number): boolean {
    const record = this.records.get(target);
    return record !== undefined && record.violationCount >= threshold;
  }

  /** Get a snapshot of all records */
  getAll(): Map<string, EscalationRecord> {
    return new Map(this.records);
  }
}
