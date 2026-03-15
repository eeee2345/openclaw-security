/**
 * Respond Agent shared types
 * @module @panguard-ai/panguard-guard/agent/respond/types
 */

import type { ResponseAction } from '../../types.js';

/** Action manifest record for persistence and rollback */
export interface ActionManifestEntry {
  readonly id: string;
  readonly action: ResponseAction;
  readonly target: string;
  readonly timestamp: string;
  readonly expiresAt?: string;
  rolledBack: boolean;
  readonly verdict: { readonly conclusion: string; readonly confidence: number };
}

/** Escalation tracker: IP/target violation count */
export interface EscalationRecord {
  readonly target: string;
  violationCount: number;
  readonly firstSeen: string;
  lastSeen: string;
}
