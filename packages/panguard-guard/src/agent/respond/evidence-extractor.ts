/**
 * Pure functions to extract structured data from ThreatVerdict evidence.
 * @module @panguard-ai/panguard-guard/agent/respond/evidence-extractor
 */

import type { ThreatVerdict } from '../../types.js';

/** Extract IP address from verdict evidence */
export function extractIP(verdict: ThreatVerdict): string | undefined {
  for (const e of verdict.evidence) {
    const data = e.data as Record<string, unknown> | undefined;
    if (data?.['ip']) return data['ip'] as string;
    if (data?.['sourceIP']) return data['sourceIP'] as string;
  }
  return undefined;
}

/** Extract PID from verdict evidence */
export function extractPID(verdict: ThreatVerdict): number | undefined {
  for (const e of verdict.evidence) {
    const data = e.data as Record<string, unknown> | undefined;
    if (data?.['pid']) return Number(data['pid']);
  }
  return undefined;
}

/** Extract username from verdict evidence */
export function extractUsername(verdict: ThreatVerdict): string | undefined {
  for (const e of verdict.evidence) {
    const data = e.data as Record<string, unknown> | undefined;
    if (data?.['username']) return data['username'] as string;
  }
  return undefined;
}

/** Extract file path from verdict evidence */
export function extractFilePath(verdict: ThreatVerdict): string | undefined {
  for (const e of verdict.evidence) {
    const data = e.data as Record<string, unknown> | undefined;
    if (data?.['filePath']) return data['filePath'] as string;
  }
  return undefined;
}

/** Extract process name from verdict evidence */
export function extractProcessName(verdict: ThreatVerdict): string | undefined {
  for (const e of verdict.evidence) {
    const data = e.data as Record<string, unknown> | undefined;
    if (data?.['processName']) return data['processName'] as string;
  }
  return undefined;
}

/** Extract the most relevant target identifier from verdict */
export function extractTarget(verdict: ThreatVerdict): string | undefined {
  return (
    extractIP(verdict) ??
    extractProcessName(verdict) ??
    extractUsername(verdict) ??
    extractFilePath(verdict)
  );
}
