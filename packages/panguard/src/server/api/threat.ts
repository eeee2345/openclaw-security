/**
 * /api/threat/* - Threat intelligence endpoints
 * Queries real ThreatCloudDB for statistics.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { ThreatCloudDB } from '@openclaw/threat-cloud';

let db: ThreatCloudDB | null = null;

function getDB(): ThreatCloudDB {
  if (!db) {
    const dbPath = process.env['THREAT_CLOUD_DB'] ?? join(homedir(), '.panguard-guard', 'threat-cloud.db');
    db = new ThreatCloudDB(dbPath);
  }
  return db;
}

/**
 * GET /api/threat/stats - Get threat intelligence statistics (real data)
 */
export function handleThreatStats(_req: IncomingMessage, res: ServerResponse): void {
  try {
    const threatDB = getDB();
    const stats = threatDB.getStats();

    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, data: stats }));
  } catch (err) {
    // If DB can't be opened (first run, no data yet), return empty stats
    res.writeHead(200);
    res.end(JSON.stringify({
      ok: true,
      data: {
        totalThreats: 0,
        totalRules: 0,
        topAttackTypes: [],
        topMitreTechniques: [],
        last24hThreats: 0,
        message: 'No threat data yet. Start Guard or Trap to begin collecting intelligence.',
      },
    }));
  }
}
