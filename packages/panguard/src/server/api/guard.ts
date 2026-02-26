/**
 * /api/guard/* - Guard engine endpoints
 * Returns REAL status by checking PID file and process state.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { PidFile } from '@openclaw/panguard-guard';

const DEFAULT_DATA_DIR = join(homedir(), '.panguard-guard');

/**
 * GET /api/guard/status - Get guard engine status (real check)
 */
export function handleGuardStatus(_req: IncomingMessage, res: ServerResponse): void {
  const dataDir = process.env['PANGUARD_GUARD_DATA_DIR'] ?? DEFAULT_DATA_DIR;
  const pidFile = new PidFile(dataDir);
  const pid = pidFile.read();
  const running = pidFile.isRunning();

  const status = {
    running,
    pid: running ? pid : null,
    mode: running ? 'protection' : 'stopped',
    agents: [
      { name: 'DetectAgent', status: running ? 'active' : 'stopped', description: 'Threat detection' },
      { name: 'AnalyzeAgent', status: running ? 'active' : 'stopped', description: 'Threat analysis' },
      { name: 'RespondAgent', status: running ? 'active' : 'stopped', description: 'Auto-response' },
      { name: 'ReportAgent', status: running ? 'active' : 'stopped', description: 'Report generation' },
    ],
    license: { tier: 'free', features: ['basic_detection', 'log_monitoring'] },
    dashboard: { enabled: false },
    message: running
      ? `Guard is running (PID: ${pid})`
      : 'Guard is not running. Start with: panguard guard start',
  };

  res.writeHead(200);
  res.end(JSON.stringify({ ok: true, data: status }));
}
