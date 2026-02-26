/**
 * /api/scan/* - Security scan endpoints
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { runScan } from '@openclaw/panguard-scan';
import type { ScanResult } from '@openclaw/panguard-scan';

/** Cache latest scan result in memory (exported for report API) */
export let latestScanResult: ScanResult | null = null;
let scanInProgress = false;

/**
 * GET /api/scan/start - Trigger a quick scan via SSE
 * Returns Server-Sent Events with progress and final result.
 */
export async function handleScanStart(_req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (scanInProgress) {
    res.writeHead(409);
    res.end(JSON.stringify({ ok: false, error: 'Scan already in progress' }));
    return;
  }

  // SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });

  const sendEvent = (data: unknown) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  scanInProgress = true;
  sendEvent({ phase: 'starting', progress: 0 });

  try {
    sendEvent({ phase: 'scanning', progress: 20 });

    const result = await runScan({ depth: 'quick', lang: 'en', verbose: false });
    latestScanResult = result;

    const safetyScore = Math.max(0, 100 - result.riskScore);
    const grade = safetyScore >= 90 ? 'A' : safetyScore >= 75 ? 'B' : safetyScore >= 60 ? 'C' : safetyScore >= 40 ? 'D' : 'F';

    sendEvent({
      phase: 'complete',
      progress: 100,
      result: {
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        safetyScore,
        grade,
        findingsCount: result.findings.length,
        findings: result.findings.map(f => ({
          title: f.title,
          severity: f.severity,
          description: f.description,
        })),
        scanDuration: result.scanDuration,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (err) {
    sendEvent({
      phase: 'error',
      error: err instanceof Error ? err.message : 'Scan failed',
    });
  } finally {
    scanInProgress = false;
    res.end();
  }
}

/**
 * GET /api/scan/latest - Get the most recent scan result
 */
export function handleScanLatest(_req: IncomingMessage, res: ServerResponse): void {
  if (!latestScanResult) {
    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, data: null }));
    return;
  }

  const result = latestScanResult;
  const safetyScore = Math.max(0, 100 - result.riskScore);
  const grade = safetyScore >= 90 ? 'A' : safetyScore >= 75 ? 'B' : safetyScore >= 60 ? 'C' : safetyScore >= 40 ? 'D' : 'F';

  res.writeHead(200);
  res.end(JSON.stringify({
    ok: true,
    data: {
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      safetyScore,
      grade,
      findingsCount: result.findings.length,
      findings: result.findings.map(f => ({
        title: f.title,
        severity: f.severity,
        description: f.description,
      })),
      scanDuration: result.scanDuration,
      timestamp: new Date().toISOString(),
    },
  }));
}
