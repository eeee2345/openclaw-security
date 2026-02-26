/**
 * /api/report/* - Compliance report endpoints
 * Uses REAL scan findings (not hardcoded samples).
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  getSupportedFrameworks,
  getFrameworkName,
  generateComplianceReport,
  reportToJSON,
  generateSummaryText,
} from '@openclaw/panguard-report';
import type { ComplianceFramework, ReportLanguage } from '@openclaw/panguard-report';
import { latestScanResult } from './scan.js';

/** Framework metadata for the API */
const FRAMEWORK_DESCRIPTIONS: Record<string, string> = {
  tw_cyber_security_act: 'Taiwan information security compliance standard',
  iso27001: 'International information security management standard',
  soc2: 'Service organization control trust criteria',
};

/**
 * GET /api/report/frameworks - List supported compliance frameworks
 */
export function handleReportFrameworks(_req: IncomingMessage, res: ServerResponse): void {
  const frameworks = getSupportedFrameworks();
  res.writeHead(200);
  res.end(JSON.stringify({
    ok: true,
    data: frameworks.map(f => ({
      id: f,
      name: getFrameworkName(f, 'en'),
      nameZh: getFrameworkName(f, 'zh-TW'),
      description: FRAMEWORK_DESCRIPTIONS[f] ?? f,
    })),
  }));
}

/**
 * POST /api/report/generate - Generate a compliance report using real scan findings
 *
 * Body: { framework: string, language: string }
 */
export async function handleReportGenerate(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);

  const framework = (body?.['framework'] as string) ?? 'iso27001';
  const language = (body?.['language'] as string) ?? 'en';

  // Use real scan findings if available
  if (!latestScanResult || latestScanResult.findings.length === 0) {
    res.writeHead(400);
    res.end(JSON.stringify({
      ok: false,
      error: 'No scan results available. Run a scan first (POST /api/scan/start).',
    }));
    return;
  }

  // Convert real scan findings to report finding format
  const findings = latestScanResult.findings.map((f, i) => ({
    findingId: f.id ?? `SCAN-${String(i + 1).padStart(3, '0')}`,
    severity: f.severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
    title: f.title,
    description: f.description,
    category: f.category ?? 'general',
    timestamp: new Date(),
    source: 'panguard-scan' as const,
  }));

  try {
    const report = generateComplianceReport(
      findings,
      framework as ComplianceFramework,
      language as ReportLanguage,
      { includeRecommendations: true },
    );

    const json = reportToJSON(report);
    const summary = generateSummaryText(report);

    res.writeHead(200);
    res.end(JSON.stringify({
      ok: true,
      data: {
        report: JSON.parse(json),
        summary,
        scanRiskScore: latestScanResult.riskScore,
        scanRiskLevel: latestScanResult.riskLevel,
        totalFindings: findings.length,
      },
    }));
  } catch (err) {
    res.writeHead(400);
    res.end(JSON.stringify({
      ok: false,
      error: err instanceof Error ? err.message : 'Failed to generate report',
    }));
  }
}

/** Read JSON body from request */
async function readBody(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf-8');
        resolve(JSON.parse(raw) as Record<string, unknown>);
      } catch {
        resolve(null);
      }
    });
    req.on('error', () => resolve(null));
  });
}
