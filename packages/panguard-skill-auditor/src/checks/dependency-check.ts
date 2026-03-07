/**
 * Dependency and external resource analysis
 * 依賴和外部資源分析
 *
 * Extracts URLs, API endpoints, and tool references from skill instructions.
 * 從技能指令中擷取 URL、API 端點和工具引用。
 */

import type { SkillManifest, AuditFinding, CheckResult } from '../types.js';

/** Well-known safe domains */
const SAFE_DOMAINS = new Set([
  'github.com', 'gitlab.com', 'bitbucket.org',
  'npmjs.com', 'pypi.org', 'crates.io',
  'google.com', 'googleapis.com', 'microsoft.com',
  'stackoverflow.com', 'developer.mozilla.org',
  'docs.python.org', 'nodejs.org',
]);

const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;
const NPM_INSTALL_RE = /npm\s+install\s+(?:-[gD]\s+)?([^\s;|&]+)/gi;
const PIP_INSTALL_RE = /pip\s+install\s+([^\s;|&]+)/gi;

export function checkDependencies(manifest: SkillManifest): CheckResult {
  const findings: AuditFinding[] = [];
  const instructions = manifest.instructions;

  // Extract URLs
  const urls = [...new Set(instructions.match(URL_RE) ?? [])];
  const externalDomainSet = new Set<string>();

  for (const url of urls) {
    try {
      const parsed = new URL(url);
      const domain = parsed.hostname;
      const baseDomain = domain.split('.').slice(-2).join('.');
      if (!SAFE_DOMAINS.has(baseDomain) && !SAFE_DOMAINS.has(domain)) {
        externalDomainSet.add(domain);
      }
    } catch {
      // Invalid URL, skip
    }
  }

  const externalDomains = [...externalDomainSet];

  if (externalDomains.length > 0) {
    findings.push({
      id: 'dep-external-urls',
      title: `References ${externalDomains.length} external domain(s)`,
      description: `Skill references non-standard domains: ${externalDomains.join(', ')}. Verify these are legitimate.`,
      severity: 'low',
      category: 'dependency',
    });
  }

  // Check for npm/pip installs
  const npmPackages: string[] = [];
  let npmMatch: RegExpExecArray | null;
  while ((npmMatch = NPM_INSTALL_RE.exec(instructions)) !== null) {
    if (npmMatch[1]) npmPackages.push(npmMatch[1]);
  }

  const pipPackages: string[] = [];
  let pipMatch: RegExpExecArray | null;
  while ((pipMatch = PIP_INSTALL_RE.exec(instructions)) !== null) {
    if (pipMatch[1]) pipPackages.push(pipMatch[1]);
  }

  if (npmPackages.length > 0 || pipPackages.length > 0) {
    const all = [...npmPackages.map((p) => `npm:${p}`), ...pipPackages.map((p) => `pip:${p}`)];
    findings.push({
      id: 'dep-package-installs',
      title: 'Skill installs external packages',
      description: `Packages: ${all.join(', ')}. Review these for supply chain risks.`,
      severity: 'medium',
      category: 'dependency',
    });
  }

  // Check metadata requires
  const requires = manifest.metadata?.openclaw?.requires;
  if (requires?.bins && requires.bins.length > 0) {
    findings.push({
      id: 'dep-required-bins',
      title: `Requires ${requires.bins.length} system binary(ies)`,
      description: `Required binaries: ${requires.bins.join(', ')}`,
      severity: 'low',
      category: 'dependency',
    });
  }

  if (requires?.env && requires.env.length > 0) {
    findings.push({
      id: 'dep-required-env',
      title: `Requires ${requires.env.length} environment variable(s)`,
      description: `Required env vars: ${requires.env.join(', ')}. Ensure these don't expose sensitive credentials.`,
      severity: 'low',
      category: 'dependency',
    });
  }

  const status = findings.some((f) => f.severity === 'high' || f.severity === 'critical')
    ? 'warn'
    : findings.length > 0
      ? 'warn'
      : 'pass';

  const urlCount = urls.length;
  const label = urlCount > 0
    ? `Dependencies: ${urlCount} URL(s), ${externalDomains.length} external domain(s)`
    : 'Dependencies: No external references found';

  return { status, label, findings };
}
