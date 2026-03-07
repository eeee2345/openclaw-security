'use client';

import { useState } from 'react';
import { Copy, Check, Shield, Globe, Terminal, FileCode, Server, Wifi, Lock, Search, Database, Clock } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';

function CodeBlock({ code, title }: { code: string; title?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="relative bg-[#111] border border-border rounded-xl overflow-hidden">
      {title && (
        <div className="px-4 py-2 border-b border-border text-xs text-text-muted font-mono">
          {title}
        </div>
      )}
      <pre className="p-4 font-mono text-sm text-gray-300 overflow-x-auto whitespace-pre">
        {code}
      </pre>
      <button
        onClick={handleCopy}
        className="absolute top-3 right-3 p-1.5 rounded-md bg-surface-2/50 hover:bg-surface-2 transition-colors"
        aria-label="Copy"
      >
        {copied ? (
          <Check className="w-3.5 h-3.5 text-panguard-green" />
        ) : (
          <Copy className="w-3.5 h-3.5 text-text-muted" />
        )}
      </button>
    </div>
  );
}

export default function ScanDocsContent() {
  return (
    <SectionWrapper className="py-16 sm:py-24">
      <div className="max-w-3xl mx-auto">
        {/* Header */}
        <FadeInUp>
          <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-panguard-green/70 font-semibold mb-4">
            <Link href="/docs" className="hover:text-panguard-green transition-colors">
              Docs
            </Link>
            <span>/</span>
            <span>Scan</span>
          </div>
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-text-primary">
            Panguard Scan
          </h1>
          <p className="text-lg text-text-secondary mt-4 max-w-2xl">
            Run comprehensive security audits with a single command. Scan your infrastructure,
            analyze code, check remote targets, and generate machine-readable reports for
            CI/CD pipelines.
          </p>
        </FadeInUp>

        {/* Quick Start */}
        <FadeInUp className="mt-12">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Quick Start</h2>
          <div className="space-y-4">
            <CodeBlock
              title="Run a default scan on the local machine"
              code="panguard scan"
            />
            <CodeBlock
              title="Deep scan — enables all scanner engines"
              code="panguard scan --deep"
            />
            <CodeBlock
              title="JSON output for scripting and CI/CD"
              code="panguard scan --json"
            />
          </div>
        </FadeInUp>

        {/* Scan Types */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Scan Types</h2>
          <div className="space-y-6">
            <div className="border border-border rounded-xl p-5 bg-surface-1/30">
              <div className="flex items-center gap-3 mb-3">
                <Clock className="w-5 h-5 text-panguard-green" />
                <h3 className="text-lg font-semibold text-text-primary">Quick Scan</h3>
                <span className="text-xs bg-panguard-green/10 text-panguard-green border border-panguard-green/30 rounded-full px-2.5 py-0.5 font-medium">
                  ~60s
                </span>
              </div>
              <p className="text-sm text-text-secondary mb-3">
                Default mode. Runs the fastest checks — open ports, password policies,
                environment discovery — and returns a risk score within a minute.
              </p>
              <CodeBlock code="panguard scan" />
            </div>

            <div className="border border-border rounded-xl p-5 bg-surface-1/30">
              <div className="flex items-center gap-3 mb-3">
                <Search className="w-5 h-5 text-panguard-green" />
                <h3 className="text-lg font-semibold text-text-primary">Deep Scan</h3>
              </div>
              <p className="text-sm text-text-secondary mb-3">
                Enables every scanner engine: CVE lookup, shared folder enumeration,
                scheduled task analysis, and full SSL certificate validation. Takes longer
                but leaves no stone unturned.
              </p>
              <CodeBlock code="panguard scan --deep" />
            </div>

            <div className="border border-border rounded-xl p-5 bg-surface-1/30">
              <div className="flex items-center gap-3 mb-3">
                <Globe className="w-5 h-5 text-panguard-green" />
                <h3 className="text-lg font-semibold text-text-primary">Remote Scan</h3>
              </div>
              <p className="text-sm text-text-secondary mb-3">
                Scan a remote host by domain name or IP address. Checks externally visible
                attack surface without requiring agent installation on the target.
              </p>
              <CodeBlock code="panguard scan --target example.com" />
            </div>

            <div className="border border-border rounded-xl p-5 bg-surface-1/30">
              <div className="flex items-center gap-3 mb-3">
                <FileCode className="w-5 h-5 text-panguard-green" />
                <h3 className="text-lg font-semibold text-text-primary">Code Scan (SAST)</h3>
                <span className="text-xs bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 rounded-full px-2.5 py-0.5 font-medium">
                  Beta
                </span>
              </div>
              <p className="text-sm text-text-secondary mb-3">
                Static application security testing for your source code. Detects
                vulnerabilities, hardcoded secrets, and insecure patterns.
              </p>
              <CodeBlock code="panguard scan code --dir ." />
            </div>
          </div>
        </FadeInUp>

        {/* Understanding Results */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Understanding Results</h2>

          <h3 className="text-lg font-semibold text-text-primary mb-3">Risk Score</h3>
          <p className="text-sm text-text-secondary mb-4">
            Every scan produces a risk score from 0 to 100. The score is calculated from the
            number and severity of findings, weighted by impact. Lower is better.
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
            {[
              { range: '0-20', grade: 'A', color: 'bg-green-500/10 border-green-500/30 text-green-400', label: 'Excellent' },
              { range: '21-40', grade: 'B', color: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400', label: 'Good' },
              { range: '41-60', grade: 'C', color: 'bg-orange-500/10 border-orange-500/30 text-orange-400', label: 'Fair' },
              { range: '61-80', grade: 'D', color: 'bg-orange-600/10 border-orange-600/30 text-orange-500', label: 'Poor' },
              { range: '81-90', grade: 'E', color: 'bg-red-500/10 border-red-500/30 text-red-400', label: 'Bad' },
              { range: '91-100', grade: 'F', color: 'bg-red-600/10 border-red-600/30 text-red-500', label: 'Critical' },
            ].map((item) => (
              <div key={item.grade} className={`border rounded-xl p-4 text-center ${item.color}`}>
                <div className="text-2xl font-bold">{item.grade}</div>
                <div className="text-xs font-semibold mt-1">{item.range}</div>
                <div className="text-xs mt-2 opacity-70">{item.label}</div>
              </div>
            ))}
          </div>

          <h3 className="text-lg font-semibold text-text-primary mb-3">Severity Levels</h3>
          <div className="overflow-x-auto mb-6">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Severity</th>
                  <th className="px-4 py-3 text-left font-medium">Meaning</th>
                  <th className="px-4 py-3 text-left font-medium">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                <tr>
                  <td className="px-4 py-3 text-red-400 font-medium">Critical</td>
                  <td className="px-4 py-3 text-text-secondary">Actively exploitable vulnerability</td>
                  <td className="px-4 py-3 text-text-primary">Fix immediately</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-orange-400 font-medium">High</td>
                  <td className="px-4 py-3 text-text-secondary">Significant security weakness</td>
                  <td className="px-4 py-3 text-text-primary">Fix within 24 hours</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-yellow-400 font-medium">Medium</td>
                  <td className="px-4 py-3 text-text-secondary">Potential risk under certain conditions</td>
                  <td className="px-4 py-3 text-text-primary">Schedule a fix</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-gray-400 font-medium">Low</td>
                  <td className="px-4 py-3 text-text-secondary">Minor hardening recommendation</td>
                  <td className="px-4 py-3 text-text-primary">Fix when convenient</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3 className="text-lg font-semibold text-text-primary mb-3">Sample Output</h3>
          <CodeBlock
            code={`$ panguard scan

PANGUARD SCAN REPORT
=====================
Host:       workstation-01
OS:         macOS 15.2 (Darwin)
Risk Score: 34/100
Grade:      B
Duration:   48s

FINDINGS:
  [HIGH]     Open port 3306 (MySQL) exposed to 0.0.0.0
             Bind MySQL to 127.0.0.1 or use firewall rules

  [MEDIUM]   SSL certificate expires in 12 days
             Renew certificate for *.example.com

  [MEDIUM]   Password policy: no complexity requirement
             Enable minimum 12-char passwords with mixed case

  [LOW]      SSH allows password authentication
             Switch to key-based authentication

SUMMARY: 1 high, 2 medium, 1 low — Grade B`}
          />
        </FadeInUp>

        {/* What Gets Scanned */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">What Gets Scanned</h2>
          <p className="text-sm text-text-secondary mb-6">
            Panguard Scan runs seven independent scanner modules. Each module focuses on a
            specific attack surface and contributes findings to the final risk score.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Module</th>
                  <th className="px-4 py-3 text-left font-medium">What It Checks</th>
                  <th className="px-4 py-3 text-left font-medium">Mode</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[
                  ['Password Policies', 'Complexity rules, expiration, lockout thresholds, reuse limits', 'Quick + Deep'],
                  ['Open Ports', 'TCP/UDP listeners, unexpected services, binding scope (0.0.0.0 vs 127.0.0.1)', 'Quick + Deep'],
                  ['SSL Certificates', 'Expiry dates, weak ciphers, chain validity, revocation status', 'Quick + Deep'],
                  ['Scheduled Tasks', 'Cron jobs, launchd plists, systemd timers running as root or with write-world paths', 'Deep only'],
                  ['Shared Folders', 'SMB/NFS shares, permission misconfiguration, guest access, world-readable exports', 'Deep only'],
                  ['Environment Discovery', 'OS version, installed software, missing patches, EOL detection', 'Quick + Deep'],
                  ['CVE Lookup', 'Matches installed packages against NVD/MITRE CVE databases for known vulnerabilities', 'Deep only'],
                ].map(([module, checks, mode]) => (
                  <tr key={module}>
                    <td className="px-4 py-3 text-text-primary font-medium whitespace-nowrap">{module}</td>
                    <td className="px-4 py-3 text-text-secondary">{checks}</td>
                    <td className="px-4 py-3 text-panguard-green whitespace-nowrap">{mode}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </FadeInUp>

        {/* JSON Output */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">JSON Output for Automation</h2>
          <p className="text-sm text-text-secondary mb-4">
            Add the <code className="text-panguard-green bg-panguard-green/10 px-1.5 py-0.5 rounded text-xs font-mono">--json</code> flag
            to any scan command to get structured output suitable for parsing, dashboards, and
            CI/CD pipeline gates.
          </p>
          <CodeBlock
            title="Generate JSON report"
            code="panguard scan --json > report.json"
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">Sample JSON Structure</h3>
          <CodeBlock
            title="report.json"
            code={`{
  "version": "1.0",
  "host": "workstation-01",
  "os": "macOS 15.2",
  "scanType": "quick",
  "riskScore": 34,
  "grade": "B",
  "duration": "48s",
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 1,
    "total": 4
  },
  "findings": [
    {
      "id": "PORT-001",
      "severity": "high",
      "title": "Open port 3306 (MySQL) exposed to 0.0.0.0",
      "module": "open-ports",
      "remediation": "Bind MySQL to 127.0.0.1 or use firewall rules",
      "references": ["CIS-benchmark-5.4"]
    }
  ],
  "modules": [
    { "name": "password-policies", "status": "pass", "findings": 1 },
    { "name": "open-ports", "status": "fail", "findings": 1 },
    { "name": "ssl-certificates", "status": "warn", "findings": 1 },
    { "name": "environment-discovery", "status": "pass", "findings": 1 }
  ]
}`}
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">CI/CD Integration</h3>
          <p className="text-sm text-text-secondary mb-4">
            Use the exit code and JSON output to gate deployments. Panguard exits with
            code 1 when critical or high findings are present.
          </p>
          <CodeBlock
            title="GitHub Actions example"
            code={`- name: Security Scan
  run: |
    panguard scan --json > scan-report.json
    SCORE=$(jq '.riskScore' scan-report.json)
    if [ "$SCORE" -gt 60 ]; then
      echo "Risk score $SCORE exceeds threshold (60). Blocking deploy."
      jq '.findings[] | "  [\\(.severity)] \\(.title)"' scan-report.json
      exit 1
    fi`}
          />
        </FadeInUp>

        {/* Remote Scanning */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Remote Scanning</h2>
          <p className="text-sm text-text-secondary mb-4">
            Use the <code className="text-panguard-green bg-panguard-green/10 px-1.5 py-0.5 rounded text-xs font-mono">--target</code> flag
            to scan a remote host by domain name or IP address. No agent installation is
            required on the target — Panguard probes the externally visible attack surface.
          </p>
          <CodeBlock
            title="Scan a domain"
            code="panguard scan --target example.com"
          />
          <CodeBlock
            title="Scan an IP address"
            code="panguard scan --target 192.168.1.100"
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">What Remote Scan Checks</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {[
              { icon: Wifi, title: 'Open Ports', description: 'TCP port scan of common service ports (22, 80, 443, 3306, 5432, 8080, etc.) with service fingerprinting.' },
              { icon: Lock, title: 'SSL / TLS', description: 'Certificate validity, expiration, cipher strength, protocol version, and chain-of-trust verification.' },
              { icon: Shield, title: 'HTTP Headers', description: 'Security headers analysis: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.' },
              { icon: Server, title: 'DNS Records', description: 'SPF, DKIM, DMARC validation. Detects dangling CNAMEs and zone transfer misconfigurations.' },
            ].map((item) => (
              <div key={item.title} className="border border-border rounded-xl p-5 bg-surface-1/30">
                <item.icon className="w-5 h-5 text-panguard-green mb-3" />
                <h4 className="text-sm font-semibold text-text-primary mb-2">{item.title}</h4>
                <p className="text-xs text-text-secondary leading-relaxed">{item.description}</p>
              </div>
            ))}
          </div>
        </FadeInUp>

        {/* Code Scanning */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-4">
            Code Scanning (SAST)
          </h2>
          <span className="inline-block text-xs bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 rounded-full px-2.5 py-0.5 font-medium mb-6">
            Beta
          </span>
          <p className="text-sm text-text-secondary mb-4">
            Panguard includes a built-in static application security testing engine.
            Point it at any source directory to detect vulnerabilities, insecure patterns,
            and leaked secrets before they reach production.
          </p>
          <CodeBlock
            title="Scan the current directory"
            code="panguard scan code --dir ."
          />
          <CodeBlock
            title="Scan a specific project with JSON output"
            code="panguard scan code --dir ./my-app --json"
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">How It Works</h3>
          <div className="space-y-4">
            <div className="border border-border rounded-xl p-5 bg-surface-1/30">
              <div className="flex items-center gap-3 mb-2">
                <Terminal className="w-5 h-5 text-panguard-green" />
                <h4 className="text-sm font-semibold text-text-primary">Semgrep Integration</h4>
              </div>
              <p className="text-xs text-text-secondary leading-relaxed">
                When Semgrep is installed locally, Panguard delegates to it for deep
                pattern-based analysis across 30+ languages. If Semgrep is not available,
                Panguard falls back to its own built-in rule engine.
              </p>
            </div>
            <div className="border border-border rounded-xl p-5 bg-surface-1/30">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="w-5 h-5 text-panguard-green" />
                <h4 className="text-sm font-semibold text-text-primary">Built-in Patterns</h4>
              </div>
              <p className="text-xs text-text-secondary leading-relaxed">
                Even without Semgrep, Panguard scans for SQL injection, command injection,
                path traversal, insecure deserialization, and XSS vulnerabilities using
                its own regex-based engine.
              </p>
            </div>
            <div className="border border-border rounded-xl p-5 bg-surface-1/30">
              <div className="flex items-center gap-3 mb-2">
                <Database className="w-5 h-5 text-panguard-green" />
                <h4 className="text-sm font-semibold text-text-primary">Secrets Detection</h4>
              </div>
              <p className="text-xs text-text-secondary leading-relaxed">
                Scans all files for hardcoded API keys, AWS credentials, private keys,
                database connection strings, and tokens. Supports detection of 40+
                secret formats including GitHub, Stripe, and cloud provider patterns.
              </p>
            </div>
          </div>

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">Sample Output</h3>
          <CodeBlock
            code={`$ panguard scan code --dir ./my-app

PANGUARD CODE SCAN
===================
Directory:  ./my-app
Files:      142 scanned (38 skipped)
Engine:     semgrep + built-in
Duration:   6.2s

FINDINGS:
  [CRITICAL]  SQL injection in db/queries.py:47
              Use parameterized queries instead of string concatenation

  [HIGH]      Hardcoded AWS access key in config/settings.py:12
              Move to environment variable or secrets manager

  [MEDIUM]    Missing CSRF protection on POST /api/update
              Add CSRF token validation middleware

  [LOW]       Console.log left in production code (3 instances)
              Remove debug logging before deploy

SUMMARY: 1 critical, 1 high, 1 medium, 1 low`}
          />
        </FadeInUp>

        {/* CTA */}
        <FadeInUp className="mt-16">
          <div className="bg-surface-1/50 border border-border rounded-2xl p-8 text-center">
            <h3 className="text-xl font-bold text-text-primary mb-3">Start Scanning</h3>
            <p className="text-text-secondary mb-6 max-w-lg mx-auto">
              Install Panguard and run your first security scan in under a minute. The
              Community plan includes unlimited local scans, free forever.
            </p>
            <CodeBlock code="curl -fsSL https://panguard.ai/api/install | bash && panguard scan" />
            <div className="flex flex-wrap justify-center gap-3 mt-6">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center gap-2 bg-panguard-green text-white font-semibold rounded-full px-6 py-2.5 text-sm hover:bg-panguard-green-light transition-all"
              >
                Getting Started Guide
              </Link>
              <Link
                href="/docs/cli"
                className="inline-flex items-center gap-2 border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-6 py-2.5 text-sm transition-all"
              >
                CLI Reference
              </Link>
            </div>
          </div>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
