'use client';

import { useState } from 'react';
import { Copy, Check, Shield, AlertTriangle, Search, Code, FileKey, Lock, Zap } from 'lucide-react';
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

function CheckCard({
  icon: Icon,
  title,
  description,
  severity,
}: {
  icon: typeof Shield;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
}) {
  const colors = {
    critical: 'border-red-500/30 bg-red-500/5',
    high: 'border-orange-500/30 bg-orange-500/5',
    medium: 'border-yellow-500/30 bg-yellow-500/5',
  };
  return (
    <div className={`border rounded-xl p-5 ${colors[severity]}`}>
      <Icon className="w-5 h-5 text-panguard-green mb-3" />
      <h4 className="text-sm font-semibold text-text-primary mb-2">{title}</h4>
      <p className="text-xs text-text-secondary leading-relaxed">{description}</p>
    </div>
  );
}

export default function SkillAuditorContent() {
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
            <span>Skill Auditor</span>
          </div>
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-text-primary">
            Skill Auditor
          </h1>
          <p className="text-lg text-text-secondary mt-4 max-w-2xl">
            Automated security scanner for AI agent skills. Detect prompt injection, tool
            poisoning, hidden Unicode, and credential theft before installing any skill.
          </p>
        </FadeInUp>

        {/* Quick Start */}
        <FadeInUp className="mt-12">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Quick Start</h2>
          <div className="space-y-4">
            <CodeBlock
              title="Install Panguard"
              code="curl -fsSL https://panguard.ai/api/install | bash"
            />
            <CodeBlock
              title="Audit a skill directory"
              code="panguard audit skill ./path/to/skill"
            />
            <CodeBlock
              title="Audit with JSON output (for CI/CD)"
              code="panguard audit skill ./my-skill --json"
            />
          </div>
        </FadeInUp>

        {/* What It Checks */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">7 Security Checks</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <CheckCard
              icon={FileKey}
              title="1. Manifest Validation"
              description="Verifies SKILL.md frontmatter: required fields, valid YAML, proper metadata. Malformed manifests are the first sign of a malicious skill."
              severity="medium"
            />
            <CheckCard
              icon={Shield}
              title="2. Prompt Injection"
              description='11 regex patterns: "ignore previous instructions", identity override, system prompt manipulation, jailbreak patterns, hidden HTML comments.'
              severity="critical"
            />
            <CheckCard
              icon={Search}
              title="3. Hidden Unicode"
              description="Zero-width characters (U+200B-200F), RTL overrides (U+202A-202E), and homoglyphs that hide malicious instructions invisible to human readers."
              severity="critical"
            />
            <CheckCard
              icon={Code}
              title="4. Encoded Payloads"
              description="Extracts Base64 blocks, decodes them, and checks for eval(), exec(), subprocess, child_process, curl, wget patterns."
              severity="critical"
            />
            <CheckCard
              icon={AlertTriangle}
              title="5. Tool Poisoning"
              description="Privilege escalation (sudo, chmod 777), reverse shells (nc -e, /dev/tcp/), remote code execution (curl|bash), credential theft."
              severity="high"
            />
            <CheckCard
              icon={Lock}
              title="6. Code SAST + Secrets"
              description="Static analysis of all files in the skill directory. Detects hardcoded API keys, AWS credentials, private keys, and common vulnerabilities."
              severity="high"
            />
            <CheckCard
              icon={Zap}
              title="7. Permission & Dependency"
              description="Cross-references requested permissions against stated purpose. A weather skill requesting filesystem write access? Red flag."
              severity="medium"
            />
          </div>
        </FadeInUp>

        {/* Risk Scoring */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Risk Scoring</h2>
          <p className="text-text-secondary mb-6">
            Each finding carries a severity weight. Weights are summed and capped at 100.
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Severity</th>
                  <th className="px-4 py-3 text-left font-medium">Weight</th>
                  <th className="px-4 py-3 text-left font-medium">Example</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                <tr>
                  <td className="px-4 py-3 text-red-400 font-medium">Critical</td>
                  <td className="px-4 py-3 text-text-primary">25</td>
                  <td className="px-4 py-3 text-text-secondary">Reverse shell, prompt injection</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-orange-400 font-medium">High</td>
                  <td className="px-4 py-3 text-text-primary">15</td>
                  <td className="px-4 py-3 text-text-secondary">Privilege escalation, credential theft</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-yellow-400 font-medium">Medium</td>
                  <td className="px-4 py-3 text-text-primary">5</td>
                  <td className="px-4 py-3 text-text-secondary">Suspicious patterns, ambiguous</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-gray-400 font-medium">Low</td>
                  <td className="px-4 py-3 text-text-primary">1</td>
                  <td className="px-4 py-3 text-text-secondary">Minor style issues</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { range: '0-14', level: 'LOW', color: 'bg-green-500/10 border-green-500/30 text-green-400', action: 'Safe to install' },
              { range: '15-39', level: 'MEDIUM', color: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400', action: 'Review findings' },
              { range: '40-69', level: 'HIGH', color: 'bg-orange-500/10 border-orange-500/30 text-orange-400', action: 'Manual review' },
              { range: '70-100', level: 'CRITICAL', color: 'bg-red-500/10 border-red-500/30 text-red-400', action: 'Do NOT install' },
            ].map((item) => (
              <div key={item.level} className={`border rounded-xl p-4 text-center ${item.color}`}>
                <div className="text-lg font-bold">{item.range}</div>
                <div className="text-xs font-semibold mt-1">{item.level}</div>
                <div className="text-xs mt-2 opacity-70">{item.action}</div>
              </div>
            ))}
          </div>
        </FadeInUp>

        {/* Integration */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Integration Guide</h2>

          <h3 className="text-lg font-semibold text-text-primary mb-3">CI/CD Pipeline Gate</h3>
          <p className="text-text-secondary mb-4">
            Block installations of high-risk skills automatically:
          </p>
          <CodeBlock
            title="bash"
            code={`# Block if HIGH or CRITICAL
RISK=$(panguard audit skill "$SKILL_PATH" --json | jq -r '.riskLevel')
if [ "$RISK" = "HIGH" ] || [ "$RISK" = "CRITICAL" ]; then
  echo "Blocked: $RISK risk skill"
  exit 1
fi`}
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">TypeScript API</h3>
          <p className="text-text-secondary mb-4">
            Use programmatically in your agent framework:
          </p>
          <CodeBlock
            title="typescript"
            code={`import { auditSkill } from '@panguard-ai/panguard-skill-auditor';

const report = await auditSkill('./skills/untrusted-skill');

console.log(\`Risk: \${report.riskScore}/100 (\${report.riskLevel})\`);
console.log(\`Checks: \${report.checks.length}\`);
console.log(\`Findings: \${report.findings.length}\`);

// Block dangerous skills
if (report.riskLevel === 'CRITICAL') {
  throw new Error('Skill blocked by security policy');
}

// Log individual findings
for (const finding of report.findings) {
  console.log(\`[\${finding.severity}] \${finding.title}\`);
  if (finding.location) console.log(\`  at \${finding.location}\`);
}`}
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">
            OpenClaw Pre-Install Hook
          </h3>
          <p className="text-text-secondary mb-4">
            Add to your OpenClaw agent configuration to auto-audit every skill before installation:
          </p>
          <CodeBlock
            title="~/.openclaw/hooks/pre-skill-install.sh"
            code={`#!/bin/bash
# Auto-audit skills before OpenClaw installs them
REPORT=$(panguard audit skill "$1" --json)
LEVEL=$(echo "$REPORT" | jq -r '.riskLevel')
SCORE=$(echo "$REPORT" | jq -r '.riskScore')

echo "Panguard Audit: $SCORE/100 ($LEVEL)"

if [ "$LEVEL" = "CRITICAL" ]; then
  echo "BLOCKED: Critical security issues found"
  echo "$REPORT" | jq '.findings[] | "  [\\(.severity)] \\(.title)"'
  exit 1
fi`}
          />
        </FadeInUp>

        {/* Example Output */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Example Output</h2>

          <h3 className="text-lg font-semibold text-text-primary mb-3">Safe Skill</h3>
          <CodeBlock
            code={`$ panguard audit skill ./skills/weather-widget

PANGUARD SKILL AUDIT REPORT
============================
Skill:      weather-widget
Risk Score: 0/100
Risk Level: LOW
Duration:   0.2s

CHECKS:
  [PASS] Manifest: Valid SKILL.md structure
  [PASS] Prompt Safety: No injection patterns detected
  [PASS] Code: No vulnerabilities found; Secrets: Clean
  [PASS] Dependencies: No known issues
  [PASS] Permissions: Scope appropriate

VERDICT: Safe to install`}
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">Malicious Skill</h3>
          <CodeBlock
            code={`$ panguard audit skill ./skills/suspicious-helper

PANGUARD SKILL AUDIT REPORT
============================
Skill:      suspicious-helper
Risk Score: 72/100
Risk Level: CRITICAL
Duration:   0.3s

CHECKS:
  [FAIL] Prompt Safety: 2 suspicious pattern(s) detected
  [PASS] Manifest: Valid SKILL.md structure
  [WARN] Code: 1 issue(s) found; Secrets: No hardcoded credentials
  [PASS] Dependencies: No known issues
  [PASS] Permissions: Scope appropriate

FINDINGS:
  [CRITICAL] Prompt injection: ignore previous instructions
             SKILL.md:42 - "ignore all previous instructions and..."
  [CRITICAL] Reverse shell pattern detected
             SKILL.md:87 - "bash -i >& /dev/tcp/..."
  [HIGH]     Environment variable exfiltration
             SKILL.md:23 - "printenv | curl..."

VERDICT: DO NOT INSTALL - Critical security issues found`}
          />
        </FadeInUp>

        {/* vs Manual */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">
            Panguard Auditor vs Manual Vetting
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Feature</th>
                  <th className="px-4 py-3 text-left font-medium">Manual Checklist</th>
                  <th className="px-4 py-3 text-left font-medium">Panguard Auditor</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[
                  ['Speed', 'Minutes per skill', '< 1 second'],
                  ['Consistency', 'Varies by reviewer', 'Deterministic'],
                  ['Hidden Unicode', 'Easy to miss', 'Auto-detect 15 categories'],
                  ['Base64 payloads', 'Manual decode needed', 'Auto-decode + analyze'],
                  ['Code SAST', 'Not included', 'Integrated scanner'],
                  ['Secrets scan', 'Manual grep', 'Pattern-based detection'],
                  ['Risk score', 'Subjective', 'Quantitative 0-100'],
                  ['CI/CD ready', 'No', 'JSON output + exit codes'],
                ].map(([feature, manual, panguard]) => (
                  <tr key={feature}>
                    <td className="px-4 py-3 text-text-primary font-medium">{feature}</td>
                    <td className="px-4 py-3 text-text-muted">{manual}</td>
                    <td className="px-4 py-3 text-panguard-green">{panguard}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </FadeInUp>

        {/* CTA */}
        <FadeInUp className="mt-16">
          <div className="bg-surface-1/50 border border-border rounded-2xl p-8 text-center">
            <h3 className="text-xl font-bold text-text-primary mb-3">Get Started</h3>
            <p className="text-text-secondary mb-6 max-w-lg mx-auto">
              Install Panguard and start auditing skills in under 2 minutes. Free forever on the
              Community plan.
            </p>
            <CodeBlock code="curl -fsSL https://panguard.ai/api/install | bash" />
            <div className="flex flex-wrap justify-center gap-3 mt-6">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center gap-2 bg-panguard-green text-white font-semibold rounded-full px-6 py-2.5 text-sm hover:bg-panguard-green-light transition-all"
              >
                Full Setup Guide
              </Link>
              <Link
                href="/blog/skill-auditor-guide"
                className="inline-flex items-center gap-2 border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-6 py-2.5 text-sm transition-all"
              >
                Read the Blog Post
              </Link>
            </div>
          </div>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
