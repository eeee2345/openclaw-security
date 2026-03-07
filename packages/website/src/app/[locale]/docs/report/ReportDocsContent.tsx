'use client';

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';

/* ────────────────────────  CodeBlock  ──────────────────────────── */

function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copyText = code.replace(/^#.*\n?/gm, '').trim();
  const handleCopy = () => {
    navigator.clipboard.writeText(copyText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#111] border border-border rounded-xl overflow-hidden group">
      {label && (
        <div className="px-4 py-2 border-b border-border/60 flex items-center justify-between">
          <span className="text-xs text-text-muted font-mono">{label}</span>
          <button
            onClick={handleCopy}
            className="text-text-muted hover:text-text-secondary transition-colors p-1 opacity-0 group-hover:opacity-100"
            aria-label="Copy code"
          >
            {copied ? (
              <Check className="w-3.5 h-3.5 text-status-safe" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      )}
      <pre className="p-4 font-mono text-sm text-gray-300 overflow-x-auto leading-relaxed whitespace-pre-wrap">
        {code.split('\n').map((line, i) => (
          <span key={i} className={line.startsWith('#') ? 'text-text-muted' : 'text-text-primary'}>
            {line}
            {i < code.split('\n').length - 1 && '\n'}
          </span>
        ))}
      </pre>
    </div>
  );
}

/* ────────────────────────  Data  ──────────────────────────── */

const FRAMEWORKS = [
  { name: 'ISO 27001', controls: '114 Annex A controls', coverage: '92%', flag: '--framework iso27001' },
  { name: 'SOC 2', controls: '64 Trust Services Criteria', coverage: '88%', flag: '--framework soc2' },
  { name: 'Taiwan TCSA', controls: 'ISMS requirements', coverage: '85%', flag: '--framework tcsa' },
];

const REPORT_CONTENTS = [
  { title: 'Executive Summary', desc: 'High-level overview of security posture, risk score, and key recommendations for stakeholders.' },
  { title: 'Risk Score', desc: 'Quantified risk assessment (0-100) with historical trend and comparison to industry benchmarks.' },
  { title: 'Prioritized Findings', desc: 'All findings ranked by severity and business impact, with effort estimates for remediation.' },
  { title: 'Control Mapping', desc: 'Each finding mapped to specific framework controls (e.g., ISO 27001 A.12.6.1) with compliance status.' },
  { title: 'Evidence Snapshots', desc: 'Auto-collected evidence from scan and guard data, timestamped and linked to relevant controls.' },
  { title: 'Remediation Steps', desc: 'AI-generated step-by-step fix instructions for each finding, including code examples where applicable.' },
];

/* ════════════════════════  Component  ═════════════════════════ */

export default function ReportDocsContent() {
  return (
    <>
      {/* Hero */}
      <SectionWrapper spacing="spacious">
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <div className="flex items-center gap-2 text-sm text-text-muted mb-4">
              <Link href="/docs" className="hover:text-brand-sage transition-colors">
                Docs
              </Link>
              <span>/</span>
              <span className="text-text-secondary">Report</span>
            </div>
            <h1 className="text-[clamp(32px,4vw,48px)] font-bold text-text-primary leading-[1.1]">
              Panguard Report
            </h1>
            <p className="text-text-secondary mt-4 text-lg leading-relaxed">
              Generate compliance reports for ISO 27001, SOC 2, and Taiwan TCSA.
              Automated evidence collection, AI-generated remediation steps, and bilingual PDF export.
            </p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Quick Start */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Quick Start</h2>
            <p className="text-text-secondary mb-6">
              Generate your first compliance report with a single command.
            </p>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Generate an ISO 27001 compliance report:
                </p>
                <CodeBlock
                  code="panguard report generate --framework iso27001"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  View a quick summary of the latest report:
                </p>
                <CodeBlock
                  code="panguard report summary"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  List all supported compliance frameworks:
                </p>
                <CodeBlock
                  code="panguard report list-frameworks"
                  label="Terminal"
                />
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Supported Frameworks */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Supported Frameworks</h2>
            <p className="text-text-secondary mb-6">
              Three compliance frameworks are supported out of the box. Each maps scan findings to specific controls.
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left">
                    <th className="pb-3 text-text-muted font-medium">Framework</th>
                    <th className="pb-3 text-text-muted font-medium">Scope</th>
                    <th className="pb-3 text-text-muted font-medium text-right">Auto-Coverage</th>
                    <th className="pb-3 text-text-muted font-medium">Flag</th>
                  </tr>
                </thead>
                <tbody>
                  {FRAMEWORKS.map((fw, i) => (
                    <tr
                      key={fw.name}
                      className={i < FRAMEWORKS.length - 1 ? 'border-b border-border/50' : ''}
                    >
                      <td className="py-3 text-text-primary font-medium">{fw.name}</td>
                      <td className="py-3 text-text-secondary">{fw.controls}</td>
                      <td className="py-3 text-brand-sage font-mono text-right">{fw.coverage}</td>
                      <td className="py-3 font-mono text-xs text-text-muted">{fw.flag}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Report Contents */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Report Contents</h2>
            <p className="text-text-secondary mb-6">
              Every generated report includes six sections designed for both technical teams and executive stakeholders.
            </p>

            <div className="space-y-3">
              {REPORT_CONTENTS.map((item) => (
                <div key={item.title} className="bg-surface-1 border border-border rounded-xl p-5">
                  <p className="text-sm font-semibold text-text-primary mb-1">{item.title}</p>
                  <p className="text-sm text-text-secondary leading-relaxed">{item.desc}</p>
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* PDF Export */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">PDF Export</h2>
            <p className="text-text-secondary mb-6">
              Export reports as professionally formatted PDF documents ready for stakeholder review.
            </p>

            <div className="space-y-4">
              <CodeBlock
                code={`# Generate and export as PDF
panguard report generate --framework soc2 --pdf

# Bilingual output (English + Traditional Chinese)
panguard report generate --framework iso27001 --pdf --lang en,zh-TW

# Include company branding
panguard report generate --framework tcsa --pdf --logo ./company-logo.png --company "Acme Corp"`}
                label="Terminal"
              />

              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">PDF Features</p>
                <ul className="space-y-2 text-sm text-text-secondary">
                  <li>Auto-generated table of contents with page numbers</li>
                  <li>Bilingual support: English and Traditional Chinese (zh-TW)</li>
                  <li>Custom company logo and branding on cover page</li>
                  <li>Charts and graphs for risk score trends</li>
                  <li>Appendix with raw evidence data</li>
                </ul>
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Scheduled Reports */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Scheduled Reports</h2>
            <p className="text-text-secondary mb-6">
              Automate report generation on a recurring schedule using cron-based scheduling.
            </p>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Schedule a weekly SOC 2 report:
                </p>
                <CodeBlock
                  code="panguard report schedule --weekly --framework soc2"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Schedule a monthly ISO 27001 report with PDF export:
                </p>
                <CodeBlock
                  code="panguard report schedule --monthly --framework iso27001 --pdf"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Custom cron schedule:
                </p>
                <CodeBlock
                  code={`# Every Friday at 18:00
panguard report schedule --cron "0 18 * * 5" --framework soc2 --pdf`}
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  List and manage scheduled reports:
                </p>
                <CodeBlock
                  code={`panguard report schedule --list
panguard report schedule --remove <schedule-id>`}
                  label="Terminal"
                />
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Evidence Collection */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Evidence Collection</h2>
            <p className="text-text-secondary mb-6">
              Panguard automatically collects and timestamps evidence from scan and guard data to support compliance findings.
            </p>

            <div className="bg-surface-1 border border-border rounded-xl p-5">
              <p className="text-sm font-semibold text-text-primary mb-3">How Evidence is Collected</p>
              <ul className="space-y-2 text-sm text-text-secondary">
                <li>Scan results are stored with timestamps and linked to framework controls</li>
                <li>Guard events provide real-time evidence of detection and response capabilities</li>
                <li>Configuration snapshots document security settings at the time of the report</li>
                <li>Trap intelligence demonstrates proactive threat detection measures</li>
              </ul>
            </div>

            <div className="bg-surface-1 border border-border rounded-xl p-5 mt-4">
              <p className="text-sm font-semibold text-text-primary mb-3">Log Retention by Tier</p>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left">
                      <th className="pb-3 text-text-muted font-medium">Tier</th>
                      <th className="pb-3 text-text-muted font-medium text-right">Retention</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-border/50">
                      <td className="py-3 text-text-secondary">Community</td>
                      <td className="py-3 text-text-primary font-mono text-right">7 days</td>
                    </tr>
                    <tr className="border-b border-border/50">
                      <td className="py-3 text-text-secondary">Solo</td>
                      <td className="py-3 text-text-primary font-mono text-right">30 days</td>
                    </tr>
                    <tr className="border-b border-border/50">
                      <td className="py-3 text-text-secondary">Pro</td>
                      <td className="py-3 text-text-primary font-mono text-right">90 days</td>
                    </tr>
                    <tr>
                      <td className="py-3 text-text-secondary">Business</td>
                      <td className="py-3 text-text-primary font-mono text-right">90+ days (configurable)</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* CI/CD Integration */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">CI/CD Integration</h2>
            <p className="text-text-secondary mb-6">
              Integrate compliance checks into your deployment pipeline with JSON output and exit codes.
            </p>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Generate a report in JSON format for automated processing:
                </p>
                <CodeBlock
                  code="panguard report generate --framework iso27001 --json"
                  label="Terminal"
                />
              </div>

              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Fail the pipeline if the risk score exceeds a threshold:
                </p>
                <CodeBlock
                  code={`# Exit code 1 if risk score > 70
panguard report generate --framework soc2 --json --fail-on-score 70`}
                  label="Terminal"
                />
              </div>

              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Example GitHub Actions step:
                </p>
                <CodeBlock
                  code={`# .github/workflows/compliance.yml
- name: Compliance Check
  run: |
    panguard report generate --framework iso27001 --json --fail-on-score 70
  env:
    PANGUARD_API_KEY: \${{ secrets.PANGUARD_API_KEY }}`}
                  label=".github/workflows/compliance.yml"
                />
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* CTA */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto text-center">
          <FadeInUp>
            <h2 className="text-2xl font-bold text-text-primary mb-3">Get Started</h2>
            <p className="text-text-secondary mb-8 max-w-md mx-auto leading-relaxed">
              Install Panguard and generate your first compliance report in minutes.
            </p>
            <div className="flex flex-wrap justify-center gap-3">
              <Link
                href="/docs/getting-started"
                className="bg-brand-sage text-surface-0 rounded-full px-8 py-3.5 font-semibold hover:bg-brand-sage-light transition-colors"
              >
                Getting Started Guide
              </Link>
              <Link
                href="/docs"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                All Documentation
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
