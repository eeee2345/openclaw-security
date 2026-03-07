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

const CHANNELS = [
  { name: 'Telegram', config: 'Bot token + Chat ID', command: 'panguard chat setup --channel telegram' },
  { name: 'Slack', config: 'Webhook URL', command: 'panguard chat setup --channel slack' },
  { name: 'LINE', config: 'Channel access token', command: 'panguard chat setup --channel line' },
  { name: 'Email', config: 'SMTP credentials', command: 'panguard chat setup --channel email' },
  { name: 'Webhook', config: 'Custom URL + secret', command: 'panguard chat setup --channel webhook' },
];

const NOTIFICATION_TYPES = [
  { type: 'Threat Alerts', timing: 'Immediate', description: 'Real-time notifications when threats are detected. Includes severity, source IP, and recommended action.' },
  { type: 'Daily Summaries', timing: 'Daily at 09:00', description: 'Aggregated overview of all security events from the past 24 hours with trend analysis.' },
  { type: 'Weekly Reports', timing: 'Monday 09:00', description: 'Comprehensive weekly digest with risk score changes, top threats, and compliance status.' },
  { type: 'System Status', timing: 'On change', description: 'Guard start/stop events, scan completions, configuration changes, and license alerts.' },
];

/* ════════════════════════  Component  ═════════════════════════ */

export default function ChatDocsContent() {
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
              <span className="text-text-secondary">Chat</span>
            </div>
            <h1 className="text-[clamp(32px,4vw,48px)] font-bold text-text-primary leading-[1.1]">
              Panguard Chat
            </h1>
            <p className="text-text-secondary mt-4 text-lg leading-relaxed">
              AI-powered security notifications delivered to your preferred channels.
              Get threat alerts in plain language via Telegram, Slack, LINE, Email, or custom Webhook.
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
              Connect your first notification channel in under two minutes.
            </p>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Launch the interactive setup wizard:
                </p>
                <CodeBlock
                  code="panguard chat setup"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Send a test message to verify connectivity:
                </p>
                <CodeBlock
                  code="panguard chat test"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Check which channels are currently active:
                </p>
                <CodeBlock
                  code="panguard chat status"
                  label="Terminal"
                />
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Supported Channels */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Supported Channels</h2>
            <p className="text-text-secondary mb-6">
              Panguard Chat supports five notification channels. Each can be configured independently.
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left">
                    <th className="pb-3 text-text-muted font-medium">Channel</th>
                    <th className="pb-3 text-text-muted font-medium">Configuration</th>
                    <th className="pb-3 text-text-muted font-medium">Setup Command</th>
                  </tr>
                </thead>
                <tbody>
                  {CHANNELS.map((ch, i) => (
                    <tr
                      key={ch.name}
                      className={i < CHANNELS.length - 1 ? 'border-b border-border/50' : ''}
                    >
                      <td className="py-3 text-text-primary font-medium">{ch.name}</td>
                      <td className="py-3 text-text-secondary">{ch.config}</td>
                      <td className="py-3 font-mono text-xs text-brand-sage">{ch.command}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Notification Types */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Notification Types</h2>
            <p className="text-text-secondary mb-6">
              Four categories of notifications keep you informed without overwhelming your inbox.
            </p>

            <div className="space-y-4">
              {NOTIFICATION_TYPES.map((nt) => (
                <div key={nt.type} className="bg-surface-1 border border-border rounded-xl p-5">
                  <div className="flex items-baseline justify-between mb-2">
                    <p className="text-sm font-semibold text-text-primary">{nt.type}</p>
                    <span className="text-xs text-text-muted font-mono">{nt.timing}</span>
                  </div>
                  <p className="text-sm text-text-secondary leading-relaxed">{nt.description}</p>
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Message Format */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Message Format</h2>
            <p className="text-text-secondary mb-6">
              Threat alerts are formatted for quick scanning with all critical context inline.
            </p>

            <CodeBlock
              code={`[CRITICAL] Brute-force SSH detected
Host:       prod-web-01 (192.168.1.50)
Source IP:  203.0.113.42 (CN)
Attempts:   847 in 5 minutes
Confidence: 98.2%
Action:     IP blocked via iptables
Rule:       SIGMA/brute_force_ssh_T1110.001
Timestamp:  2025-03-08 14:23:07 UTC

View full report: https://app.panguard.ai/events/evt_abc123`}
              label="Example Notification"
            />
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Preferences */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Preferences</h2>
            <p className="text-text-secondary mb-6">
              Fine-tune notification behavior to reduce noise and match your workflow.
            </p>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Open the interactive preferences editor:
                </p>
                <CodeBlock
                  code="panguard chat prefs"
                  label="Terminal"
                />
              </div>

              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-3">Available Settings</p>
                <div className="space-y-3">
                  <div>
                    <p className="text-sm text-text-primary font-medium">Severity Threshold</p>
                    <p className="text-sm text-text-secondary">
                      Only receive alerts at or above a chosen severity: low, medium, high, or critical.
                    </p>
                    <CodeBlock
                      code="panguard chat prefs --severity high"
                      label="Terminal"
                    />
                  </div>
                  <div className="pt-2 border-t border-border/40">
                    <p className="text-sm text-text-primary font-medium">Quiet Hours</p>
                    <p className="text-sm text-text-secondary">
                      Suppress non-critical notifications during specified hours. Critical alerts always deliver.
                    </p>
                    <CodeBlock
                      code="panguard chat prefs --quiet-hours 22:00-08:00"
                      label="Terminal"
                    />
                  </div>
                  <div className="pt-2 border-t border-border/40">
                    <p className="text-sm text-text-primary font-medium">Language</p>
                    <p className="text-sm text-text-secondary">
                      Set the notification language. Supported: en, zh-TW.
                    </p>
                    <CodeBlock
                      code="panguard chat prefs --lang zh-TW"
                      label="Terminal"
                    />
                  </div>
                </div>
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Multiple Channels */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Multiple Channels</h2>
            <p className="text-text-secondary mb-6">
              Configure multiple channels simultaneously and route different severity levels to different destinations.
            </p>

            <CodeBlock
              code={`# Route critical alerts to Telegram (immediate attention)
panguard chat setup --channel telegram --severity critical

# Send all alerts to Slack for team visibility
panguard chat setup --channel slack --severity low

# Weekly summaries via email to management
panguard chat setup --channel email --type weekly`}
              label="Terminal"
            />

            <div className="bg-surface-1 border border-border rounded-xl p-5 mt-4">
              <p className="text-sm font-semibold text-text-primary mb-2">Routing Example</p>
              <p className="text-sm text-text-secondary leading-relaxed">
                A common pattern is to send critical and high alerts to Telegram for immediate mobile notifications,
                all severity levels to a dedicated Slack channel for team-wide visibility, and weekly
                compliance summaries via email to management stakeholders.
              </p>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* CTA */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto text-center">
          <FadeInUp>
            <h2 className="text-2xl font-bold text-text-primary mb-3">Get Started</h2>
            <p className="text-text-secondary mb-8 max-w-md mx-auto leading-relaxed">
              Install Panguard and connect your first notification channel in minutes.
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
