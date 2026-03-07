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

const HONEYPOT_TYPES = [
  {
    name: 'SSH Honeypot',
    port: '2222',
    captures: 'Credentials, commands, session recordings',
    description: 'Emulates an OpenSSH server. Captures login attempts, passwords, and post-auth commands entered by attackers.',
  },
  {
    name: 'HTTP Honeypot',
    port: '8080',
    captures: 'URLs, payloads, user agents, exploit attempts',
    description: 'Serves fake admin panels (WordPress, phpMyAdmin, cPanel). Records all HTTP requests and submitted credentials.',
  },
  {
    name: 'DNS Honeypot',
    port: '5353',
    captures: 'Query patterns, tunneling attempts, exfiltration',
    description: 'Detects DNS tunneling and data exfiltration. Identifies C2 communication channels hidden in DNS traffic.',
  },
];

/* ════════════════════════  Component  ═════════════════════════ */

export default function TrapDocsContent() {
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
              <span className="text-text-secondary">Trap</span>
            </div>
            <h1 className="text-[clamp(32px,4vw,48px)] font-bold text-text-primary leading-[1.1]">
              Panguard Trap
            </h1>
            <p className="text-text-secondary mt-4 text-lg leading-relaxed">
              Deploy honeypot decoys to detect, profile, and block attackers before they reach real assets.
              Captured intelligence feeds directly into Guard blocklists.
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
              Deploy honeypots with a single command. All services run in isolated containers.
            </p>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Deploy all configured honeypots:
                </p>
                <CodeBlock
                  code="panguard trap start"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Check running honeypots and captured events:
                </p>
                <CodeBlock
                  code="panguard trap status"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Stop all honeypot services:
                </p>
                <CodeBlock
                  code="panguard trap stop"
                  label="Terminal"
                />
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Honeypot Types */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Honeypot Types</h2>
            <p className="text-text-secondary mb-6">
              Three honeypot services cover the most common attack vectors.
            </p>

            <div className="space-y-4">
              {HONEYPOT_TYPES.map((hp) => (
                <div key={hp.name} className="bg-surface-1 border border-border rounded-xl p-5">
                  <div className="flex items-baseline justify-between mb-2">
                    <p className="text-sm font-semibold text-text-primary">{hp.name}</p>
                    <span className="text-xs text-text-muted font-mono">Port {hp.port}</span>
                  </div>
                  <p className="text-sm text-text-secondary leading-relaxed mb-3">{hp.description}</p>
                  <p className="text-xs text-text-muted">
                    <span className="text-brand-sage font-medium">Captures:</span> {hp.captures}
                  </p>
                </div>
              ))}
            </div>

            <div className="mt-6">
              <p className="text-sm text-text-secondary mb-2">
                Deploy a specific honeypot type:
              </p>
              <CodeBlock
                code={`panguard trap start --type ssh --port 2222
panguard trap start --type http --port 8080
panguard trap start --type dns --port 5353`}
                label="Terminal"
              />
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* How It Works */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">How It Works</h2>
            <p className="text-text-secondary mb-6">
              The Trap pipeline operates in four stages, from initial contact to automated defense.
            </p>

            <div className="space-y-3">
              {[
                { step: '1', title: 'Attacker Connects', desc: 'An attacker discovers and connects to a decoy service, believing it to be a real target.' },
                { step: '2', title: 'Capture Intelligence', desc: 'Panguard records credentials, source IP, geolocation, tools used, and attack techniques (mapped to MITRE ATT&CK).' },
                { step: '3', title: 'Auto-Block', desc: 'The attacker IP is automatically added to Guard blocklists, preventing access to real services.' },
                { step: '4', title: 'Feed Threat Intel', desc: 'Captured data enriches your local threat intelligence database and optionally uploads to Panguard Threat Cloud.' },
              ].map((item) => (
                <div key={item.step} className="flex gap-4 bg-surface-1 border border-border rounded-xl p-5">
                  <span className="text-brand-sage font-bold text-lg shrink-0 w-6">{item.step}</span>
                  <div>
                    <p className="text-sm font-semibold text-text-primary mb-1">{item.title}</p>
                    <p className="text-sm text-text-secondary leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Threat Intelligence */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Threat Intelligence</h2>
            <p className="text-text-secondary mb-6">
              View and manage the intelligence captured by your honeypots.
            </p>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  View captured threat data:
                </p>
                <CodeBlock
                  code="panguard trap intel"
                  label="Terminal"
                />
              </div>
              <div>
                <p className="text-sm text-text-secondary mb-2">
                  Export intelligence as JSON for integration with SIEMs:
                </p>
                <CodeBlock
                  code="panguard trap intel --json --last 7d"
                  label="Terminal"
                />
              </div>
            </div>

            <div className="bg-surface-1 border border-border rounded-xl p-5 mt-4">
              <p className="text-sm font-semibold text-text-primary mb-2">Auto-feed to Guard</p>
              <p className="text-sm text-text-secondary leading-relaxed">
                All captured attacker IPs are automatically added to Guard blocklists.
                No manual configuration required. The integration is bidirectional:
                Guard events can also trigger Trap to deploy targeted honeypots.
              </p>
            </div>

            <div className="bg-surface-1 border border-border rounded-xl p-5 mt-4">
              <p className="text-sm font-semibold text-text-primary mb-2">Threat Cloud (Optional)</p>
              <p className="text-sm text-text-secondary leading-relaxed">
                Opt in to share anonymized threat data with the Panguard Threat Cloud.
                In return, receive community-sourced blocklists from other Panguard deployments worldwide.
              </p>
              <div className="mt-3">
                <CodeBlock
                  code="panguard trap intel --cloud-upload enable"
                  label="Terminal"
                />
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Configuration */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Configuration</h2>
            <p className="text-text-secondary mb-6">
              Customize ports, interaction levels, and auto-block behavior.
            </p>

            <CodeBlock
              code={`# panguard.yaml — Trap configuration
trap:
  ssh:
    enabled: true
    port: 2222
    interaction: medium    # low | medium | high
    auto_block: true
  http:
    enabled: true
    port: 8080
    interaction: high
    auto_block: true
    panels:
      - wordpress
      - phpmyadmin
  dns:
    enabled: false
    port: 5353
    interaction: low
    auto_block: true
  auto_block_duration: 24h   # how long IPs stay blocked
  resource_limits:
    max_memory: 256m
    max_cpu: 0.5`}
              label="panguard.yaml"
            />

            <div className="bg-surface-1 border border-border rounded-xl p-5 mt-4">
              <p className="text-sm font-semibold text-text-primary mb-3">Interaction Levels</p>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left">
                      <th className="pb-3 text-text-muted font-medium">Level</th>
                      <th className="pb-3 text-text-muted font-medium">Behavior</th>
                      <th className="pb-3 text-text-muted font-medium">Use Case</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-border/50">
                      <td className="py-3 text-brand-sage font-mono">low</td>
                      <td className="py-3 text-text-secondary">Captures connection metadata only</td>
                      <td className="py-3 text-text-secondary">Minimal resource usage, IP collection</td>
                    </tr>
                    <tr className="border-b border-border/50">
                      <td className="py-3 text-brand-sage font-mono">medium</td>
                      <td className="py-3 text-text-secondary">Accepts credentials, records commands</td>
                      <td className="py-3 text-text-secondary">Balanced intelligence gathering</td>
                    </tr>
                    <tr>
                      <td className="py-3 text-brand-sage font-mono">high</td>
                      <td className="py-3 text-text-secondary">Full emulation with fake file system</td>
                      <td className="py-3 text-text-secondary">Maximum attacker profiling</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Safety */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">Safety</h2>
            <p className="text-text-secondary mb-6">
              Honeypots are designed to be safe by default. No real data is ever exposed.
            </p>

            <div className="space-y-3">
              {[
                { title: 'Container Isolation', desc: 'Each honeypot runs in an isolated container with no access to the host filesystem or network services.' },
                { title: 'No Real Data', desc: 'Decoy services contain only synthetic data. Fake credentials, dummy files, and fabricated database entries.' },
                { title: 'Resource Limits', desc: 'Configurable CPU and memory caps prevent honeypots from consuming production resources.' },
                { title: 'Network Segmentation', desc: 'Honeypot traffic is isolated on a dedicated virtual network, separate from production traffic.' },
              ].map((item) => (
                <div key={item.title} className="flex items-start gap-3 bg-surface-1 border border-border rounded-xl p-5">
                  <Check className="w-4 h-4 text-brand-sage shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-semibold text-text-primary mb-1">{item.title}</p>
                    <p className="text-sm text-text-secondary leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
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
              Deploy your first honeypot and start collecting threat intelligence today.
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
