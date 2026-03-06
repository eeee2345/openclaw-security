'use client';

import { useState, useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Copy, Check, Terminal, Monitor, Server } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';
import { STATS } from '@/lib/stats';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Platform = 'macos' | 'linux' | 'windows';
type InstallMethod = 'curl' | 'npm';

const PLATFORM_META: Record<Platform, { label: string; icon: typeof Terminal }> = {
  macos: { label: 'macOS', icon: Terminal },
  linux: { label: 'Linux', icon: Server },
  windows: { label: 'Windows', icon: Monitor },
};

// ---------------------------------------------------------------------------
// Install data — inspired by Claude Code's nested-tab pattern
// ---------------------------------------------------------------------------

interface InstallOption {
  method: InstallMethod;
  label: string;
  recommended?: boolean;
  prereq?: string;
  command: string;
  note?: string;
}

const INSTALL_OPTIONS: Record<Platform, InstallOption[]> = {
  macos: [
    {
      method: 'curl',
      label: 'One-line Install',
      recommended: true,
      command: 'curl -fsSL https://get.panguard.ai | bash',
      note: 'Apple Silicon (ARM64) native binary. Intel Mac users: install via npm, or enable Rosetta 2 first.',
    },
    {
      method: 'npm',
      label: 'npm',
      command: 'npm install -g @panguard-ai/panguard',
      note: 'Requires Node.js 20+. Works on both Apple Silicon and Intel Mac.',
    },
  ],
  linux: [
    {
      method: 'curl',
      label: 'One-line Install',
      recommended: true,
      command: 'curl -fsSL https://get.panguard.ai | bash',
      note: 'Supports x64 and ARM64 architectures. Requires Node.js 20+.',
    },
    {
      method: 'npm',
      label: 'npm',
      prereq:
        '# Ubuntu / Debian\ncurl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -\nsudo apt-get install -y nodejs\n\n# CentOS / RHEL\ncurl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -\nsudo yum install -y nodejs',
      command: 'npm install -g @panguard-ai/panguard',
    },
  ],
  windows: [
    {
      method: 'npm',
      label: 'npm (Recommended)',
      recommended: true,
      prereq: '# Install Node.js first (pick one):\nwinget install OpenJS.NodeJS.LTS\n# Or download from https://nodejs.org (v20+ LTS)',
      command: 'npm install -g @panguard-ai/panguard',
    },
    {
      method: 'curl',
      label: 'PowerShell',
      command: 'powershell -ExecutionPolicy Bypass -Command "irm https://get.panguard.ai/windows | iex"',
      note: 'If using PowerShell 7+: pwsh -ExecutionPolicy Bypass -Command "irm https://get.panguard.ai/windows | iex"',
    },
  ],
};

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

function useDetectedPlatform(): Platform {
  const [platform, setPlatform] = useState<Platform>('macos');
  useEffect(() => {
    const ua = navigator.userAgent;
    if (/Win/.test(ua)) setPlatform('windows');
    else if (/Linux/.test(ua)) setPlatform('linux');
  }, []);
  return platform;
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copyText = code.replace(/^#.*\n?/gm, '').trim();
  const handleCopy = () => {
    navigator.clipboard.writeText(copyText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#0c0d0c] border border-border rounded-xl overflow-hidden group">
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
      <pre className="p-4 text-sm font-mono text-text-secondary overflow-x-auto leading-relaxed whitespace-pre-wrap">
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

function PlatformTabs({
  selected,
  onChange,
}: {
  selected: Platform;
  onChange: (p: Platform) => void;
}) {
  const platforms: Platform[] = ['macos', 'linux', 'windows'];
  return (
    <div className="flex gap-1 bg-surface-1 border border-border rounded-lg p-1 w-fit">
      {platforms.map((p) => {
        const Icon = PLATFORM_META[p].icon;
        return (
          <button
            key={p}
            onClick={() => onChange(p)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
              selected === p
                ? 'bg-brand-sage text-white'
                : 'text-text-muted hover:text-text-secondary'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {PLATFORM_META[p].label}
          </button>
        );
      })}
    </div>
  );
}

function MethodTabs({
  options,
  selected,
  onChange,
}: {
  options: InstallOption[];
  selected: InstallMethod;
  onChange: (m: InstallMethod) => void;
}) {
  return (
    <div className="flex gap-1 bg-surface-1/50 border border-border/60 rounded-lg p-0.5 w-fit">
      {options.map((opt) => (
        <button
          key={opt.method}
          onClick={() => onChange(opt.method)}
          className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 ${
            selected === opt.method
              ? 'bg-surface-1 text-text-primary border border-border'
              : 'text-text-muted hover:text-text-secondary border border-transparent'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

function TerminalOutput({ lines }: { lines: string[] }) {
  return (
    <div className="bg-[#0c0d0c] border border-border rounded-xl p-4 font-mono text-sm space-y-1">
      {lines.map((line, i) => {
        const isOk = line.startsWith('[OK]');
        return (
          <p key={i} className={isOk ? 'text-status-safe' : 'text-text-muted'}>
            {line}
          </p>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function GettingStartedContent() {
  const t = useTranslations('docs.gettingStarted');
  const detectedPlatform = useDetectedPlatform();
  const [platform, setPlatform] = useState<Platform>('macos');
  const [method, setMethod] = useState<InstallMethod>('curl');

  useEffect(() => {
    setPlatform(detectedPlatform);
    setMethod(INSTALL_OPTIONS[detectedPlatform][0].method);
  }, [detectedPlatform]);

  const handlePlatformChange = (p: Platform) => {
    setPlatform(p);
    setMethod(INSTALL_OPTIONS[p][0].method);
  };

  const options = INSTALL_OPTIONS[platform];
  const activeOption = options.find((o) => o.method === method) || options[0];

  return (
    <>
      {/* Hero */}
      <SectionWrapper spacing="spacious">
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <Link
              href="/docs"
              className="text-sm text-text-muted hover:text-brand-sage transition-colors"
            >
              {t('backToDocs')}
            </Link>
            <h1 className="text-[clamp(32px,4vw,48px)] font-bold text-text-primary mt-4 leading-[1.1]">
              {t('title')}
            </h1>
            <p className="text-text-secondary mt-4 text-lg leading-relaxed">{t('subtitle')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 1: Install */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step1Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step1Desc')}</p>

            {/* Platform selector */}
            <PlatformTabs selected={platform} onChange={handlePlatformChange} />

            {/* Method selector */}
            <div className="mt-4 mb-5">
              <MethodTabs options={options} selected={method} onChange={setMethod} />
            </div>

            {/* Prereq (if any) */}
            {activeOption.prereq && (
              <div className="mb-3">
                <CodeBlock code={activeOption.prereq} label="Prerequisites" />
              </div>
            )}

            {/* Install command */}
            <CodeBlock code={activeOption.command} label="Install" />

            {/* Note */}
            {activeOption.note && (
              <p className="text-xs text-text-muted mt-2">{activeOption.note}</p>
            )}

            {/* Verify */}
            <div className="mt-6 pt-6 border-t border-border/40">
              <p className="text-sm text-text-secondary mb-3">
                Verify the installation:
              </p>
              <CodeBlock
                code={`panguard --version\n# Expected: ${STATS.cliVersion}`}
                label="Terminal"
              />
            </div>

            {/* Then start */}
            <div className="mt-4">
              <p className="text-sm text-text-secondary mb-3">
                Then start Panguard in any project:
              </p>
              <CodeBlock
                code={`cd your-project\npanguard scan`}
                label="Terminal"
              />
            </div>

            <div className="mt-4">
              <TerminalOutput
                lines={[
                  `[OK] Panguard v${STATS.cliVersion} installed`,
                  `[OK] Rule engine loaded (${STATS.sigmaRules.toLocaleString()} Sigma + ${STATS.yaraRules.toLocaleString()} YARA rules)`,
                  '[OK] Monitoring started. Learning period: 7 days.',
                ]}
              />
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 2: What you can do */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-6">{t('step2Title')}</h2>

            <div className="space-y-4">
              {/* Scan */}
              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">{t('step2Desc')}</p>
                <CodeBlock code="panguard scan" label="Terminal" />
                <p className="text-text-secondary text-sm mt-3">{t('step2Deep')}</p>
                <div className="mt-2">
                  <CodeBlock code="panguard scan --deep" label="Terminal" />
                </div>
              </div>

              {/* Guard */}
              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">{t('step3Title')}</p>
                <p className="text-text-secondary text-sm mb-3">{t('step3Desc')}</p>
                <CodeBlock code="panguard guard start" label="Terminal" />
              </div>

              {/* Chat */}
              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">{t('step4Title')}</p>
                <p className="text-text-secondary text-sm mb-3">{t('step4Desc')}</p>
                <CodeBlock
                  code={`panguard chat config\n# Follow the prompts to connect LINE, Slack, or Telegram`}
                  label="Terminal"
                />
              </div>

              {/* Understanding Scan Results */}
              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">{t('step5Title')}</p>
                <p className="text-text-secondary text-sm mb-3">{t('step5Desc')}</p>
                <ul className="space-y-1 text-sm text-text-secondary">
                  <li>{t('step5Score')}</li>
                  <li>{t('step5Grade')}</li>
                  <li>{t('step5Findings')}</li>
                </ul>
              </div>

              {/* JSON output */}
              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">{t('step6Title')}</p>
                <p className="text-text-secondary text-sm mb-3">{t('step6Desc')}</p>
                <CodeBlock code="panguard scan --json" label="Terminal" />
                <div className="mt-3">
                  <TerminalOutput
                    lines={[
                      '{"riskScore": 72, "findings": 8, "critical": 1, "high": 2, "medium": 3, "low": 2,',
                      ' "scanDuration": "47s", "framework": "ISO 27001",',
                      ' "topFinding": "SSH root login enabled (critical)"}',
                    ]}
                  />
                </div>
              </div>

              {/* SAST code scanning */}
              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">SAST Code Scanning</p>
                <p className="text-text-secondary text-sm mb-3">
                  Scan your source code for SQL injection, XSS, hardcoded secrets, and more.
                </p>
                <CodeBlock code="panguard scan code --dir ./my-app --json" label="Terminal" />
                <div className="mt-3">
                  <TerminalOutput
                    lines={[
                      '[OK] Scanning ./my-app (142 files)',
                      '[OK] Semgrep: 3 findings',
                      '[OK] Built-in patterns: 1 finding',
                      '[OK] Secrets scanner: 0 findings',
                      '{"totalFindings": 4, "critical": 1, "high": 2, "medium": 1,',
                      ' "topFinding": "Hardcoded AWS access key in config.js (critical)"}',
                    ]}
                  />
                </div>
                <span className="inline-block mt-2 text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-yellow-900/30 text-yellow-400">Beta</span>
              </div>

              {/* Remote scanning */}
              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">{t('step7Title')}</p>
                <p className="text-text-secondary text-sm mb-3">{t('step7Desc')}</p>
                <CodeBlock
                  code={`panguard scan --target example.com\npanguard scan --target 1.2.3.4 --json`}
                  label="Terminal"
                />
              </div>

              {/* Reports */}
              <div className="bg-surface-1 border border-border rounded-xl p-5">
                <p className="text-sm font-semibold text-text-primary mb-2">{t('step8Title')}</p>
                <p className="text-text-secondary text-sm mb-3">{t('step8Desc')}</p>
                <CodeBlock
                  code={`panguard report generate --framework iso27001\npanguard report generate --framework soc2\npanguard report generate --framework tcsa`}
                  label="Terminal"
                />
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* CLI Reference */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step9Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step9Desc')}</p>

            <div className="bg-[#0c0d0c] border border-border rounded-xl overflow-hidden">
              <div className="px-4 py-2 border-b border-border/60">
                <span className="text-xs text-text-muted font-mono">CLI Commands</span>
              </div>
              <div className="p-4 font-mono text-sm space-y-2">
                {[
                  { cmd: 'panguard scan', desc: 'Run security scan' },
                  { cmd: 'panguard scan --deep', desc: 'Deep scan with all engines' },
                  { cmd: 'panguard scan --json', desc: 'JSON output for AI agents' },
                  { cmd: 'panguard scan --target <host>', desc: 'Remote scanning' },
                  { cmd: 'panguard guard start', desc: 'Start real-time protection' },
                  { cmd: 'panguard guard status', desc: 'Check protection status' },
                  { cmd: 'panguard chat config', desc: 'Configure notifications' },
                  { cmd: 'panguard trap deploy', desc: 'Deploy honeypot decoys' },
                  { cmd: 'panguard report generate', desc: 'Generate compliance report' },
                  { cmd: 'panguard scan code --dir .', desc: 'SAST code scanning' },
                  { cmd: 'panguard doctor', desc: 'Diagnose installation' },
                  { cmd: 'panguard whoami', desc: 'Show account info' },
                  { cmd: 'panguard --help', desc: 'Show all commands' },
                ].map(({ cmd, desc }) => (
                  <div key={cmd} className="flex items-baseline gap-3">
                    <code className="text-text-primary whitespace-nowrap">{cmd}</code>
                    <span className="text-text-muted text-xs hidden sm:inline">{'—'}</span>
                    <span className="text-text-muted text-xs hidden sm:inline">{desc}</span>
                  </div>
                ))}
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Deployment Checklist */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('checklistTitle')}</h2>
            <p className="text-text-secondary mb-6">{t('checklistDesc')}</p>

            <div className="space-y-4">
              {(['cl1', 'cl2', 'cl3', 'cl4', 'cl5'] as const).map((key) => (
                <div key={key} className="bg-surface-1 border border-border rounded-xl p-5">
                  <p className="text-sm font-semibold text-text-primary mb-1">
                    {t(`${key}.title`)}
                  </p>
                  <p className="text-text-secondary text-sm mb-3">{t(`${key}.desc`)}</p>
                  <CodeBlock code={t(`${key}.cmd`)} label="Terminal" />
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Advanced Configuration Hints */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">
              {t('advancedHintTitle')}
            </h2>
            <p className="text-text-secondary mb-6">{t('advancedHintDesc')}</p>

            <div className="space-y-3">
              {[
                t('advancedHintOllama'),
                t('advancedHintFalco'),
                t('advancedHintSuricata'),
              ].map((hint) => (
                <div key={hint} className="flex items-start gap-3">
                  <Check className="w-4 h-4 text-brand-sage shrink-0 mt-0.5" />
                  <p className="text-sm text-text-secondary leading-relaxed">{hint}</p>
                </div>
              ))}
            </div>

            <p className="text-xs text-text-muted mt-4 mb-4">{t('advancedHintEnv')}</p>

            <Link
              href="/docs/advanced-setup"
              className="inline-flex items-center gap-1.5 text-sm text-brand-sage hover:text-brand-sage-light transition-colors font-medium"
            >
              {t('advancedHintLink')}
            </Link>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Multi-Endpoint Deployment Hints */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">
              {t('multiEndpointTitle')}
            </h2>
            <p className="text-text-secondary mb-6">{t('multiEndpointDesc')}</p>

            <CodeBlock
              code={`#!/bin/bash\n# servers.txt: one IP per line\nfor server in $(cat servers.txt); do\n  ssh root@$server 'curl -fsSL https://get.panguard.ai | bash && panguard guard start'\ndone`}
              label={t('multiEndpointSshLabel')}
            />

            <p className="text-sm text-text-secondary mt-4 mb-4">
              {t('multiEndpointAnsibleHint')}
            </p>

            <Link
              href="/docs/deployment"
              className="inline-flex items-center gap-1.5 text-sm text-brand-sage hover:text-brand-sage-light transition-colors font-medium"
            >
              {t('multiEndpointLink')}
            </Link>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Next steps CTA */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto text-center">
          <FadeInUp>
            <h2 className="text-2xl font-bold text-text-primary mb-3">{t('nextTitle')}</h2>
            <p className="text-text-secondary mb-8">{t('nextDesc')}</p>
            <div className="flex flex-wrap justify-center gap-3">
              <Link
                href="/docs"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('nextDocs')}
              </Link>
              <a
                href="https://github.com/panguard-ai/panguard-ai"
                target="_blank"
                rel="noopener noreferrer"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                GitHub
              </a>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
