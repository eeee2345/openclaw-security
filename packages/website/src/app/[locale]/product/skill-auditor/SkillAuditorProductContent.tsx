'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Gauge,
  GitBranch,
  Globe,
  Terminal,
  Laptop,
  ChevronRight,
  Copy,
  Check,
  Eye,
  Lock,
  AlertTriangle,
  Search,
  Code,
  FileKey,
  Binary,
  Server,
  UserCheck,
  ScanLine,
  ClipboardCheck,
  Smartphone,
} from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';

/* ── Reusable CodeBlock ── */
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

/* ── Static config ── */
const pillarKeys = ['preInstall', 'riskScore', 'cicd', 'crossPlatform'] as const;
const pillarIcons = [ShieldAlert, Gauge, GitBranch, Globe];

const checkKeys = [
  'promptInjection',
  'hiddenUnicode',
  'encodedPayloads',
  'toolPoisoning',
  'sastSecrets',
  'permissionScope',
  'manifestValidation',
] as const;
const checkIcons = [Shield, Eye, Binary, AlertTriangle, Code, FileKey, Search];

const workflowKeys = ['developer', 'smb', 'enterprise'] as const;
const workflowIcons = [Terminal, Laptop, GitBranch];
const workflowSteps = [
  [
    '$ panguard audit skill ./new-tool',
    'Scanning... done (0.3s)',
    'Risk: 8/100 (LOW)',
    'Safe to install.',
  ],
  [
    '# .github/workflows/skill-gate.yml',
    '- run: panguard audit skill ./skills/',
    '    --json --threshold 40',
    '  # Blocks PR if risk > 40',
  ],
  [
    '# panguard-manager policy',
    'skill_policy:',
    '  require_audit: true',
    '  max_risk_score: 39',
  ],
];

const riskLevels = [
  { range: '0-14', level: 'LOW', color: 'text-green-400', bg: 'bg-green-400/10', key: 'low' as const },
  { range: '15-39', level: 'MEDIUM', color: 'text-yellow-400', bg: 'bg-yellow-400/10', key: 'medium' as const },
  { range: '40-69', level: 'HIGH', color: 'text-orange-400', bg: 'bg-orange-400/10', key: 'high' as const },
  { range: '70-100', level: 'CRITICAL', color: 'text-red-400', bg: 'bg-red-400/10', key: 'critical' as const },
];

const comparisonRows = ['method', 'speed', 'coverage', 'consistency', 'output'] as const;

export default function SkillAuditorProductContent() {
  const t = useTranslations('product.skillAuditor');

  return (
    <>
      {/* ── Hero ── */}
      <section className="relative min-h-[60vh] flex items-center px-4 sm:px-6 lg:px-[120px] py-20 sm:py-32 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[500px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative text-center w-full">
          <FadeInUp>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-brand-sage/20 bg-brand-sage/5 text-brand-sage text-xs font-semibold tracking-wide mb-6">
              <Shield className="w-3.5 h-3.5" />
              {t('overline')}
            </div>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <h1 className="text-[clamp(32px,5vw,64px)] font-extrabold leading-[1.05] tracking-tight text-text-primary max-w-4xl mx-auto">
              {t('title')}
              <span className="text-brand-sage">{t('titleHighlight')}</span>
              {t('titleSuffix') && ` ${t('titleSuffix')}`}
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-2xl mx-auto mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.15}>
            <div className="flex flex-col sm:flex-row gap-3 justify-center mt-8">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-full bg-brand-sage text-surface-0 font-semibold text-sm hover:opacity-90 transition-opacity"
              >
                {t('cta1')} <ChevronRight className="w-4 h-4" />
              </Link>
              <Link
                href="/docs/skill-auditor"
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-full border border-border text-text-primary font-semibold text-sm hover:bg-surface-1 transition-colors"
              >
                {t('cta2')}
              </Link>
            </div>
          </FadeInUp>

          <FadeInUp delay={0.2}>
            <div className="max-w-2xl mx-auto mt-12">
              <CodeBlock
                title="terminal"
                code={`$ panguard audit skill ./skills/suspicious-agent

Scanning suspicious-agent... done (0.3s)
Risk Score: 72/100 (CRITICAL)

  [CRITICAL] Prompt injection: "ignore previous instructions"
             SKILL.md:42
  [HIGH]     Reverse shell: "bash -i >& /dev/tcp/..."
             SKILL.md:87

VERDICT: DO NOT INSTALL
Run with --json for machine-readable output.`}
              />
            </div>
          </FadeInUp>
        </div>
      </section>

      {/* ── Problem Statement ── */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto text-center">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4">
              {t('problem.overline')}
            </p>
            <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1]">
              {t('problem.title')}
            </h2>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-text-secondary mt-6 leading-relaxed text-lg">
              {t('problem.desc')}
            </p>
            <p className="text-text-secondary mt-4 leading-relaxed text-lg">
              {t('problem.desc2')}
            </p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Skill Vetting vs Panguard Comparison ── */}
      <SectionWrapper className="border-t border-border">
        <div className="max-w-[1000px] mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4 text-center">
              {t('comparison.overline')}
            </p>
            <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1] text-center max-w-2xl mx-auto">
              {t('comparison.title')}
            </h2>
            <p className="text-text-secondary mt-4 text-center max-w-xl mx-auto">
              {t('comparison.desc')}
            </p>
          </FadeInUp>

          {/* Desktop: table layout */}
          <FadeInUp delay={0.1}>
            <div className="mt-10 overflow-x-auto -mx-4 px-4">
              <div className="min-w-[560px] overflow-hidden rounded-2xl border border-border">
                {/* Table header */}
                <div className="grid grid-cols-3 bg-surface-1/50">
                  <div className="p-3 sm:p-4 border-b border-r border-border" />
                  <div className="p-3 sm:p-4 border-b border-r border-border text-center">
                    <div className="flex items-center justify-center gap-2">
                      <UserCheck className="w-4 h-4 text-text-muted" />
                      <span className="text-xs sm:text-sm font-bold text-text-secondary">
                        {t('comparison.vettingLabel')}
                      </span>
                    </div>
                  </div>
                  <div className="p-3 sm:p-4 border-b border-border text-center bg-brand-sage/5">
                    <div className="flex items-center justify-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-brand-sage" />
                      <span className="text-xs sm:text-sm font-bold text-brand-sage">
                        {t('comparison.panguardLabel')}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Table rows */}
                {comparisonRows.map((row, i) => (
                  <div
                    key={row}
                    className={`grid grid-cols-3 ${i < comparisonRows.length - 1 ? 'border-b border-border' : ''}`}
                  >
                    <div className="p-3 sm:p-4 border-r border-border flex items-center">
                      <span className="text-xs sm:text-sm font-semibold text-text-primary">
                        {t(`comparison.rows.${row}.label`)}
                      </span>
                    </div>
                    <div className="p-3 sm:p-4 border-r border-border flex items-center">
                      <span className="text-xs sm:text-sm text-text-muted">
                        {t(`comparison.rows.${row}.vetting`)}
                      </span>
                    </div>
                    <div className="p-3 sm:p-4 bg-brand-sage/5 flex items-center">
                      <span className="text-xs sm:text-sm text-text-primary font-medium">
                        {t(`comparison.rows.${row}.panguard`)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </FadeInUp>

          <FadeInUp delay={0.15}>
            <p className="text-text-muted text-xs text-center mt-4 italic">
              {t('comparison.footnote')}
            </p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── 4 Pillars (Why Panguard) ── */}
      <SectionWrapper className="border-t border-border">
        <div className="max-w-[1200px] mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4 text-center">
              {t('pillars.overline')}
            </p>
            <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1] text-center max-w-2xl mx-auto">
              {t('pillars.title')}
            </h2>
          </FadeInUp>

          <div className="grid md:grid-cols-2 gap-6 mt-12">
            {pillarKeys.map((key, i) => {
              const Icon = pillarIcons[i];
              return (
                <FadeInUp key={key} delay={0.05 * i}>
                  <div className="group p-6 rounded-2xl border border-border bg-surface-0 hover:border-brand-sage/30 transition-colors h-full">
                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 rounded-xl bg-brand-sage/10 flex items-center justify-center flex-shrink-0">
                        <Icon className="w-5 h-5 text-brand-sage" />
                      </div>
                      <div>
                        <h3 className="text-lg font-bold text-text-primary">
                          {t(`pillars.${key}.title`)}
                        </h3>
                        <p className="text-sm text-brand-sage font-medium mt-0.5">
                          {t(`pillars.${key}.subtitle`)}
                        </p>
                        <p className="text-text-secondary mt-3 text-sm leading-relaxed">
                          {t(`pillars.${key}.desc`)}
                        </p>
                        <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
                          <div className="p-2.5 rounded-lg bg-red-500/5 border border-red-500/10">
                            <span className="text-red-400 font-semibold block mb-1">
                              {t('pillars.themLabel')}
                            </span>
                            <span className="text-text-muted">{t(`pillars.${key}.them`)}</span>
                          </div>
                          <div className="p-2.5 rounded-lg bg-brand-sage/5 border border-brand-sage/10">
                            <span className="text-brand-sage font-semibold block mb-1">
                              {t('pillars.usLabel')}
                            </span>
                            <span className="text-text-muted">{t(`pillars.${key}.us`)}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </FadeInUp>
              );
            })}
          </div>
        </div>
      </SectionWrapper>

      {/* ── 7 Checks ── */}
      <SectionWrapper className="border-t border-border">
        <div className="max-w-[1200px] mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4 text-center">
              {t('checks.overline')}
            </p>
            <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1] text-center">
              {t('checks.title')}
            </h2>
          </FadeInUp>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-10">
            {checkKeys.map((key, i) => {
              const Icon = checkIcons[i];
              return (
                <FadeInUp key={key} delay={0.04 * i}>
                  <div className="p-5 rounded-xl border border-border bg-surface-0 hover:border-brand-sage/20 transition-colors h-full">
                    <Icon className="w-5 h-5 text-brand-sage mb-3" />
                    <h3 className="font-semibold text-text-primary text-sm">
                      {t(`checks.${key}.name`)}
                    </h3>
                    <p className="text-text-muted text-xs mt-1.5 leading-relaxed">
                      {t(`checks.${key}.detail`)}
                    </p>
                  </div>
                </FadeInUp>
              );
            })}
            <FadeInUp delay={0.04 * checkKeys.length}>
              <div className="p-5 rounded-xl border border-brand-sage/20 bg-brand-sage/5 h-full flex flex-col justify-center">
                <div className="flex items-center gap-6">
                  <div>
                    <div className="text-3xl font-extrabold text-brand-sage">{'<'}1s</div>
                    <div className="text-xs text-text-muted mt-1">{t('checks.scanTime')}</div>
                  </div>
                  <div>
                    <div className="text-3xl font-extrabold text-text-primary">7</div>
                    <div className="text-xs text-text-muted mt-1">{t('checks.checkCategories')}</div>
                  </div>
                  <div>
                    <div className="text-3xl font-extrabold text-text-primary">11+</div>
                    <div className="text-xs text-text-muted mt-1">{t('checks.injectionPatterns')}</div>
                  </div>
                </div>
              </div>
            </FadeInUp>
          </div>
        </div>
      </SectionWrapper>

      {/* ── Three Layers ── */}
      <SectionWrapper className="border-t border-border">
        <div className="max-w-[1000px] mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4 text-center">
              {t('checks.layers.overline')}
            </p>
            <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1] text-center max-w-2xl mx-auto">
              {t('checks.layers.title')}
            </h2>
          </FadeInUp>

          <FadeInUp delay={0.1}>
            <div className="mt-10 space-y-4">
              {(['layer1', 'layer2', 'layer3'] as const).map((key, i) => (
                <div key={key} className={`flex items-start gap-4 p-5 rounded-xl border ${i === 1 ? 'border-brand-sage/30 bg-brand-sage/5' : 'border-border bg-surface-0'}`}>
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 text-sm font-extrabold ${i === 1 ? 'bg-brand-sage/20 text-brand-sage' : 'bg-surface-1 text-text-muted'}`}>
                    {i + 1}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-semibold ${i === 1 ? 'text-brand-sage' : 'text-text-muted'}`}>
                        {t(`checks.layers.${key}.label`)}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-text-primary mt-0.5">
                      {t(`checks.layers.${key}.name`)}
                    </h3>
                    <p className="text-sm text-text-secondary mt-1 leading-relaxed">
                      {t(`checks.layers.${key}.desc`)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Risk Score ── */}
      <SectionWrapper className="border-t border-border">
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4 text-center">
              {t('riskScoring.overline')}
            </p>
            <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1] text-center">
              {t('riskScoring.title')}
            </h2>
            <p className="text-text-secondary mt-4 text-center max-w-xl mx-auto">
              {t('riskScoring.desc')}
            </p>
          </FadeInUp>
          <div className="mt-8 space-y-3">
            {riskLevels.map((r, i) => (
              <FadeInUp key={r.level} delay={0.05 * i}>
                <div className={`flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 p-4 rounded-xl border border-border ${r.bg}`}>
                  <div className="flex items-center gap-3 sm:gap-4">
                    <div className={`text-xl sm:text-2xl font-extrabold ${r.color} w-16 sm:w-20 text-center flex-shrink-0`}>
                      {r.range}
                    </div>
                    <div className={`text-sm font-bold ${r.color} w-20 flex-shrink-0`}>{r.level}</div>
                  </div>
                  <div className="text-text-secondary text-sm flex-1 pl-16 sm:pl-0">
                    {t(`riskScoring.${r.key}`)}
                  </div>
                </div>
              </FadeInUp>
            ))}
          </div>
        </div>
      </SectionWrapper>

      {/* ── Real Workflows ── */}
      <SectionWrapper className="border-t border-border">
        <div className="max-w-[1200px] mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4 text-center">
              {t('workflows.overline')}
            </p>
            <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1] text-center">
              {t('workflows.title')}
            </h2>
          </FadeInUp>
          <div className="grid lg:grid-cols-3 gap-6 mt-10">
            {workflowKeys.map((key, i) => {
              const Icon = workflowIcons[i];
              return (
                <FadeInUp key={key} delay={0.05 * i}>
                  <div className="p-6 rounded-2xl border border-border bg-surface-0 h-full flex flex-col">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="w-8 h-8 rounded-lg bg-brand-sage/10 flex items-center justify-center">
                        <Icon className="w-4 h-4 text-brand-sage" />
                      </div>
                      <div>
                        <div className="text-xs text-brand-sage font-semibold">
                          {t(`workflows.${key}.persona`)}
                        </div>
                        <div className="text-sm font-bold text-text-primary">
                          {t(`workflows.${key}.title`)}
                        </div>
                      </div>
                    </div>
                    <div className="bg-[#111] rounded-lg p-3 font-mono text-xs text-gray-400 leading-relaxed flex-1">
                      {workflowSteps[i].map((s, j) => (
                        <div
                          key={j}
                          className={
                            s.startsWith('$') || s.startsWith('#') ? 'text-gray-200' : ''
                          }
                        >
                          {s}
                        </div>
                      ))}
                    </div>
                  </div>
                </FadeInUp>
              );
            })}
          </div>
        </div>
      </SectionWrapper>

      {/* ── Complementary Defense ── */}
      <SectionWrapper className="border-t border-border">
        <div className="max-w-[1000px] mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4 text-center">
              {t('complementary.overline')}
            </p>
            <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1] text-center max-w-2xl mx-auto">
              {t('complementary.title')}
            </h2>
            <p className="text-text-secondary mt-4 text-center max-w-xl mx-auto">
              {t('complementary.desc')}
            </p>
          </FadeInUp>

          {/* 3-layer defense pipeline */}
          <FadeInUp delay={0.1}>
            <div className="mt-10 grid md:grid-cols-3 gap-4">
              {/* Layer 1: Panguard Auditor */}
              <div className="p-6 rounded-2xl border-2 border-brand-sage/30 bg-brand-sage/5 text-center">
                <div className="w-12 h-12 rounded-xl bg-brand-sage/10 flex items-center justify-center mx-auto mb-4">
                  <ScanLine className="w-6 h-6 text-brand-sage" />
                </div>
                <div className="text-xs text-brand-sage font-semibold mb-1">
                  {t('complementary.layer1.phase')}
                </div>
                <h3 className="text-lg font-bold text-text-primary">
                  {t('complementary.layer1.name')}
                </h3>
                <p className="text-sm text-text-secondary mt-2">
                  {t('complementary.layer1.desc')}
                </p>
                <div className="mt-4 px-3 py-2 rounded-lg bg-surface-0 border border-border">
                  <div className="flex items-center gap-2 justify-center">
                    <ClipboardCheck className="w-4 h-4 text-brand-sage" />
                    <span className="text-xs text-text-muted italic">
                      {t('complementary.layer1.analogy')}
                    </span>
                  </div>
                </div>
              </div>

              {/* Layer 2: Runtime Permissions */}
              <div className="p-6 rounded-2xl border border-border bg-surface-0 text-center">
                <div className="w-12 h-12 rounded-xl bg-surface-1 flex items-center justify-center mx-auto mb-4">
                  <Lock className="w-6 h-6 text-text-secondary" />
                </div>
                <div className="text-xs text-text-muted font-semibold mb-1">
                  {t('complementary.layer2.phase')}
                </div>
                <h3 className="text-lg font-bold text-text-primary">
                  {t('complementary.layer2.name')}
                </h3>
                <p className="text-sm text-text-secondary mt-2">
                  {t('complementary.layer2.desc')}
                </p>
                <div className="mt-4 px-3 py-2 rounded-lg bg-surface-1/50 border border-border">
                  <div className="flex items-center gap-2 justify-center">
                    <Smartphone className="w-4 h-4 text-text-muted" />
                    <span className="text-xs text-text-muted italic">
                      {t('complementary.layer2.analogy')}
                    </span>
                  </div>
                </div>
              </div>

              {/* Layer 3: Panguard Guard */}
              <div className="p-6 rounded-2xl border-2 border-brand-sage/30 bg-brand-sage/5 text-center">
                <div className="w-12 h-12 rounded-xl bg-brand-sage/10 flex items-center justify-center mx-auto mb-4">
                  <Server className="w-6 h-6 text-brand-sage" />
                </div>
                <div className="text-xs text-brand-sage font-semibold mb-1">
                  {t('complementary.layer3.phase')}
                </div>
                <h3 className="text-lg font-bold text-text-primary">
                  {t('complementary.layer3.name')}
                </h3>
                <p className="text-sm text-text-secondary mt-2">
                  {t('complementary.layer3.desc')}
                </p>
                <div className="mt-4 px-3 py-2 rounded-lg bg-surface-0 border border-border">
                  <div className="flex items-center gap-2 justify-center">
                    <Shield className="w-4 h-4 text-brand-sage" />
                    <span className="text-xs text-text-muted italic">
                      {t('complementary.layer3.analogy')}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </FadeInUp>

          {/* Arrow flow */}
          <FadeInUp delay={0.15}>
            <div className="mt-6 flex items-center justify-center gap-2 text-xs text-text-muted">
              <span className="px-3 py-1 rounded-full bg-brand-sage/10 text-brand-sage font-semibold">
                {t('complementary.flowLabel')}
              </span>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── CTA ── */}
      <SectionWrapper className="border-t border-border">
        <div className="max-w-[800px] mx-auto text-center">
          <FadeInUp>
            <blockquote className="text-[clamp(18px,2.5vw,28px)] font-bold text-text-primary leading-[1.3] italic">
              &ldquo;{t('positioning.quote')}&rdquo;
            </blockquote>
            <p className="text-text-secondary mt-4 text-base leading-relaxed max-w-xl mx-auto">
              {t('positioning.explanation')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="mt-12">
              <h2 className="text-[clamp(28px,3.5vw,44px)] font-bold text-text-primary leading-[1.1]">
                {t('cta.title')}
              </h2>
              <p className="text-text-secondary mt-4 text-lg">
                {t('cta.desc')}
              </p>
            </div>
          </FadeInUp>
          <FadeInUp delay={0.15}>
            <div className="max-w-lg mx-auto mt-8">
              <CodeBlock code="curl -fsSL https://panguard.ai/api/install | bash" title={t('cta.installTitle')} />
            </div>
            <div className="flex flex-col sm:flex-row gap-3 justify-center mt-6">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-full bg-brand-sage text-surface-0 font-semibold text-sm hover:opacity-90 transition-opacity"
              >
                {t('cta.cta1')} <ChevronRight className="w-4 h-4" />
              </Link>
              <Link
                href="/pricing"
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-full border border-border text-text-primary font-semibold text-sm hover:bg-surface-1 transition-colors"
              >
                {t('cta.cta2')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
