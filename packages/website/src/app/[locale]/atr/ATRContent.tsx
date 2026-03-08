'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import {
  ArrowRight,
  Shield,
  FileCode2,
  AlertTriangle,
  Check,
  X,
  Cpu,
  Lock,
  Eye,
  Users,
  KeyRound,
  Zap,
  Wrench,
  Database,
} from 'lucide-react';
import {
  ShieldIcon,
  ScanIcon,
  LockIcon,
  AlertIcon,
  CheckIcon,
} from '@/components/ui/BrandIcons';

/* -- Category config -- */

const categoryKeys = [
  'prompt-injection',
  'tool-poisoning',
  'context-exfiltration',
  'agent-manipulation',
  'privilege-escalation',
  'excessive-autonomy',
  'skill-compromise',
  'data-poisoning',
] as const;

const categoryIcons = [
  AlertTriangle,
  Wrench,
  Eye,
  Users,
  KeyRound,
  Zap,
  Lock,
  Database,
];

/* -- How-it-works steps -- */

const stepKeys = ['step1', 'step2', 'step3', 'step4'] as const;
const stepIcons = [FileCode2, Shield, Cpu, Zap];

/* -- YAML example block -- */

const YAML_EXAMPLE = `title: "Direct Prompt Injection via User Input"
id: ATR-2026-001
status: experimental
severity: high

references:
  owasp_llm:
    - "LLM01:2025 - Prompt Injection"

detection:
  conditions:
    - field: user_input
      operator: regex
      value: "(?i)(ignore|disregard)\\\\s+previous\\\\s+instructions"
  condition: any

response:
  actions:
    - block_input
    - alert
    - snapshot`;

export default function ATRContent() {
  const t = useTranslations('atrPage');

  return (
    <>
      {/* -- Hero -- */}
      <section className="relative min-h-[60vh] flex items-center px-5 sm:px-6 lg:px-[120px] py-16 sm:py-28 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative text-center w-full">
          <FadeInUp>
            <div className="relative w-20 h-20 mx-auto mb-4 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-brand-sage/20 animate-[spin_12s_linear_infinite]" />
              <div className="absolute inset-2 rounded-full border border-brand-sage/10 animate-[spin_8s_linear_infinite_reverse]" />
              <ShieldIcon className="w-10 h-10 text-brand-sage relative" />
            </div>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4">
              {t('hero.overline')}
            </p>
            <h1 className="text-[clamp(24px,4.5vw,56px)] font-extrabold leading-[1.08] tracking-tight text-text-primary max-w-3xl mx-auto">
              {t('hero.title')}{' '}
              <span className="text-brand-sage">{t('hero.titleHighlight')}</span>
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-2xl mx-auto mt-6 leading-relaxed">
              {t('hero.subtitle')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.15}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <a
                href={t('cta.githubUrl')}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.contribute')} <ArrowRight className="w-4 h-4" />
              </a>
              <Link
                href="/docs/getting-started"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.getStarted')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </section>

      {/* -- Problem Statement -- */}
      <SectionWrapper>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('problem.overline')}
              </p>
              <h2 className="text-[clamp(20px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('problem.title')}
              </h2>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <p className="text-text-secondary mt-6 leading-relaxed">{t('problem.desc1')}</p>
              <p className="text-text-secondary mt-4 leading-relaxed">{t('problem.desc2')}</p>
              <p className="text-text-primary font-semibold mt-4">{t('problem.desc3')}</p>
            </FadeInUp>
          </div>
          <FadeInUp delay={0.15}>
            <div className="space-y-4">
              {/* Sigma */}
              <div className="bg-surface-1 rounded-xl border border-border p-5 flex items-start gap-4">
                <div className="w-10 h-10 rounded-full bg-text-muted/10 flex items-center justify-center shrink-0">
                  <X className="w-5 h-5 text-text-muted" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-text-primary">{t('problem.sigmaTitle')}</p>
                  <p className="text-sm text-text-secondary mt-1">{t('problem.sigmaDesc')}</p>
                </div>
              </div>
              {/* YARA */}
              <div className="bg-surface-1 rounded-xl border border-border p-5 flex items-start gap-4">
                <div className="w-10 h-10 rounded-full bg-text-muted/10 flex items-center justify-center shrink-0">
                  <X className="w-5 h-5 text-text-muted" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-text-primary">{t('problem.yaraTitle')}</p>
                  <p className="text-sm text-text-secondary mt-1">{t('problem.yaraDesc')}</p>
                </div>
              </div>
              {/* ATR */}
              <div className="bg-surface-1 rounded-xl border border-brand-sage/30 p-5 flex items-start gap-4">
                <div className="w-10 h-10 rounded-full bg-brand-sage/10 flex items-center justify-center shrink-0">
                  <Check className="w-5 h-5 text-brand-sage" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-brand-sage">{t('problem.atrTitle')}</p>
                  <p className="text-sm text-text-secondary mt-1">{t('problem.atrDesc')}</p>
                </div>
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Rule Categories -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('categories.overline')}
          title={t('categories.title')}
          subtitle={t('categories.subtitle')}
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-14">
          {categoryKeys.map((key, i) => {
            const Icon = categoryIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.05}>
                <div className="bg-surface-2 rounded-xl border border-border p-6 h-full card-glow">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-9 h-9 rounded-full bg-brand-sage/10 flex items-center justify-center">
                      <Icon className="w-4 h-4 text-brand-sage" />
                    </div>
                    <span className="text-xs font-semibold text-brand-sage bg-brand-sage/10 px-2 py-0.5 rounded-full">
                      {t(`categories.items.${key}.count`)}
                    </span>
                  </div>
                  <p className="text-sm font-bold text-text-primary mb-2">
                    {t(`categories.items.${key}.name`)}
                  </p>
                  <p className="text-xs text-text-secondary leading-relaxed">
                    {t(`categories.items.${key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* -- How it Works -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('howItWorks.overline')}
          title={t('howItWorks.title')}
          subtitle={t('howItWorks.subtitle')}
        />
        <div className="grid lg:grid-cols-2 gap-12 mt-14 items-start">
          {/* Steps */}
          <div>
            <div className="relative">
              <div className="absolute left-[18px] top-0 bottom-0 w-px bg-border hidden sm:block" />
              {stepKeys.map((key, i) => {
                const Icon = stepIcons[i];
                return (
                  <FadeInUp key={key} delay={i * 0.08}>
                    <div className="flex gap-6 mb-8 last:mb-0">
                      <div className="relative shrink-0">
                        <div className="w-9 h-9 rounded-full border border-brand-sage/30 bg-surface-1 flex items-center justify-center">
                          <Icon className="w-4 h-4 text-brand-sage" />
                        </div>
                      </div>
                      <div className="pb-2">
                        <p className="text-sm font-semibold text-text-primary">
                          {t(`howItWorks.${key}.name`)}
                        </p>
                        <p className="text-sm text-text-secondary mt-1 leading-relaxed">
                          {t(`howItWorks.${key}.desc`)}
                        </p>
                      </div>
                    </div>
                  </FadeInUp>
                );
              })}
            </div>
          </div>

          {/* YAML example */}
          <FadeInUp delay={0.2}>
            <div className="bg-surface-1 rounded-xl border border-border overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-surface-2">
                <FileCode2 className="w-4 h-4 text-brand-sage" />
                <span className="text-xs font-semibold text-text-secondary">
                  {t('howItWorks.ruleExample')}
                </span>
              </div>
              <pre className="p-4 text-xs text-text-secondary overflow-x-auto leading-relaxed font-mono">
                <code>{YAML_EXAMPLE}</code>
              </pre>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- OWASP Mapping -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('owasp.overline')}
          title={t('owasp.title')}
          subtitle={t('owasp.subtitle')}
        />
        <FadeInUp delay={0.1}>
          <div className="max-w-2xl mx-auto mt-14">
            <div className="bg-surface-2 rounded-xl border border-border overflow-hidden">
              {(
                t.raw('owasp.items') as Array<{
                  id: string;
                  name: string;
                  covered: boolean;
                }>
              ).map((item, i) => (
                <div
                  key={item.id}
                  className={`flex items-center justify-between px-5 py-3.5 ${
                    i < 9 ? 'border-b border-border/50' : ''
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono font-semibold text-text-muted w-14">
                      {item.id}
                    </span>
                    <span className="text-sm text-text-primary">{item.name}</span>
                  </div>
                  {item.covered ? (
                    <CheckIcon className="w-4 h-4 text-status-safe" />
                  ) : (
                    <span className="text-[10px] text-text-muted bg-surface-1 px-2 py-0.5 rounded-full">
                      Roadmap
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* -- CTA -- */}
      <SectionWrapper>
        <div className="text-center max-w-2xl mx-auto">
          <FadeInUp>
            <h2 className="text-[clamp(20px,3.5vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 mb-8">{t('cta.desc')}</p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3">
              <a
                href={t('cta.githubUrl')}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.contribute')} <ArrowRight className="w-4 h-4" />
              </a>
              <Link
                href="/docs/getting-started"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.getStarted')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
