'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  AnalyticsIcon,
  ShieldIcon,
  GlobalIcon,
  DeployIcon,
  TerminalIcon,
  TeamIcon,
  EnterpriseIcon,
} from '@/components/ui/BrandIcons';

/* ─── Icon Mapping ─── */
const frameworkIcons = [ShieldIcon, AnalyticsIcon, GlobalIcon];
const taiwanIcons = [GlobalIcon, EnterpriseIcon, TerminalIcon, TeamIcon];

/* ─── Report Types ─── */
const reportTypes = [
  { name: 'ISO 27001 Gap Analysis', coverage: '94%', controls: 114, status: 'Ready' },
  { name: 'SOC 2 Type II Evidence', coverage: '87%', controls: 64, status: 'Ready' },
  { name: 'Taiwan Cyber Security Act', coverage: '91%', controls: 38, status: 'Ready' },
  { name: 'Executive Security Summary', coverage: '100%', controls: null, status: 'Ready' },
  { name: 'Incident Response Report', coverage: '100%', controls: null, status: 'Ready' },
  { name: 'Bilingual Report (EN/zh-TW)', coverage: '100%', controls: null, status: 'Ready' },
];

/* ─── Cost Comparison ─── */
const costRows = [
  { label: 'SOC 2 Preparation', consultant: '$30,000 - $60,000', panguard: 'Included' },
  { label: 'ISO 27001 Gap Analysis', consultant: '$15,000 - $40,000', panguard: 'Included' },
  { labelKey: 'tcsaRow' as const },
  { label: 'Time to Report', consultant: '2 - 4 months', panguard: 'Instant' },
  { labelKey: 'freshnessRow' as const },
  { label: 'Evidence Gathering', consultant: 'Manual', panguard: 'Automatic' },
];

/* ═══════════════════════════════════════════════════════════════════
   Compliance Content
   ═══════════════════════════════════════════════════════════════════ */
export default function ComplianceContent() {
  const t = useTranslations('compliance');

  const frameworkKeys = ['iso27001', 'soc2', 'tcsa'] as const;
  const taiwanKeys = ['item1', 'item2', 'item3', 'item4'] as const;

  return (
    <>
      {/* -- Hero -- */}
      <section className="relative min-h-[50vh] flex items-center px-6 lg:px-[120px] py-24 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[700px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative text-center w-full">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4">
              {t('overline')}
            </p>
            <h1 className="text-[clamp(36px,4.5vw,56px)] font-extrabold leading-[1.08] tracking-tight text-text-primary max-w-3xl mx-auto">
              {t('title')} <span className="text-brand-sage">{t('titleHighlight')}</span>
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-xl mx-auto mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.2}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/early-access"
                className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                Generate Your First Report
              </Link>
              <Link
                href="/demo"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                Schedule Demo
              </Link>
            </div>
          </FadeInUp>
        </div>
      </section>

      {/* -- Problem -- */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              The Problem
            </p>
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
              {t('problem.title')}
            </h2>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-text-secondary mt-5 leading-relaxed">{t('problem.desc')}</p>
            <p className="text-text-secondary mt-4 leading-relaxed">{t('problem.desc2')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Framework Detail Cards -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('frameworks.overline')}
          title={t('frameworks.title')}
          subtitle={t('frameworks.subtitle')}
        />
        <div className="grid md:grid-cols-3 gap-6 mt-14">
          {frameworkKeys.map((key, i) => {
            const Icon = frameworkIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-2 rounded-xl border border-border p-6 h-full flex flex-col">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-brand-sage/10 flex items-center justify-center">
                      <Icon className="w-5 h-5 text-brand-sage" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-text-primary">
                        {t(`frameworks.${key}.name`)}
                      </p>
                      <p className="text-[11px] text-text-muted">
                        {t(`frameworks.${key}.fullName`)}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 mb-5 py-3 border-y border-border">
                    <div className="text-center flex-1">
                      <p className="text-2xl font-extrabold text-brand-sage">
                        {t(`frameworks.${key}.coverage`)}
                      </p>
                      <p className="text-[10px] text-text-muted uppercase tracking-wider">
                        Coverage
                      </p>
                    </div>
                    <div className="text-center flex-1">
                      <p className="text-2xl font-extrabold text-text-primary">
                        {t(`frameworks.${key}.controls`)}
                      </p>
                      <p className="text-[10px] text-text-muted uppercase tracking-wider">
                        Controls
                      </p>
                    </div>
                  </div>

                  <div className="space-y-3 flex-1">
                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-brand-sage font-semibold mb-1">
                        Who needs it
                      </p>
                      <p className="text-xs text-text-secondary leading-relaxed">
                        {t(`frameworks.${key}.whoNeeds`)}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-brand-sage font-semibold mb-1">
                        What it covers
                      </p>
                      <p className="text-xs text-text-secondary leading-relaxed">
                        {t(`frameworks.${key}.whatItCovers`)}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-brand-sage font-semibold mb-1">
                        What Panguard does
                      </p>
                      <p className="text-xs text-text-secondary leading-relaxed">
                        {t(`frameworks.${key}.panguardDoes`)}
                      </p>
                    </div>
                  </div>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* -- Taiwan Focus -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('taiwanMarket.overline')}
          title={t('taiwanMarket.title')}
          subtitle={t('taiwanMarket.subtitle')}
        />
        <div className="grid sm:grid-cols-2 gap-6 mt-14">
          {taiwanKeys.map((key, i) => {
            const Icon = taiwanIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-1 rounded-xl border border-border p-6 h-full">
                  <Icon className="w-5 h-5 text-brand-sage mb-4" />
                  <p className="text-sm font-bold text-text-primary mb-2">
                    {t(`taiwanMarket.${key}.title`)}
                  </p>
                  <p className="text-xs text-text-secondary leading-relaxed">
                    {t(`taiwanMarket.${key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* -- Report Preview -- */}
      <SectionWrapper dark>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('reports.overline')}
              </p>
              <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('reports.title')}
              </h2>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <p className="text-text-secondary mt-5 leading-relaxed">{t('reports.desc')}</p>
            </FadeInUp>
          </div>
          <FadeInUp delay={0.15}>
            <div className="bg-surface-2 rounded-xl border border-border overflow-hidden">
              <div className="bg-surface-3 px-4 py-3 border-b border-border">
                <span className="text-sm font-semibold text-text-primary">Available Reports</span>
              </div>
              <div className="divide-y divide-border">
                {reportTypes.map((report) => (
                  <div
                    key={report.name}
                    className="px-4 py-3 flex items-center justify-between gap-4 hover:bg-surface-3/50 transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <AnalyticsIcon className="w-4 h-4 text-brand-sage shrink-0" />
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-text-primary truncate">
                          {report.name}
                        </p>
                        {report.controls && (
                          <p className="text-[11px] text-text-muted">
                            {report.controls} controls | {report.coverage} coverage
                          </p>
                        )}
                      </div>
                    </div>
                    <DeployIcon className="w-4 h-4 text-text-muted shrink-0" />
                  </div>
                ))}
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Cost Comparison -- */}
      <SectionWrapper>
        <div className="max-w-2xl mx-auto">
          <FadeInUp>
            <div className="text-center mb-10">
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('costComparison.overline')}
              </p>
              <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('costComparison.title')}
              </h2>
            </div>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="bg-surface-1 rounded-xl border border-border overflow-hidden">
              <div className="grid grid-cols-3 text-center text-xs font-semibold text-text-muted uppercase tracking-wider border-b border-border">
                <div className="p-3"></div>
                <div className="p-3 border-l border-border">Consultant</div>
                <div className="p-3 border-l border-border text-brand-sage">Panguard</div>
              </div>
              {costRows.map((row, i) => {
                const label =
                  'labelKey' in row ? t(`costComparison.${row.labelKey}.label`) : row.label;
                const consultant =
                  'labelKey' in row
                    ? t(`costComparison.${row.labelKey}.consultant`)
                    : row.consultant;
                const panguard =
                  'labelKey' in row ? t(`costComparison.${row.labelKey}.panguard`) : row.panguard;
                return (
                  <div
                    key={label}
                    className={`grid grid-cols-3 text-sm ${
                      i < costRows.length - 1 ? 'border-b border-border' : ''
                    }`}
                  >
                    <div className="p-3 text-text-primary font-medium">{label}</div>
                    <div className="p-3 text-text-tertiary border-l border-border">
                      {consultant}
                    </div>
                    <div className="p-3 text-brand-sage font-semibold border-l border-border">
                      {panguard}
                    </div>
                  </div>
                );
              })}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- CTA -- */}
      <SectionWrapper dark>
        <div className="text-center">
          <FadeInUp>
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-3 max-w-lg mx-auto">{t('cta.desc')}</p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/early-access"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/product/report"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.cta2')}
              </Link>
            </div>
          </FadeInUp>
          <FadeInUp delay={0.2}>
            <p className="text-xs text-text-muted mt-6">
              {t('cta.trustNote')}{' '}
              <Link
                href="/trust"
                className="text-brand-sage hover:text-brand-sage-light underline underline-offset-2"
              >
                {t('cta.trustLink')}
              </Link>
            </p>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
