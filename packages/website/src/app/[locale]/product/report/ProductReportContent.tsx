'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  AnalyticsIcon,
  CheckIcon,
  ShieldIcon,
  HistoryIcon,
  TerminalIcon,
  TeamIcon,
  EnterpriseIcon,
  DeployIcon,
} from '@/components/ui/BrandIcons';

/* ─── Icon maps ─── */
const featureIcons = [
  AnalyticsIcon,
  CheckIcon,
  ShieldIcon,
  AnalyticsIcon,
  HistoryIcon,
  AnalyticsIcon,
];
const featureKeys = ['item1', 'item2', 'item3', 'item4', 'item5', 'item6'] as const;

const useCaseIcons = [TerminalIcon, TeamIcon, EnterpriseIcon];
const useCaseKeys = ['item1', 'item2', 'item3'] as const;

const reportKeys = ['iso27001', 'soc2', 'tcsa', 'executive', 'incident', 'bilingual'] as const;
const reportsWithControls = new Set(['iso27001', 'soc2', 'tcsa']);

const costComparisonKeys = ['soc2Prep', 'isoGap', 'timeToReport', 'freshness', 'evidence'] as const;

export default function ProductReportContent() {
  const t = useTranslations('product.report');

  return (
    <>
      {/* ── Hero ── */}
      <section className="relative min-h-[50vh] flex items-center px-6 lg:px-[120px] py-24 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[700px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative text-center w-full">
          <FadeInUp>
            <div className="relative w-20 h-20 mx-auto mb-4 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-brand-sage/20 animate-[spin_12s_linear_infinite]" />
              <div className="absolute inset-2 rounded-full border border-brand-sage/10 animate-[spin_8s_linear_infinite_reverse]" />
              <AnalyticsIcon className="w-10 h-10 text-brand-sage relative" />
            </div>
          </FadeInUp>
          <FadeInUp delay={0.05}>
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
        </div>
      </section>

      {/* ── Pain Point ── */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('problem.overline')}
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

      {/* ── Report Types Mockup ── */}
      <SectionWrapper dark>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('reportTypes.overline')}
              </p>
              <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('reportTypes.title')}
              </h2>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <p className="text-text-secondary mt-5 leading-relaxed">{t('reportTypes.desc')}</p>
            </FadeInUp>
          </div>
          <FadeInUp delay={0.15}>
            <div className="bg-surface-2 rounded-xl border border-border overflow-hidden">
              <div className="bg-surface-3 px-4 py-3 border-b border-border">
                <span className="text-sm font-semibold text-text-primary">
                  {t('reportTypes.libraryTitle')}
                </span>
              </div>
              <div className="divide-y divide-border">
                {reportKeys.map((key) => {
                  const name = t(`reports.${key}.name`);
                  const coverage = t(`reports.${key}.coverage`);
                  const hasControls = reportsWithControls.has(key);
                  const controls = hasControls ? String(t.raw(`reports.${key}.controls`)) : null;
                  return (
                    <div
                      key={key}
                      className="px-4 py-3 flex items-center justify-between gap-4 hover:bg-surface-3/50 transition-colors"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <AnalyticsIcon className="w-4 h-4 text-brand-sage shrink-0" />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-text-primary truncate">{name}</p>
                          {controls && (
                            <p className="text-[11px] text-text-muted">
                              {controls} controls | {coverage} coverage
                            </p>
                          )}
                        </div>
                      </div>
                      <DeployIcon className="w-4 h-4 text-text-muted shrink-0" />
                    </div>
                  );
                })}
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Features ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('features.overline')}
          title={t('features.title')}
          subtitle={t('features.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-14">
          {featureKeys.map((key, i) => {
            const Icon = featureIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-1 rounded-xl border border-border p-6 h-full card-glow">
                  <Icon className="w-5 h-5 text-brand-sage mb-4" />
                  <p className="text-sm font-bold text-text-primary mb-2">
                    {t(`featuresList.${key}.title`)}
                  </p>
                  <p className="text-xs text-text-secondary leading-relaxed">
                    {t(`featuresList.${key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── Cost Comparison ── */}
      <SectionWrapper dark>
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
            <div className="bg-surface-2 rounded-xl border border-border overflow-hidden">
              <div className="grid grid-cols-3 text-center text-xs font-semibold text-text-muted uppercase tracking-wider border-b border-border">
                <div className="p-3"></div>
                <div className="p-3 border-l border-border">{t('costComparison.consultant')}</div>
                <div className="p-3 border-l border-border text-brand-sage">
                  {t('costComparison.panguard')}
                </div>
              </div>
              {costComparisonKeys.map((key, i) => (
                <div
                  key={key}
                  className={`grid grid-cols-3 text-sm ${
                    i < costComparisonKeys.length - 1 ? 'border-b border-border' : ''
                  }`}
                >
                  <div className="p-3 text-text-primary font-medium">
                    {t(`costComparison.${key}.label`)}
                  </div>
                  <div className="p-3 text-text-tertiary border-l border-border">
                    {t(`costComparison.${key}.consultant`)}
                  </div>
                  <div className="p-3 text-brand-sage font-semibold border-l border-border">
                    {t(`costComparison.${key}.panguard`)}
                  </div>
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Use Cases ── */}
      <SectionWrapper>
        <SectionTitle overline={t('useCases.overline')} title={t('useCases.title')} />
        <div className="grid sm:grid-cols-3 gap-6 mt-14">
          {useCaseKeys.map((key, i) => {
            const Icon = useCaseIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.1}>
                <div className="bg-surface-1 rounded-xl border border-border p-6 h-full card-glow">
                  <Icon className="w-6 h-6 text-brand-sage mb-4" />
                  <p className="text-sm font-bold text-text-primary mb-2">
                    {t(`useCases.${key}.title`)}
                  </p>
                  <p className="text-xs text-text-secondary leading-relaxed">
                    {t(`useCases.${key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── CTA ── */}
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
                href="/security"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
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
