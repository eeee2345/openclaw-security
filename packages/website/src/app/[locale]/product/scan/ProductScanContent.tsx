'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  ScanIcon,
  ResponseIcon,
  AnalyticsIcon,
  ShieldIcon,
  NetworkIcon,
  HistoryIcon,
  TerminalIcon,
  TeamIcon,
  EnterpriseIcon,
} from '@/components/ui/BrandIcons';

/* ─── Icon maps for features and use cases ─── */
const featureIcons = [
  ResponseIcon,
  AnalyticsIcon,
  ShieldIcon,
  NetworkIcon,
  NetworkIcon,
  HistoryIcon,
];
const featureKeys = ['item1', 'item2', 'item3', 'item4', 'item5', 'item6'] as const;

const useCaseIcons = [TerminalIcon, TeamIcon, EnterpriseIcon];
const useCaseKeys = ['item1', 'item2', 'item3'] as const;

export default function ProductScanContent() {
  const t = useTranslations('product.scan');

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
              <ScanIcon className="w-10 h-10 text-brand-sage relative" />
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
            <p className="text-text-secondary mt-4 leading-relaxed">{t('problem.conclusion')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Features ── */}
      <SectionWrapper dark>
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
                <div className="bg-surface-2 rounded-xl border border-border p-6 h-full card-glow">
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
                href="/docs"
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
