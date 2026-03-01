'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  ResponseIcon,
  TerminalIcon,
  NetworkIcon,
  ShieldIcon,
  GlobalIcon,
} from '@/components/ui/BrandIcons';

/* ─── Belief Icons ─── */
const beliefIcons = [ShieldIcon, TerminalIcon, ResponseIcon, NetworkIcon];
const beliefKeys = ['tenet1', 'tenet2', 'tenet3', 'tenet4'] as const;

export default function AboutContent() {
  const t = useTranslations('about');

  return (
    <>
      {/* ── Hero ── */}
      <section className="relative min-h-[60vh] flex items-center px-6 lg:px-[120px] py-24 border-b border-border overflow-hidden">
        <div className="absolute top-1/4 left-1/3 w-[700px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-6">
              {t('overline')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <h1 className="text-[clamp(36px,4.5vw,56px)] font-extrabold leading-[1.1] tracking-tight text-text-primary max-w-4xl">
              {t('title')} <span className="text-brand-sage">{t('titleHighlight')}</span>
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-2xl text-text-secondary max-w-3xl mt-8 leading-relaxed italic">
              &ldquo;{t('oneLiner')}&rdquo;
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* ── Origin Story ── */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('origin.overline')}
            </p>
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
              {t('origin.title')}
            </h2>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-text-secondary mt-8 leading-relaxed text-lg">{t('origin.p1')}</p>
          </FadeInUp>
          <FadeInUp delay={0.15}>
            <p className="text-text-secondary mt-8 leading-relaxed text-lg">{t('origin.p2')}</p>
          </FadeInUp>
          <FadeInUp delay={0.2}>
            <p className="text-text-secondary mt-8 leading-relaxed text-lg">{t('origin.p3a')}</p>
            <p className="text-text-secondary mt-4 leading-relaxed text-lg">{t('origin.p3b')}</p>
            <p className="text-text-secondary mt-4 leading-relaxed text-lg">{t('origin.p3c')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── What We Believe ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('beliefs.overline')}
          title={t('beliefs.title')}
          subtitle={t('beliefs.subtitle')}
        />
        <div className="grid sm:grid-cols-2 gap-6 mt-14">
          {beliefKeys.map((key, i) => {
            const Icon = beliefIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-2 rounded-xl border border-border p-6 h-full card-glow">
                  <Icon className="w-6 h-6 text-brand-sage mb-4" />
                  <p className="text-base font-bold text-text-primary mb-2">
                    {t(`beliefs.${key}.title`)}
                  </p>
                  <p className="text-sm text-text-secondary leading-relaxed">
                    {t(`beliefs.${key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── By the Numbers ── */}
      <SectionWrapper>
        <SectionTitle overline={t('numbers.overline')} title={t('numbers.title')} />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-14">
          {(t.raw('numbers.stats') as Array<{ value: string; label: string }>).map((stat, i) => (
            <FadeInUp key={stat.label} delay={i * 0.05}>
              <div className="text-center">
                <p className="text-[clamp(28px,3.5vw,44px)] font-extrabold text-brand-sage">
                  {stat.value}
                </p>
                <p className="text-sm text-text-secondary mt-1">{stat.label}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── Built in Taiwan ── */}
      <SectionWrapper dark>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('taiwan.overline')}
              </p>
              <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('taiwan.title')}
              </h2>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <p className="text-text-secondary mt-6 leading-relaxed">{t('taiwan.desc1')}</p>
              <p className="text-text-secondary mt-4 leading-relaxed">{t('taiwan.desc2')}</p>
            </FadeInUp>
          </div>
          <FadeInUp delay={0.15}>
            <div className="bg-surface-2 rounded-xl border border-border p-8 text-center">
              <GlobalIcon className="w-12 h-12 text-brand-sage mx-auto mb-4" />
              <p className="text-4xl font-bold text-text-primary">Taiwan</p>
              <p className="text-sm text-text-tertiary mt-2">
                Open Source / MIT License / Global Impact
              </p>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── CTA ── */}
      <SectionWrapper>
        <div className="text-center max-w-2xl mx-auto">
          <FadeInUp>
            <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 mb-8">{t('cta.desc')}</p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3">
              <Link
                href="/careers"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.primary')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/contact"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.secondary')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
