'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight, Check, X } from 'lucide-react';
import {
  GlobalIcon,
  ShieldIcon,
  ScanIcon,
  NetworkIcon,
  LockIcon,
  CheckIcon,
  AnalyticsIcon,
} from '@/components/ui/BrandIcons';

/* ─── Flow Step Icons ─── */
const flowIcons = [ScanIcon, LockIcon, ShieldIcon, NetworkIcon, GlobalIcon];
const flowKeys = ['step1', 'step2', 'step3', 'step4', 'step5'] as const;

/* ─── Privacy Icons ─── */
const privacyIcons = [LockIcon, ShieldIcon, CheckIcon];

/* ─── Flywheel Config ─── */
const flywheelIcons = [GlobalIcon, ScanIcon, NetworkIcon, ShieldIcon];
const flywheelKeys = ['step1', 'step2', 'step3', 'step4'] as const;

export default function ThreatCloudContent() {
  const t = useTranslations('threatCloud');

  return (
    <>
      {/* ── Hero ── */}
      <section className="relative min-h-[60vh] flex items-center px-4 sm:px-6 lg:px-[120px] py-16 sm:py-28 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative text-center w-full">
          <FadeInUp>
            <div className="relative w-20 h-20 mx-auto mb-4 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-brand-sage/20 animate-[spin_12s_linear_infinite]" />
              <div className="absolute inset-2 rounded-full border border-brand-sage/10 animate-[spin_8s_linear_infinite_reverse]" />
              <GlobalIcon className="w-10 h-10 text-brand-sage relative" />
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
            <p className="text-xl text-text-secondary max-w-2xl mx-auto mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* ── Vision ── */}
      <SectionWrapper>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('vision.overline')}
              </p>
              <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('vision.title')}
              </h2>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <p className="text-text-secondary mt-6 leading-relaxed">{t('vision.desc1')}</p>
              <p className="text-text-secondary mt-4 leading-relaxed">{t('vision.desc2')}</p>
            </FadeInUp>
          </div>
          <FadeInUp delay={0.15}>
            <div className="bg-surface-1 rounded-xl border border-border p-8">
              <GlobalIcon className="w-10 h-10 text-brand-sage mb-6" />
              <div className="space-y-4">
                {(['users10', 'users1k', 'users100k'] as const).map((key, i) => (
                  <div key={key} className="flex items-start gap-3">
                    <div
                      className={`w-2 h-2 rounded-full mt-2 shrink-0 ${
                        i === 0 ? 'bg-text-tertiary' : i === 1 ? 'bg-[#60a5fa]' : 'bg-brand-sage'
                      }`}
                    />
                    <p className="text-sm text-text-secondary">{t(`flywheel.scale.${key}`)}</p>
                  </div>
                ))}
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── How it Works (5-step flow) ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('flow.overline')}
          title={t('flow.title')}
          subtitle={t('flow.subtitle')}
        />
        <div className="max-w-3xl mx-auto mt-14">
          <div className="relative">
            <div className="absolute left-[18px] top-0 bottom-0 w-px bg-border hidden sm:block" />
            {flowKeys.map((key, i) => {
              const Icon = flowIcons[i];
              return (
                <FadeInUp key={key} delay={i * 0.08}>
                  <div className="flex gap-6 mb-8 last:mb-0">
                    <div className="relative shrink-0">
                      <div className="w-9 h-9 rounded-full border border-brand-sage/30 bg-surface-2 flex items-center justify-center">
                        <Icon className="w-4 h-4 text-brand-sage" />
                      </div>
                    </div>
                    <div className="pb-2">
                      <p className="text-sm font-semibold text-text-primary">
                        {t(`flow.${key}.name`)}
                      </p>
                      <p className="text-sm text-text-secondary mt-1 leading-relaxed">
                        {t(`flow.${key}.desc`)}
                      </p>
                    </div>
                  </div>
                </FadeInUp>
              );
            })}
          </div>
        </div>
      </SectionWrapper>

      {/* ── Privacy Design ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('privacy.overline')}
          title={t('privacy.title')}
          subtitle={t('privacy.subtitle')}
        />
        <div className="grid sm:grid-cols-3 gap-4 mt-14">
          {(['item1', 'item2', 'item3'] as const).map((key, i) => {
            const Icon = privacyIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-1 rounded-xl border border-border p-6 h-full card-glow">
                  <Icon className="w-6 h-6 text-brand-sage mb-4" />
                  <p className="text-sm font-bold text-text-primary mb-2">
                    {t(`privacy.${key}.title`)}
                  </p>
                  <p className="text-sm text-text-secondary leading-relaxed">
                    {t(`privacy.${key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── Data Boundary ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('dataBoundary.overline')}
          title={t('dataBoundary.title')}
          subtitle={t('dataBoundary.subtitle')}
        />
        <div className="grid sm:grid-cols-2 gap-6 mt-14 max-w-3xl mx-auto">
          {/* Shared */}
          <FadeInUp>
            <div className="bg-surface-2 rounded-xl border border-border p-6">
              <p className="text-sm font-bold text-text-primary mb-4">
                {t('dataBoundary.shared.title')}
              </p>
              <ul className="space-y-2.5">
                {(t.raw('dataBoundary.shared.items') as string[]).map((item, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-sm text-text-secondary">
                    <Check className="w-4 h-4 text-brand-sage mt-0.5 shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </FadeInUp>

          {/* Private */}
          <FadeInUp delay={0.1}>
            <div className="bg-surface-2 rounded-xl border border-border p-6">
              <p className="text-sm font-bold text-text-primary mb-4">
                {t('dataBoundary.private.title')}
              </p>
              <ul className="space-y-2.5">
                {(t.raw('dataBoundary.private.items') as string[]).map((item, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-sm text-text-secondary">
                    <X className="w-4 h-4 text-[#ef4444] mt-0.5 shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Network Effect Flywheel ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('flywheel.overline')}
          title={t('flywheel.title')}
          subtitle={t('flywheel.subtitle')}
        />
        <div className="grid grid-cols-2 gap-4 mt-14 max-w-2xl mx-auto">
          {flywheelKeys.map((key, i) => {
            const Icon = flywheelIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-1 rounded-xl border border-border p-6 text-center card-glow">
                  <div className="w-10 h-10 rounded-full bg-brand-sage/10 mx-auto mb-3 flex items-center justify-center">
                    <Icon className="w-5 h-5 text-brand-sage" />
                  </div>
                  <p className="text-sm font-semibold text-text-primary">
                    {t(`flywheel.${key}.name`)}
                  </p>
                  <p className="text-xs text-text-secondary mt-1">{t(`flywheel.${key}.desc`)}</p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── API ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('api.overline')}
          title={t('api.title')}
          subtitle={t('api.subtitle')}
        />
        <div className="max-w-2xl mx-auto mt-14">
          <FadeInUp>
            <div className="bg-surface-2 rounded-xl border border-border p-6">
              <div className="grid sm:grid-cols-2 gap-4">
                {(t.raw('api.endpoints') as Array<{ name: string; desc: string }>).map((ep, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <AnalyticsIcon className="w-4 h-4 text-brand-sage mt-0.5 shrink-0" />
                    <div>
                      <p className="text-sm font-semibold text-text-primary">{ep.name}</p>
                      <p className="text-xs text-text-tertiary">{ep.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Tier Note ── */}
      <SectionWrapper dark>
        <div className="max-w-2xl mx-auto">
          <FadeInUp>
            <div className="bg-brand-sage/5 border border-brand-sage/20 rounded-xl p-6">
              <p className="text-sm font-bold text-brand-sage mb-2">{t('tierNote.title')}</p>
              <p className="text-sm text-text-secondary leading-relaxed">{t('tierNote.desc')}</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4">
                <div className="bg-surface-2/50 rounded-lg p-3">
                  <p className="text-xs text-text-muted">{t('tierNote.freeLabel')}</p>
                  <p className="text-sm font-semibold text-text-primary mt-1">
                    {t('tierNote.freeDesc')}
                  </p>
                </div>
                <div className="bg-surface-2/50 rounded-lg p-3">
                  <p className="text-xs text-text-muted">{t('tierNote.paidLabel')}</p>
                  <p className="text-sm font-semibold text-brand-sage mt-1">
                    {t('tierNote.paidDesc')}
                  </p>
                </div>
              </div>
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
            <code className="block text-sm bg-black/50 text-brand-sage px-6 py-3 rounded-lg mb-8 inline-block font-mono">
              $ curl -fsSL https://get.panguard.ai | bash
            </code>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.primary')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/docs/api"
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
