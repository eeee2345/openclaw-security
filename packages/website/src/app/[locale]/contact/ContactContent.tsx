'use client';

import { useTranslations } from 'next-intl';
import { AnalyticsIcon, SupportIcon, TeamIcon, GlobalIcon } from '@/components/ui/BrandIcons';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import ContactForm from './ContactForm';

/* ────────────────────────  Channel Cards  ─────────────────────── */

const channelIcons = [AnalyticsIcon, SupportIcon, TeamIcon, AnalyticsIcon];
const channelKeys = ['sales', 'support', 'partnership', 'press'] as const;

/* ════════════════════════  Component  ═══════════════════════ */

export default function ContactContent() {
  const t = useTranslations('contact');

  return (
    <>
      <NavBar />
      <main>
        {/* ───────────── Hero ───────────── */}
        <section className="pt-24 pb-4 px-6 text-center">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('overline')}
            </p>
            <h1 className="text-[clamp(40px,5vw,64px)] font-bold text-text-primary leading-[1.08] max-w-3xl mx-auto">
              {t('title')}
            </h1>
            <p className="text-text-secondary mt-4 text-lg max-w-xl mx-auto leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </section>

        {/* ───────────── Channel Cards ───────────── */}
        <SectionWrapper>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 max-w-5xl mx-auto">
            {channelKeys.map((key, i) => {
              const Icon = channelIcons[i];
              return (
                <FadeInUp key={key} delay={i * 0.06}>
                  <div className="card-glow bg-surface-1 rounded-2xl border border-border p-6 h-full flex flex-col">
                    <div className="w-9 h-9 rounded-lg bg-surface-2 border border-border flex items-center justify-center mb-4">
                      <Icon className="w-4 h-4 text-brand-sage" />
                    </div>
                    <h3 className="text-text-primary font-semibold">
                      {t(`channels.${key}.title`)}
                    </h3>
                    <p className="text-sm text-text-secondary mt-2 leading-relaxed flex-1">
                      {t(`channels.${key}.desc`)}
                    </p>
                    <a
                      href={`mailto:${t(`channels.${key}.email`)}`}
                      className="text-sm text-brand-sage hover:text-brand-sage-light font-medium mt-4 transition-colors"
                    >
                      {t(`channels.${key}.email`)}
                    </a>
                  </div>
                </FadeInUp>
              );
            })}
          </div>
        </SectionWrapper>

        {/* ───────────── Contact Form + Location ───────────── */}
        <SectionWrapper dark>
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-12 max-w-5xl mx-auto">
            {/* Form */}
            <div className="lg:col-span-3">
              <FadeInUp>
                <h2 className="text-2xl font-bold text-text-primary mb-2">
                  {t('formSection.title')}
                </h2>
                <p className="text-text-secondary text-sm mb-8">{t('formSection.subtitle')}</p>
                <ContactForm />
              </FadeInUp>
            </div>

            {/* Location */}
            <div className="lg:col-span-2">
              <FadeInUp delay={0.1}>
                <div className="bg-surface-0 rounded-2xl border border-border p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <GlobalIcon className="w-4 h-4 text-brand-sage" />
                    <h3 className="text-text-primary font-semibold">{t('location.title')}</h3>
                  </div>
                  <p className="text-text-secondary text-sm leading-relaxed whitespace-pre-line">
                    {t('location.address')}
                  </p>
                  <div className="mt-6 pt-6 border-t border-border">
                    <p className="text-xs uppercase tracking-wider text-text-muted font-semibold mb-3">
                      {t('hours.title')}
                    </p>
                    <p className="text-sm text-text-secondary whitespace-pre-line">
                      {t('hours.schedule')}
                    </p>
                  </div>
                  <div className="mt-6 pt-6 border-t border-border">
                    <p className="text-xs uppercase tracking-wider text-text-muted font-semibold mb-3">
                      {t('responseTime.title')}
                    </p>
                    <p className="text-sm text-text-secondary">
                      {t('responseTime.general')}
                      <br />
                      {t('responseTime.support')}
                      <br />
                      {t('responseTime.security')}
                    </p>
                  </div>
                </div>
              </FadeInUp>
            </div>
          </div>
        </SectionWrapper>
      </main>
      <Footer />
    </>
  );
}
