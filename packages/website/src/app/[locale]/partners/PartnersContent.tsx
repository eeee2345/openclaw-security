'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  NetworkIcon,
  SettingsIcon,
  GlobalIcon,
  AnalyticsIcon,
  DeployIcon,
  SupportIcon,
  TeamIcon,
  MonitorIcon,
  LockIcon,
  CheckIcon,
  ShieldIcon,
  EnterpriseIcon,
} from '@/components/ui/BrandIcons';

/* ────────────────────────────  Config  ──────────────────────────── */

const partnerTypeConfigs = [
  { key: 'msp' as const, icon: NetworkIcon },
  { key: 'technology' as const, icon: SettingsIcon },
  { key: 'reseller' as const, icon: GlobalIcon },
];

const benefitConfigs = [
  { key: 'item1' as const, icon: AnalyticsIcon },
  { key: 'item2' as const, icon: DeployIcon },
  { key: 'item3' as const, icon: SupportIcon },
  { key: 'item4' as const, icon: TeamIcon },
  { key: 'item5' as const, icon: LockIcon },
  { key: 'item6' as const, icon: MonitorIcon },
];

const tierConfigs = [
  { key: 'registered' as const, highlighted: false },
  { key: 'silver' as const, highlighted: true },
  { key: 'gold' as const, highlighted: false },
];

const statKeys = ['stat1', 'stat2', 'stat3', 'stat4'] as const;

/* ═══════════════════════  Component  ═══════════════════════════ */

export default function PartnersContent() {
  const t = useTranslations('partners');
  const tc = useTranslations('common');

  return (
    <>
      {/* -- Hero -- */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} serif subtitle={t('subtitle')} />
      </SectionWrapper>

      {/* -- Partner Types -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('models.overline')}
          title={t('models.title')}
          subtitle={t('models.subtitle')}
        />
        <div className="grid md:grid-cols-3 gap-6 mt-14">
          {partnerTypeConfigs.map((partner, i) => {
            const highlights = t.raw(`models.${partner.key}.highlights`) as string[];
            return (
              <FadeInUp key={partner.key} delay={i * 0.08}>
                <div className="bg-surface-1 border border-border rounded-2xl p-8 card-glow hover:border-brand-sage/40 transition-all h-full flex flex-col">
                  <partner.icon className="w-8 h-8 text-brand-sage mb-5" />
                  <h3 className="text-lg font-bold text-text-primary">
                    {t(`models.${partner.key}.title`)}
                  </h3>
                  <p className="text-[11px] uppercase tracking-wider text-brand-sage font-semibold mt-1 mb-3">
                    {t(`models.${partner.key}.subtitle`)}
                  </p>
                  <p className="text-sm text-text-secondary leading-relaxed mb-6">
                    {t(`models.${partner.key}.desc`)}
                  </p>
                  <ul className="space-y-2.5 mt-auto">
                    {highlights.map((item: string) => (
                      <li
                        key={item}
                        className="flex items-start gap-2.5 text-sm text-text-secondary"
                      >
                        <CheckIcon className="w-4 h-4 text-brand-sage mt-0.5 shrink-0" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* -- Benefits Grid -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('benefits.overline')}
          title={t('benefits.title')}
          subtitle={t('benefits.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 mt-14">
          {benefitConfigs.map((benefit, i) => (
            <FadeInUp key={benefit.key} delay={i * 0.06}>
              <div className="bg-surface-1 rounded-xl border border-border p-6 h-full hover:border-brand-sage/40 transition-all">
                <benefit.icon className="w-6 h-6 text-brand-sage mb-4" />
                <p className="text-sm font-bold text-text-primary">
                  {t(`benefits.${benefit.key}.title`)}
                </p>
                <p className="text-sm text-text-secondary mt-2 leading-relaxed">
                  {t(`benefits.${benefit.key}.desc`)}
                </p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Partner Tiers -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('tiers.overline')}
          title={t('tiers.title')}
          subtitle={t('tiers.subtitle')}
        />
        <div className="grid md:grid-cols-3 gap-5 mt-14 max-w-4xl mx-auto">
          {tierConfigs.map((tier, i) => {
            const features = t.raw(`tiers.${tier.key}.features`) as string[];
            return (
              <FadeInUp key={tier.key} delay={i * 0.08}>
                <div
                  className={`relative bg-surface-1 rounded-2xl p-8 border h-full flex flex-col ${
                    tier.highlighted ? 'border-brand-sage' : 'border-border'
                  }`}
                >
                  {tier.highlighted && (
                    <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-brand-sage text-surface-0 text-[11px] font-bold uppercase tracking-wider px-3 py-1 rounded-full">
                      {tc('mostPopular')}
                    </span>
                  )}

                  <div className="flex items-center gap-2 mb-1">
                    <ShieldIcon className="w-4 h-4 text-brand-sage" />
                    <p className="text-xs uppercase tracking-wider text-text-muted font-semibold">
                      {t(`tiers.${tier.key}.name`)}
                    </p>
                  </div>

                  <div className="mt-3 mb-2">
                    <span className="text-2xl font-extrabold text-text-primary">
                      {t(`tiers.${tier.key}.requirement`)}
                    </span>
                  </div>

                  <p className="text-sm text-text-secondary leading-relaxed mb-6">
                    {t(`tiers.${tier.key}.desc`)}
                  </p>

                  <ul className="space-y-3 flex-1">
                    {features.map((feature: string) => (
                      <li
                        key={feature}
                        className="flex items-start gap-2.5 text-sm text-text-secondary"
                      >
                        <CheckIcon className="w-4 h-4 text-brand-sage mt-0.5 shrink-0" />
                        {feature}
                      </li>
                    ))}
                  </ul>

                  <Link
                    href="/contact"
                    className={`mt-8 block text-center font-semibold rounded-full px-6 py-3 transition-all duration-200 active:scale-[0.98] ${
                      tier.highlighted
                        ? 'bg-brand-sage text-surface-0 hover:bg-brand-sage-light'
                        : 'border border-border text-text-secondary hover:border-brand-sage hover:text-text-primary'
                    }`}
                  >
                    {t('cta.applyNow')}
                  </Link>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* -- Stats -- */}
      <SectionWrapper spacing="tight">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 md:gap-8">
          {statKeys.map((key, i) => (
            <FadeInUp key={key} delay={i * 0.06}>
              <div className="text-center">
                <p className="text-[clamp(28px,3.5vw,40px)] font-extrabold text-brand-sage leading-none">
                  {t(`stats.${key}.value`)}
                </p>
                <p className="text-sm text-text-secondary mt-2">{t(`stats.${key}.label`)}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Apply CTA -- */}
      <SectionWrapper dark>
        <div className="text-center">
          <FadeInUp>
            <EnterpriseIcon className="w-10 h-10 text-brand-sage mx-auto mb-6" />
            <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary leading-[1.1]">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 max-w-xl mx-auto leading-relaxed">
              {t('cta.desc')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
              <Link
                href="/contact"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/demo"
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
